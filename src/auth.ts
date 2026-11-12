import { signValue, verifySignedValue } from "./crypto";
import { forbidden, unauthorized } from "./errors";
import { findActiveApiKey, touchApiKey } from "./keys";
import { verifyJwt } from "./oidc";
import { assertSameOriginMutation } from "./security";
import type { AdminPrincipal, ApiScope, AppContext, Env, SessionUser, TenantRow } from "./types";

type Ctx = AppContext;

/* ------------------------------------------------------------------ */
/* API key (headless admin API)                                        */
/* ------------------------------------------------------------------ */

export async function findTenantByApiKey(
  env: Env,
  apiKey: string,
): Promise<TenantRow | null> {
  const found = await findActiveApiKey(env, apiKey);
  return found?.tenant ?? null;
}

export function bearerToken(c: Ctx): string | null {
  const header = c.req.header("authorization");
  if (!header) return null;
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match ? (match[1] as string).trim() : null;
}

/* ------------------------------------------------------------------ */
/* Session cookie (admin UI, signed with SESSION_SECRET)               */
/* ------------------------------------------------------------------ */

export const SESSION_COOKIE = "__Host-hv_session";
export const FLOW_COOKIE = "__Host-hv_oidc_flow";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days
const FLOW_TTL_SECONDS = 60 * 10; // 10 minutes

function httpsRequest(requestUrl: string): boolean {
  return new URL(requestUrl).protocol === "https:";
}

export function sessionCookieName(requestUrl: string): string {
  return httpsRequest(requestUrl) ? SESSION_COOKIE : "hv_session";
}

export function flowCookieName(requestUrl: string): string {
  return httpsRequest(requestUrl) ? FLOW_COOKIE : "hv_oidc_flow";
}

export function parseCookies(c: Ctx): Record<string, string> {
  const header = c.req.header("cookie");
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq > 0) {
      out[part.slice(0, eq).trim()] = decodeURIComponent(part.slice(eq + 1).trim());
    }
  }
  return out;
}

function cookieHeader(name: string, value: string, maxAge: number, secure: boolean): string {
  const secureAttr = secure ? "; Secure" : "";
  const expires = maxAge === 0 ? "; Expires=Thu, 01 Jan 1970 00:00:00 GMT" : "";
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${expires}${secureAttr}`;
}

export async function makeSessionCookie(
  env: Env,
  user: Omit<SessionUser, "exp" | "kind">,
  requestUrl: string,
): Promise<string> {
  const payload: SessionUser = {
    kind: "session",
    ...user,
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
  };
  const value = await signValue(env.SESSION_SECRET, payload);
  const https = httpsRequest(requestUrl);
  return cookieHeader(sessionCookieName(requestUrl), value, SESSION_TTL_SECONDS, https);
}

export function clearSessionCookie(requestUrl: string): string {
  const https = httpsRequest(requestUrl);
  return cookieHeader(sessionCookieName(requestUrl), "", 0, https);
}

export async function getSessionUser(c: Ctx): Promise<SessionUser | null> {
  const cookies = parseCookies(c);
  const raw = cookies[sessionCookieName(c.req.url)];
  if (!raw) return null;
  const payload = await verifySignedValue<SessionUser>(c.env.SESSION_SECRET, raw);
  if (!payload || payload.kind !== "session") return null;
  if (typeof payload.sub !== "string" || payload.sub.length === 0 || payload.sub.length > 256) {
    return null;
  }
  if (typeof payload.exp !== "number" || payload.exp <= Math.floor(Date.now() / 1000)) return null;
  return payload;
}

export interface FlowState {
  kind: "flow";
  state: string;
  nonce: string;
  verifier: string;
  exp: number;
}

export async function makeFlowCookie(env: Env, flow: FlowState, requestUrl: string): Promise<string> {
  const value = await signValue(env.SESSION_SECRET, flow);
  const https = httpsRequest(requestUrl);
  return cookieHeader(flowCookieName(requestUrl), value, FLOW_TTL_SECONDS, https);
}

export async function readFlowCookie(c: Ctx): Promise<FlowState | null> {
  const cookies = parseCookies(c);
  const raw = cookies[flowCookieName(c.req.url)];
  if (!raw) return null;
  const flow = await verifySignedValue<FlowState>(c.env.SESSION_SECRET, raw);
  if (!flow || flow.kind !== "flow") return null;
  if (typeof flow.state !== "string" || typeof flow.nonce !== "string" || typeof flow.verifier !== "string") {
    return null;
  }
  if (typeof flow.exp !== "number" || flow.exp <= Math.floor(Date.now() / 1000)) return null;
  return flow;
}

export function clearFlowCookie(requestUrl: string): string {
  const https = httpsRequest(requestUrl);
  return cookieHeader(flowCookieName(requestUrl), "", 0, https);
}

/* ------------------------------------------------------------------ */
/* Tenant membership (OIDC users)                                      */
/* ------------------------------------------------------------------ */

export async function isTenantMember(
  env: Env,
  tenantId: string,
  sub: string,
): Promise<boolean> {
  const row = await env.DB.prepare(
    "SELECT 1 AS ok FROM tenant_members WHERE tenant_id = ?1 AND user_sub = ?2",
  )
    .bind(tenantId, sub)
    .first<{ ok: number }>();
  return row !== null;
}

export async function listTenantsForUser(
  env: Env,
  sub: string,
): Promise<TenantRow[]> {
  const res = await env.DB.prepare(
    `SELECT t.* FROM tenants t
     JOIN tenant_members m ON m.tenant_id = t.id
     WHERE m.user_sub = ?1 ORDER BY t.created_at ASC`,
  )
    .bind(sub)
    .all<TenantRow>();
  return res.results;
}

/* ------------------------------------------------------------------ */
/* Guards                                                              */
/* ------------------------------------------------------------------ */

/**
 * Authorize an admin operation on `tenantId`. Accepts either:
 * - `Authorization: Bearer <tenant API key>` for that tenant, or
 * - a valid admin-UI session whose user is a member of that tenant.
 */
export async function memberRole(
  env: Env,
  tenantId: string,
  sub: string,
): Promise<"owner" | "member" | null> {
  const row = await env.DB.prepare(
    "SELECT role FROM tenant_members WHERE tenant_id = ?1 AND user_sub = ?2",
  )
    .bind(tenantId, sub)
    .first<{ role: string }>();
  if (!row) return null;
  return row.role === "owner" ? "owner" : "member";
}

/**
 * `access: "owner"` is required for members, keys, webhooks, origins, and deletion.
 * A write API key counts as owner. A read key does not.
 */
export async function requireAdmin(
  c: Ctx,
  tenantId: string,
  need: ApiScope = "write",
  access: "member" | "owner" = "member",
): Promise<AdminPrincipal> {
  const token = bearerToken(c);
  if (token) {
    const found = await findActiveApiKey(c.env, token);
    if (!found || found.tenant.id !== tenantId) {
      throw unauthorized("INVALID_API_KEY", "API key is not valid for this tenant");
    }
    if (need === "write" && found.key.scope !== "write") {
      throw forbidden("This API key is read-only");
    }
    if (access === "owner" && found.key.scope !== "write") {
      throw forbidden("Owner access is required");
    }
    await touchApiKey(c.env, found.key.id);
    return {
      kind: "api_key",
      tenantId,
      keyId: found.key.id,
      prefix: found.key.key_prefix,
      scope: found.key.scope,
    };
  }
  const method = c.req.method.toUpperCase();
  if (method !== "GET" && method !== "HEAD") {
    assertSameOriginMutation(c);
  }
  const user = await getSessionUser(c);
  const role = user ? await memberRole(c.env, tenantId, user.sub) : null;
  if (user && role) {
    if (access === "owner" && role !== "owner") throw forbidden("Owner access is required");
    return { kind: "session", tenantId, sub: user.sub, role };
  }
  throw unauthorized("UNAUTHORIZED", "Admin authentication required");
}

/**
 * Optional voter identity for the voting API.
 * Returns the 0g0-id `sub` when a valid JWT is presented, null when no
 * Authorization header is present. Throws 401 when a token is presented
 * but invalid (never silently downgrades to anonymous).
 */
export async function optionalVoterSub(c: Ctx): Promise<string | null> {
  const token = bearerToken(c);
  if (!token) return null;
  if (!c.env.OIDC_CLIENT_ID) {
    throw unauthorized("INVALID_TOKEN", "Presented login token is not valid");
  }
  try {
    const verified = await verifyJwt(c.env, token, {
      audience: c.env.OIDC_CLIENT_ID,
    });
    return verified.sub;
  } catch {
    throw unauthorized("INVALID_TOKEN", "Presented login token is not valid");
  }
}

function cleanClaim(value: unknown, max: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > max) return undefined;
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) return undefined;
  return trimmed;
}

export async function newSessionCookieForToken(
  env: Env,
  claims: Record<string, unknown>,
  sub: string,
  requestUrl: string,
): Promise<string> {
  return makeSessionCookie(
    env,
    {
      sub,
      name: cleanClaim(claims["name"], 120),
      email: cleanClaim(claims["email"], 200),
    },
    requestUrl,
  );
}

export { signValue };
