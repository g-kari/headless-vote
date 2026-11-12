import { sha256Hex, signValue, verifySignedValue } from "./crypto";
import { unauthorized } from "./errors";
import { verifyJwt } from "./oidc";
import type { AdminPrincipal, AppContext, Env, SessionUser, TenantRow } from "./types";

type Ctx = AppContext;

/* ------------------------------------------------------------------ */
/* API key (headless admin API)                                        */
/* ------------------------------------------------------------------ */

export async function findTenantByApiKey(
  env: Env,
  apiKey: string,
): Promise<TenantRow | null> {
  const hash = await sha256Hex(apiKey);
  return env.DB.prepare("SELECT * FROM tenants WHERE api_key_hash = ?1")
    .bind(hash)
    .first<TenantRow>();
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

export const SESSION_COOKIE = "hv_session";
export const FLOW_COOKIE = "hv_oidc_flow";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days
const FLOW_TTL_SECONDS = 60 * 10; // 10 minutes

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

function cookieHeader(name: string, value: string, maxAge: number): string {
  const secure = "; Secure";
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

export async function makeSessionCookie(
  env: Env,
  user: Omit<SessionUser, "exp">,
): Promise<string> {
  const payload: SessionUser = {
    ...user,
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
  };
  const value = await signValue(env.SESSION_SECRET, payload);
  return cookieHeader(SESSION_COOKIE, value, SESSION_TTL_SECONDS);
}

export function clearSessionCookie(): string {
  return cookieHeader(SESSION_COOKIE, "", 0);
}

export async function getSessionUser(c: Ctx): Promise<SessionUser | null> {
  const cookies = parseCookies(c);
  const raw = cookies[SESSION_COOKIE];
  if (!raw) return null;
  const payload = await verifySignedValue<SessionUser>(c.env.SESSION_SECRET, raw);
  if (!payload || typeof payload.sub !== "string") return null;
  if (payload.exp <= Math.floor(Date.now() / 1000)) return null;
  return payload;
}

export interface FlowState {
  state: string;
  nonce: string;
  verifier: string;
  exp: number;
}

export async function makeFlowCookie(env: Env, flow: FlowState): Promise<string> {
  const value = await signValue(env.SESSION_SECRET, flow);
  return cookieHeader(FLOW_COOKIE, value, FLOW_TTL_SECONDS);
}

export async function readFlowCookie(c: Ctx): Promise<FlowState | null> {
  const cookies = parseCookies(c);
  const raw = cookies[FLOW_COOKIE];
  if (!raw) return null;
  const flow = await verifySignedValue<FlowState>(c.env.SESSION_SECRET, raw);
  if (!flow || flow.exp <= Math.floor(Date.now() / 1000)) return null;
  return flow;
}

export function clearFlowCookie(): string {
  return cookieHeader(FLOW_COOKIE, "", 0);
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
export async function requireAdmin(
  c: Ctx,
  tenantId: string,
): Promise<AdminPrincipal> {
  const token = bearerToken(c);
  if (token) {
    const tenant = await findTenantByApiKey(c.env, token);
    if (tenant && tenant.id === tenantId) {
      return { kind: "api_key", tenantId };
    }
    throw unauthorized("INVALID_API_KEY", "API key is not valid for this tenant");
  }
  const user = await getSessionUser(c);
  if (user && (await isTenantMember(c.env, tenantId, user.sub))) {
    return { kind: "session", tenantId, sub: user.sub };
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
  try {
    const verified = await verifyJwt(c.env, token, {
      audience: c.env.OIDC_CLIENT_ID || undefined,
    });
    return verified.sub;
  } catch {
    throw unauthorized("INVALID_TOKEN", "Presented login token is not valid");
  }
}

export async function newSessionCookieForToken(
  env: Env,
  claims: Record<string, unknown>,
  sub: string,
): Promise<string> {
  return makeSessionCookie(env, {
    sub,
    name: typeof claims["name"] === "string" ? (claims["name"] as string) : undefined,
    email: typeof claims["email"] === "string" ? (claims["email"] as string) : undefined,
  });
}

export { signValue };
