import {
  hmacSha256Hex,
  randomToken,
  sha256Hex,
  signValue,
  timingSafeEqual,
  verifySignedValue,
} from "./crypto";
import { forbidden, unauthorized } from "./errors";
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
/* Session cookie (admin UI). The cookie carries an opaque session id; */
/* the session record itself lives in D1 so it can be revoked.        */
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

interface SessionRow {
  user_sub: string;
  name: string | null;
  email: string | null;
  expires_at: number;
  revoked_at: number | null;
}

/** Create a server-side session and return the Set-Cookie header value. */
export async function makeSessionCookie(
  env: Env,
  user: Omit<SessionUser, "exp">,
): Promise<string> {
  const rawId = randomToken("ses");
  const idHash = await sha256Hex(rawId);
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare(
    `INSERT INTO sessions (id_hash, user_sub, name, email, created_at, expires_at, revoked_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)`,
  )
    .bind(idHash, user.sub, user.name ?? null, user.email ?? null, now, now + SESSION_TTL_SECONDS)
    .run();
  return cookieHeader(SESSION_COOKIE, rawId, SESSION_TTL_SECONDS);
}

export function clearSessionCookie(): string {
  return cookieHeader(SESSION_COOKIE, "", 0);
}

export async function getSessionUser(c: Ctx): Promise<SessionUser | null> {
  const cookies = parseCookies(c);
  const raw = cookies[SESSION_COOKIE];
  if (!raw) return null;
  const idHash = await sha256Hex(raw);
  const row = await c.env.DB.prepare(
    "SELECT user_sub, name, email, expires_at, revoked_at FROM sessions WHERE id_hash = ?1",
  )
    .bind(idHash)
    .first<SessionRow>();
  if (!row || row.revoked_at !== null) return null;
  if (row.expires_at <= Math.floor(Date.now() / 1000)) return null;
  return {
    sub: row.user_sub,
    name: row.name ?? undefined,
    email: row.email ?? undefined,
    exp: row.expires_at,
  };
}

/** Revoke the session presented with this request (logout). */
export async function revokeCurrentSession(c: Ctx): Promise<void> {
  const cookies = parseCookies(c);
  const raw = cookies[SESSION_COOKIE];
  if (!raw) return;
  const idHash = await sha256Hex(raw);
  await c.env.DB.prepare(
    "UPDATE sessions SET revoked_at = ?1 WHERE id_hash = ?2 AND revoked_at IS NULL",
  )
    .bind(Math.floor(Date.now() / 1000), idHash)
    .run();
}

/** Revoke every session of a user, including the current one. */
export async function revokeAllSessions(env: Env, sub: string): Promise<void> {
  await env.DB.prepare(
    "UPDATE sessions SET revoked_at = ?1 WHERE user_sub = ?2 AND revoked_at IS NULL",
  )
    .bind(Math.floor(Date.now() / 1000), sub)
    .run();
}

/* ------------------------------------------------------------------ */
/* CSRF tokens (derived from the session id, HMAC-signed by design)    */
/* ------------------------------------------------------------------ */

/**
 * The CSRF token for the current session. It is the HMAC of the opaque
 * session id, so it is stable for the session's lifetime, cannot be
 * derived from anything a cross-site page can read, and changes with
 * every new login.
 */
export async function csrfTokenForSession(c: Ctx): Promise<string | null> {
  const cookies = parseCookies(c);
  const raw = cookies[SESSION_COOKIE];
  if (!raw) return null;
  return hmacSha256Hex(c.env.SESSION_SECRET, `csrf:${raw}`);
}

export async function verifyCsrfToken(c: Ctx, token: string | null): Promise<boolean> {
  if (!token) return false;
  const expected = await csrfTokenForSession(c);
  if (!expected) return false;
  return timingSafeEqual(token, expected);
}

/** For fetch-based mutations: the token travels in a custom header. */
export async function assertCsrfHeader(c: Ctx): Promise<void> {
  const token = c.req.header("x-csrf-token") ?? null;
  if (!(await verifyCsrfToken(c, token))) {
    throw forbidden("CSRF token is missing or invalid");
  }
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
    // Session-authenticated mutations must carry the CSRF token in a
    // custom header (API-key calls are not cookie-based and are exempt).
    if (c.req.method !== "GET" && c.req.method !== "HEAD") {
      await assertCsrfHeader(c);
    }
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
