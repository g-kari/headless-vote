import { accountById, resolveAccount, subjectForAccount } from "./accounts";
import { signValue, verifySignedValue } from "./crypto";
import { forbidden, unauthorized } from "./errors";
import { findActiveApiKey, touchApiKey } from "./keys";
import { selectAuthProvider } from "./platform";
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
  const out: Record<string, string> = Object.create(null);
  const seen = new Set<string>();
  if (!header) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq > 0) {
      const name = part.slice(0, eq).trim();
      if (seen.has(name)) { delete out[name]; continue; }
      seen.add(name);
      try { out[name] = decodeURIComponent(part.slice(eq + 1).trim()); } catch { /* Ignore malformed cookies. */ }
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

/* ------------------------------------------------------------------ */
/* OIDC session epochs (revoke-all for stateless session cookies)      */
/* ------------------------------------------------------------------ */

/** Current session epoch for an OIDC account; 0 when never revoked. */
export async function getSessionEpoch(env: Env, accountId: string): Promise<number> {
  const row = await env.DB.prepare("SELECT epoch FROM session_epochs WHERE account_id = ?1")
    .bind(accountId)
    .first<{ epoch: number }>();
  return Number(row?.epoch ?? 0);
}

/** Invalidate every outstanding OIDC session cookie for this account. */
export async function bumpSessionEpoch(env: Env, accountId: string): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO session_epochs (account_id, epoch) VALUES (?1, 1)
     ON CONFLICT(account_id) DO UPDATE SET epoch = epoch + 1`,
  )
    .bind(accountId)
    .run();
}

/**
 * Raw session-cookie payload. Current cookies carry the Hyo-internal
 * `accountId`; cookies issued before the internal-id rollout carry the
 * IdP `sub` instead and are migrated transparently on read (the subject
 * is resolved to an account id server-side and never re-exposed).
 */
interface SessionPayload {
  kind?: unknown;
  accountId?: unknown;
  sub?: unknown;
  authProvider?: unknown;
  sessionVersion?: unknown;
  sessionEpoch?: unknown;
  name?: unknown;
  email?: unknown;
  exp?: unknown;
}

export async function getSessionUser(c: Ctx): Promise<SessionUser | null> {
  const cookies = parseCookies(c);
  const raw = cookies[sessionCookieName(c.req.url)];
  if (!raw) return null;
  const payload = await verifySignedValue<SessionPayload>(c.env.SESSION_SECRET, raw);
  if (!payload || payload.kind !== "session") return null;
  if (typeof payload.exp !== "number" || payload.exp <= Math.floor(Date.now() / 1000)) return null;
  const provider = selectAuthProvider(c.env.AUTH_PROVIDER).id;

  // Resolve the account id and the IdP subject (subject stays server-side).
  let accountId: string;
  let subject: string;
  if (typeof payload.accountId === "string" && payload.accountId.length > 0) {
    const account = await accountById(c.env, payload.accountId);
    if (!account) return null;
    accountId = account.id;
    subject = account.subject;
  } else if (typeof payload.sub === "string" && payload.sub.length > 0 && payload.sub.length <= 256) {
    // Legacy cookie: preserve OIDC sessions, but never treat an old
    // unversioned local cookie as a current local login.
    subject = payload.sub;
    const legacyProvider = payload.authProvider ?? (subject.startsWith("local:") ? "local" : "oidc");
    if (legacyProvider !== provider) return null;
    const account = await resolveAccount(c.env, subject, {
      email: typeof payload.email === "string" ? payload.email : null,
      name: typeof payload.name === "string" ? payload.name : null,
    });
    accountId = account.id;
  } else {
    return null;
  }

  const sessionProvider = payload.authProvider ?? (subject.startsWith("local:") ? "local" : "oidc");
  if (sessionProvider !== provider) return null;
  if (sessionProvider === "local") {
    if (!subject.startsWith("local:") || !Number.isSafeInteger(payload.sessionVersion)) return null;
    const user = await c.env.DB.prepare("SELECT session_version FROM local_users WHERE id = ?1 AND email_verified_at IS NOT NULL")
      .bind(subject.slice("local:".length)).first<{ session_version: number }>();
    if (!user || user.session_version !== payload.sessionVersion) return null;
  }
  if (sessionProvider === "oidc") {
    // Revoke-all support for stateless cookies (PR #4 parity): the epoch
    // baked into the cookie must still match the server-side epoch.
    const epoch = await getSessionEpoch(c.env, accountId);
    if ((typeof payload.sessionEpoch === "number" ? payload.sessionEpoch : 0) !== epoch) return null;
  }
  return {
    kind: "session",
    accountId,
    authProvider: sessionProvider === "local" ? "local" : "oidc",
    sessionVersion: typeof payload.sessionVersion === "number" ? payload.sessionVersion : undefined,
    sessionEpoch: typeof payload.sessionEpoch === "number" ? payload.sessionEpoch : undefined,
    name: typeof payload.name === "string" ? payload.name : undefined,
    email: typeof payload.email === "string" ? payload.email : undefined,
    exp: payload.exp,
  };
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
  accountId: string,
): Promise<boolean> {
  const row = await env.DB.prepare(
    "SELECT 1 AS ok FROM tenant_members WHERE tenant_id = ?1 AND account_id = ?2",
  )
    .bind(tenantId, accountId)
    .first<{ ok: number }>();
  return row !== null;
}

export async function listTenantsForUser(
  env: Env,
  accountId: string,
): Promise<TenantRow[]> {
  const res = await env.DB.prepare(
    `SELECT t.* FROM tenants t
     JOIN tenant_members m ON m.tenant_id = t.id
     WHERE m.account_id = ?1 ORDER BY t.created_at ASC`,
  )
    .bind(accountId)
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
  accountId: string,
): Promise<"owner" | "member" | null> {
  const row = await env.DB.prepare(
    "SELECT role FROM tenant_members WHERE tenant_id = ?1 AND account_id = ?2",
  )
    .bind(tenantId, accountId)
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
  const role = user ? await memberRole(c.env, tenantId, user.accountId) : null;
  if (user && role) {
    if (access === "owner" && role !== "owner") throw forbidden("Owner access is required");
    return { kind: "session", tenantId, accountId: user.accountId, role };
  }
  throw unauthorized("UNAUTHORIZED", "Admin authentication required");
}

/**
 * Optional voter identity for the voting API. The returned subject is
 * resolved server-side and used only as the input to the voter-key HMAC
 * (the raw value is never stored, logged, or returned to clients).
 * A bearer token is checked by the configured auth provider. When no token
 * is present, a valid session cookie is used. Throws 401 when a token is
 * presented but invalid (never silently downgrades to anonymous).
 */
export async function optionalVoterIdentity(c: Ctx): Promise<string | null> {
  const token = bearerToken(c);
  if (token) {
    const verified = await selectAuthProvider(c.env.AUTH_PROVIDER).verifyAccessToken(c.env, token);
    return verified.sub;
  }
  const session = await getSessionUser(c);
  if (!session) return null;
  return subjectForAccount(c.env, session.accountId);
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
  sessionVersion?: number,
): Promise<string> {
  // The subject is resolved to the Hyo-internal account id here, at login
  // time; the issued cookie carries only the internal id.
  const name = cleanClaim(claims["name"], 120);
  const email = cleanClaim(claims["email"], 200);
  const account = await resolveAccount(env, sub, {
    email: email ?? null,
    name: name ?? null,
  });
  const sessionEpoch =
    sessionVersion === undefined ? await getSessionEpoch(env, account.id) : undefined;
  return makeSessionCookie(
    env,
    {
      accountId: account.id,
      authProvider: sessionVersion === undefined ? "oidc" : "local",
      sessionVersion,
      sessionEpoch,
      name: name ?? account.name ?? undefined,
      email: email ?? account.email ?? undefined,
    },
    requestUrl,
  );
}

export { signValue };
