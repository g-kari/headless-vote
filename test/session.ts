import { SELF } from "cloudflare:test";

/**
 * Session helpers for tests. Tenant creation requires a verified login
 * (KAZAMI-306 #10), so fixtures that provision tenants through the public
 * API reuse one logged-in session per test file.
 */

const BASE = "https://vote.test";

function cookieValue(res: Response, name: string): string | null {
  for (const header of res.headers.getSetCookie()) {
    const [pair] = header.split(";");
    const eq = pair?.indexOf("=") ?? -1;
    if (eq > 0 && pair?.slice(0, eq).trim() === name) {
      return pair.slice(eq + 1).trim() as string;
    }
  }
  return null;
}

function decodeFlowPayload(cookieValue: string): { state: string; nonce: string } {
  const decoded = decodeURIComponent(cookieValue);
  const payloadPart = decoded.split(".")[0] as string;
  const padded = payloadPart.replace(/-/g, "+").replace(/_/g, "/");
  const json = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  return JSON.parse(json) as { state: string; nonce: string };
}

/** Run a full OIDC login against the mock IdP. Returns the session cookie value. */
export async function loginForTests(sub: string, email: string): Promise<string> {
  const loginRes = await SELF.fetch(`${BASE}/admin/login`, { redirect: "manual" });
  if (loginRes.status !== 302) throw new Error(`login start failed: ${loginRes.status}`);
  const flowCookie = cookieValue(loginRes, "__Host-hv_oidc_flow");
  if (!flowCookie) throw new Error("flow cookie missing");
  const flow = decodeFlowPayload(flowCookie);
  // The mock IdP mints an id_token for this code (mock:<sub>:<nonce>:<email>).
  const code = `mock:${sub}:${flow.nonce}:${email}`;
  const callbackRes = await SELF.fetch(
    `${BASE}/auth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(flow.state)}`,
    { redirect: "manual", headers: { cookie: `__Host-hv_oidc_flow=${flowCookie}` } },
  );
  if (callbackRes.status !== 302) throw new Error(`login callback failed: ${callbackRes.status}`);
  const session = cookieValue(callbackRes, "__Host-hv_session");
  if (!session) throw new Error("session cookie missing");
  return session;
}

let cached: Promise<string> | null = null;

/** Shared session cookie value for fixture tenant creation (one login per file). */
export function fixtureSessionCookie(): Promise<string> {
  cached ??= loginForTests("fixture-tenant-creator", "fixture-creator@example.com");
  return cached;
}

/** Cookie header for a session value returned by loginForTests/fixtureSessionCookie. */
export function sessionCookieHeader(session: string): Record<string, string> {
  return { cookie: `__Host-hv_session=${session}` };
}

/** Session cookie header for the shared fixture session (await before spreading). */
export async function fixtureSessionHeaders(): Promise<Record<string, string>> {
  return sessionCookieHeader(await fixtureSessionCookie());
}
