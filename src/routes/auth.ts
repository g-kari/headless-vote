import { Hono } from "hono";
import {
  clearFlowCookie,
  clearSessionCookie,
  getSessionUser,
  makeFlowCookie,
  newSessionCookieForToken,
  readFlowCookie,
  revokeCurrentSession,
  verifyCsrfToken,
} from "../auth";
import { pkceChallenge, randomToken, timingSafeEqual } from "../crypto";
import { badRequest, forbidden } from "../errors";
import { exchangeCode, getDiscovery, verifyJwt } from "../oidc";
import { clientIp, enforceRateLimit, HOUR, LIMITS } from "../rate-limit";
import type { Env, Variables } from "../types";

export const authRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

function redirectUri(c: { req: { url: string } }): string {
  return `${new URL(c.req.url).origin}/auth/callback`;
}

/** Start the 0g0-id login (authorization code flow + PKCE S256). */
authRoutes.get("/admin/login", async (c) => {
  await enforceRateLimit(
    c.env,
    "login-start",
    clientIp(c),
    LIMITS.loginStartPerIpPerHour,
    HOUR,
  );
  if (!c.env.OIDC_CLIENT_ID) {
    return c.html(
      "<!doctype html><meta charset=utf-8><title>Login not configured</title>" +
        "<p>OIDC_CLIENT_ID is not configured yet. Register the client first (see README).</p>",
      503,
    );
  }
  const discovery = await getDiscovery(c.env);
  const state = randomToken("st");
  const nonce = randomToken("no");
  const verifier = randomToken("cv");
  const challenge = await pkceChallenge(verifier);
  const flow = {
    state,
    nonce,
    verifier,
    exp: Math.floor(Date.now() / 1000) + 600,
  };
  const params = new URLSearchParams({
    response_type: "code",
    client_id: c.env.OIDC_CLIENT_ID,
    redirect_uri: redirectUri(c),
    scope: c.env.OIDC_SCOPES ?? "openid profile email",
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  c.header("Set-Cookie", await makeFlowCookie(c.env, flow));
  return c.redirect(`${discovery.authorization_endpoint}?${params.toString()}`, 302);
});

/** OIDC callback: exchange the code, verify the id_token, start a session. */
authRoutes.get("/auth/callback", async (c) => {
  const code = c.req.query("code");
  const state = c.req.query("state");
  const error = c.req.query("error");
  if (error) throw badRequest(`Login failed at 0g0-id: ${error}`);
  if (!code || !state) throw badRequest("Missing code/state in callback");
  const flow = await readFlowCookie(c);
  if (!flow || !timingSafeEqual(flow.state, state)) {
    throw badRequest("Login flow expired or state mismatch. Please try again.");
  }
  const { idToken } = await exchangeCode(c.env, {
    code,
    codeVerifier: flow.verifier,
    redirectUri: redirectUri(c),
  });
  const verified = await verifyJwt(c.env, idToken, {
    audience: c.env.OIDC_CLIENT_ID,
    nonce: flow.nonce,
  });
  const sessionCookie = await newSessionCookieForToken(c.env, verified.claims, verified.sub);
  c.header("Set-Cookie", sessionCookie);
  c.header("Set-Cookie", clearFlowCookie(), { append: true });
  return c.redirect("/admin", 302);
});

/**
 * Logout is POST-only (a GET here would be a logout-CSRF) and requires
 * the session's CSRF token. The server-side session row is revoked, so
 * the cookie value stops working immediately, not just in this browser.
 *
 * Note on RP-initiated logout: the discovery document advertises an
 * end_session_endpoint, but it currently answers browser GETs with 404
 * (verified 2026-11-13), so redirecting there would strand the user on
 * an error page. Local logout + revocation is the reliable behavior
 * until 0g0-id serves a browser logout flow.
 */
authRoutes.post("/admin/logout", async (c) => {
  const user = await getSessionUser(c);
  if (user) {
    let token: string | null = null;
    try {
      const form = await c.req.formData();
      token = String(form.get("csrf_token") ?? "") || null;
    } catch {
      token = null;
    }
    if (!(await verifyCsrfToken(c, token))) {
      throw forbidden("CSRF token is missing or invalid");
    }
    await revokeCurrentSession(c);
  }
  c.header("Set-Cookie", clearSessionCookie());
  return c.redirect("/admin", 302);
});
