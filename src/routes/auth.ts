import { Hono } from "hono";
import {
  clearFlowCookie,
  clearSessionCookie,
  makeFlowCookie,
  newSessionCookieForToken,
  readFlowCookie,
} from "../auth";
import { pkceChallenge, randomToken } from "../crypto";
import { badRequest } from "../errors";
import { exchangeCode, getDiscovery, verifyJwt } from "../oidc";
import type { Env, Variables } from "../types";

export const authRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

function redirectUri(c: { req: { url: string } }): string {
  return `${new URL(c.req.url).origin}/auth/callback`;
}

/** Start the 0g0-id login (authorization code flow + PKCE S256). */
authRoutes.get("/admin/login", async (c) => {
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
  if (!flow || flow.state !== state) {
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

authRoutes.post("/admin/logout", (c) => {
  c.header("Set-Cookie", clearSessionCookie());
  return c.redirect("/admin", 302);
});

/** Logout that also works from a plain link (GET). */
authRoutes.get("/admin/logout", (c) => {
  c.header("Set-Cookie", clearSessionCookie());
  return c.redirect("/admin", 302);
});
