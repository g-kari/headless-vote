import { Hono } from "hono";
import {
  clearFlowCookie,
  clearSessionCookie,
  makeFlowCookie,
  newSessionCookieForToken,
  readFlowCookie,
  type FlowState,
} from "../auth";
import { pkceChallenge, randomToken, sha256Hex, timingSafeEqual } from "../crypto";
import { badRequest } from "../errors";
import { exchangeCode, getDiscovery, verifyJwt } from "../oidc";
import { assertSameOriginMutation, rateLimitByIp, requireRequestOrigin } from "../security";
import { layout } from "../views";
import type { Env, Variables } from "../types";

export const authRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

const OIDC_ERROR = /^[A-Za-z0-9_]{1,64}$/;

/** Start the 0g0-id login (authorization code flow + PKCE S256). */
authRoutes.get("/admin/login", async (c) => {
  if (!c.env.OIDC_CLIENT_ID) {
    return c.html(
      "<!doctype html><meta charset=utf-8><title>Login not configured</title>" +
        "<p>OIDC_CLIENT_ID is not configured yet. Register the client first (see README).</p>",
      503,
    );
  }
  const origin = requireRequestOrigin(c.env, c.req.url);
  await rateLimitByIp(c, "login", 30, 3600);
  const discovery = await getDiscovery(c.env);
  const state = randomToken("st");
  const nonce = randomToken("no");
  const verifier = randomToken("cv");
  const challenge = await pkceChallenge(verifier);
  const flow: FlowState = {
    kind: "flow",
    state,
    nonce,
    verifier,
    exp: Math.floor(Date.now() / 1000) + 600,
  };
  const now = Math.floor(Date.now() / 1000);
  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM oidc_states WHERE expires_at <= ?1").bind(now),
    c.env.DB.prepare(
      "INSERT INTO oidc_states (state_hash, expires_at) VALUES (?1, ?2)",
    ).bind(await sha256Hex(state), flow.exp),
  ]);
  const params = new URLSearchParams({
    response_type: "code",
    client_id: c.env.OIDC_CLIENT_ID,
    redirect_uri: `${origin}/auth/callback`,
    scope: c.env.OIDC_SCOPES ?? "openid profile email",
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  c.header("Set-Cookie", await makeFlowCookie(c.env, flow, c.req.url));
  c.header("Cache-Control", "no-store");
  return c.redirect(`${discovery.authorization_endpoint}?${params.toString()}`, 302);
});

/** OIDC callback: exchange the code, verify the id_token, start a session. */
authRoutes.get("/auth/callback", async (c) => {
  const origin = requireRequestOrigin(c.env, c.req.url);
  const code = c.req.query("code");
  const state = c.req.query("state");
  const error = c.req.query("error");
  if (error) {
    const codeName = OIDC_ERROR.test(error) ? error : "unknown_error";
    throw badRequest(`Login failed at the identity provider (${codeName}). Please try again.`);
  }
  if (!code || !state || code.length > 2048 || state.length > 512) {
    throw badRequest("Missing code/state in callback");
  }
  if (!c.env.OIDC_CLIENT_ID) throw badRequest("Login is not configured");
  const flow = await readFlowCookie(c);
  if (!flow || !timingSafeEqual(flow.state, state)) {
    throw badRequest("Login flow expired or state mismatch. Please try again.");
  }
  const consumed = await c.env.DB.prepare(
    "DELETE FROM oidc_states WHERE state_hash = ?1 AND expires_at > ?2",
  )
    .bind(await sha256Hex(flow.state), Math.floor(Date.now() / 1000))
    .run();
  if (Number(consumed.meta.changes ?? 0) !== 1) {
    throw badRequest("Login flow expired or state mismatch. Please try again.");
  }
  const { idToken } = await exchangeCode(c.env, {
    code,
    codeVerifier: flow.verifier,
    redirectUri: `${origin}/auth/callback`,
  });
  const verified = await verifyJwt(c.env, idToken, {
    audience: c.env.OIDC_CLIENT_ID,
    nonce: flow.nonce,
  });
  const sessionCookie = await newSessionCookieForToken(
    c.env,
    verified.claims,
    verified.sub,
    c.req.url,
  );
  c.header("Set-Cookie", sessionCookie);
  c.header("Set-Cookie", clearFlowCookie(c.req.url), { append: true });
  c.header("Cache-Control", "no-store");
  return c.redirect("/admin", 302);
});

authRoutes.post("/admin/logout", (c) => {
  assertSameOriginMutation(c);
  c.header("Set-Cookie", clearSessionCookie(c.req.url));
  c.header("Clear-Site-Data", '"cookies", "storage"');
  c.header("Cache-Control", "no-store");
  return c.redirect("/admin", 302);
});

/** Confirm logout. GET does not end the session (that would be a cross-site logout). */
authRoutes.get("/admin/logout", (c) => {
  const nonce = c.get("cspNonce") ?? "";
  const body = `
    <h1>ログアウト</h1>
    <p class="lead">管理画面からログアウトします。ログイン中のセッションは、このボタンを押したときだけ終了します。</p>
    <form method="post" action="/admin/logout" aria-labelledby="logout-title">
      <h2 id="logout-title" class="muted">ログアウトの確認</h2>
      <div class="actions"><button class="btn primary" type="submit">ログアウトする</button></div>
    </form>`;
  return c.html(
    layout({
      title: "ログアウト",
      userEmail: null,
      body,
      origin: new URL(c.req.url).origin,
      nonce,
    }),
  );
});
