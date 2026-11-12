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
import { badRequest, notFound } from "../errors";
import { exchangeCode, getDiscovery, verifyJwt } from "../oidc";
import {
  loginLocalUser,
  registerLocalUser,
  requestPasswordReset,
  resetLocalPassword,
  verifyLocalEmail,
} from "../platform/auth-local";
import { createEmailSender } from "../platform/email";
import { selectAuthProvider } from "../platform";
import { assertSameOriginMutation, rateLimitByIp, readUrlEncodedForm, requireRequestOrigin } from "../security";
import { escapeHtml, layout } from "../views";
import type { Env, Variables } from "../types";

export const authRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

const OIDC_ERROR = /^[A-Za-z0-9_]{1,64}$/;

function localPage(c: { req: { url: string }; get: (key: "cspNonce") => string | undefined }, title: string, body: string, status = 200) {
  return c instanceof Object
    ? layout({
        title,
        userEmail: null,
        body,
        origin: new URL(c.req.url).origin,
        nonce: c.get("cspNonce") ?? "",
      })
    : "";
}

function requireLocalProvider(env: Env) {
  const provider = selectAuthProvider(env.AUTH_PROVIDER);
  if (provider.id !== "local") throw notFound("Not found");
  return provider;
}

/** Start login with the configured auth provider. */
authRoutes.get("/admin/login", async (c) => {
  if (selectAuthProvider(c.env.AUTH_PROVIDER).id === "local") {
    const body = `
      <h1>ログイン</h1>
      <form method="post" action="/auth/local/login">
        <label for="email">メールアドレス</label>
        <input id="email" name="email" type="email" required maxlength="200" autocomplete="username">
        <label for="password">パスワード</label>
        <input id="password" name="password" type="password" required minlength="10" maxlength="200" autocomplete="current-password">
        <div class="actions"><button class="btn primary" type="submit">ログイン</button></div>
      </form>
      <p class="muted"><a href="/auth/local/register">アカウントを作成</a> · <a href="/auth/local/forgot">パスワードを再設定</a></p>`;
    return c.html(localPage(c, "ログイン", body));
  }
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

authRoutes.post("/auth/local/login", async (c) => {
  requireLocalProvider(c.env);
  assertSameOriginMutation(c);
  await rateLimitByIp(c, "login", 30, 3600);
  const form = await readUrlEncodedForm(c);
  const identity = await loginLocalUser(c.env, String(form.get("email") ?? ""), String(form.get("password") ?? ""));
  c.header("Set-Cookie", await newSessionCookieForToken(c.env, { email: identity.email, name: identity.name }, identity.sub, c.req.url));
  c.header("Cache-Control", "no-store");
  return c.redirect("/admin", 302);
});

authRoutes.get("/auth/local/register", (c) => {
  requireLocalProvider(c.env);
  const body = `
    <h1>アカウント作成</h1>
    <form method="post" action="/auth/local/register">
      <label for="name">名前</label>
      <input id="name" name="name" type="text" maxlength="120" autocomplete="name">
      <label for="email">メールアドレス</label>
      <input id="email" name="email" type="email" required maxlength="200" autocomplete="username">
      <label for="password">パスワード <span class="hint">10 文字以上。</span></label>
      <input id="password" name="password" type="password" required minlength="10" maxlength="200" autocomplete="new-password">
      <div class="actions"><button class="btn primary" type="submit">作成する</button></div>
    </form>`;
  return c.html(localPage(c, "アカウント作成", body));
});

authRoutes.post("/auth/local/register", async (c) => {
  requireLocalProvider(c.env);
  assertSameOriginMutation(c);
  await rateLimitByIp(c, "login", 30, 3600);
  const origin = requireRequestOrigin(c.env, c.req.url);
  const form = await readUrlEncodedForm(c);
  await registerLocalUser(c.env, {
    email: String(form.get("email") ?? ""),
    password: String(form.get("password") ?? ""),
    name: String(form.get("name") ?? ""),
    origin,
  }, createEmailSender(c.env));
  const body = `<h1>確認メールを送りました</h1><p>メールのリンクを開くとログインできます。送信先は設定したメールアダプタです。</p>`;
  return c.html(localPage(c, "確認メール", body));
});

authRoutes.get("/auth/local/verify", async (c) => {
  requireLocalProvider(c.env);
  await verifyLocalEmail(c.env, c.req.query("token") ?? "");
  const body = `<h1>メールを確認しました</h1><p><a href="/admin/login">ログイン</a></p>`;
  return c.html(localPage(c, "メールを確認しました", body));
});

authRoutes.get("/auth/local/forgot", (c) => {
  requireLocalProvider(c.env);
  const body = `
    <h1>パスワード再設定</h1>
    <form method="post" action="/auth/local/forgot">
      <label for="email">メールアドレス</label>
      <input id="email" name="email" type="email" required maxlength="200" autocomplete="username">
      <div class="actions"><button class="btn primary" type="submit">再設定リンクを送る</button></div>
    </form>`;
  return c.html(localPage(c, "パスワード再設定", body));
});

authRoutes.post("/auth/local/forgot", async (c) => {
  requireLocalProvider(c.env);
  assertSameOriginMutation(c);
  await rateLimitByIp(c, "login", 30, 3600);
  const origin = requireRequestOrigin(c.env, c.req.url);
  const form = await readUrlEncodedForm(c);
  await requestPasswordReset(c.env, String(form.get("email") ?? ""), origin, createEmailSender(c.env));
  const body = `<h1>送信しました</h1><p>そのメールのアカウントがある場合、再設定リンクを送りました。</p>`;
  return c.html(localPage(c, "パスワード再設定", body));
});

authRoutes.get("/auth/local/reset", (c) => {
  requireLocalProvider(c.env);
  const token = c.req.query("token") ?? "";
  const body = `
    <h1>新しいパスワード</h1>
    <form method="post" action="/auth/local/reset">
      <input type="hidden" name="token" value="${escapeHtml(token)}">
      <label for="password">パスワード</label>
      <input id="password" name="password" type="password" required minlength="10" maxlength="200" autocomplete="new-password">
      <div class="actions"><button class="btn primary" type="submit">保存する</button></div>
    </form>`;
  return c.html(localPage(c, "新しいパスワード", body));
});

authRoutes.post("/auth/local/reset", async (c) => {
  requireLocalProvider(c.env);
  assertSameOriginMutation(c);
  const form = await readUrlEncodedForm(c);
  await resetLocalPassword(c.env, String(form.get("token") ?? ""), String(form.get("password") ?? ""));
  const body = `<h1>パスワードを更新しました</h1><p><a href="/admin/login">ログイン</a></p>`;
  return c.html(localPage(c, "パスワードを更新しました", body));
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
