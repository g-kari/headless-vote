import { env } from "cloudflare:test";
import { Hono } from "hono";
import { beforeAll, describe, expect, it } from "vitest";
import { accountBySubject } from "../src/accounts";
import { sha256Hex, signValue } from "../src/crypto";
import { getSessionUser, newSessionCookieForToken } from "../src/auth";
import { deleteLocalAccount, loginLocalUser, registerLocalUser, requestPasswordReset, resetLocalPassword, verifyLocalEmail } from "../src/platform/auth-local";
import type { AuthIdentity } from "../src/platform/ports";
import type { Env, Variables } from "../src/types";
import { applySchema } from "./fixtures";

const BASE = "https://vote.test";
const localEnv: Env = { ...env, AUTH_PROVIDER: "local" };
const sessionProbe = new Hono<{ Bindings: Env; Variables: Variables }>();
sessionProbe.get("/", async (c) => c.json(await getSessionUser(c)));
beforeAll(async () => { await applySchema(env.DB); });

async function readSession(cookie: string, bindings = localEnv) {
  const res = await sessionProbe.request(BASE, { headers: { cookie: cookie.split(";")[0] ?? "" } }, bindings);
  return res.json();
}
async function cookieFor(identity: AuthIdentity) {
  return newSessionCookieForToken(localEnv, {}, identity.sub, BASE, identity.sessionVersion);
}
/** Forge a pre-internal-id session cookie (payload carries the IdP sub). */
async function legacyCookie(bindings: Env, payload: Record<string, unknown>) {
  const value = await signValue(bindings.SESSION_SECRET, {
    kind: "session",
    exp: Math.floor(Date.now() / 1000) + 3600,
    ...payload,
  });
  return `__Host-hv_session=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax`;
}
async function accountIdOf(bindings: Env, subject: string) {
  return (await accountBySubject(bindings, subject))!.id;
}
async function account() {
  const address = `${crypto.randomUUID()}@example.com`;
  const messages: string[] = [];
  const sender = { id: "test", async send(message: { text: string }) { messages.push(message.text); } };
  const latestToken = () => decodeURIComponent(/token=([^\s]+)/.exec(messages.at(-1) ?? "")?.[1] ?? "");
  await registerLocalUser(localEnv, { email: address, password: "original-password", name: "Test", origin: BASE }, sender);
  await verifyLocalEmail(localEnv, latestToken());
  const identity = await loginLocalUser(localEnv, address, "original-password");
  return { address, identity, async resetToken() {
    await requestPasswordReset(localEnv, address, BASE, sender);
    return latestToken();
  } };
}

describe("local recovery and session revocation", () => {
  it("revokes previous sessions and every outstanding reset link", async () => {
    const user = await account();
    const cookie = await cookieFor(user.identity);
    expect(await readSession(cookie)).toMatchObject({ accountId: await accountIdOf(localEnv, user.identity.sub) });
    const older = await user.resetToken();
    const newer = await user.resetToken();
    await resetLocalPassword(localEnv, newer, "replacement-password");
    expect(await readSession(cookie)).toBeNull();
    await expect(resetLocalPassword(localEnv, older, "attacker-password")).rejects.toThrow();
    await expect(resetLocalPassword(localEnv, newer, "attacker-password")).rejects.toThrow();
    const fresh = await loginLocalUser(localEnv, user.address, "replacement-password");
    expect(fresh.sessionVersion).toBe((user.identity.sessionVersion ?? 0) + 1);
    expect(await readSession(await cookieFor(fresh))).toMatchObject({ accountId: await accountIdOf(localEnv, fresh.sub) });
  });

  it("allows only one concurrent use of a recovery token", async () => {
    const user = await account();
    const token = await user.resetToken();
    const results = await Promise.allSettled([
      resetLocalPassword(localEnv, token, "replacement-one"),
      resetLocalPassword(localEnv, token, "replacement-two"),
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    const row = await env.DB.prepare("SELECT session_version FROM local_users WHERE id = ?1")
      .bind(user.identity.sub.slice("local:".length)).first<{ session_version: number }>();
    expect(row?.session_version).toBe(1);
  });

  it("rejects expired and wrong-purpose tokens without changing credentials", async () => {
    const user = await account();
    const expired = await user.resetToken();
    await env.DB.prepare("UPDATE local_tokens SET expires_at = ?1 WHERE token_hash = ?2")
      .bind("2000-01-01T00:00:00.000Z", await sha256Hex(expired)).run();
    await expect(resetLocalPassword(localEnv, expired, "replacement-password")).rejects.toThrow();
    const wrongPurpose = await user.resetToken();
    await env.DB.prepare("UPDATE local_tokens SET purpose = 'verify' WHERE token_hash = ?1")
      .bind(await sha256Hex(wrongPurpose)).run();
    await expect(resetLocalPassword(localEnv, wrongPurpose, "replacement-password")).rejects.toThrow();
    await expect(loginLocalUser(localEnv, user.address, "original-password")).resolves.toMatchObject({ sessionVersion: 0 });
  });

  it("does not burn a reset token on an invalid new password", async () => {
    const user = await account();
    const token = await user.resetToken();
    await expect(resetLocalPassword(localEnv, token, "short")).rejects.toThrow();
    await resetLocalPassword(localEnv, token, "valid-new-password");
    await expect(loginLocalUser(localEnv, user.address, "valid-new-password")).resolves.toMatchObject({ sub: user.identity.sub });
  });

  it("rejects a session signed after reset from an earlier password-verification snapshot", async () => {
    const user = await account();
    // Simulate reset between successful password verification and cookie issuance.
    await resetLocalPassword(localEnv, await user.resetToken(), "replacement-password");
    expect(await readSession(await cookieFor(user.identity))).toBeNull();
  });

  it("rejects deleted local accounts and legacy unversioned local sessions", async () => {
    const user = await account();
    const cookie = await cookieFor(user.identity);
    const legacy = await legacyCookie(localEnv, { sub: user.identity.sub });
    expect(await readSession(legacy)).toBeNull();
    await deleteLocalAccount(localEnv, user.identity.sub);
    expect(await readSession(cookie)).toBeNull();
  });

  it("preserves OIDC sessions while preventing provider-switch reuse", async () => {
    const oidcEnv: Env = { ...env, AUTH_PROVIDER: "oidc" };
    const legacy = await legacyCookie(oidcEnv, { sub: "oidc-user" });
    const fresh = await newSessionCookieForToken(oidcEnv, {}, "oidc-user", BASE);
    const oidcAccountId = await accountIdOf(oidcEnv, "oidc-user");
    for (const cookie of [legacy, fresh]) {
      const session = await readSession(cookie, oidcEnv) as { accountId?: string; sub?: string };
      expect(session).toMatchObject({ accountId: oidcAccountId });
      // The IdP subject must not be part of the resolved session object.
      expect(session.sub).toBeUndefined();
      expect(await readSession(cookie)).toBeNull();
    }
    const user = await account();
    expect(await readSession(await cookieFor(user.identity), oidcEnv)).toBeNull();
  });
});
