import { env, SELF } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { bucketCounts, MemoryAnalyticsStore } from "../src/platform/analytics-store";
import {
  loginLocalUser,
  registerLocalUser,
  requestPasswordReset,
  resetLocalPassword,
  verifyLocalEmail,
} from "../src/platform/auth-local";
import { assertEmailEndpoint, createHttpEmail, createOutboxEmail } from "../src/platform/email";
import { selectAuthProvider } from "../src/platform";
import { MemoryObjectStore } from "../src/platform/objects";
import { MemoryRateLimitStore } from "../src/platform/ratelimit";
import { RecordingWebhookTransport } from "../src/platform/webhook-transport";
import { sendSignedWebhook, signWebhookBody } from "../src/webhooks";
import { applySchema } from "./fixtures";

beforeAll(async () => {
  await applySchema(env.DB);
});

describe("adapter selection", () => {
  it("does not expose local password routes while OIDC is selected", async () => {
    const res = await SELF.fetch("https://vote.test/auth/local/login", { method: "POST" });
    expect(res.status).toBe(404);
  });

  it("defaults to generic OIDC and can select local auth", () => {
    expect(selectAuthProvider(undefined).id).toBe("oidc");
    expect(selectAuthProvider("oidc").capabilities.localPasswords).toBe(false);
    expect(selectAuthProvider("local").id).toBe("local");
    expect(selectAuthProvider("local").capabilities.emailVerification).toBe(true);
    expect(selectAuthProvider("LOCAL").label({})).toBe("メールとパスワード");
    expect(() => selectAuthProvider("vendor")).toThrow(/AUTH_PROVIDER/);
  });

  it("rejects a non-https mail endpoint", () => {
    expect(() => assertEmailEndpoint("http://mail.example/send")).toThrow();
    expect(() => assertEmailEndpoint("https://user:pass@mail.example/send")).toThrow();
    expect(assertEmailEndpoint("https://mail.example/send")).toBe("https://mail.example/send");
  });
});

describe("local auth adapter", () => {
  it("verifies email through the sender, then accepts only the right password", async () => {
    const sent: { to: string; text: string }[] = [];
    const sender = { id: "test", async send(message: { to: string; text: string }) { sent.push(message); } };
    await registerLocalUser(env, {
      email: "local-user@example.com",
      password: "correct-horse",
      name: "Local User",
      origin: "https://vote.test",
    }, sender);
    expect(sent).toHaveLength(1);
    const token = /token=([^&\s]+)/.exec(sent[0]?.text ?? "")?.[1];
    expect(token).toBeTruthy();
    await expect(loginLocalUser(env, "local-user@example.com", "correct-horse")).rejects.toMatchObject({
      code: "EMAIL_UNVERIFIED",
    });
    await verifyLocalEmail(env, decodeURIComponent(token as string));
    const identity = await loginLocalUser(env, "local-user@example.com", "correct-horse");
    expect(identity.sub.startsWith("local:")).toBe(true);
    await expect(loginLocalUser(env, "local-user@example.com", "wrong-password")).rejects.toMatchObject({
      status: 401,
    });

    sent.length = 0;
    await requestPasswordReset(env, "local-user@example.com", "https://vote.test", sender);
    const reset = /token=([^&\s]+)/.exec(sent[0]?.text ?? "")?.[1];
    await resetLocalPassword(env, decodeURIComponent(reset as string), "a-new-secret");
    const again = await loginLocalUser(env, "local-user@example.com", "a-new-secret");
    expect(again.sub).toBe(identity.sub);
  });

  it("stores outbox mail and posts http mail without following the provider", async () => {
    const outbox = createOutboxEmail(env);
    await outbox.send({ to: "box@example.com", subject: "Hello", text: "body" });
    const row = await env.DB.prepare("SELECT subject FROM email_outbox WHERE recipient = ?1")
      .bind("box@example.com")
      .first<{ subject: string }>();
    expect(row?.subject).toBe("Hello");

    const calls: string[] = [];
    const http = createHttpEmail("https://mail.example/send", (async (url: string) => {
      calls.push(url);
      return new Response(null, { status: 202 });
    }) as typeof fetch);
    await http.send({ to: "box@example.com", subject: "Hello", text: "body" });
    expect(calls).toEqual(["https://mail.example/send"]);
  });
});

describe("swappable stores", () => {
  it("enforces a limit on the memory rate-limit store", async () => {
    const store = new MemoryRateLimitStore();
    await store.hit("bucket", 2, 60);
    await store.hit("bucket", 2, 60);
    await expect(store.hit("bucket", 2, 60)).rejects.toMatchObject({ status: 429 });
  });

  it("records analytics events without a voter id", async () => {
    const store = new MemoryAnalyticsStore();
    const at = new Date().toISOString();
    await store.record("poll-1", at);
    const series = await store.pollSeries("poll-1", 14);
    expect(series.reduce((sum, day) => sum + day.count, 0)).toBe(1);
    expect(JSON.stringify(series)).not.toContain("voter");
    expect(bucketCounts([{ created_at: at }], 14)).toHaveLength(14);
  });

  it("round-trips an object through the memory store", async () => {
    const store = new MemoryObjectStore();
    const body = new TextEncoder().encode("png");
    await store.put("t/a/b.png", body, "image/png");
    expect(await store.head("t/a/b.png")).toBe(true);
    const stored = await store.get("t/a/b.png");
    expect(stored?.contentType).toBe("image/png");
    expect(stored?.body).toBeTruthy();
  });

  it("signs a webhook through the transport boundary", async () => {
    const transport = new RecordingWebhookTransport();
    const payload = JSON.stringify({ type: "vote.cast", poll_id: "p1" });
    const status = await sendSignedWebhook(transport, "https://hooks.example/vote", "secret", payload, "vote.cast");
    expect(status).toBe(204);
    expect(transport.calls[0]?.body).toBe(payload);
    expect(transport.calls[0]?.body).not.toContain("voter_token");
    const header = transport.calls[0]?.headers["x-headless-vote-signature"] ?? "";
    expect(header).toBe(`v1=${await signWebhookBody("secret", payload)}`);
  });
});
