import { env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { assertWebhookUrl, createWebhook, sendSignedWebhook } from "../src/webhooks";
import { MemoryObjectStore } from "../src/platform/objects";
import { RecordingWebhookTransport } from "../src/platform/webhook-transport";
import { applySchema } from "./fixtures";

beforeAll(async () => { await applySchema(env.DB); });

describe("webhook egress policy", () => {
  it.each([
    "http://localhost/hook", "https://localhost/hook", "https://localhost./hook",
    "https://a.localhost/hook", "https://a.internal/hook", "https://a.local/hook",
    "https://[::1]/hook", "https://[::]/hook", "https://[fd00::1]/hook",
    "https://[fe80::1]/hook", "https://[::ffff:127.0.0.1]/hook",
    "https://[2001:db8::1]/hook", "https://[2002:7f00:1::]/hook",
    "https://127.1/hook", "https://2130706433/hook", "https://0x7f000001/hook",
    "https://10.0.0.1/hook", "https://169.254.169.254/hook", "https://100.64.0.1/hook",
    "https://192.0.2.1/hook", "https://198.18.0.1/hook", "https://224.0.0.1/hook",
  ])("rejects non-public destination %s", (url) => {
    expect(() => assertWebhookUrl(url)).toThrow();
  });

  it("accepts HTTPS public hosts and global addresses", () => {
    for (const url of ["https://example.com/hook", "https://8.8.8.8/hook", "https://[2606:4700:4700::1111]/hook"]) {
      expect(assertWebhookUrl(url)).toBe(url);
    }
  });

  it("revalidates persisted destinations before invoking a transport", async () => {
    const transport = new RecordingWebhookTransport();
    await expect(sendSignedWebhook(transport, "https://[::1]/hook", "secret", "{}", "vote.cast")).rejects.toThrow();
    expect(transport.calls).toHaveLength(0);
  });

  it("admits at most the remaining webhook quota under concurrent creation", async () => {
    const id = crypto.randomUUID();
    await env.DB.prepare("INSERT INTO tenants (id, name, api_key_hash, created_at, quota_webhooks) VALUES (?1, 'quota test', ?2, ?3, 1)")
      .bind(id, crypto.randomUUID(), new Date().toISOString()).run();
    const outcomes = await Promise.allSettled(Array.from({ length: 4 }, () =>
      createWebhook(env, id, "https://example.com/hook", ["vote.cast"])));
    expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM webhooks WHERE tenant_id = ?1").bind(id).first<{ n: number }>();
    expect(count?.n).toBe(1);
  });
});

describe("bounded tenant object cleanup", () => {
  it("deletes multiple pages while preserving another tenant", async () => {
    const store = new MemoryObjectStore();
    const prefix = `t/${crypto.randomUUID()}/`;
    const other = `t/${crypto.randomUUID()}/image.png`;
    await store.put(other, new Uint8Array([1]), "image/png");
    for (let i = 0; i < 101; i++) await store.put(`${prefix}${i}.png`, new Uint8Array([1]), "image/png");
    const cursor = await store.deletePrefix(prefix);
    expect(cursor).not.toBeNull();
    expect(await store.deletePrefix(prefix, cursor!)).toBeNull();
    expect(await store.head(`${prefix}100.png`)).toBe(false);
    expect(await store.head(other)).toBe(true);
    await expect(store.deletePrefix("t/")).rejects.toThrow();
  });
});
