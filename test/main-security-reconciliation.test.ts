import { SELF, env } from "cloudflare:test";
import { Hono } from "hono";
import { beforeAll, describe, expect, it } from "vitest";
import { parseCookies } from "../src/auth";
import { limitKeyRotation } from "../src/keys";
import { sha256Hex } from "../src/crypto";
import { createD1RateLimitStore } from "../src/platform/ratelimit";
import type { Env, Variables } from "../src/types";
import { applySchema } from "./fixtures";

beforeAll(async () => { await applySchema(env.DB); });
const probe = new Hono<{ Bindings: Env; Variables: Variables }>();
probe.get("/", (c) => c.json(parseCookies(c)));

describe("cookie parsing", () => {
  it("ignores malformed values without breaking other cookies", async () => {
    const res = await probe.request("https://vote.test", { headers: { cookie: "bad=%ZZ; good=value" } }, env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ good: "value" });
  });
  it("rejects every duplicate value, including a third occurrence", async () => {
    const res = await probe.request("https://vote.test", { headers: { cookie: "__Host-hv_session=a; __Host-hv_session=b; __Host-hv_session=c; good=value" } }, env);
    expect(await res.json()).toEqual({ good: "value" });
  });
});

describe("rate limit reconciliation", () => {
  it("globally removes at most 100 expired one-off identifiers per hit", async () => {
    const prefix = crypto.randomUUID();
    const now = Math.floor(Date.now() / 1000);
    await env.DB.batch(Array.from({ length: 105 }, (_, i) => env.DB.prepare(
      "INSERT INTO rate_limits (bucket, hits, reset_at) VALUES (?1, 1, ?2)",
    ).bind(`${prefix}:${i}`, now - 1000000)));
    await createD1RateLimitStore(env).hit(`${prefix}:active`, 2, 60);
    const remaining = await env.DB.prepare("SELECT COUNT(*) AS n FROM rate_limits WHERE bucket LIKE ?1 AND reset_at < ?2")
      .bind(`${prefix}:%`, now).first<{ n: number }>();
    expect(remaining?.n).toBe(5);
  });
  it("caps authenticated rotations at 30 per tenant per hour", async () => {
    const id = crypto.randomUUID();
    for (let i = 0; i < 30; i++) await limitKeyRotation(env, id);
    await expect(limitKeyRotation(env, id)).rejects.toMatchObject({ status: 429 });
    await expect(limitKeyRotation(env, crypto.randomUUID())).resolves.toBeUndefined();
  });
  it("does not let unauthenticated rotation consume a tenant's rate limit", async () => {
    const id = crypto.randomUUID();
    const res = await SELF.fetch(`https://vote.test/api/v1/tenants/${id}/rotate-key`, { method: "POST" });
    expect(res.status).toBe(401);
    const row = await env.DB.prepare("SELECT hits FROM rate_limits WHERE bucket = ?1")
      .bind(await sha256Hex(`rl:rotate-key:${id}`)).first();
    expect(row).toBeNull();
  });
});
