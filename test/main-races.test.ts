import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import app from "../src/index";
import type { Env } from "../src/types";
import { consumeRateLimit } from "../src/rate-limit";
import { sha256Hex } from "../src/crypto";
import { applySchema } from "./fixtures";

const BASE = "https://vote.test";
beforeAll(async () => { await applySchema(env.DB); });

async function fixture() {
  const tenant = crypto.randomUUID();
  const key = crypto.randomUUID();
  const poll = crypto.randomUUID();
  const options = [crypto.randomUUID(), crypto.randomUUID()];
  await env.DB.batch([
    env.DB.prepare("INSERT INTO tenants VALUES (?1, 'test', ?2, '2026-01-01')").bind(tenant, await sha256Hex(key)),
    env.DB.prepare("INSERT INTO polls (id, tenant_id, question, status, allow_multiple, created_at, updated_at) VALUES (?1, ?2, 'test', 'published', 1, '2026-01-01', '2026-01-01')").bind(poll, tenant),
    ...options.map((id, index) => env.DB.prepare("INSERT INTO options (id, poll_id, label, position, created_at) VALUES (?1, ?2, 'option', ?3, '2026-01-01')").bind(id, poll, index)),
  ]);
  return { tenant, key, poll, options };
}

// Deterministically commit a competing request after route validation, just
// before its transaction. This tests the actual route, not a copied predicate.
function interleave(beforeBatch: () => Promise<unknown>): Env {
  let pending = true;
  const db = new Proxy(env.DB, {
    get(target, property) {
      if (property === "batch") return async (statements: D1PreparedStatement[]) => {
        if (pending) { pending = false; await beforeBatch(); }
        return target.batch(statements);
      };
      const value = Reflect.get(target, property);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { ...env, DB: db } as Env;
}

const headers = (key: string) => ({ authorization: `Bearer ${key}`, "content-type": "application/json" });

describe("main security transaction races", () => {
  for (const change of ["status = 'closed'", "status = 'draft'", "require_login = 1", "allow_multiple = 0", "closes_at = '2000-01-01T00:00:00.000Z'"]) {
    it(`rejects a vote when ${change} changes before commit`, async () => {
      const f = await fixture();
      const response = await app.request(`${BASE}/api/v1/polls/${f.poll}/vote`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ voter_token: "anonymous-token", option_ids: f.options }),
      }, interleave(() => env.DB.prepare(`UPDATE polls SET ${change}, revision = revision + 1 WHERE id = ?1`).bind(f.poll).run()));
      expect(response.status).toBe(409);
      expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM votes WHERE poll_id = ?1").bind(f.poll).first("n")).toBe(0);
      expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM poll_mutation_guards").first("n")).toBe(0);
    });
  }

  it("preserves the previous ballot when closing races with replacement", async () => {
    const f = await fixture();
    const body = JSON.stringify({ voter_token: "keep-this-ballot", option_ids: [f.options[0]] });
    const initial = await SELF.fetch(`${BASE}/api/v1/polls/${f.poll}/vote`, {
      method: "POST", headers: { "content-type": "application/json" }, body,
    });
    expect(initial.status).toBe(200);
    const response = await app.request(`${BASE}/api/v1/polls/${f.poll}/vote`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ voter_token: "keep-this-ballot", option_ids: [f.options[1]] }),
    }, interleave(() => env.DB.prepare("UPDATE polls SET status = 'closed', revision = revision + 1 WHERE id = ?1").bind(f.poll).run()));
    expect(response.status).toBe(409);
    expect(await env.DB.prepare("SELECT option_id FROM votes WHERE poll_id = ?1").bind(f.poll).first("option_id")).toBe(f.options[0]);
  });

  it("rejects stale edits without overwriting a concurrent administrator", async () => {
    const f = await fixture();
    const response = await app.request(`${BASE}/api/v1/tenants/${f.tenant}/polls/${f.poll}`, {
      method: "PATCH", headers: headers(f.key), body: JSON.stringify({ question: "stale edit" }),
    }, interleave(() => env.DB.prepare("UPDATE polls SET question = 'latest edit', revision = revision + 1 WHERE id = ?1").bind(f.poll).run()));
    expect(response.status).toBe(409);
    expect(await env.DB.prepare("SELECT question FROM polls WHERE id = ?1").bind(f.poll).first("question")).toBe("latest edit");
  });

  it("does not cascade-delete a vote arriving during option replacement", async () => {
    const f = await fixture();
    const response = await app.request(`${BASE}/api/v1/tenants/${f.tenant}/polls/${f.poll}`, {
      method: "PATCH", headers: headers(f.key),
      body: JSON.stringify({ options: [{ label: "new A" }, { label: "new B" }] }),
    }, interleave(() => env.DB.prepare("INSERT INTO votes VALUES (?1, ?2, ?3, 'user:test', '2026-01-01', '2026-01-01')").bind(crypto.randomUUID(), f.poll, f.options[0]).run()));
    expect(response.status).toBe(409);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM votes WHERE poll_id = ?1").bind(f.poll).first("n")).toBe(1);
    expect(await env.DB.prepare("SELECT id FROM options WHERE id = ?1").bind(f.options[0]).first("id")).toBe(f.options[0]);
  });

  it("cannot reopen a poll closed by a competing status request", async () => {
    const f = await fixture();
    const response = await app.request(`${BASE}/api/v1/tenants/${f.tenant}/polls/${f.poll}/status`, {
      method: "POST", headers: headers(f.key), body: JSON.stringify({ status: "draft" }),
    }, interleave(() => env.DB.prepare("UPDATE polls SET status = 'closed', revision = revision + 1 WHERE id = ?1").bind(f.poll).run()));
    expect(response.status).toBe(409);
    expect(await env.DB.prepare("SELECT status FROM polls WHERE id = ?1").bind(f.poll).first("status")).toBe("closed");
  });

  it("unauthenticated rotation does not consume the tenant's budget", async () => {
    const f = await fixture();
    for (let i = 0; i < 31; i++) {
      const res = await SELF.fetch(`${BASE}/api/v1/tenants/${f.tenant}/rotate-key`, { method: "POST" });
      expect(res.status).toBe(401);
    }
    const res = await SELF.fetch(`${BASE}/api/v1/tenants/${f.tenant}/rotate-key`, { method: "POST", headers: headers(f.key) });
    expect(res.status).toBe(200);
  });

  it("reclaims old one-off rate identifiers globally in bounded batches", async () => {
    const prefix = crypto.randomUUID();
    await env.DB.batch(Array.from({ length: 105 }, (_, i) => env.DB.prepare("INSERT INTO rate_limit_buckets VALUES (?1, 0, 1)").bind(`${prefix}:${i}`)));
    await consumeRateLimit(env as Env, "test-cleanup", crypto.randomUUID(), 10, 3600);
    const remaining = await env.DB.prepare("SELECT COUNT(*) AS n FROM rate_limit_buckets WHERE bucket LIKE ?1").bind(`${prefix}:%`).first<number>("n");
    expect(remaining).toBeGreaterThanOrEqual(5);
    expect(remaining).toBeLessThan(105);
  });
});
