import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { applySchema } from "./fixtures";
import { upsertBallot } from "../src/ballots";
import { getPollRow } from "../src/domain";
import { newSessionCookieForToken } from "../src/auth";
import { replaceQuestionStatements, questionTextStatements, listQuestionRows } from "../src/questions";
import type { Env, PollRow } from "../src/types";

const BASE = "https://vote.test";
const bindings = env as unknown as Env;
beforeAll(async () => { await applySchema(env.DB); });

async function fixture() {
  const tenant = crypto.randomUUID();
  const poll = crypto.randomUUID();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO tenants (id, name, api_key_hash, created_at, quota_votes_per_day) VALUES (?1, 'race', ?2, ?3, 1)")
      .bind(tenant, crypto.randomUUID(), new Date().toISOString()),
    env.DB.prepare("INSERT INTO polls (id, tenant_id, question, status, created_at, updated_at, revision) VALUES (?1, ?2, 'Question', 'published', ?3, ?3, 'initial')")
      .bind(poll, tenant, new Date().toISOString()),
  ]);
  await env.DB.batch(replaceQuestionStatements(bindings, poll, [{ prompt: "Text", description: "", image_key: null, kind: "text", required: false, options: [] }], "initial"));
  return { tenant, poll: (await getPollRow(bindings, poll)) as PollRow };
}

async function counts(id: string) {
  return env.DB.prepare("SELECT (SELECT COUNT(*) FROM vote_ballots WHERE poll_id = ?1) AS ballots, (SELECT COUNT(*) FROM vote_events WHERE poll_id = ?1) AS events")
    .bind(id).first<{ ballots: number; events: number }>();
}

describe("atomic voting boundaries", () => {
  it.each(["closed", "draft"])("rejects a stale snapshot after %s", async (status) => {
    const { poll } = await fixture();
    await env.DB.prepare("UPDATE polls SET status = ?1 WHERE id = ?2").bind(status, poll.id).run();
    await expect(upsertBallot(bindings, poll, "anon:test", '{"v":2,"answers":[]}', false)).rejects.toThrow();
    expect(await counts(poll.id)).toEqual({ ballots: 0, events: 0 });
  });

  it("rejects a stale revision, elapsed deadline, future opening and tightened login", async () => {
    for (const update of ["revision = 'changed'", "closes_at = '2000-01-01T00:00:00.000Z'", "opens_at = '2999-01-01T00:00:00.000Z'", "require_login = 1"]) {
      const { poll } = await fixture();
      await env.DB.prepare(`UPDATE polls SET ${update} WHERE id = ?1`).bind(poll.id).run();
      await expect(upsertBallot(bindings, poll, "anon:test", '{"v":2,"answers":[]}', false)).rejects.toThrow();
      expect(await counts(poll.id)).toEqual({ ballots: 0, events: 0 });
    }
  });

  it("reserves only one final quota slot across concurrent ballots", async () => {
    const { poll } = await fixture();
    const results = await Promise.allSettled(["one", "two"].map((id) => upsertBallot(bindings, poll, `anon:${id}`, '{"v":2,"answers":[]}', false)));
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(await counts(poll.id)).toEqual({ ballots: 1, events: 1 });
  });

  it("maintains the D1 quota ledger with memory analytics", async () => {
    const { poll } = await fixture();
    const memory = { ...bindings, ANALYTICS_STORE: "memory" } as Env;
    await upsertBallot(memory, poll, "anon:one", '{"v":2,"answers":[]}', false);
    await expect(upsertBallot(memory, poll, "anon:two", '{"v":2,"answers":[]}', false)).rejects.toThrow();
    expect(await counts(poll.id)).toEqual({ ballots: 1, events: 1 });
  });

  it("failed compare-and-swap cannot replace questions or edit their text", async () => {
    const { poll } = await fixture();
    const before = await listQuestionRows(bindings, poll.id);
    const input = [{ id: before[0]!.id, prompt: "Tampered", description: "", image_key: null, kind: "text" as const, required: false, options: [] }];
    await env.DB.batch([
      env.DB.prepare("UPDATE polls SET revision = 'loser' WHERE id = ?1 AND revision = 'stale'").bind(poll.id),
      ...questionTextStatements(bindings, poll.id, input, before, [], "loser"),
      ...replaceQuestionStatements(bindings, poll.id, input, "loser"),
    ]);
    expect(await listQuestionRows(bindings, poll.id)).toEqual(before);
  });

  it("rejects credentialed sibling-origin simple requests before voting", async () => {
    const { poll } = await fixture();
    const cookie = (await newSessionCookieForToken(bindings, {}, "csrf-voter", BASE)).split(";")[0]!;
    const origins: Record<string, string>[] = [
      { origin: "https://evil.vote.test", "sec-fetch-site": "same-site" },
      { origin: "null", "sec-fetch-site": "same-site" },
      { "sec-fetch-site": "same-site" },
    ];
    for (const headers of origins) {
      const response = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/vote`, {
        method: "POST", headers: { ...headers, cookie, "content-type": "text/plain" }, body: '{"answers":[]}',
      });
      expect(response.status).toBe(403);
    }
    expect(await counts(poll.id)).toEqual({ ballots: 0, events: 0 });
  });

  it("allows a tenant-approved cookie voting origin", async () => {
    const { tenant, poll } = await fixture();
    const origin = "https://embed.example.test";
    await env.DB.prepare("INSERT INTO tenant_origins (tenant_id, origin, created_at) VALUES (?1, ?2, ?3)")
      .bind(tenant, origin, new Date().toISOString()).run();
    const cookie = (await newSessionCookieForToken(bindings, {}, "allowed-voter", BASE)).split(";")[0]!;
    const response = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/vote`, {
      method: "POST", headers: { cookie, origin, "sec-fetch-site": "cross-site", "content-type": "application/json" },
      body: '{"answers":[]}',
    });
    expect(response.status).toBe(200);
    expect(await counts(poll.id)).toEqual({ ballots: 1, events: 1 });
  });

  it("atomically enforces poll creation quota", async () => {
    const response = await SELF.fetch(`${BASE}/api/v1/tenants`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: "poll-quota" }),
    });
    const data = await response.json() as { tenant: { id: string }; api_key: string };
    await env.DB.prepare("UPDATE tenants SET quota_polls = 1 WHERE id = ?1").bind(data.tenant.id).run();
    const attempts = await Promise.all([1, 2].map(() => SELF.fetch(`${BASE}/api/v1/tenants/${data.tenant.id}/polls`, {
      method: "POST", headers: { authorization: `Bearer ${data.api_key}`, "content-type": "application/json" },
      body: JSON.stringify({ question: "Quota", options: [{ label: "A" }, { label: "B" }] }),
    })));
    expect(attempts.filter((r) => r.status === 201)).toHaveLength(1);
    expect(attempts.filter((r) => r.status === 409)).toHaveLength(1);
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM polls WHERE tenant_id = ?1").bind(data.tenant.id).first<{ n: number }>();
    expect(count?.n).toBe(1);
  });

});
