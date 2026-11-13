import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { applySchema } from "./fixtures";
import { hashVoterKey, upsertBallot } from "../src/ballots";
import { sha256Hex } from "../src/crypto";
import { getPollRow } from "../src/domain";
import { replaceQuestionStatements } from "../src/questions";
import type { Env, PollRow } from "../src/types";

const bindings = env as unknown as Env;
const IP = "192.0.2.14";
const BASE = "https://vote.test";
const original = '{"v":2,"answers":[]}';
beforeAll(async () => { await applySchema(env.DB); });

async function fixture() {
  const id = crypto.randomUUID();
  const tenant = crypto.randomUUID();
  const now = new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (?1, 'IP ownership', ?2, ?3)").bind(tenant, crypto.randomUUID(), now),
    env.DB.prepare("INSERT INTO polls (id, tenant_id, question, status, ip_single_vote, created_at, updated_at, revision) VALUES (?1, ?2, 'Private answers', 'published', 1, ?3, ?3, 'initial')").bind(id, tenant, now),
  ]);
  await env.DB.batch(replaceQuestionStatements(bindings, id, [{ prompt: "Private text", description: "", image_key: null, kind: "text", required: false, options: [] }], "initial"));
  return (await getPollRow(bindings, id)) as PollRow;
}
async function count(poll: PollRow) {
  return env.DB.prepare("SELECT (SELECT COUNT(*) FROM vote_ballots WHERE poll_id = ?1) AS ballots, (SELECT COUNT(*) FROM vote_events WHERE poll_id = ?1) AS events, (SELECT COUNT(*) FROM poll_ip_ballot_owners WHERE poll_id = ?1) AS owners").bind(poll.id).first();
}
function vote(poll: PollRow, key: string, authenticated = false, anonymousToken?: string, ip = IP) {
  return upsertBallot(bindings, poll, key, original, authenticated, { ip, anonymousToken });
}

describe("IP uniqueness never grants ballot ownership", () => {
  it("does not disclose a NAT neighbor's ballot or permit overwriting with another token", async () => {
    const poll = await fixture();
    await vote(poll, "anon:owner-token");
    const missing = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/ballot`, { headers: { "cf-connecting-ip": IP } });
    expect(missing.status).toBe(400);
    const other = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/ballot?voter_token=other-token`, { headers: { "cf-connecting-ip": IP } });
    expect(other.status).toBe(200);
    expect((await other.json() as { ballot: unknown }).ballot).toBeNull();
    const owner = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/ballot?voter_token=owner-token`, { headers: { "cf-connecting-ip": IP } });
    expect((await owner.json() as { ballot: unknown }).ballot).not.toBeNull();
    await expect(vote(poll, "anon:other-token")).rejects.toThrow();
    await vote(poll, "anon:owner-token");
    expect(await count(poll)).toEqual({ ballots: 1, events: 2, owners: 1 });
  });

  it("reserves one owner atomically for concurrent different tokens", async () => {
    const poll = await fixture();
    const attempts = await Promise.allSettled([vote(poll, "anon:token-one"), vote(poll, "anon:token-two")]);
    expect(attempts.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(await count(poll)).toEqual({ ballots: 1, events: 1, owners: 1 });
  });

  it("applies IP uniqueness to logged-in voters and atomically claims a proven anonymous ballot", async () => {
    const poll = await fixture();
    await vote(poll, "anon:owner-token");
    await expect(vote(poll, "user:neighbor", true)).rejects.toThrow();
    await expect(vote(poll, "user:neighbor", true, "wrong-token")).rejects.toThrow();
    await vote(poll, "user:owner", true, "owner-token");
    expect(await count(poll)).toEqual({ ballots: 1, events: 2, owners: 1 });
    const row = await env.DB.prepare("SELECT voter_key FROM vote_ballots WHERE poll_id = ?1").bind(poll.id).first<{ voter_key: string }>();
    expect(row?.voter_key).toBe(await hashVoterKey(bindings, "user:owner"));
    await expect(vote(poll, "anon:owner-token")).rejects.toThrow();
    await expect(vote(poll, "user:neighbor", true)).rejects.toThrow();
  });

  it("does not delete or transfer the anonymous ballot on a failed login merge", async () => {
    const poll = await fixture();
    await vote(poll, "anon:owner-token");
    await env.DB.prepare("UPDATE polls SET status = 'closed' WHERE id = ?1").bind(poll.id).run();
    await expect(vote(poll, "user:owner", true, "owner-token")).rejects.toThrow();
    expect(await count(poll)).toEqual({ ballots: 1, events: 1, owners: 1 });
    const row = await env.DB.prepare("SELECT owner_key FROM poll_ip_ballot_owners WHERE poll_id = ?1").bind(poll.id).first<{ owner_key: string }>();
    expect(row?.owner_key).toBe(await hashVoterKey(bindings, "anon:owner-token"));
  });

  it.each([IP, "unknown"])("preserves legacy %s ballots without disclosing or silently duplicating them", async (legacyIp) => {
    const poll = await fixture();
    const legacy = await hashVoterKey(bindings, `ip:${await sha256Hex(legacyIp)}`);
    await env.DB.prepare("INSERT INTO vote_ballots (poll_id, voter_key, option_ids, updated_at) VALUES (?1, ?2, ?3, ?4)").bind(poll.id, legacy, original, new Date().toISOString()).run();
    await expect(vote(poll, "anon:unknown-owner")).rejects.toThrow();
    await expect(vote(poll, "user:unknown-owner", true)).rejects.toThrow();
    const read = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/ballot?voter_token=unknown-owner`, { headers: { "cf-connecting-ip": IP } });
    expect((await read.json() as { ballot: unknown }).ballot).toBeNull();
    expect(await count(poll)).toEqual({ ballots: 1, events: 0, owners: 0 });
  });

  it("fails closed when a trusted IP is missing, without allocating shared unknown identity", async () => {
    const poll = await fixture();
    await expect(vote(poll, "anon:owner-token", false, undefined, "")).rejects.toThrow("trusted client IP");
    expect(await count(poll)).toEqual({ ballots: 0, events: 0, owners: 0 });
  });
});
