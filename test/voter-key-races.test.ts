import { env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { anonVoterKey, migrateLegacyAnonVoterKeys } from "../src/voter-keys";
import type { Env } from "../src/types";
import { applySchema } from "./fixtures";

beforeAll(async () => { await applySchema(env.DB); });

async function fixture() {
  const tenant = crypto.randomUUID();
  const poll = crypto.randomUUID();
  const token = crypto.randomUUID();
  const canonical = await anonVoterKey(env.SESSION_SECRET, token);
  const legacy = `anon:${token}`;
  const options = Array.from({ length: 3 }, () => crypto.randomUUID());
  await env.DB.batch([
    env.DB.prepare("INSERT INTO tenants VALUES (?1, 'migration test', ?2, '2026-01-01')").bind(tenant, crypto.randomUUID()),
    env.DB.prepare("INSERT INTO polls (id, tenant_id, question, status, created_at, updated_at) VALUES (?1, ?2, 'migration', 'published', '2026-01-01', '2026-01-01')").bind(poll, tenant),
    ...options.map((id, i) => env.DB.prepare("INSERT INTO options VALUES (?1, ?2, 'option', NULL, ?3, '2026-01-01')").bind(id, poll, i)),
  ]);
  const insert = (key: string, option: number, updated: string) => env.DB.prepare(
    "INSERT INTO votes VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
  ).bind(crypto.randomUUID(), poll, options[option], key, updated);
  const ballots = async () => (await env.DB.prepare(
    "SELECT option_id, voter_key, updated_at FROM votes WHERE poll_id = ?1 ORDER BY option_id",
  ).bind(poll).all<{ option_id: string; voter_key: string; updated_at: string }>()).results;
  return { poll, canonical, legacy, options, insert, ballots };
}

function delayedMigration(before: () => Promise<void>): Env {
  let pending = true;
  const DB = new Proxy(env.DB, {
    get(target, property) {
      if (property === "batch") return async (statements: D1PreparedStatement[]) => {
        if (pending) { pending = false; await before(); }
        return target.batch(statements);
      };
      const value = Reflect.get(target, property);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { ...env, DB } as Env;
}

describe("atomic legacy voter migration", () => {
  for (const [legacyTime, canonicalTime, expected] of [
    ["2026-01-03", "2026-01-02", "legacy"],
    ["2026-01-02", "2026-01-03", "canonical"],
    ["2026-01-03", "2026-01-03", "canonical"],
  ] as const) {
    it(`preserves the entire ${expected} set for ${legacyTime}/${canonicalTime}`, async () => {
      const f = await fixture();
      await env.DB.batch([f.insert(f.legacy, 0, legacyTime), f.insert(f.legacy, 1, legacyTime), f.insert(f.canonical, 2, canonicalTime)]);
      await migrateLegacyAnonVoterKeys(env as Env, f.poll);
      const rows = await f.ballots();
      expect(rows.map((r) => r.option_id).sort()).toEqual((expected === "legacy" ? f.options.slice(0, 2) : f.options.slice(2)).sort());
      expect(rows.every((r) => r.voter_key === f.canonical)).toBe(true);
      await migrateLegacyAnonVoterKeys(env as Env, f.poll);
      expect(await f.ballots()).toEqual(rows);
    });
  }

  it("a delayed second migration cannot erase a subsequent canonical vote", async () => {
    const f = await fixture();
    await env.DB.batch([f.insert(f.legacy, 0, "2026-01-02"), f.insert(f.canonical, 1, "2026-01-01")]);
    const delayed = delayedMigration(async () => {
      await migrateLegacyAnonVoterKeys(env as Env, f.poll);
      await env.DB.batch([
        env.DB.prepare("DELETE FROM votes WHERE poll_id = ?1 AND voter_key = ?2").bind(f.poll, f.canonical),
        f.insert(f.canonical, 2, "2026-01-03"),
      ]);
    });
    await migrateLegacyAnonVoterKeys(delayed, f.poll);
    expect(await f.ballots()).toEqual([{ option_id: f.options[2], voter_key: f.canonical, updated_at: "2026-01-03" }]);
  });

  it("chooses timestamps at commit rather than at discovery", async () => {
    const f = await fixture();
    await env.DB.batch([f.insert(f.legacy, 0, "2026-01-02"), f.insert(f.canonical, 1, "2026-01-01")]);
    await migrateLegacyAnonVoterKeys(delayedMigration(async () => {
      await env.DB.prepare("UPDATE votes SET updated_at = '2026-01-03' WHERE poll_id = ?1 AND voter_key = ?2").bind(f.poll, f.canonical).run();
    }), f.poll);
    expect(await f.ballots()).toEqual([{ option_id: f.options[1], voter_key: f.canonical, updated_at: "2026-01-03" }]);
  });

  it("propagates storage failures instead of serving an unmigrated ballot", async () => {
    const f = await fixture();
    await f.insert(f.legacy, 0, "2026-01-01").run();
    await expect(migrateLegacyAnonVoterKeys(delayedMigration(async () => { throw new Error("simulated storage failure"); }), f.poll)).rejects.toThrow("simulated storage failure");
    expect((await f.ballots())[0]?.voter_key).toBe(f.legacy);
  });
});
