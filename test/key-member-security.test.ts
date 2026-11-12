import { env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { randomId, randomToken, sha256Hex } from "../src/crypto";
import { findActiveApiKey, issueApiKey, provisionTenant, revokeApiKey, rotatePresentedKey } from "../src/keys";
import { addMember, removeMember, setMemberRole } from "../src/members";
import type { AdminPrincipal, Env } from "../src/types";
import { applySchema } from "./fixtures";

const bindings = env as unknown as Env;
beforeAll(async () => { await applySchema(env.DB); });

function actor(tenantId: string): AdminPrincipal {
  return { kind: "session", tenantId, sub: "owner-a", role: "owner" };
}
async function workspace() {
  const created = await provisionTenant(bindings, "Security regression", "owner-a");
  const presented = await findActiveApiKey(bindings, created.apiKey);
  expect(presented).not.toBeNull();
  return { ...created, presented: presented!, actor: actor(created.tenantId) };
}
async function activeCount(tenantId: string) {
  return (await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM api_keys WHERE tenant_id = ?1 AND revoked_at IS NULL",
  ).bind(tenantId).first<{ n: number }>())!.n;
}
async function ownerCount(tenantId: string) {
  return (await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM tenant_members WHERE tenant_id = ?1 AND role = 'owner'",
  ).bind(tenantId).first<{ n: number }>())!.n;
}

describe("atomic API key changes", () => {
  it("consumes a presented key only once across concurrent rotations", async () => {
    const w = await workspace();
    const rotations = await Promise.allSettled(Array.from({ length: 4 }, () =>
      rotatePresentedKey(bindings, w.tenantId, w.presented)));
    expect(rotations.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(await activeCount(w.tenantId)).toBe(1);
    expect(await findActiveApiKey(bindings, w.apiKey)).toBeNull();
    const winner = rotations.find((r) => r.status === "fulfilled") as PromiseFulfilledResult<string>;
    expect(await findActiveApiKey(bindings, winner.value)).not.toBeNull();
  });

  it("does not mint a successor from a revoked authentication snapshot", async () => {
    const w = await workspace();
    await revokeApiKey(bindings, w.tenantId, w.presented.key.id, w.actor);
    await expect(rotatePresentedKey(bindings, w.tenantId, w.presented))
      .rejects.toMatchObject({ status: 401 });
    expect(await activeCount(w.tenantId)).toBe(0);
    expect(await findActiveApiKey(bindings, w.apiKey)).toBeNull();
  });

  it("does not rotate a read key or a key from another tenant", async () => {
    const w = await workspace();
    const read = await issueApiKey(bindings, w.tenantId, "Read", "read", w.actor);
    const presented = (await findActiveApiKey(bindings, read.apiKey))!;
    await expect(rotatePresentedKey(bindings, w.tenantId, presented)).rejects.toMatchObject({ status: 401 });
    const other = await workspace();
    await expect(rotatePresentedKey(bindings, other.tenantId, w.presented)).rejects.toMatchObject({ status: 401 });
    expect(await activeCount(other.tenantId)).toBe(1);
  });

  it("consumes legacy fallback once without reviving it", async () => {
    const tenantId = randomId();
    const token = randomToken("hvk");
    await env.DB.prepare("INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (?1, 'Legacy', ?2, ?3)")
      .bind(tenantId, await sha256Hex(token), new Date().toISOString()).run();
    const presented = (await findActiveApiKey(bindings, token))!;
    expect(presented.key.id).toBe("legacy");
    const rotations = await Promise.allSettled(Array.from({ length: 3 }, () =>
      rotatePresentedKey(bindings, tenantId, presented)));
    expect(rotations.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(await activeCount(tenantId)).toBe(1);
    expect(await findActiveApiKey(bindings, token)).toBeNull();
  });

  it("rejects a legacy snapshot after its fallback hash changed", async () => {
    const w = await workspace();
    // Emulate a legacy database, authenticate, then concurrently invalidate its fallback.
    await env.DB.prepare("DELETE FROM api_keys WHERE tenant_id = ?1").bind(w.tenantId).run();
    const legacy = (await findActiveApiKey(bindings, w.apiKey))!;
    await env.DB.prepare("UPDATE tenants SET api_key_hash = ?1 WHERE id = ?2")
      .bind(await sha256Hex(randomToken("revoked")), w.tenantId).run();
    await expect(rotatePresentedKey(bindings, w.tenantId, legacy)).rejects.toMatchObject({ status: 401 });
    expect(await activeCount(w.tenantId)).toBe(0);
  });

  it("atomically enforces issuance quota while allowing replacement at the cap", async () => {
    const w = await workspace();
    await env.DB.prepare("UPDATE tenants SET quota_keys = 2 WHERE id = ?1").bind(w.tenantId).run();
    const issued = await Promise.allSettled(Array.from({ length: 5 }, (_, i) =>
      issueApiKey(bindings, w.tenantId, `Key ${i}`, "write", w.actor)));
    expect(issued.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(await activeCount(w.tenantId)).toBe(2);
    await rotatePresentedKey(bindings, w.tenantId, w.presented);
    expect(await activeCount(w.tenantId)).toBe(2);
  });
});

describe("atomic last-owner protection", () => {
  it.each(["demote", "remove", "mixed"])("keeps an owner during competing %s operations", async (mode) => {
    const w = await workspace();
    await addMember(bindings, w.tenantId, "owner-b", "owner", w.actor);
    const outcomes = await Promise.allSettled(["owner-a", "owner-b"].map((sub, i) =>
      mode === "demote" || (mode === "mixed" && i === 0)
        ? setMemberRole(bindings, w.tenantId, sub, "member", w.actor)
        : removeMember(bindings, w.tenantId, sub, w.actor)));
    expect(outcomes.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(await ownerCount(w.tenantId)).toBe(1);
  });

  it.each(["demote", "remove"])("rejects a stale member role during %s", async (operation) => {
    const w = await workspace();
    await addMember(bindings, w.tenantId, "member", "member", w.actor);
    let intercepted = false;
    // Force the role to change after the function reads it, before its write.
    const racingEnv = {
      ...bindings,
      DB: {
        prepare(sql: string) {
          const statement = env.DB.prepare(sql);
          if (!intercepted && sql.startsWith("SELECT role FROM tenant_members")) {
            return {
              bind(...values: unknown[]) {
                const bound = statement.bind(...values);
                return {
                  async first() {
                    const snapshot = await bound.first();
                    intercepted = true;
                    await env.DB.batch([
                      env.DB.prepare("UPDATE tenant_members SET role = 'owner' WHERE tenant_id = ?1 AND user_sub = 'member'").bind(w.tenantId),
                      env.DB.prepare("UPDATE tenant_members SET role = 'member' WHERE tenant_id = ?1 AND user_sub = 'owner-a'").bind(w.tenantId),
                    ]);
                    return snapshot;
                  },
                };
              },
            };
          }
          return statement;
        },
      },
    } as unknown as Env;
    const change = operation === "demote"
      ? setMemberRole(racingEnv, w.tenantId, "member", "member", w.actor)
      : removeMember(racingEnv, w.tenantId, "member", w.actor);
    await expect(change).rejects.toMatchObject({ code: "LAST_OWNER" });
    expect(await ownerCount(w.tenantId)).toBe(1);
  });

  it("allows ordinary member changes and keeping the sole owner role", async () => {
    const w = await workspace();
    await setMemberRole(bindings, w.tenantId, "owner-a", "owner", w.actor);
    await addMember(bindings, w.tenantId, "member", "member", w.actor);
    await removeMember(bindings, w.tenantId, "member", w.actor);
    await expect(setMemberRole(bindings, w.tenantId, "owner-a", "member", w.actor))
      .rejects.toMatchObject({ code: "LAST_OWNER" });
    await expect(removeMember(bindings, w.tenantId, "owner-a", w.actor))
      .rejects.toMatchObject({ code: "LAST_OWNER" });
    expect(await ownerCount(w.tenantId)).toBe(1);
  });
});

it("enforces main's global provisioning ceiling before writing tenants", async () => {
  const bucket = await sha256Hex("rl:tenant-create-global:all");
  await env.DB.prepare("INSERT INTO rate_limits (bucket, hits, reset_at) VALUES (?1, 1000, ?2) ON CONFLICT(bucket) DO UPDATE SET hits = 1000, reset_at = excluded.reset_at")
    .bind(bucket, Math.floor(Date.now() / 1000) + 86_400).run();
  const before = await env.DB.prepare("SELECT COUNT(*) AS n FROM tenants").first<{ n: number }>();
  try {
    await expect(provisionTenant(bindings, "Over limit", null)).rejects.toMatchObject({ status: 429 });
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM tenants").first()).toEqual(before);
  } finally {
    await env.DB.prepare("DELETE FROM rate_limits WHERE bucket = ?1").bind(bucket).run();
  }
});
