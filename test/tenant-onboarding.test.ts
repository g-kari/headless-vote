import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { provisionTenant } from "../src/keys";
import type { Env } from "../src/types";
import { applySchema } from "./fixtures";
import { fixtureSessionHeaders, loginForTests, sessionCookieHeader } from "./session";

const BASE = "https://vote.test";
const bindings = env as unknown as Env;

beforeAll(async () => {
  await applySchema(env.DB);
});

async function tenantCount(): Promise<number> {
  const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM tenants").first<{ n: number }>();
  return Number(row?.n ?? 0);
}

describe("tenant onboarding requires a verified login (KAZAMI-306 #10)", () => {
  it("rejects anonymous tenant creation and writes nothing", async () => {
    const before = await tenantCount();
    const res = await SELF.fetch(`${BASE}/api/v1/tenants`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "匿名の作成" }),
    });
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("UNAUTHORIZED");
    expect(await tenantCount()).toBe(before);
  });

  it("blocks cross-site creation even with a session cookie", async () => {
    const before = await tenantCount();
    const res = await SELF.fetch(`${BASE}/api/v1/tenants`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(await fixtureSessionHeaders()),
        origin: "https://evil.example",
        "sec-fetch-site": "cross-site",
      },
      body: JSON.stringify({ name: "乗っ取り" }),
    });
    expect(res.status).toBe(403);
    expect(await tenantCount()).toBe(before);
  });

  it("creates the workspace with the logged-in creator as owner", async () => {
    const session = await loginForTests("onboarding-owner", "onboarding@example.com");
    const account = await env.DB.prepare("SELECT id FROM accounts WHERE subject = ?1")
      .bind("onboarding-owner")
      .first<{ id: string }>();
    expect(account).not.toBeNull();

    const res = await SELF.fetch(`${BASE}/api/v1/tenants`, {
      method: "POST",
      headers: { "content-type": "application/json", ...sessionCookieHeader(session) },
      body: JSON.stringify({ name: "オーナー付き" }),
    });
    expect(res.status).toBe(201);
    const data = (await res.json()) as { tenant: { id: string }; api_key: string };
    expect(data.api_key.startsWith("hvk_")).toBe(true);

    const member = await env.DB.prepare(
      "SELECT account_id, role FROM tenant_members WHERE tenant_id = ?1",
    )
      .bind(data.tenant.id)
      .first<{ account_id: string; role: string }>();
    expect(member).toEqual({ account_id: account!.id, role: "owner" });
  });
});

describe("total tenant cap (KAZAMI-306 #10)", () => {
  it("rejects provisioning at the cap without writing partial rows", async () => {
    const before = await tenantCount();
    const capped = { ...bindings, MAX_TENANTS: String(before) } as Env;
    await expect(provisionTenant(capped, "上限到達", null)).rejects.toMatchObject({
      status: 503,
      code: "TENANT_LIMIT_REACHED",
    });
    expect(await tenantCount()).toBe(before);
    const orphans = await env.DB.prepare(
      `SELECT (SELECT COUNT(*) FROM api_keys k LEFT JOIN tenants t ON t.id = k.tenant_id WHERE t.id IS NULL) AS keys,
              (SELECT COUNT(*) FROM tenant_members m LEFT JOIN tenants t ON t.id = m.tenant_id WHERE t.id IS NULL) AS members`,
    ).first<{ keys: number; members: number }>();
    expect(orphans).toEqual({ keys: 0, members: 0 });
  });

  it("allows exactly one more tenant when the cap leaves room for one", async () => {
    const before = await tenantCount();
    const roomForOne = { ...bindings, MAX_TENANTS: String(before + 1) } as Env;
    const created = await provisionTenant(roomForOne, "上限手前", null);
    expect(created.tenantId).toBeTruthy();
    expect(await tenantCount()).toBe(before + 1);
    await expect(provisionTenant(roomForOne, "上限超過", null)).rejects.toMatchObject({
      status: 503,
      code: "TENANT_LIMIT_REACHED",
    });
    expect(await tenantCount()).toBe(before + 1);
  });
});
