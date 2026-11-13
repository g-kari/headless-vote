import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { applySchema } from "./fixtures";
import {
  decryptIpEntries,
  encryptIpEntries,
  ipMatchesEntries,
  ipRestrictionAvailable,
  isAdminIpAllowed,
  loadIpRestriction,
  parseIpEntry,
  saveIpRestriction,
  validateIpEntries,
} from "../src/ip-restriction";
import type { Env } from "../src/types";

const bindings = env as unknown as Env;
const BASE = "https://vote.test";
const ISSUER = "https://idp.example.test";
const ALLOWED_IP = "198.51.100.7";
const BLOCKED_IP = "203.0.113.9";

beforeAll(async () => {
  await applySchema(env.DB);
});

/* ------------------------------------------------------------------ */
/* Parsing and matching                                                */
/* ------------------------------------------------------------------ */

describe("IP / CIDR parsing and matching", () => {
  it("parses plain addresses and CIDRs for both families", () => {
    expect(parseIpEntry("192.0.2.10")?.prefixBits).toBe(32);
    expect(parseIpEntry("198.51.100.0/24")?.prefixBits).toBe(24);
    expect(parseIpEntry("2001:db8::1")?.prefixBits).toBe(128);
    expect(parseIpEntry("2001:db8::/32")?.prefixBits).toBe(32);
    expect(parseIpEntry("::1")).not.toBeNull();
    expect(parseIpEntry("::ffff:192.0.2.1")).not.toBeNull();
    expect(parseIpEntry("0.0.0.0/0")).not.toBeNull();
  });

  it("rejects malformed entries", () => {
    for (const bad of [
      "999.1.1.1",
      "192.0.2",
      "01.2.3.4",
      "10.0.0.0/33",
      "10.0.0.0/-1",
      "2001:db8::/129",
      "1::2::3",
      "12345::",
      "hello",
      "192.0.2.1/24/1",
      "",
    ]) {
      expect(parseIpEntry(bad), bad).toBeNull();
    }
  });

  it("matches exact addresses and CIDR ranges", () => {
    expect(ipMatchesEntries("192.0.2.10", ["192.0.2.10"])).toBe(true);
    expect(ipMatchesEntries("192.0.2.11", ["192.0.2.10"])).toBe(false);
    expect(ipMatchesEntries("198.51.100.200", ["198.51.100.0/24"])).toBe(true);
    expect(ipMatchesEntries("198.51.101.1", ["198.51.100.0/24"])).toBe(false);
    // Partial-byte prefix.
    expect(ipMatchesEntries("192.0.2.200", ["192.0.2.128/25"])).toBe(true);
    expect(ipMatchesEntries("192.0.2.100", ["192.0.2.128/25"])).toBe(false);
    expect(ipMatchesEntries("203.0.113.9", ["0.0.0.0/0"])).toBe(true);
  });

  it("matches IPv6 ranges and never crosses families", () => {
    expect(ipMatchesEntries("2001:db8::5", ["2001:db8::/32"])).toBe(true);
    expect(ipMatchesEntries("2001:db9::5", ["2001:db8::/32"])).toBe(false);
    expect(ipMatchesEntries("::ffff:192.0.2.1", ["::ffff:192.0.2.0/120"])).toBe(true);
    expect(ipMatchesEntries("192.0.2.1", ["::ffff:192.0.2.0/120"])).toBe(false);
    expect(ipMatchesEntries("2001:db8::5", ["192.0.2.0/24"])).toBe(false);
    expect(ipMatchesEntries("not-an-ip", ["0.0.0.0/0"])).toBe(false);
  });

  it("validates lists with line numbers and dedupes", () => {
    expect(validateIpEntries(["192.0.2.1", "", " 192.0.2.1 ", "2001:DB8::/32"])).toEqual([
      "192.0.2.1",
      "2001:db8::/32",
    ]);
    expect(() => validateIpEntries(["192.0.2.1", "bogus"])).toThrow(/2 行目/);
  });
});

/* ------------------------------------------------------------------ */
/* Encryption at rest                                                  */
/* ------------------------------------------------------------------ */

describe("encrypted storage", () => {
  it("round-trips and never stores plaintext", async () => {
    const entries = ["198.51.100.0/24", "2001:db8::/32"];
    const stored = await encryptIpEntries(bindings, entries);
    expect(stored).not.toContain("198.51");
    expect(stored).not.toContain("2001");
    expect(await decryptIpEntries(bindings, stored)).toEqual(entries);
    // Random IV per record: the same plaintext encrypts differently.
    expect(await encryptIpEntries(bindings, entries)).not.toBe(stored);
  });

  it("detects tampering and wrong keys", async () => {
    const stored = await encryptIpEntries(bindings, ["192.0.2.1"]);
    const tampered = stored.slice(0, -2) + (stored.endsWith("A") ? "B" : "A") + stored.slice(-1);
    await expect(decryptIpEntries(bindings, tampered)).rejects.toThrow();
    const otherKey = {
      IP_LIST_ENCRYPTION_KEY: btoa("9876543210fedcba9876543210fedcba"),
    } as unknown as Env;
    await expect(decryptIpEntries(otherKey, stored)).rejects.toThrow();
  });

  it("is disabled when the key is unset, and an undecryptable row fails closed", async () => {
    expect(await ipRestrictionAvailable(bindings)).toBe(true);
    const noKey = { DB: env.DB } as unknown as Env;
    expect(await ipRestrictionAvailable(noKey)).toBe(false);

    const tenantId = crypto.randomUUID();
    const now = new Date().toISOString();
    await env.DB.prepare(
      "INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (?1, 'ip', 'x', ?2)",
    )
      .bind(tenantId, now)
      .run();
    await saveIpRestriction(bindings, tenantId, ["198.51.100.0/24"]);
    expect((await loadIpRestriction(bindings, tenantId)).kind).toBe("enabled");
    // Key removed from the environment: feature off, restriction ignored.
    expect((await loadIpRestriction(noKey, tenantId)).kind).toBe("disabled");
    expect(await isAdminIpAllowed(noKey, tenantId, BLOCKED_IP)).toBe(true);
    // Wrong key: the stored row cannot be read, so access is denied.
    const wrongKey = {
      DB: env.DB,
      IP_LIST_ENCRYPTION_KEY: btoa("9876543210fedcba9876543210fedcba"),
    } as unknown as Env;
    expect((await loadIpRestriction(wrongKey, tenantId)).kind).toBe("error");
    expect(await isAdminIpAllowed(wrongKey, tenantId, ALLOWED_IP)).toBe(false);
    // Right key: matching network passes, others do not, missing IP fails.
    expect(await isAdminIpAllowed(bindings, tenantId, ALLOWED_IP)).toBe(true);
    expect(await isAdminIpAllowed(bindings, tenantId, BLOCKED_IP)).toBe(false);
    expect(await isAdminIpAllowed(bindings, tenantId, "")).toBe(false);
    // The D1 row itself holds ciphertext only.
    const row = await env.DB.prepare(
      "SELECT entries_enc FROM tenant_admin_ip_rules WHERE tenant_id = ?1",
    )
      .bind(tenantId)
      .first<{ entries_enc: string }>();
    expect(row?.entries_enc).toBeTruthy();
    expect(row?.entries_enc).not.toContain("198.51");
  });
});

/* ------------------------------------------------------------------ */
/* Admin API enforcement                                               */
/* ------------------------------------------------------------------ */

async function createTenant(): Promise<{ tenantId: string; apiKey: string }> {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: "IP制限テスト" }),
  });
  expect(res.status).toBe(201);
  const data = (await res.json()) as { tenant: { id: string }; api_key: string };
  return { tenantId: data.tenant.id, apiKey: data.api_key };
}

function adminGet(tenantId: string, apiKey: string, ip: string, path = "api-keys") {
  return SELF.fetch(`${BASE}/api/v1/tenants/${tenantId}/${path}`, {
    headers: { authorization: `Bearer ${apiKey}`, "cf-connecting-ip": ip },
  });
}

describe("admin API enforcement", () => {
  it("blocks non-listed IPs on admin routes only", async () => {
    const { tenantId, apiKey } = await createTenant();
    // Configure the restriction through the owner API from an allowed IP.
    const put = await SELF.fetch(`${BASE}/api/v1/tenants/${tenantId}/admin-ip-restriction`, {
      method: "PUT",
      headers: {
        authorization: `Bearer ${apiKey}`,
        "content-type": "application/json",
        "cf-connecting-ip": ALLOWED_IP,
      },
      body: JSON.stringify({ entries: ["198.51.100.0/24"] }),
    });
    expect(put.status).toBe(200);

    expect((await adminGet(tenantId, apiKey, ALLOWED_IP)).status).toBe(200);
    expect((await adminGet(tenantId, apiKey, BLOCKED_IP)).status).toBe(403);
    // Even the restriction endpoint itself is unreachable from a blocked IP.
    expect((await adminGet(tenantId, apiKey, BLOCKED_IP, "admin-ip-restriction")).status).toBe(403);

    // The audit trail records the change without the values.
    const audit = await adminGet(tenantId, apiKey, ALLOWED_IP, "audit");
    expect(audit.status).toBe(200);
    const auditText = await audit.text();
    expect(auditText).toContain("admin_ip_restriction.update");
    expect(auditText).not.toContain("198.51.100");

    // Public voting surface is not affected by the admin restriction.
    const pollRes = await SELF.fetch(`${BASE}/api/v1/tenants/${tenantId}/polls`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${apiKey}`,
        "content-type": "application/json",
        "cf-connecting-ip": ALLOWED_IP,
      },
      body: JSON.stringify({ question: "公開確認", options: [{ label: "はい" }, { label: "いいえ" }] }),
    });
    expect(pollRes.status).toBe(201);
    const poll = (await pollRes.json()) as { poll: { id: string } };
    const publish = await SELF.fetch(`${BASE}/api/v1/tenants/${tenantId}/polls/${poll.poll.id}/status`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${apiKey}`,        "content-type": "application/json",
        "cf-connecting-ip": ALLOWED_IP,
      },
      body: JSON.stringify({ status: "published" }),
    });
    expect(publish.status).toBe(200);
    const pub = await SELF.fetch(`${BASE}/api/v1/polls/${poll.poll.id}`, {
      headers: { "cf-connecting-ip": BLOCKED_IP },
    });
    expect(pub.status).toBe(200);
  });

  it("requires explicit confirmation before saving a list that excludes the caller", async () => {
    const { tenantId, apiKey } = await createTenant();
    const put = (confirm: boolean) =>
      SELF.fetch(`${BASE}/api/v1/tenants/${tenantId}/admin-ip-restriction`, {
        method: "PUT",
        headers: {
          authorization: `Bearer ${apiKey}`,
          "content-type": "application/json",
          "cf-connecting-ip": ALLOWED_IP,
        },
        body: JSON.stringify({
          entries: ["203.0.113.0/24"],
          ...(confirm ? { confirm_lockout: true } : {}),
        }),
      });
    expect((await put(false)).status).toBe(400);
    // Not saved yet: the caller is still allowed.
    expect((await adminGet(tenantId, apiKey, ALLOWED_IP)).status).toBe(200);
    expect((await put(true)).status).toBe(200);
    expect((await adminGet(tenantId, apiKey, ALLOWED_IP)).status).toBe(403);
    expect((await adminGet(tenantId, apiKey, BLOCKED_IP)).status).toBe(200);
    // Clearing from an allowed IP turns the restriction off again.
    const clear = await SELF.fetch(`${BASE}/api/v1/tenants/${tenantId}/admin-ip-restriction`, {
      method: "PUT",
      headers: {
        authorization: `Bearer ${apiKey}`,
        "content-type": "application/json",
        "cf-connecting-ip": BLOCKED_IP,
      },
      body: JSON.stringify({ entries: [] }),
    });
    expect(clear.status).toBe(200);
    expect((await adminGet(tenantId, apiKey, ALLOWED_IP)).status).toBe(200);
  });

  it("rejects invalid entries through the API", async () => {
    const { tenantId, apiKey } = await createTenant();
    const res = await SELF.fetch(`${BASE}/api/v1/tenants/${tenantId}/admin-ip-restriction`, {
      method: "PUT",
      headers: {
        authorization: `Bearer ${apiKey}`,
        "content-type": "application/json",
        "cf-connecting-ip": ALLOWED_IP,
      },
      body: JSON.stringify({ entries: ["not-an-ip"] }),
    });
    expect(res.status).toBe(400);
    expect((await adminGet(tenantId, apiKey, BLOCKED_IP)).status).toBe(200);
  });
});

/* ------------------------------------------------------------------ */
/* Admin UI enforcement + settings form                                */
/* ------------------------------------------------------------------ */

function getCookie(res: Response, name: string): string | null {
  for (const header of res.headers.getSetCookie()) {
    const [pair] = header.split(";");
    const eq = pair?.indexOf("=") ?? -1;
    if (eq > 0 && pair?.slice(0, eq).trim() === name) return pair.slice(eq + 1).trim() as string;
  }
  return null;
}

function decodeFlowPayload(cookieValue: string): { state: string; nonce: string } {
  const decoded = decodeURIComponent(cookieValue);
  const payloadPart = decoded.split(".")[0] as string;
  const padded = payloadPart.replace(/-/g, "+").replace(/_/g, "/");
  const json = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  return JSON.parse(json) as { state: string; nonce: string };
}

async function loginAs(sub: string, email: string): Promise<string> {
  const loginRes = await SELF.fetch(`${BASE}/admin/login`, { redirect: "manual" });
  expect(loginRes.status).toBe(302);
  const params = new URL(loginRes.headers.get("location") ?? "").searchParams;
  const flowCookie = getCookie(loginRes, "__Host-hv_oidc_flow");
  expect(flowCookie).toBeTruthy();
  const flow = decodeFlowPayload(flowCookie as string);
  expect(params.get("state")).toBe(flow.state);
  const code = `mock:${sub}:${flow.nonce}:${email}`;
  const callbackRes = await SELF.fetch(
    `${BASE}/auth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(flow.state)}`,
    { redirect: "manual", headers: { cookie: `__Host-hv_oidc_flow=${flowCookie}` } },
  );
  const session = getCookie(callbackRes, "__Host-hv_session");
  expect(session).toBeTruthy();
  return session as string;
}

describe("admin UI enforcement and settings", () => {
  it("manages the restriction from the settings screen and enforces it", async () => {
    const session = await loginAs("ip-ui-owner", "ip-ui@example.test");
    const cookie = `__Host-hv_session=${session}`;
    const created = await SELF.fetch(`${BASE}/admin/workspaces`, {
      method: "POST",
      headers: { cookie, origin: BASE, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ name: "IP制限UI" }).toString(),
    });
    expect(created.status).toBe(200);
    const tenantId = /\/admin\/workspaces\/([0-9a-f-]{36})/.exec(await created.text())?.[1];
    expect(tenantId).toBeTruthy();

    const settings = await SELF.fetch(`${BASE}/admin/workspaces/${tenantId}/settings`, {
      headers: { cookie, "cf-connecting-ip": ALLOWED_IP },
    });
    expect(settings.status).toBe(200);
    const settingsHtml = await settings.text();
    expect(settingsHtml).toContain("管理画面の IP 制限");
    expect(settingsHtml).toContain(ALLOWED_IP);

    const post = (entries: string, ip: string, confirm = false) =>
      SELF.fetch(`${BASE}/admin/workspaces/${tenantId}/ip-restriction`, {
        method: "POST",
        redirect: "manual",
        headers: { cookie, origin: BASE, "content-type": "application/x-www-form-urlencoded", "cf-connecting-ip": ip },
        body: new URLSearchParams({
          entries,
          ...(confirm ? { confirm_lockout: "1" } : {}),
        }).toString(),
      });

    // Save a list that includes the current IP: straight through.
    expect((await post("198.51.100.0/24", ALLOWED_IP)).status).toBe(303);
    const dash = (ip: string) =>
      SELF.fetch(`${BASE}/admin/workspaces/${tenantId}`, { headers: { cookie, "cf-connecting-ip": ip } });
    expect((await dash(ALLOWED_IP)).status).toBe(200);
    const blocked = await dash(BLOCKED_IP);
    expect(blocked.status).toBe(403);
    expect(await blocked.text()).toContain("IP 制限");

    // Lockout guard: a list without the caller's IP needs confirmation.
    const warned = await post("203.0.113.0/24", ALLOWED_IP);
    expect(warned.status).toBe(400);
    expect(await warned.text()).toContain("含まれていません");
    // Still the old list in force.
    expect((await dash(ALLOWED_IP)).status).toBe(200);
    expect((await post("203.0.113.0/24", ALLOWED_IP, true)).status).toBe(303);
    expect((await dash(ALLOWED_IP)).status).toBe(403);
    expect((await dash(BLOCKED_IP)).status).toBe(200);

    // Clearing the list from an allowed IP lifts the restriction.
    expect((await post("", BLOCKED_IP)).status).toBe(303);
    expect((await dash(ALLOWED_IP)).status).toBe(200);
  });
});
