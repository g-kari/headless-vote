import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { applySchema } from "./fixtures";

const BASE = "https://vote.test";

beforeAll(async () => {
  await applySchema(env.DB);
});

function getCookie(res: Response, name: string): string | null {
  for (const header of res.headers.getSetCookie()) {
    const [pair] = header.split(";");
    const eq = pair?.indexOf("=") ?? -1;
    if (eq > 0 && pair?.slice(0, eq).trim() === name) return pair.slice(eq + 1).trim();
  }
  return null;
}

async function loginAs(sub: string, email: string): Promise<string> {
  const loginRes = await SELF.fetch(`${BASE}/admin/login`, { redirect: "manual" });
  const flowCookie = getCookie(loginRes, "__Host-hv_oidc_flow");
  expect(flowCookie).toBeTruthy();
  const payloadPart = decodeURIComponent(flowCookie as string).split(".")[0] as string;
  const padded = payloadPart.replace(/-/g, "+").replace(/_/g, "/");
  const flow = JSON.parse(atob(padded + "=".repeat((4 - (padded.length % 4)) % 4))) as {
    state: string;
    nonce: string;
  };
  const code = `mock:${sub}:${flow.nonce}:${email}`;
  const callbackRes = await SELF.fetch(
    `${BASE}/auth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(flow.state)}`,
    { redirect: "manual", headers: { cookie: `__Host-hv_oidc_flow=${flowCookie}` } },
  );
  expect(callbackRes.headers.get("location")).toBe("/admin");
  const session = getCookie(callbackRes, "__Host-hv_session");
  expect(session).toBeTruthy();
  return session as string;
}

function sessionHeaders(session: string): Record<string, string> {
  return { cookie: `__Host-hv_session=${session}` };
}

async function createTenant(name: string) {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name }),
  });
  expect(res.status).toBe(201);
  const data = (await res.json()) as { tenant: { id: string }; api_key: string };
  return { id: data.tenant.id, apiKey: data.api_key };
}

function keyAuth(apiKey: string): Record<string, string> {
  return { authorization: `Bearer ${apiKey}`, "content-type": "application/json" };
}

async function accountRow(subject: string) {
  return env.DB.prepare("SELECT id, email, name FROM accounts WHERE subject = ?1")
    .bind(subject)
    .first<{ id: string; email: string | null; name: string | null }>();
}

describe("internal account ids", () => {
  it("exposes only the internal account id in /me, the session cookie, and the account page", async () => {
    const sub = "oidc-sub-alpha";
    const session = await loginAs(sub, "alpha@example.com");

    // The session cookie payload carries the internal id, not the sub.
    const payloadPart = decodeURIComponent(session).split(".")[0] as string;
    const padded = payloadPart.replace(/-/g, "+").replace(/_/g, "/");
    const payload = JSON.parse(atob(padded + "=".repeat((4 - (padded.length % 4)) % 4))) as Record<string, unknown>;
    const account = await accountRow(sub);
    expect(account).not.toBeNull();
    expect(payload.accountId).toBe(account!.id);
    expect(JSON.stringify(payload)).not.toContain(sub);

    const meRes = await SELF.fetch(`${BASE}/api/v1/me`, { headers: sessionHeaders(session) });
    expect(meRes.status).toBe(200);
    const meText = await meRes.text();
    expect(meText).not.toContain(sub);
    expect(meText).not.toContain('"sub"');
    const me = JSON.parse(meText) as { profile: { account_id: string; email: string } };
    expect(me.profile.account_id).toBe(account!.id);
    expect(me.profile.email).toBe("alpha@example.com");

    const pageRes = await SELF.fetch(`${BASE}/admin/account`, { headers: sessionHeaders(session) });
    const page = await pageRes.text();
    expect(page).toContain("アカウント ID");
    expect(page).toContain(account!.id);
    expect(page).not.toContain(sub);
  });

  it("manages members by account id and keeps the sub out of member lists and audit", async () => {
    const ownerSub = "oidc-sub-owner";
    const memberSub = "oidc-sub-member";
    const ownerSession = await loginAs(ownerSub, "owner@example.com");
    const memberSession = await loginAs(memberSub, "member@example.com");
    const memberAccount = await accountRow(memberSub);
    expect(memberAccount).not.toBeNull();

    // Owner creates a workspace through the UI (session-provisioned owner).
    const created = await SELF.fetch(`${BASE}/admin/workspaces`, {
      method: "POST",
      headers: {
        ...sessionHeaders(ownerSession),
        "content-type": "application/x-www-form-urlencoded",
        origin: BASE,
      },
      body: new URLSearchParams({ name: "内部IDテスト" }).toString(),
    });
    expect(created.status).toBe(200);
    const html = await created.text();
    const tenantId = /\/admin\/workspaces\/([0-9a-f-]{36})/.exec(html)?.[1];
    expect(tenantId).toBeTruthy();

    const added = await SELF.fetch(`${BASE}/api/v1/tenants/${tenantId}/members`, {
      method: "POST",
      headers: { ...sessionHeaders(ownerSession), "content-type": "application/json", origin: BASE },
      body: JSON.stringify({ account_id: memberAccount!.id, role: "member" }),
    });
    expect(added.status).toBe(201);
    const addedText = await added.text();
    expect(addedText).not.toContain(memberSub);
    expect(addedText).toContain(memberAccount!.id);

    const listed = await SELF.fetch(`${BASE}/api/v1/tenants/${tenantId}/members`, {
      headers: sessionHeaders(memberSession),
    });
    expect(listed.status).toBe(200);
    const listedText = await listed.text();
    expect(listedText).not.toContain(ownerSub);
    expect(listedText).not.toContain(memberSub);
    const listedJson = JSON.parse(listedText) as { members: { account_id: string; email: string | null }[] };
    expect(listedJson.members.map((m) => m.account_id)).toContain(memberAccount!.id);
    expect(listedJson.members.find((m) => m.account_id === memberAccount!.id)?.email).toBe("member@example.com");

    const audit = await SELF.fetch(`${BASE}/api/v1/tenants/${tenantId}/audit`, {
      headers: sessionHeaders(ownerSession),
    });
    const auditText = await audit.text();
    expect(auditText).not.toContain(ownerSub);
    expect(auditText).not.toContain(memberSub);
    expect(auditText).toContain(memberAccount!.id);

    // Settings page renders members without any sub.
    const settings = await SELF.fetch(`${BASE}/admin/workspaces/${tenantId}/settings`, {
      headers: sessionHeaders(ownerSession),
    });
    const settingsHtml = await settings.text();
    expect(settingsHtml).not.toContain(ownerSub);
    expect(settingsHtml).not.toContain(memberSub);
    expect(settingsHtml).toContain("member@example.com");
    expect(settingsHtml).not.toContain("利用者 ID（sub）");
  });

  it("invites by email: existing accounts join at once, new accounts join at first login", async () => {
    const tenant = await createTenant("招待テスト");
    const existingSub = "oidc-sub-invitee";
    await loginAs(existingSub, "invitee@example.com");
    const existingAccount = await accountRow(existingSub);

    const immediate = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/members`, {
      method: "POST",
      headers: keyAuth(tenant.apiKey),
      body: JSON.stringify({ email: "invitee@example.com", role: "member" }),
    });
    expect(immediate.status).toBe(201);
    const immediateJson = (await immediate.json()) as { member?: { account_id: string } };
    expect(immediateJson.member?.account_id).toBe(existingAccount!.id);

    const pending = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/members`, {
      method: "POST",
      headers: keyAuth(tenant.apiKey),
      body: JSON.stringify({ email: "later@example.com", role: "member" }),
    });
    expect(pending.status).toBe(201);
    const pendingJson = (await pending.json()) as { invite?: { email: string } };
    expect(pendingJson.invite?.email).toBe("later@example.com");

    // The invite is claimed when that person first signs in.
    const laterSession = await loginAs("oidc-sub-later", "later@example.com");
    const meRes = await SELF.fetch(`${BASE}/api/v1/me`, { headers: sessionHeaders(laterSession) });
    const me = (await meRes.json()) as { workspaces: { id: string }[] };
    expect(me.workspaces.map((w) => w.id)).toContain(tenant.id);

    const listed = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/members`, {
      headers: keyAuth(tenant.apiKey),
    });
    const listedJson = (await listed.json()) as {
      members: { email: string | null }[];
      invites: { email: string }[];
    };
    expect(listedJson.members.map((m) => m.email)).toContain("later@example.com");
    expect(listedJson.invites).toHaveLength(0);
  });

  it("resolves pre-existing memberships (seeded by subject mapping) after login", async () => {
    const tenant = await createTenant("移行テスト");
    const sub = "oidc-sub-legacy-member";
    const now = new Date().toISOString();
    const accountId = crypto.randomUUID();
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO accounts (id, subject, email, name, created_at, last_seen_at) VALUES (?1, ?2, 'legacy@example.com', NULL, ?3, ?3)",
      ).bind(accountId, sub, now),
      env.DB.prepare(
        "INSERT INTO tenant_members (tenant_id, account_id, role, created_at) VALUES (?1, ?2, 'member', ?3)",
      ).bind(tenant.id, accountId, now),
    ]);
    const session = await loginAs(sub, "legacy@example.com");
    const meRes = await SELF.fetch(`${BASE}/api/v1/me`, { headers: sessionHeaders(session) });
    const me = (await meRes.json()) as { profile: { account_id: string }; workspaces: { id: string }[] };
    // The login reuses the pre-existing mapping instead of minting a new id.
    expect(me.profile.account_id).toBe(accountId);
    expect(me.workspaces.map((w) => w.id)).toContain(tenant.id);
  });

  it("deleting the account removes the mapping row and kills the session", async () => {
    const sub = "oidc-sub-delete-me";
    const session = await loginAs(sub, "delete-me@example.com");
    expect(await accountRow(sub)).not.toBeNull();

    const removed = await SELF.fetch(`${BASE}/api/v1/me`, {
      method: "DELETE",
      headers: { ...sessionHeaders(session), "content-type": "application/json", origin: BASE },
      body: JSON.stringify({ confirm: "delete my data" }),
    });
    expect(removed.status).toBe(200);
    expect(await accountRow(sub)).toBeNull();

    const meRes = await SELF.fetch(`${BASE}/api/v1/me`, { headers: sessionHeaders(session) });
    expect(meRes.status).toBe(401);
  });
});
