import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { assertWebhookUrl, signWebhookBody } from "../src/webhooks";
import { applySchema } from "./fixtures";

const BASE = "https://vote.test";
const ISSUER = "https://idp.example.test";

beforeAll(async () => {
  await applySchema(env.DB);
});

async function createTenant(name = "運用") {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name }),
  });
  expect(res.status).toBe(201);
  const data = (await res.json()) as { tenant: { id: string }; api_key: string };
  return { id: data.tenant.id, apiKey: data.api_key };
}

function auth(apiKey: string): Record<string, string> {
  return { authorization: `Bearer ${apiKey}`, "content-type": "application/json" };
}

async function publishedPoll(tenant: { id: string; apiKey: string }) {
  const created = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/polls`, {
    method: "POST",
    headers: auth(tenant.apiKey),
    body: JSON.stringify({
      question: "今日の気分は？",
      options: [{ label: "良い" }, { label: "普通" }],
    }),
  });
  expect(created.status).toBe(201);
  const poll = (await created.json()) as { poll: { id: string; options: { id: string }[] } };
  const published = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/polls/${poll.poll.id}/status`, {
    method: "POST",
    headers: auth(tenant.apiKey),
    body: JSON.stringify({ status: "published" }),
  });
  expect(published.status).toBe(200);
  return poll.poll;
}

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

describe("webhook signing and delivery", () => {
  it("rejects private and non-https targets", () => {
    expect(() => assertWebhookUrl("http://example.com/hook")).toThrow();
    expect(() => assertWebhookUrl("https://169.254.169.254/latest")).toThrow();
    expect(() => assertWebhookUrl("https://user:pass@example.com/hook")).toThrow();
    expect(assertWebhookUrl("https://example.com/hook")).toBe("https://example.com/hook");
    expect(assertWebhookUrl("http://localhost:8787/hook")).toBe("http://localhost:8787/hook");
  });

  it("signs the raw body and records a delivery without the voter token", async () => {
    const secret = "test-secret";
    const body = JSON.stringify({ type: "vote.cast", voter_token: "must-not-matter" });
    const sig = await signWebhookBody(secret, body);
    expect(sig).toMatch(/^[0-9a-f]{64}$/);
    expect(await signWebhookBody(secret, body)).toBe(sig);
    expect(await signWebhookBody("other", body)).not.toBe(sig);

    const tenant = await createTenant("通知");
    const created = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/webhooks`, {
      method: "POST",
      headers: auth(tenant.apiKey),
      body: JSON.stringify({ url: `${ISSUER}/hooks/vote` }),
    });
    expect(created.status).toBe(201);
    const hook = (await created.json()) as { secret: string; webhook: { id: string; url: string } };
    expect(hook.secret.length).toBeGreaterThan(20);
    const listed = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/webhooks`, {
      headers: { authorization: `Bearer ${tenant.apiKey}` },
    });
    const listText = await listed.text();
    expect(listText).not.toContain(hook.secret);
    expect(listText).toContain(hook.webhook.url);

    const poll = await publishedPoll(tenant);
    const vote = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/vote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ voter_token: "voter-token-secret", option_ids: [poll.options[0]?.id] }),
    });
    expect(vote.status).toBe(200);
    const voteText = await vote.text();
    expect(voteText).not.toContain("voter-token-secret");

    const delivery = await env.DB.prepare(
      "SELECT event, status FROM webhook_deliveries WHERE webhook_id = ?1 AND event = 'vote.cast'",
    )
      .bind(hook.webhook.id)
      .first<{ event: string; status: number }>();
    expect(delivery?.event).toBe("vote.cast");
    expect(delivery?.status).toBe(404);

    const stored = await env.DB.prepare("SELECT secret_enc FROM webhooks WHERE id = ?1")
      .bind(hook.webhook.id)
      .first<{ secret_enc: string }>();
    expect(stored?.secret_enc).not.toContain(hook.secret);

    const analytics = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/polls/${poll.id}/analytics`, {
      headers: { authorization: `Bearer ${tenant.apiKey}` },
    });
    const series = (await analytics.json()) as { days: { count: number }[]; note: string };
    expect(series.days.reduce((sum, day) => sum + day.count, 0)).toBe(1);
    expect(series.note).toContain("not unique");
  });
});

describe("roles, quotas, and account data", () => {
  it("keeps the last owner and blocks a read key from owner actions", async () => {
    const tenant = await createTenant("権限");
    const read = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/api-keys`, {
      method: "POST",
      headers: auth(tenant.apiKey),
      body: JSON.stringify({ name: "読", scope: "read" }),
    });
    const readKey = ((await read.json()) as { api_key: string }).api_key;
    const denied = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/members`, {
      method: "POST",
      headers: auth(readKey),
      body: JSON.stringify({ user_sub: "member-sub", role: "member" }),
    });
    expect(denied.status).toBe(403);

    const added = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/members`, {
      method: "POST",
      headers: auth(tenant.apiKey),
      body: JSON.stringify({ user_sub: "member-sub", role: "member" }),
    });
    expect(added.status).toBe(201);
    await env.DB.prepare(
      "INSERT INTO tenant_members (tenant_id, user_sub, role, created_at) VALUES (?1, 'only-owner', 'owner', ?2)",
    )
      .bind(tenant.id, new Date().toISOString())
      .run();
    const demote = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/members`, {
      method: "PATCH",
      headers: auth(tenant.apiKey),
      body: JSON.stringify({ user_sub: "only-owner", role: "member" }),
    });
    expect(demote.status).toBe(409);

    const quotas = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/quotas`, {
      headers: { authorization: `Bearer ${tenant.apiKey}` },
    });
    const quotaBody = (await quotas.json()) as { plan: string; limits: { polls: number; votes_per_day: number } };
    expect(quotaBody.plan).toBe("free");
    expect(quotaBody.limits.polls).toBe(100);

    await env.DB.prepare("UPDATE tenants SET quota_votes_per_day = 1 WHERE id = ?1").bind(tenant.id).run();
    const poll = await publishedPoll(tenant);
    const first = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/vote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ voter_token: "quota-voter-1", option_ids: [poll.options[0]?.id] }),
    });
    expect(first.status).toBe(200);
    const second = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/vote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ voter_token: "quota-voter-2", option_ids: [poll.options[0]?.id] }),
    });
    expect(second.status).toBe(429);

    const session = await loginAs("account-owner", "owner@example.com");
    const created = await SELF.fetch(`${BASE}/admin/workspaces`, {
      method: "POST",
      headers: {
        cookie: `__Host-hv_session=${session}`,
        "content-type": "application/x-www-form-urlencoded",
        origin: BASE,
      },
      body: new URLSearchParams({ name: "個人の場" }).toString(),
    });
    expect(created.status).toBe(200);
    const html = await created.text();
    const tenantId = /\/admin\/workspaces\/([0-9a-f-]{36})/.exec(html)?.[1];
    expect(tenantId).toBeTruthy();

    await env.DB.prepare(
      "INSERT INTO tenant_members (tenant_id, user_sub, role, created_at) VALUES (?1, 'plain-member', 'member', ?2)",
    )
      .bind(tenantId, new Date().toISOString())
      .run();
    const memberSession = await loginAs("plain-member", "member@example.com");
    const settings = await SELF.fetch(`${BASE}/admin/workspaces/${tenantId}/settings`, {
      headers: { cookie: `__Host-hv_session=${memberSession}` },
    });
    expect(settings.status).toBe(200);
    expect(await settings.text()).toContain("利用上限");
    const originPost = await SELF.fetch(`${BASE}/admin/workspaces/${tenantId}/origins`, {
      method: "POST",
      headers: {
        cookie: `__Host-hv_session=${memberSession}`,
        "content-type": "application/x-www-form-urlencoded",
        origin: BASE,
      },
      body: new URLSearchParams({ origin: "https://example.com" }).toString(),
    });
    expect(originPost.status).toBe(403);

    const account = await SELF.fetch(`${BASE}/admin/account`, {
      headers: { cookie: `__Host-hv_session=${session}` },
    });
    const accountHtml = await account.text();
    expect(accountHtml).toContain("owner@example.com");
    expect(accountHtml).toContain("OpenID Connect");
    expect(accountHtml).toContain("パスワード");

    const exported = await SELF.fetch(`${BASE}/api/v1/me/export`, {
      headers: { cookie: `__Host-hv_session=${session}` },
    });
    const exportedText = await exported.text();
    expect(exportedText).toContain("個人の場");
    expect(exportedText).not.toContain("hvk_");

    const removed = await SELF.fetch(`${BASE}/api/v1/me`, {
      method: "DELETE",
      headers: {
        cookie: `__Host-hv_session=${session}`,
        "content-type": "application/json",
        origin: BASE,
      },
      body: JSON.stringify({ confirm: "delete my data" }),
    });
    expect(removed.status).toBe(200);
    const gone = await env.DB.prepare("SELECT id FROM tenants WHERE id = ?1").bind(tenantId).first();
    expect(gone).toBeNull();
  });
});
