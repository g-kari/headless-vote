import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { applySchema } from "./fixtures";

const BASE = "https://vote.test";

beforeAll(async () => {
  await applySchema(env.DB);
});

async function createTenant(name = "SaaS") {
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

describe("scoped API keys", () => {
  it("issues a read key that cannot mutate, and revoke kills it", async () => {
    const tenant = await createTenant("キー管理");
    const issued = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/api-keys`, {
      method: "POST",
      headers: auth(tenant.apiKey),
      body: JSON.stringify({ name: "読み取り", scope: "read" }),
    });
    expect(issued.status).toBe(201);
    const body = (await issued.json()) as {
      api_key: string;
      key: { id: string; prefix: string; scope: string };
    };
    expect(body.api_key.startsWith("hvk_")).toBe(true);
    expect(body.key.scope).toBe("read");
    expect(body.api_key.startsWith(body.key.prefix)).toBe(true);

    const listed = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/api-keys`, {
      headers: { authorization: `Bearer ${tenant.apiKey}` },
    });
    const keys = (await listed.json()) as { api_keys: { prefix: string }[] };
    expect(JSON.stringify(keys)).not.toContain(body.api_key);
    expect(keys.api_keys.some((key) => key.prefix === body.key.prefix)).toBe(true);

    const readPolls = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/polls`, {
      headers: { authorization: `Bearer ${body.api_key}` },
    });
    expect(readPolls.status).toBe(200);
    const denied = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/polls`, {
      method: "POST",
      headers: auth(body.api_key),
      body: JSON.stringify({
        question: "だめ",
        options: [{ label: "a" }, { label: "b" }],
      }),
    });
    expect(denied.status).toBe(403);

    const revoked = await SELF.fetch(
      `${BASE}/api/v1/tenants/${tenant.id}/api-keys/${body.key.id}/revoke`,
      { method: "POST", headers: auth(tenant.apiKey), body: "{}" },
    );
    expect(revoked.status).toBe(200);
    const after = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/polls`, {
      headers: { authorization: `Bearer ${body.api_key}` },
    });
    expect(after.status).toBe(401);
  });
});

describe("scheduling, export, audit, and deletion", () => {
  it("rejects votes before opens_at and exports aggregates without voter secrets", async () => {
    const tenant = await createTenant("予定");
    const future = new Date(Date.now() + 86_400_000).toISOString();
    const created = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/polls`, {
      method: "POST",
      headers: auth(tenant.apiKey),
      body: JSON.stringify({
        question: "いつ投票？",
        opens_at: future,
        options: [{ label: "=1+1" }, { label: "普通" }],
      }),
    });
    expect(created.status).toBe(201);
    const poll = (await created.json()) as {
      poll: { id: string; opens_at: string; options: { id: string }[] };
    };
    expect(poll.poll.opens_at).toBe(future);
    await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/polls/${poll.poll.id}/status`, {
      method: "POST",
      headers: auth(tenant.apiKey),
      body: JSON.stringify({ status: "published" }),
    });
    const early = await SELF.fetch(`${BASE}/api/v1/polls/${poll.poll.id}/vote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        voter_token: "secret-voter-token",
        option_ids: [poll.poll.options[0]?.id],
      }),
    });
    expect(early.status).toBe(409);
    expect(((await early.json()) as { error: { code: string } }).error.code).toBe(
      "POLL_NOT_OPEN",
    );

    const badWindow = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/polls`, {
      method: "POST",
      headers: auth(tenant.apiKey),
      body: JSON.stringify({
        question: "逆順",
        opens_at: future,
        closes_at: new Date(Date.now() + 1000).toISOString(),
        options: [{ label: "a" }, { label: "b" }],
      }),
    });
    expect(badWindow.status).toBe(400);

    await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/polls/${poll.poll.id}`, {
      method: "PATCH",
      headers: auth(tenant.apiKey),
      body: JSON.stringify({ opens_at: new Date(Date.now() - 60_000).toISOString() }),
    });
    const voted = await SELF.fetch(`${BASE}/api/v1/polls/${poll.poll.id}/vote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        voter_token: "secret-voter-token",
        option_ids: [poll.poll.options[0]?.id],
      }),
    });
    expect(voted.status).toBe(200);

    const csv = await SELF.fetch(
      `${BASE}/api/v1/tenants/${tenant.id}/polls/${poll.poll.id}/export?format=csv`,
      { headers: { authorization: `Bearer ${tenant.apiKey}` } },
    );
    expect(csv.status).toBe(200);
    expect(csv.headers.get("content-type")).toContain("text/csv");
    const text = await csv.text();
    expect(text).toContain("'=1+1");
    expect(text).not.toContain("secret-voter-token");

    const audit = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/audit`, {
      headers: { authorization: `Bearer ${tenant.apiKey}` },
    });
    const events = (await audit.json()) as { events: { action: string }[] };
    expect(events.events.some((event) => event.action === "poll.create")).toBe(true);
    expect(events.events.some((event) => event.action === "results.export")).toBe(true);

    const wrong = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}`, {
      method: "DELETE",
      headers: auth(tenant.apiKey),
      body: JSON.stringify({ confirm_name: "ちがう" }),
    });
    expect(wrong.status).toBe(400);
    const gone = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}`, {
      method: "DELETE",
      headers: auth(tenant.apiKey),
      body: JSON.stringify({ confirm_name: "予定" }),
    });
    expect(gone.status).toBe(200);
    const after = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/polls`, {
      headers: { authorization: `Bearer ${tenant.apiKey}` },
    });
    expect(after.status).toBe(401);
  });
});
