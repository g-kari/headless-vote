import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { applySchema, signTestJwt, TEST_CLIENT_ID } from "./fixtures";

/**
 * Parity tests for the countermeasures that existed only in PR #4
 * (main's security review fixes) and were ported onto the feature
 * stack during integration: OIDC iat/azp validation, the
 * anonymous-to-login ballot fold, OIDC session revoke-all, and the
 * per-tenant image quota.
 */

const BASE = "https://vote.test";
const ISSUER = "https://idp.example.test";

beforeAll(async () => {
  await applySchema(env.DB);
});

interface TenantInfo {
  tenant: { id: string };
  api_key: string;
}

async function createTenant(name: string): Promise<TenantInfo> {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name }),
  });
  expect(res.status).toBe(201);
  return (await res.json()) as TenantInfo;
}

async function createPublishedPoll(
  t: TenantInfo,
  overrides: Record<string, unknown> = {},
): Promise<{ pollId: string; optionIds: string[] }> {
  const pRes = await SELF.fetch(`${BASE}/api/v1/tenants/${t.tenant.id}/polls`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${t.api_key}`,
    },
    body: JSON.stringify({
      question: "同等性テスト",
      options: [{ label: "賛成" }, { label: "反対" }],
      ...overrides,
    }),
  });
  expect(pRes.status).toBe(201);
  const p = (await pRes.json()) as {
    poll: { id: string; options: { id: string }[] };
  };
  const sRes = await SELF.fetch(
    `${BASE}/api/v1/tenants/${t.tenant.id}/polls/${p.poll.id}/status`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${t.api_key}`,
      },
      body: JSON.stringify({ status: "published" }),
    },
  );
  expect(sRes.status).toBe(200);
  return { pollId: p.poll.id, optionIds: p.poll.options.map((o) => o.id) };
}

async function vote(
  pollId: string,
  body: Record<string, unknown>,
  token?: string,
): Promise<Response> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (token) headers["authorization"] = `Bearer ${token}`;
  return SELF.fetch(`${BASE}/api/v1/polls/${pollId}/vote`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

async function totals(pollId: string) {
  const res = await SELF.fetch(`${BASE}/api/v1/polls/${pollId}/results`);
  const data = (await res.json()) as {
    results: { total_voters: number; options: { id: string; votes: number }[] };
  };
  return data.results;
}

describe("OIDC claim validation (PR #4 parity)", () => {
  it("rejects a voter token whose iat is in the future", async () => {
    const t = await createTenant("iat未来");
    const { pollId, optionIds } = await createPublishedPoll(t, { require_login: true });
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signTestJwt({ sub: "future-iat-user", iat: now + 3600, exp: now + 7200 });
    const res = await vote(pollId, { option_ids: [optionIds[0]] }, jwt);
    expect(res.status).toBe(401);
  });

  it("rejects a voter token without iat", async () => {
    const t = await createTenant("iatなし");
    const { pollId, optionIds } = await createPublishedPoll(t, { require_login: true });
    const jwt = await signTestJwt({ sub: "no-iat-user", iat: undefined });
    const res = await vote(pollId, { option_ids: [optionIds[0]] }, jwt);
    expect(res.status).toBe(401);
  });

  it("rejects a multi-audience token whose azp names another client", async () => {
    const t = await createTenant("azp不一致");
    const { pollId, optionIds } = await createPublishedPoll(t, { require_login: true });
    const jwt = await signTestJwt({
      sub: "azp-user",
      aud: [TEST_CLIENT_ID, "someone-else"],
      azp: "someone-else",
    });
    const res = await vote(pollId, { option_ids: [optionIds[0]] }, jwt);
    expect(res.status).toBe(401);
  });

  it("accepts a multi-audience token whose azp matches", async () => {
    const t = await createTenant("azp一致");
    const { pollId, optionIds } = await createPublishedPoll(t, { require_login: true });
    const jwt = await signTestJwt({
      sub: "azp-ok-user",
      aud: [TEST_CLIENT_ID, "someone-else"],
      azp: TEST_CLIENT_ID,
    });
    const res = await vote(pollId, { option_ids: [optionIds[0]] }, jwt);
    expect(res.status).toBe(200);
  });
});

describe("anonymous ballot folds into login ballot (PR #4 L7)", () => {
  it("does not double-count when a login vote presents the same voter token", async () => {
    const t = await createTenant("票の統合");
    const { pollId, optionIds } = await createPublishedPoll(t);
    const anon = await vote(pollId, {
      option_ids: [optionIds[0]],
      voter_token: "fold-token-123",
    });
    expect(anon.status).toBe(200);
    let r = await totals(pollId);
    expect(r.total_voters).toBe(1);
    expect(r.options.find((o) => o.id === optionIds[0])?.votes).toBe(1);

    const jwt = await signTestJwt({ sub: "fold-user" });
    const login = await vote(
      pollId,
      { option_ids: [optionIds[1]], voter_token: "fold-token-123" },
      jwt,
    );
    expect(login.status).toBe(200);
    r = await totals(pollId);
    expect(r.total_voters).toBe(1);
    expect(r.options.find((o) => o.id === optionIds[0])?.votes).toBe(0);
    expect(r.options.find((o) => o.id === optionIds[1])?.votes).toBe(1);
  });
});

function getCookie(res: Response, name: string): string | null {
  for (const header of res.headers.getSetCookie()) {
    const [pair] = header.split(";");
    const eq = pair?.indexOf("=") ?? -1;
    if (eq > 0 && pair?.slice(0, eq).trim() === name) return pair.slice(eq + 1).trim();
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
  const location = loginRes.headers.get("location") ?? "";
  expect(location.startsWith(`${ISSUER}/auth/authorize?`)).toBe(true);
  const flowCookie = getCookie(loginRes, "__Host-hv_oidc_flow");
  expect(flowCookie).toBeTruthy();
  const flow = decodeFlowPayload(flowCookie as string);
  const code = `mock:${sub}:${flow.nonce}:${email}`;
  const callbackRes = await SELF.fetch(
    `${BASE}/auth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(flow.state)}`,
    { redirect: "manual", headers: { cookie: `__Host-hv_oidc_flow=${flowCookie}` } },
  );
  expect(callbackRes.status).toBe(302);
  const session = getCookie(callbackRes, "__Host-hv_session");
  expect(session).toBeTruthy();
  return session as string;
}

describe("OIDC session revoke-all (PR #4 L5 parity)", () => {
  it("invalidates outstanding session cookies", async () => {
    const session = await loginAs("revoke-user", "revoke@example.com");
    const cookie = `__Host-hv_session=${session}`;

    const before = await SELF.fetch(`${BASE}/admin/account`, { headers: { cookie } });
    expect(before.status).toBe(200);

    const revoke = await SELF.fetch(`${BASE}/admin/account/revoke-sessions`, {
      method: "POST",
      redirect: "manual",
      headers: { cookie, origin: BASE },
    });
    expect(revoke.status).toBe(303);

    const after = await SELF.fetch(`${BASE}/admin/account`, {
      redirect: "manual",
      headers: { cookie },
    });
    expect(after.status).toBe(302);

    // A fresh login still works and sees the account page.
    const fresh = await loginAs("revoke-user", "revoke@example.com");
    const ok = await SELF.fetch(`${BASE}/admin/account`, {
      headers: { cookie: `__Host-hv_session=${fresh}` },
    });
    expect(ok.status).toBe(200);
  });
});

describe("per-tenant image quota (PR #4 M2 parity)", () => {
  const PNG_BYTES = new Uint8Array([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4,
  ]);

  it("rejects uploads once the image count quota is reached", async () => {
    const t = await createTenant("画像上限");
    await env.DB.prepare(
      "INSERT INTO tenant_image_usage (tenant_id, image_count, total_bytes, updated_at) VALUES (?1, 500, 1024, ?2)",
    )
      .bind(t.tenant.id, new Date().toISOString())
      .run();
    const res = await SELF.fetch(`${BASE}/api/v1/tenants/${t.tenant.id}/images`, {
      method: "POST",
      headers: { "content-type": "image/png", authorization: `Bearer ${t.api_key}` },
      body: PNG_BYTES,
    });
    expect(res.status).toBe(429);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "IMAGE_QUOTA_EXCEEDED",
    );
  });

  it("counts successful uploads in the usage ledger", async () => {
    const t = await createTenant("画像記録");
    const res = await SELF.fetch(`${BASE}/api/v1/tenants/${t.tenant.id}/images`, {
      method: "POST",
      headers: { "content-type": "image/png", authorization: `Bearer ${t.api_key}` },
      body: PNG_BYTES,
    });
    expect(res.status).toBe(201);
    const row = await env.DB.prepare(
      "SELECT image_count, total_bytes FROM tenant_image_usage WHERE tenant_id = ?1",
    )
      .bind(t.tenant.id)
      .first<{ image_count: number; total_bytes: number }>();
    expect(row?.image_count).toBe(1);
    expect(row?.total_bytes).toBe(PNG_BYTES.byteLength);
  });
});
