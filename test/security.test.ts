import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { sha256Hex } from "../src/crypto";
import { applySchema, signTestJwt } from "./fixtures";

const BASE = "https://vote.test";
const ISSUER = "https://id.0g0.xyz";

const PNG_BYTES = new Uint8Array([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4,
]);
const JPEG_BYTES = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3, 4]);

beforeAll(async () => {
  await applySchema(env.DB);
});

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

function getCookie(res: Response, name: string): string | null {
  for (const header of res.headers.getSetCookie()) {
    const [pair] = header.split(";");
    const eq = pair?.indexOf("=") ?? -1;
    if (eq > 0 && pair?.slice(0, eq).trim() === name) {
      return pair.slice(eq + 1).trim() as string;
    }
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
  const flowCookie = getCookie(loginRes, "hv_oidc_flow");
  expect(flowCookie).toBeTruthy();
  const flow = decodeFlowPayload(flowCookie as string);
  const code = `mock:${sub}:${flow.nonce}:${email}`;
  const callbackRes = await SELF.fetch(
    `${BASE}/auth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(flow.state)}`,
    { redirect: "manual", headers: { cookie: `hv_oidc_flow=${flowCookie}` } },
  );
  expect(callbackRes.status).toBe(302);
  const session = getCookie(callbackRes, "hv_session");
  expect(session).toBeTruthy();
  return session as string;
}

function csrfFrom(html: string): string {
  const token = /name="csrf_token" value="([0-9a-f]{64})"/.exec(html)?.[1];
  expect(token).toBeTruthy();
  return token as string;
}

async function getCsrf(session: string): Promise<string> {
  const res = await SELF.fetch(`${BASE}/admin`, {
    headers: { cookie: `hv_session=${session}` },
  });
  expect(res.status).toBe(200);
  return csrfFrom(await res.text());
}

/** Create a tenant through the UI (returns tenant id + API key). */
async function createWorkspaceViaUi(
  session: string,
  name: string,
): Promise<{ tenantId: string; apiKey: string }> {
  const csrf = await getCsrf(session);
  const res = await SELF.fetch(`${BASE}/admin/workspaces`, {
    method: "POST",
    headers: {
      cookie: `hv_session=${session}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ name, csrf_token: csrf }).toString(),
  });
  expect(res.status).toBe(200);
  const html = await res.text();
  const tenantId = /\/admin\/workspaces\/([0-9a-f-]{36})/.exec(html)?.[1];
  const apiKey = /(hvk_[A-Za-z0-9_-]+)/.exec(html)?.[1];
  expect(tenantId).toBeTruthy();
  expect(apiKey).toBeTruthy();
  return { tenantId: tenantId as string, apiKey: apiKey as string };
}

let ipCounter = 10;
async function createTenant(): Promise<{ id: string; apiKey: string }> {
  ipCounter += 1;
  const res = await SELF.fetch(`${BASE}/api/v1/tenants`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "cf-connecting-ip": `198.51.100.${ipCounter}`,
    },
    body: JSON.stringify({ name: "セキュリティテスト" }),
  });
  expect(res.status).toBe(201);
  const data = (await res.json()) as { tenant: { id: string }; api_key: string };
  return { id: data.tenant.id, apiKey: data.api_key };
}

async function createPublishedPoll(
  tenant: { id: string; apiKey: string },
  options: { label: string }[],
  extra: Record<string, unknown> = {},
): Promise<{ pollId: string; optionIds: string[] }> {
  const pRes = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/polls`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${tenant.apiKey}`,
    },
    body: JSON.stringify({ question: "テスト投票", options, ...extra }),
  });
  expect(pRes.status).toBe(201);
  const p = (await pRes.json()) as {
    poll: { id: string; options: { id: string }[] };
  };
  const sRes = await SELF.fetch(
    `${BASE}/api/v1/tenants/${tenant.id}/polls/${p.poll.id}/status`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${tenant.apiKey}`,
      },
      body: JSON.stringify({ status: "published" }),
    },
  );
  expect(sRes.status).toBe(200);
  return { pollId: p.poll.id, optionIds: p.poll.options.map((o) => o.id) };
}

async function voteAnon(
  pollId: string,
  optionId: string,
  voterToken: string,
): Promise<Response> {
  return SELF.fetch(`${BASE}/api/v1/polls/${pollId}/vote`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ option_ids: [optionId], voter_token: voterToken }),
  });
}

async function results(pollId: string) {
  const res = await SELF.fetch(`${BASE}/api/v1/polls/${pollId}/results`);
  const data = (await res.json()) as {
    results: { total_voters: number; total_votes: number };
  };
  return data.results;
}

/* ------------------------------------------------------------------ */
/* L2: security headers                                                */
/* ------------------------------------------------------------------ */

describe("security headers", () => {
  it("sets CSP and the basic headers on HTML, API and error responses", async () => {
    const html = await SELF.fetch(`${BASE}/`);
    expect(html.headers.get("content-security-policy")).toContain("default-src 'self'");
    expect(html.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(html.headers.get("x-content-type-options")).toBe("nosniff");
    expect(html.headers.get("x-frame-options")).toBe("DENY");
    expect(html.headers.get("referrer-policy")).toBe("same-origin");
    expect(html.headers.get("strict-transport-security")).toContain("max-age=");

    const api = await SELF.fetch(`${BASE}/api/v1/health`);
    expect(api.headers.get("content-security-policy")).toContain("default-src 'self'");

    const notFound = await SELF.fetch(`${BASE}/api/v1/nope`);
    expect(notFound.status).toBe(404);
    expect(notFound.headers.get("x-content-type-options")).toBe("nosniff");
  });
});

/* ------------------------------------------------------------------ */
/* M1: stored XSS via option labels                                    */
/* ------------------------------------------------------------------ */

describe("poll edit page option embedding", () => {
  it("cannot break out of the script context with a crafted label", async () => {
    const session = await loginAs("sec-xss-user", "xss@example.com");
    const { tenantId, apiKey } = await createWorkspaceViaUi(session, "XSS検証");
    const evil = "</script><script>globalThis.__xss_pwned=1</" + "script>";
    const pRes = await SELF.fetch(`${BASE}/api/v1/tenants/${tenantId}/polls`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        question: "XSS検証",
        options: [{ label: evil }, { label: "通常の選択肢" }],
      }),
    });
    expect(pRes.status).toBe(201);
    const p = (await pRes.json()) as { poll: { id: string } };

    const pageRes = await SELF.fetch(
      `${BASE}/admin/workspaces/${tenantId}/polls/${p.poll.id}`,
      { headers: { cookie: `hv_session=${session}` } },
    );
    expect(pageRes.status).toBe(200);
    const html = await pageRes.text();
    // The raw breakout sequence must not appear anywhere.
    expect(html.includes("</script><script>globalThis.__xss_pwned")).toBe(false);
    // The label travels in an application/json block with < escaped.
    expect(html).toContain('type="application/json"');
    expect(html.includes("\\u003c/script\\u003e")).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/* M3: voter_key hashing + legacy migration                            */
/* ------------------------------------------------------------------ */

describe("anonymous voter keys", () => {
  it("stores only the HMAC of the voter token", async () => {
    const tenant = await createTenant();
    const { pollId, optionIds } = await createPublishedPoll(tenant, [
      { label: "A" },
      { label: "B" },
    ]);
    const token = "my-secret-token-123";
    const res = await voteAnon(pollId, optionIds[0] as string, token);
    expect(res.status).toBe(200);

    const rows = await env.DB.prepare(
      "SELECT voter_key FROM votes WHERE poll_id = ?1",
    )
      .bind(pollId)
      .all<{ voter_key: string }>();
    expect(rows.results.length).toBe(1);
    expect(rows.results[0]?.voter_key.startsWith("anonh:")).toBe(true);
    expect(rows.results[0]?.voter_key.includes(token)).toBe(false);

    // Re-voting with the same token replaces, not duplicates.
    const again = await voteAnon(pollId, optionIds[1] as string, token);
    expect(again.status).toBe(200);
    const r = await results(pollId);
    expect(r.total_voters).toBe(1);
    expect(r.total_votes).toBe(1);
  });

  it("migrates legacy plaintext anon keys in place, preserving the ballot", async () => {
    const tenant = await createTenant();
    const { pollId, optionIds } = await createPublishedPoll(tenant, [
      { label: "A" },
      { label: "B" },
    ]);
    const now = new Date().toISOString();
    await env.DB.prepare(
      `INSERT INTO votes (id, poll_id, option_id, voter_key, created_at, updated_at)
       VALUES (?1, ?2, ?3, 'anon:legacy-token-xyz', ?4, ?4)`,
    )
      .bind(crypto.randomUUID(), pollId, optionIds[0], now)
      .run();

    const r = await results(pollId);
    expect(r.total_voters).toBe(1);

    const rows = await env.DB.prepare(
      "SELECT voter_key FROM votes WHERE poll_id = ?1",
    )
      .bind(pollId)
      .all<{ voter_key: string }>();
    expect(rows.results[0]?.voter_key.startsWith("anonh:")).toBe(true);

    // The same token can still re-vote and replace the migrated ballot.
    const revote = await voteAnon(pollId, optionIds[1] as string, "legacy-token-xyz");
    expect(revote.status).toBe(200);
    const r2 = await results(pollId);
    expect(r2.total_voters).toBe(1);
    expect(r2.total_votes).toBe(1);
  });
});

/* ------------------------------------------------------------------ */
/* M2: rate limits and quotas                                          */
/* ------------------------------------------------------------------ */

describe("rate limits", () => {
  it("limits unauthenticated tenant creation per IP", async () => {
    const ip = "203.0.113.77";
    for (let i = 0; i < 30; i++) {
      const res = await SELF.fetch(`${BASE}/api/v1/tenants`, {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": ip },
        body: JSON.stringify({ name: `rl-${i}` }),
      });
      expect(res.status).toBe(201);
    }
    const over = await SELF.fetch(`${BASE}/api/v1/tenants`, {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": ip },
      body: JSON.stringify({ name: "rl-over" }),
    });
    expect(over.status).toBe(429);
    expect(((await over.json()) as { error: { code: string } }).error.code).toBe(
      "RATE_LIMITED",
    );
    expect(Number(over.headers.get("retry-after"))).toBeGreaterThan(0);
  });

  it("limits votes per poll and IP", async () => {
    const tenant = await createTenant();
    const { pollId, optionIds } = await createPublishedPoll(tenant, [
      { label: "A" },
      { label: "B" },
    ]);
    const ip = "203.0.113.99";
    const bucket = await sha256Hex(`rl:vote:${pollId}:${ip}`);
    const windowStart = Math.floor(Math.floor(Date.now() / 1000) / 3600) * 3600;
    await env.DB.prepare(
      "INSERT INTO rate_limit_buckets (bucket, window_start, count) VALUES (?1, ?2, 600)",
    )
      .bind(bucket, windowStart)
      .run();
    const res = await SELF.fetch(`${BASE}/api/v1/polls/${pollId}/vote`, {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": ip },
      body: JSON.stringify({
        option_ids: [optionIds[0]],
        voter_token: "rl-voter-token",
      }),
    });
    expect(res.status).toBe(429);
  });
});

describe("image upload validation and quota", () => {
  it("rejects bytes that do not match the declared image type", async () => {
    const tenant = await createTenant();
    const text = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/images`, {
      method: "POST",
      headers: {
        "content-type": "image/png",
        authorization: `Bearer ${tenant.apiKey}`,
      },
      body: new TextEncoder().encode("this is not a png"),
    });
    expect(text.status).toBe(400);

    const mismatch = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/images`, {
      method: "POST",
      headers: {
        "content-type": "image/png",
        authorization: `Bearer ${tenant.apiKey}`,
      },
      body: JPEG_BYTES,
    });
    expect(mismatch.status).toBe(400);

    const ok = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/images`, {
      method: "POST",
      headers: {
        "content-type": "image/png",
        authorization: `Bearer ${tenant.apiKey}`,
      },
      body: PNG_BYTES,
    });
    expect(ok.status).toBe(201);
    const { url } = (await ok.json()) as { url: string };
    const served = await SELF.fetch(url.replace(/^https:\/\/[^/]+/, BASE));
    expect(served.status).toBe(200);
    expect(served.headers.get("x-content-type-options")).toBe("nosniff");
    expect(served.headers.get("content-type")).toContain("image/png");
  });

  it("enforces the per-tenant image count quota", async () => {
    const tenant = await createTenant();
    await env.DB.prepare(
      `INSERT INTO tenant_image_usage (tenant_id, image_count, total_bytes, updated_at)
       VALUES (?1, 500, 0, ?2)`,
    )
      .bind(tenant.id, new Date().toISOString())
      .run();
    const res = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/images`, {
      method: "POST",
      headers: {
        "content-type": "image/png",
        authorization: `Bearer ${tenant.apiKey}`,
      },
      body: PNG_BYTES,
    });
    expect(res.status).toBe(429);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "IMAGE_QUOTA_EXCEEDED",
    );
  });
});

/* ------------------------------------------------------------------ */
/* L3/L4/L5: CSRF, logout, session revocation                          */
/* ------------------------------------------------------------------ */

describe("CSRF protection", () => {
  it("rejects UI form posts without a CSRF token", async () => {
    const session = await loginAs("sec-csrf-user", "csrf@example.com");
    const res = await SELF.fetch(`${BASE}/admin/workspaces`, {
      method: "POST",
      headers: {
        cookie: `hv_session=${session}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ name: "CSRFなし" }).toString(),
    });
    expect(res.status).toBe(403);
  });

  it("rejects session-authenticated API mutations without the CSRF header", async () => {
    const session = await loginAs("sec-csrf-api", "csrfapi@example.com");
    const { tenantId } = await createWorkspaceViaUi(session, "CSRF API検証");
    const payload = JSON.stringify({
      question: "CSRF検証",
      options: [{ label: "A" }, { label: "B" }],
    });
    const noToken = await SELF.fetch(`${BASE}/api/v1/tenants/${tenantId}/polls`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: `hv_session=${session}`,
      },
      body: payload,
    });
    expect(noToken.status).toBe(403);

    const csrf = await getCsrf(session);
    const withToken = await SELF.fetch(`${BASE}/api/v1/tenants/${tenantId}/polls`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: `hv_session=${session}`,
        "x-csrf-token": csrf,
      },
      body: payload,
    });
    expect(withToken.status).toBe(201);
  });
});

describe("logout and session revocation", () => {
  it("has no GET logout, and POST logout revokes the session server-side", async () => {
    const session = await loginAs("sec-logout-user", "logout@example.com");
    const getLogout = await SELF.fetch(`${BASE}/admin/logout`, {
      redirect: "manual",
      headers: { cookie: `hv_session=${session}` },
    });
    expect(getLogout.status).toBe(404);

    const noCsrf = await SELF.fetch(`${BASE}/admin/logout`, {
      method: "POST",
      redirect: "manual",
      headers: {
        cookie: `hv_session=${session}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: "",
    });
    expect(noCsrf.status).toBe(403);

    const csrf = await getCsrf(session);
    const post = await SELF.fetch(`${BASE}/admin/logout`, {
      method: "POST",
      redirect: "manual",
      headers: {
        cookie: `hv_session=${session}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ csrf_token: csrf }).toString(),
    });
    expect(post.status).toBe(302);

    // The same cookie value must no longer authenticate.
    const admin = await SELF.fetch(`${BASE}/admin`, {
      headers: { cookie: `hv_session=${session}` },
    });
    expect(await admin.text()).toContain("0g0-id でログイン");
  });

  it("revoke-all invalidates the user's other sessions too", async () => {
    const s1 = await loginAs("sec-revoke-user", "revoke@example.com");
    const s2 = await loginAs("sec-revoke-user", "revoke@example.com");
    expect(s1).not.toBe(s2);
    const csrf = await getCsrf(s1);
    const res = await SELF.fetch(`${BASE}/admin/sessions/revoke-all`, {
      method: "POST",
      redirect: "manual",
      headers: {
        cookie: `hv_session=${s1}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ csrf_token: csrf }).toString(),
    });
    expect(res.status).toBe(302);
    const admin2 = await SELF.fetch(`${BASE}/admin`, {
      headers: { cookie: `hv_session=${s2}` },
    });
    expect(await admin2.text()).toContain("0g0-id でログイン");
  });
});

/* ------------------------------------------------------------------ */
/* L6: JWT details (azp / iat)                                         */
/* ------------------------------------------------------------------ */

describe("voter JWT strictness", () => {
  it("requires azp for multi-audience tokens and a sane iat", async () => {
    const tenant = await createTenant();
    const { pollId, optionIds } = await createPublishedPoll(
      tenant,
      [{ label: "A" }, { label: "B" }],
      { require_login: true },
    );
    const voteWith = async (jwt: string) =>
      SELF.fetch(`${BASE}/api/v1/polls/${pollId}/vote`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify({ option_ids: [optionIds[0]] }),
      });

    const multiAudNoAzp = await signTestJwt({
      sub: "azp-user",
      aud: ["test-client-id", "another-client"],
    });
    expect((await voteWith(multiAudNoAzp)).status).toBe(401);

    const multiAudAzp = await signTestJwt({
      sub: "azp-user",
      aud: ["test-client-id", "another-client"],
      azp: "test-client-id",
    });
    expect((await voteWith(multiAudAzp)).status).toBe(200);

    const futureIat = await signTestJwt({
      sub: "iat-user",
      iat: Math.floor(Date.now() / 1000) + 3600,
    });
    expect((await voteWith(futureIat)).status).toBe(401);
  });
});
