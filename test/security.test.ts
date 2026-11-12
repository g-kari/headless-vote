import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { assertPinnedOidcUrl } from "../src/oidc";
import { rateLimit } from "../src/security";
import { applySchema, signTestJwt, TEST_CLIENT_ID, TEST_ISSUER } from "./fixtures";

const BASE = "https://vote.test";

beforeAll(async () => {
  await applySchema(env.DB);
});

function b64url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

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

async function login(): Promise<string> {
  const loginRes = await SELF.fetch(`${BASE}/admin/login`, { redirect: "manual" });
  expect(loginRes.status).toBe(302);
  const flowCookie = getCookie(loginRes, "__Host-hv_oidc_flow");
  expect(flowCookie).toBeTruthy();
  const payloadPart = decodeURIComponent(flowCookie as string).split(".")[0] as string;
  const padded = payloadPart.replace(/-/g, "+").replace(/_/g, "/");
  const flow = JSON.parse(atob(padded + "=".repeat((4 - (padded.length % 4)) % 4))) as {
    state: string;
    nonce: string;
  };
  const code = `mock:sec-user:${flow.nonce}:sec@example.com`;
  const callback = await SELF.fetch(
    `${BASE}/auth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(flow.state)}`,
    {
      redirect: "manual",
      headers: { cookie: `__Host-hv_oidc_flow=${flowCookie}` },
    },
  );
  expect(callback.status).toBe(302);
  const session = getCookie(callback, "__Host-hv_session");
  expect(session).toBeTruthy();
  return session as string;
}

describe("OIDC endpoint pinning", () => {
  it("rejects token endpoints that leave the issuer origin", () => {
    expect(() =>
      assertPinnedOidcUrl("https://idp.example.test", "https://idp.example.test/api/token"),
    ).not.toThrow();
    expect(() =>
      assertPinnedOidcUrl("https://idp.example.test", "https://evil.example/api/token"),
    ).toThrow();
    expect(() =>
      assertPinnedOidcUrl("https://idp.example.test", "http://idp.example.test/api/token"),
    ).toThrow();
    expect(() =>
      assertPinnedOidcUrl("http://idp.example.test", "http://idp.example.test/api/token"),
    ).toThrow();
  });
});

describe("security headers and session cookies", () => {
  it("sends a strict policy on HTML and does not use script unsafe-inline", async () => {
    const res = await SELF.fetch(`${BASE}/admin`);
    expect(res.status).toBe(200);
    const csp = res.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("base-uri 'none'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("require-trusted-types-for 'script'");
    expect(csp).not.toMatch(/script-src[^;]*unsafe-inline/);
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("referrer-policy")).toBe("strict-origin-when-cross-origin");
    expect(res.headers.get("cross-origin-opener-policy")).toBe("same-origin-allow-popups");
    expect(res.headers.get("permissions-policy")).toContain("camera=()");
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
    const html = await res.text();
    const nonce = /nonce-([A-Za-z0-9_-]+)/.exec(csp)?.[1];
    expect(nonce).toBeTruthy();
    expect(html).toContain(`nonce="${nonce}"`);
  });

  it("does not reflect an unsafe OIDC error query into the response", async () => {
    const res = await SELF.fetch(
      `${BASE}/auth/callback?error=${encodeURIComponent("</script><img src=x onerror=alert(1)>")}`,
    );
    expect(res.status).toBe(400);
    const body = await res.text();
    expect(body).not.toContain("<script");
    expect(body).not.toContain("<img");
    expect(body).toContain("unknown_error");
  });

  it("rejects login started on a host other than APP_ORIGIN", async () => {
    const res = await SELF.fetch("https://evil.example/admin/login", { redirect: "manual" });
    expect(res.status).toBe(403);
  });

  it("does not log out on GET and clears the session only on same-origin POST", async () => {
    const session = await login();
    const getLogout = await SELF.fetch(`${BASE}/admin/logout`, {
      headers: { cookie: `__Host-hv_session=${session}` },
      redirect: "manual",
    });
    expect(getLogout.status).toBe(200);
    expect(getLogout.headers.get("clear-site-data")).toBeNull();
    expect(getLogout.headers.getSetCookie().join(" ")).not.toContain("Max-Age=0");
    const html = await getLogout.text();
    expect(html).toContain('method="post"');
    expect(html).toContain('action="/admin/logout"');

    const still = await SELF.fetch(`${BASE}/admin`, {
      headers: { cookie: `__Host-hv_session=${session}` },
    });
    expect(await still.text()).toContain("ワークスペース");

    const forged = await SELF.fetch(`${BASE}/admin/logout`, {
      method: "POST",
      redirect: "manual",
      headers: {
        cookie: `__Host-hv_session=${session}`,
        origin: "https://evil.example",
        "content-type": "application/x-www-form-urlencoded",
      },
    });
    expect(forged.status).toBe(403);

    const posted = await SELF.fetch(`${BASE}/admin/logout`, {
      method: "POST",
      redirect: "manual",
      headers: {
        cookie: `__Host-hv_session=${session}`,
        origin: BASE,
        "content-type": "application/x-www-form-urlencoded",
      },
    });
    expect(posted.status).toBe(302);
    expect(posted.headers.get("clear-site-data")).toContain("cookies");
    expect(posted.headers.getSetCookie().some((h) => h.includes("Max-Age=0"))).toBe(true);
  });
});

describe("admin HTML injection and request limits", () => {
  it("does not break out of script or attributes with poll text", async () => {
    const session = await login();
    const created = await SELF.fetch(`${BASE}/admin/workspaces`, {
      method: "POST",
      headers: {
        cookie: `__Host-hv_session=${session}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ name: "XSS ワークスペース" }).toString(),
    });
    expect(created.status).toBe(200);
    const createdHtml = await created.text();
    const tenantId = /\/admin\/workspaces\/([0-9a-f-]{36})/.exec(createdHtml)?.[1];
    const apiKey = /hvk_[A-Za-z0-9_-]+/.exec(createdHtml)?.[0];
    expect(tenantId).toBeTruthy();
    expect(apiKey).toBeTruthy();

    const label = "</script><img src=x onerror=alert(1)>";
    const question = '"><img src=x onerror=alert(1)>';
    const pollRes = await SELF.fetch(`${BASE}/api/v1/tenants/${tenantId}/polls`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: `__Host-hv_session=${session}`,
      },
      body: JSON.stringify({
        question,
        description: "</textarea><script>alert(1)</script>",
        options: [{ label }, { label: "安全" }],
      }),
    });
    expect(pollRes.status).toBe(201);
    const pollId = ((await pollRes.json()) as { poll: { id: string } }).poll.id;
    const page = await SELF.fetch(`${BASE}/admin/workspaces/${tenantId}/polls/${pollId}`, {
      headers: { cookie: `__Host-hv_session=${session}` },
    });
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).not.toContain("</script><img");
    expect(html).not.toContain('"><img');
    expect(html).not.toContain("</textarea><script>");
    expect(html).toContain("\\u003c");
  });

  it("rejects cross-site workspace creation and oversized JSON", async () => {
    const session = await login();
    const forged = await SELF.fetch(`${BASE}/admin/workspaces`, {
      method: "POST",
      headers: {
        cookie: `__Host-hv_session=${session}`,
        origin: "https://evil.example",
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ name: "乗っ取られた" }).toString(),
    });
    expect(forged.status).toBe(403);

    const tRes = await SELF.fetch(`${BASE}/api/v1/tenants`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "サイズ" }),
    });
    const t = (await tRes.json()) as { tenant: { id: string }; api_key: string };
    const huge = await SELF.fetch(`${BASE}/api/v1/tenants/${t.tenant.id}/polls`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${t.api_key}`,
      },
      body: JSON.stringify({
        question: "大きい",
        options: [{ label: "a" }, { label: "b" }],
        padding: "x".repeat(70_000),
      }),
    });
    expect(huge.status).toBe(413);
  });
});

describe("vote integrity and uploads", () => {
  it("stores an HMAC of the voter token and locks voting rules after a vote", async () => {
    const tRes = await SELF.fetch(`${BASE}/api/v1/tenants`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "完全性" }),
    });
    const t = (await tRes.json()) as { tenant: { id: string }; api_key: string };
    const pRes = await SELF.fetch(`${BASE}/api/v1/tenants/${t.tenant.id}/polls`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${t.api_key}`,
      },
      body: JSON.stringify({
        question: "元の設問",
        options: [{ label: "赤" }, { label: "青" }],
      }),
    });
    const poll = (await pRes.json()) as { poll: { id: string; options: { id: string }[] } };
    await SELF.fetch(`${BASE}/api/v1/tenants/${t.tenant.id}/polls/${poll.poll.id}/status`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${t.api_key}`,
      },
      body: JSON.stringify({ status: "published" }),
    });
    const optionId = poll.poll.options[0]?.id ?? "";
    const vote = await SELF.fetch(`${BASE}/api/v1/polls/${poll.poll.id}/vote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ voter_token: "privacy-token-1", option_ids: [optionId] }),
    });
    expect(vote.status).toBe(200);
    const rows = await env.DB.prepare(
      "SELECT voter_key FROM vote_ballots WHERE poll_id = ?1",
    )
      .bind(poll.poll.id)
      .all<{ voter_key: string }>();
    expect(rows.results).toHaveLength(1);
    expect(rows.results[0]?.voter_key.startsWith("v1.")).toBe(true);
    expect(rows.results[0]?.voter_key).not.toContain("privacy-token-1");

    const rules = await SELF.fetch(`${BASE}/api/v1/tenants/${t.tenant.id}/polls/${poll.poll.id}`, {
      method: "PATCH",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${t.api_key}`,
      },
      body: JSON.stringify({ allow_multiple: true }),
    });
    expect(rules.status).toBe(409);
    expect(((await rules.json()) as { error: { code: string } }).error.code).toBe("RULES_LOCKED");

    const question = await SELF.fetch(
      `${BASE}/api/v1/tenants/${t.tenant.id}/polls/${poll.poll.id}`,
      {
        method: "PATCH",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${t.api_key}`,
        },
        body: JSON.stringify({ question: "言い換えた設問" }),
      },
    );
    expect(question.status).toBe(200);

    await env.DB.prepare("DELETE FROM app_meta WHERE key = 'voter_hmac_v1'").run();
    await env.DB.prepare(
      `INSERT INTO vote_ballots (poll_id, voter_key, option_ids, updated_at)
       VALUES (?1, 'anon:legacy-secret-token', ?2, ?3)`,
    )
      .bind(poll.poll.id, JSON.stringify([optionId]), new Date().toISOString())
      .run();
    const results = await SELF.fetch(`${BASE}/api/v1/polls/${poll.poll.id}/results`);
    expect(results.status).toBe(200);
    const after = await env.DB.prepare(
      "SELECT voter_key FROM vote_ballots WHERE poll_id = ?1",
    )
      .bind(poll.poll.id)
      .all<{ voter_key: string }>();
    for (const row of after.results) {
      expect(row.voter_key.startsWith("v1.")).toBe(true);
      expect(row.voter_key).not.toContain("legacy-secret-token");
    }
  });

  it("rejects non-image bytes, path traversal, and alg=none tokens", async () => {
    const tRes = await SELF.fetch(`${BASE}/api/v1/tenants`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "画像検証" }),
    });
    const t = (await tRes.json()) as { tenant: { id: string }; api_key: string };
    const htmlUpload = await SELF.fetch(`${BASE}/api/v1/tenants/${t.tenant.id}/images`, {
      method: "POST",
      headers: {
        "content-type": "image/png",
        authorization: `Bearer ${t.api_key}`,
      },
      body: "<html><script>alert(1)</script></html>",
    });
    expect(htmlUpload.status).toBe(400);

    const traversal = await SELF.fetch(`${BASE}/images/t/..%2f..%2fetc/passwd`);
    expect(traversal.status).toBe(404);
    const junk = await SELF.fetch(
      `${BASE}/images/t/not-a-uuid/00000000-0000-0000-0000-000000000000.png`,
    );
    expect(junk.status).toBe(404);

    const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: "none", typ: "JWT" })));
    const payload = b64url(
      new TextEncoder().encode(
        JSON.stringify({
          iss: TEST_ISSUER,
          aud: TEST_CLIENT_ID,
          sub: "attacker",
          exp: Math.floor(Date.now() / 1000) + 600,
        }),
      ),
    );
    const pRes = await SELF.fetch(`${BASE}/api/v1/tenants/${t.tenant.id}/polls`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${t.api_key}`,
      },
      body: JSON.stringify({
        question: "トークン",
        options: [{ label: "A" }, { label: "B" }],
      }),
    });
    const poll = (await pRes.json()) as { poll: { id: string; options: { id: string }[] } };
    await SELF.fetch(`${BASE}/api/v1/tenants/${t.tenant.id}/polls/${poll.poll.id}/status`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${t.api_key}`,
      },
      body: JSON.stringify({ status: "published" }),
    });
    const none = await SELF.fetch(`${BASE}/api/v1/polls/${poll.poll.id}/vote`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${header}.${payload}.`,
      },
      body: JSON.stringify({ option_ids: [poll.poll.options[0]?.id] }),
    });
    expect(none.status).toBe(401);

    const crit = await signTestJwt({ sub: "crit-user" });
    const [h, p, s] = crit.split(".");
    const critHeader = b64url(
      new TextEncoder().encode(JSON.stringify({ alg: "ES256", typ: "JWT", kid: "test-key-1", crit: ["bork"] })),
    );
    const critRes = await SELF.fetch(`${BASE}/api/v1/polls/${poll.poll.id}/vote`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${critHeader}.${p}.${s}`,
      },
      body: JSON.stringify({ option_ids: [poll.poll.options[0]?.id] }),
    });
    expect(critRes.status).toBe(401);
    void h;
  });

  it("rate limit helper rejects once the bucket is over the limit", async () => {
    const bucket = `unit-${crypto.randomUUID()}`;
    await rateLimit(env, bucket, 2, 60);
    await rateLimit(env, bucket, 2, 60);
    await expect(rateLimit(env, bucket, 2, 60)).rejects.toMatchObject({
      status: 429,
      code: "RATE_LIMITED",
    });
  });
});
