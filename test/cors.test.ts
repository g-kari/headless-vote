import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { applySchema } from "./fixtures";
import { parseAllowedOrigin } from "../src/cors";

const BASE = "https://vote.test";

beforeAll(async () => {
  await applySchema(env.DB);
});

async function createPublishedPoll(): Promise<{
  tenantId: string;
  apiKey: string;
  pollId: string;
  optionId: string;
}> {
  const tRes = await SELF.fetch(`${BASE}/api/v1/tenants`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: "CORS テナント" }),
  });
  expect(tRes.status).toBe(201);
  const t = (await tRes.json()) as { tenant: { id: string }; api_key: string };
  const pRes = await SELF.fetch(`${BASE}/api/v1/tenants/${t.tenant.id}/polls`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${t.api_key}`,
    },
    body: JSON.stringify({
      question: "埋め込みのテスト",
      options: [{ label: "A" }, { label: "B" }],
    }),
  });
  expect(pRes.status).toBe(201);
  const p = (await pRes.json()) as { poll: { id: string; options: { id: string }[] } };
  const pub = await SELF.fetch(
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
  expect(pub.status).toBe(200);
  return {
    tenantId: t.tenant.id,
    apiKey: t.api_key,
    pollId: p.poll.id,
    optionId: p.poll.options[0]?.id ?? "",
  };
}

async function allow(apiKey: string, tenantId: string, origin: string): Promise<Response> {
  return SELF.fetch(`${BASE}/api/v1/tenants/${tenantId}/origins`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({ origin }),
  });
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
  const payloadPart = decodeURIComponent(flowCookie as string).split(".")[0] as string;
  const padded = payloadPart.replace(/-/g, "+").replace(/_/g, "/");
  const flow = JSON.parse(atob(padded + "=".repeat((4 - (padded.length % 4)) % 4))) as {
    state: string;
    nonce: string;
  };
  const callback = await SELF.fetch(
    `${BASE}/auth/callback?code=${encodeURIComponent(`mock:cors-ui:${flow.nonce}:cors@example.com`)}&state=${encodeURIComponent(flow.state)}`,
    {
      redirect: "manual",
      headers: { cookie: `__Host-hv_oidc_flow=${flowCookie}` },
    },
  );
  return getCookie(callback, "__Host-hv_session") as string;
}

describe("origin validation", () => {
  it("normalizes https origins and rejects paths, wildcards, and plain http", () => {
    expect(parseAllowedOrigin("HTTPS://Example.COM:443")).toBe("https://example.com");
    expect(parseAllowedOrigin("https://example.com/")).toBe("https://example.com");
    expect(parseAllowedOrigin("https://example.com:444")).toBe("https://example.com:444");
    expect(parseAllowedOrigin("http://localhost:3000")).toBe("http://localhost:3000");
    expect(parseAllowedOrigin("http://127.0.0.1:8787")).toBe("http://127.0.0.1:8787");
    for (const bad of [
      "http://example.com",
      "https://example.com/vote",
      "https://*.example.com",
      "https://user:pass@example.com",
      "https://example.com?x=1",
      "*",
      "not a url",
    ]) {
      expect(() => parseAllowedOrigin(bad), bad).toThrow();
    }
  });
});

describe("per-workspace CORS allowlist", () => {
  it("reflects the poll owner's origin only, including preflight", async () => {
    const poll = await createPublishedPoll();
    const added = await allow(poll.apiKey, poll.tenantId, "HTTPS://Embed.Example:443/");
    expect(added.status).toBe(201);
    const saved = (await added.json()) as { origin: string; created: boolean };
    expect(saved.origin).toBe("https://embed.example");
    expect(saved.created).toBe(true);

    const again = await allow(poll.apiKey, poll.tenantId, "https://embed.example");
    expect(again.status).toBe(200);
    expect(((await again.json()) as { created: boolean }).created).toBe(false);

    const list = await SELF.fetch(`${BASE}/api/v1/tenants/${poll.tenantId}/origins`, {
      headers: { authorization: `Bearer ${poll.apiKey}` },
    });
    expect(list.status).toBe(200);
    expect(((await list.json()) as { origins: string[] }).origins).toEqual([
      "https://embed.example",
    ]);

    const ok = await SELF.fetch(`${BASE}/api/v1/polls/${poll.pollId}`, {
      headers: { origin: "https://embed.example" },
    });
    expect(ok.status).toBe(200);
    expect(ok.headers.get("access-control-allow-origin")).toBe("https://embed.example");
    expect(ok.headers.get("access-control-allow-credentials")).toBe("true");
    expect(ok.headers.get("vary")?.toLowerCase()).toContain("origin");

    const missing = await SELF.fetch(`${BASE}/api/v1/polls/${poll.pollId}`);
    expect(missing.status).toBe(200);
    expect(missing.headers.get("access-control-allow-origin")).toBeNull();
    expect(missing.headers.get("access-control-allow-credentials")).toBeNull();

    const denied = await SELF.fetch(`${BASE}/api/v1/polls/${poll.pollId}`, {
      headers: { origin: "https://nope.example" },
    });
    expect(denied.status).toBe(200);
    expect(denied.headers.get("access-control-allow-origin")).toBeNull();
    expect(denied.headers.get("access-control-allow-credentials")).toBeNull();

    const suffix = await SELF.fetch(`${BASE}/api/v1/polls/${poll.pollId}`, {
      headers: { origin: "https://embed.example.evil.com" },
    });
    expect(suffix.headers.get("access-control-allow-origin")).toBeNull();

    const preflight = await SELF.fetch(`${BASE}/api/v1/polls/${poll.pollId}/vote`, {
      method: "OPTIONS",
      headers: {
        origin: "https://embed.example",
        "access-control-request-method": "POST",
        "access-control-request-headers": "content-type, authorization",
        "sec-fetch-site": "cross-site",
        "sec-fetch-mode": "cors",
      },
    });
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get("access-control-allow-origin")).toBe("https://embed.example");
    expect(preflight.headers.get("access-control-allow-methods")).toContain("POST");
    expect(preflight.headers.get("access-control-allow-headers")?.toLowerCase()).toContain(
      "authorization",
    );
    expect(preflight.headers.get("access-control-allow-credentials")).toBe("true");

    const preflightDenied = await SELF.fetch(`${BASE}/api/v1/polls/${poll.pollId}`, {
      method: "OPTIONS",
      headers: {
        origin: "https://nope.example",
        "access-control-request-method": "GET",
      },
    });
    expect(preflightDenied.status).toBe(204);
    expect(preflightDenied.headers.get("access-control-allow-origin")).toBeNull();

    const preflightMissing = await SELF.fetch(`${BASE}/api/v1/polls/${poll.pollId}`, {
      method: "OPTIONS",
    });
    expect(preflightMissing.headers.get("access-control-allow-origin")).toBeNull();

    const voteError = await SELF.fetch(`${BASE}/api/v1/polls/${poll.pollId}/vote`, {
      method: "POST",
      headers: {
        origin: "https://embed.example",
        "content-type": "application/json",
        "sec-fetch-site": "cross-site",
        "sec-fetch-mode": "cors",
      },
      body: "{}",
    });
    expect(voteError.status).toBe(400);
    expect(voteError.headers.get("access-control-allow-origin")).toBe("https://embed.example");
  });

  it("does not apply another workspace's list, and does not open admin routes", async () => {
    const a = await createPublishedPoll();
    const b = await createPublishedPoll();
    expect((await allow(b.apiKey, b.tenantId, "https://b-only.example")).status).toBe(201);

    const cross = await SELF.fetch(`${BASE}/api/v1/polls/${a.pollId}`, {
      headers: { origin: "https://b-only.example" },
    });
    expect(cross.status).toBe(200);
    expect(cross.headers.get("access-control-allow-origin")).toBeNull();

    const admin = await SELF.fetch(`${BASE}/api/v1/tenants/${a.tenantId}/polls`, {
      headers: {
        origin: "https://b-only.example",
        authorization: `Bearer ${a.apiKey}`,
      },
    });
    expect(admin.status).toBe(200);
    expect(admin.headers.get("access-control-allow-origin")).toBeNull();

    const adminPreflight = await SELF.fetch(`${BASE}/api/v1/tenants/${a.tenantId}/origins`, {
      method: "OPTIONS",
      headers: {
        origin: "https://b-only.example",
        "access-control-request-method": "POST",
      },
    });
    expect(adminPreflight.headers.get("access-control-allow-origin")).toBeNull();

    const blocked = await SELF.fetch(`${BASE}/api/v1/tenants`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://b-only.example",
        "sec-fetch-site": "cross-site",
        "sec-fetch-mode": "cors",
      },
      body: JSON.stringify({ name: "should not be created" }),
    });
    expect(blocked.status).toBe(403);
    expect(blocked.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("rejects invalid origins and enforces the per-workspace cap", async () => {
    const poll = await createPublishedPoll();
    for (const bad of [
      "http://evil.example",
      "https://evil.example/phish",
      "https://*.evil.example",
      "https://user:pass@evil.example",
    ]) {
      const res = await allow(poll.apiKey, poll.tenantId, bad);
      expect(res.status, bad).toBe(400);
    }
    expect((await allow(poll.apiKey, poll.tenantId, "http://localhost:4173")).status).toBe(201);

    const other = await createPublishedPoll();
    const stolen = await SELF.fetch(`${BASE}/api/v1/tenants/${poll.tenantId}/origins`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${other.apiKey}`,
      },
      body: JSON.stringify({ origin: "https://stolen.example" }),
    });
    expect(stolen.status).toBe(401);

    for (let i = 0; i < 19; i++) {
      const res = await allow(poll.apiKey, poll.tenantId, `https://cap-${i}.example`);
      expect(res.status).toBe(201);
    }
    const overflow = await allow(poll.apiKey, poll.tenantId, "https://cap-overflow.example");
    expect(overflow.status).toBe(400);

    const png = new Uint8Array([
      0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4,
    ]);
    const uploaded = await SELF.fetch(`${BASE}/api/v1/tenants/${poll.tenantId}/images`, {
      method: "POST",
      headers: {
        "content-type": "image/png",
        authorization: `Bearer ${poll.apiKey}`,
      },
      body: png,
    });
    expect(uploaded.status).toBe(201);
    const imageKey = ((await uploaded.json()) as { key: string }).key;
    const image = await SELF.fetch(`${BASE}/images/${imageKey}`, {
      headers: { origin: "http://localhost:4173" },
    });
    expect(image.status).toBe(200);
    expect(image.headers.get("access-control-allow-origin")).toBe("http://localhost:4173");
    expect(image.headers.get("x-content-type-options")).toBe("nosniff");

    const removed = await SELF.fetch(`${BASE}/api/v1/tenants/${poll.tenantId}/origins`, {
      method: "DELETE",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${poll.apiKey}`,
      },
      body: JSON.stringify({ origin: "http://localhost:4173" }),
    });
    expect(removed.status).toBe(200);
  });
});

describe("admin settings screen", () => {
  it("lets the workspace owner add an origin from the settings form", async () => {
    const session = await login();
    const created = await SELF.fetch(`${BASE}/admin/workspaces`, {
      method: "POST",
      headers: {
        cookie: `__Host-hv_session=${session}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ name: "設定画面" }).toString(),
    });
    expect(created.status).toBe(200);
    const createdHtml = await created.text();
    const tenantId = /\/admin\/workspaces\/([0-9a-f-]{36})/.exec(createdHtml)?.[1];
    expect(tenantId).toBeTruthy();

    const page = await SELF.fetch(`${BASE}/admin/workspaces/${tenantId}/settings`, {
      headers: { cookie: `__Host-hv_session=${session}` },
    });
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain("埋め込み設定");
    expect(html).toContain("https://vote.0g0.xyz");
    expect(html).toContain('name="origin"');

    const forged = await SELF.fetch(`${BASE}/admin/workspaces/${tenantId}/origins`, {
      method: "POST",
      headers: {
        cookie: `__Host-hv_session=${session}`,
        origin: "https://evil.example",
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ origin: "https://evil.example" }).toString(),
    });
    expect(forged.status).toBe(403);

    const added = await SELF.fetch(`${BASE}/admin/workspaces/${tenantId}/origins`, {
      method: "POST",
      redirect: "manual",
      headers: {
        cookie: `__Host-hv_session=${session}`,
        origin: BASE,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ origin: "https://events.example" }).toString(),
    });
    expect(added.status).toBe(303);
    const after = await SELF.fetch(`${BASE}/admin/workspaces/${tenantId}/settings`, {
      headers: { cookie: `__Host-hv_session=${session}` },
    });
    expect(await after.text()).toContain("https://events.example");
  });
});
