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

function decodeFlowPayload(cookie: string): { state: string; nonce: string } {
  const payloadPart = decodeURIComponent(cookie).split(".")[0] as string;
  const padded = payloadPart.replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(atob(padded + "=".repeat((4 - (padded.length % 4)) % 4))) as {
    state: string;
    nonce: string;
  };
}

async function loginAs(sub: string, email: string): Promise<string> {
  const loginRes = await SELF.fetch(`${BASE}/admin/login`, { redirect: "manual" });
  expect(loginRes.status).toBe(302);
  const flowCookie = getCookie(loginRes, "__Host-hv_oidc_flow");
  expect(flowCookie).toBeTruthy();
  const flow = decodeFlowPayload(flowCookie as string);
  const code = `mock:${sub}:${flow.nonce}:${email}`;
  const callbackRes = await SELF.fetch(
    `${BASE}/auth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(flow.state)}`,
    { redirect: "manual", headers: { cookie: `__Host-hv_oidc_flow=${flowCookie}` } },
  );
  const session = getCookie(callbackRes, "__Host-hv_session");
  expect(session).toBeTruthy();
  return session as string;
}

describe("question editor bulk option paste", () => {
  it("new-poll editor ships the bulk paste controls and logic", async () => {
    const session = await loginAs("bulk-owner", "bulk@example.test");
    const cookie = `__Host-hv_session=${session}`;
    const created = await SELF.fetch(`${BASE}/admin/workspaces`, {
      method: "POST",
      headers: { cookie, origin: BASE, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ name: "一括貼り付け" }).toString(),
    });
    expect(created.status).toBe(200);
    const tenantId = /\/admin\/workspaces\/([0-9a-f-]{36})/.exec(await created.text())?.[1];
    expect(tenantId).toBeTruthy();

    const page = await SELF.fetch(`${BASE}/admin/workspaces/${tenantId}/polls/new`, {
      headers: { cookie },
    });
    expect(page.status).toBe(200);
    const html = await page.text();
    // Bulk UI: textarea plus add/replace actions, wired to the option list.
    expect(html).toContain("選択肢をまとめて入力（1行に1つ）");
    expect(html).toContain("q-bulk-text");
    expect(html).toContain("貼り付けから追加");
    expect(html).toContain("貼り付けで置き換え");
    expect(html).toContain("applyBulk");
    // Blank lines are skipped and the 50-option cap is enforced client-side.
    expect(html).toContain("filter((s) => s.length > 0)");
    expect(html).toContain("選択肢は最大50件まで");
  });
});
