import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { applySchema } from "./fixtures";

const BASE = "https://vote.test";

beforeAll(async () => {
  await applySchema(env.DB);
});

async function tenant() {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: "印刷テスト" }),
  });
  expect(res.status).toBe(201);
  const data = (await res.json()) as { tenant: { id: string }; api_key: string };
  return { id: data.tenant.id, apiKey: data.api_key };
}

describe("results print support", () => {
  it("public results page carries a print button and print styles", async () => {
    const owner = await tenant();
    const created = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${owner.apiKey}` },
      body: JSON.stringify({
        question: "印刷できる結果",
        options: [{ label: "はい" }, { label: "いいえ" }],
      }),
    });
    expect(created.status).toBe(201);
    const { poll } = (await created.json()) as { poll: { id: string } };
    const status = await SELF.fetch(
      `${BASE}/api/v1/tenants/${owner.id}/polls/${poll.id}/status`,
      {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${owner.apiKey}` },
        body: JSON.stringify({ status: "published" }),
      },
    );
    expect(status.status).toBe(200);

    const page = await SELF.fetch(`${BASE}/polls/${poll.id}/results-page`);
    expect(page.status).toBe(200);
    const html = await page.text();
    // Print button is wired and excluded from the printout itself.
    expect(html).toContain('id="print-results"');
    expect(html).toContain("印刷／PDFに保存");
    expect(html).toContain("no-print");
    // Print stylesheet: hides navigation/controls and forces chart colors.
    expect(html).toContain("@media print");
    expect(html).toContain("print-color-adjust:exact");
  });
});
