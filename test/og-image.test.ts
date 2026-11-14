import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { applySchema } from "./fixtures";
import { bestTextOn, contrastRatio, readableOnWhite } from "../src/color";
import { shareTextWidth, wrapShareText } from "../src/routes/api";

const BASE = "https://vote.test";

beforeAll(async () => {
  await applySchema(env.DB);
});

interface Tenant {
  id: string;
  apiKey: string;
}

async function createTenant(name: string): Promise<Tenant> {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name }),
  });
  expect(res.status).toBe(201);
  const data = (await res.json()) as { tenant: { id: string }; api_key: string };
  return { id: data.tenant.id, apiKey: data.api_key };
}

function auth(t: Tenant) {
  return { "content-type": "application/json", authorization: `Bearer ${t.apiKey}` };
}

async function createPoll(
  t: Tenant,
  body: Record<string, unknown>,
): Promise<{ id: string; options: { id: string; label: string }[] }> {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants/${t.id}/polls`, {
    method: "POST",
    headers: auth(t),
    body: JSON.stringify(body),
  });
  expect(res.status).toBe(201);
  const data = (await res.json()) as {
    poll: { id: string; options: { id: string; label: string }[] };
  };
  return data.poll;
}

async function publish(t: Tenant, pollId: string) {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants/${t.id}/polls/${pollId}/status`, {
    method: "POST",
    headers: auth(t),
    body: JSON.stringify({ status: "published" }),
  });
  expect(res.status).toBe(200);
}

async function ogSvg(pollId: string): Promise<string> {
  const res = await SELF.fetch(`${BASE}/api/v1/polls/${pollId}/og.svg`);
  expect(res.status).toBe(200);
  expect(res.headers.get("content-type")).toContain("image/svg+xml");
  return res.text();
}

describe("color helpers", () => {
  it("measures contrast and darkens light colors for white backgrounds", () => {
    expect(contrastRatio("#ffffff", "#ffffff")).toBeCloseTo(1);
    expect(contrastRatio("#1e4fd8", "#ffffff")).toBeGreaterThan(4);
    expect(readableOnWhite("#1e4fd8")).toBe("#1e4fd8");
    const adjusted = readableOnWhite("#ffffff");
    expect(adjusted).not.toBe("#ffffff");
    expect(contrastRatio(adjusted, "#ffffff")).toBeGreaterThanOrEqual(3);
    expect(readableOnWhite("#ffd23e")).not.toBe("#ffd23e");
  });

  it("picks readable text colors on brand bands", () => {
    expect(bestTextOn("#1e4fd8")).toBe("#ffffff");
    expect(bestTextOn("#ffffff")).toBe("#222222");
    expect(bestTextOn("#ffd23e")).toBe("#222222");
  });
});

describe("share title wrapping", () => {
  it("wraps by estimated width, not character count", () => {
    // 21 full-width chars at 56px = 1176px: the old char-count wrap put
    // them on one line and overflowed the 1060px usable width.
    const lines = wrapShareText("あ".repeat(21), 1060, 56, 3);
    expect(lines.length).toBe(2);
    for (const line of lines) {
      expect(shareTextWidth(line, 56)).toBeLessThanOrEqual(1060);
    }
    expect(lines[0]).toBe("あ".repeat(18));
  });

  it("truncates to 3 lines with an ellipsis that still fits", () => {
    const lines = wrapShareText("あ".repeat(60), 1060, 56, 3);
    expect(lines.length).toBe(3);
    expect(lines[2]).toMatch(/…$/);
    for (const line of lines) {
      expect(shareTextWidth(line, 56)).toBeLessThanOrEqual(1060);
    }
  });

  it("keeps short and latin titles intact", () => {
    expect(wrapShareText("好きな色は？", 1060, 56, 3)).toEqual(["好きな色は？"]);
    expect(wrapShareText("", 1060, 56, 3)).toEqual([""]);
    const latin = wrapShareText("a".repeat(70), 1060, 56, 3);
    expect(latin.join("")).toBe("a".repeat(70));
  });
});

describe("share image (og.svg)", () => {
  it("uses the default blue band with white title when no brand color is set", async () => {
    const t = await createTenant("共有画像・標準");
    const poll = await createPoll(t, {
      question: "あき どっち？",
      options: [{ label: "あ" }, { label: "き" }],
    });
    await publish(t, poll.id);
    const svg = await ogSvg(poll.id);
    expect(svg).toContain('width="1200" height="630" viewBox="0 0 1200 630"');
    expect(svg).toContain('<rect width="1200" height="182" fill="#1e4fd8"/>');
    expect(svg).toContain('font-weight="bold" fill="#ffffff">あき どっち？</text>');
    expect(svg).toContain("投票者数 0 人");
  });

  it("keeps band, title and bars visible with a white brand color", async () => {
    const t = await createTenant("共有画像・白ブランド");
    const brand = await SELF.fetch(`${BASE}/api/v1/tenants/${t.id}/branding`, {
      method: "PATCH",
      headers: auth(t),
      body: JSON.stringify({ brand_color: "#ffffff" }),
    });
    expect(brand.status).toBe(200);
    const poll = await createPoll(t, {
      question: "あき どっち？",
      options: [{ label: "あ" }, { label: "き" }],
    });
    await publish(t, poll.id);
    const vote = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/vote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        voter_token: "og-white-voter",
        option_ids: [poll.options[0]?.id],
      }),
    });
    expect(vote.status).toBe(200);
    const svg = await ogSvg(poll.id);
    // The band stays the tenant's white, but the title switches to dark text.
    expect(svg).toContain('<rect width="1200" height="182" fill="#ffffff"/>');
    expect(svg).toContain('font-weight="bold" fill="#222222">あき どっち？</text>');
    expect(svg).not.toContain('fill="#ffffff">あき どっち？</text>');
    // The bar for the voted option is not painted white either.
    const bar = svg.match(/<rect x="70" y="342" width="(\d+)" height="18" fill="(#[0-9a-f]{6})"\/>/);
    expect(bar).not.toBeNull();
    expect(Number(bar?.[1])).toBeGreaterThan(0);
    expect(bar?.[2]).not.toBe("#ffffff");
    expect(contrastRatio(bar?.[2] ?? "#ffffff", "#ffffff")).toBeGreaterThanOrEqual(3);
  });

  it("moves rows below a 3-line title band and drops rows that cannot fit", async () => {
    const t = await createTenant("共有画像・長いタイトル");
    const poll = await createPoll(t, {
      question: "あ".repeat(60),
      options: [{ label: "一" }, { label: "二" }, { label: "三" }, { label: "四" }],
    });
    await publish(t, poll.id);
    const svg = await ogSvg(poll.id);
    // 3 title lines -> band is 110 + 3*72 = 326 tall.
    expect(svg).toContain('<rect width="1200" height="326" fill="#1e4fd8"/>');
    // First option label starts below the band instead of overlapping it.
    const firstLabel = svg.match(/<text x="70" y="(\d+)" font-size="30" fill="#222222">一<\/text>/);
    expect(firstLabel).not.toBeNull();
    expect(Number(firstLabel?.[1])).toBeGreaterThanOrEqual(326 + 30);
    // Only 3 of the 4 rows fit above the footer; the 4th label is omitted.
    expect(svg).toContain(">三</text>");
    expect(svg).not.toContain(">四</text>");
    expect(svg).toContain("投票者数 0 人");
  });

  it("truncates over-wide option labels with an ellipsis", async () => {
    const t = await createTenant("共有画像・長い選択肢");
    const longLabel = "選".repeat(60);
    const poll = await createPoll(t, {
      question: "確認",
      options: [{ label: longLabel }, { label: "短い" }],
    });
    await publish(t, poll.id);
    const svg = await ogSvg(poll.id);
    expect(svg).not.toContain(longLabel);
    expect(svg).toContain(`${"選".repeat(34)}…`);
  });

  it("says results are private (not 'revealed after close') for admin_only polls", async () => {
    const t = await createTenant("共有画像・非公開");
    const poll = await createPoll(t, {
      question: "内緒のアンケート",
      results_visibility: "admin_only",
      options: [{ label: "はい" }, { label: "いいえ" }],
    });
    await publish(t, poll.id);
    const svg = await ogSvg(poll.id);
    expect(svg).toContain("結果は非公開です");
    expect(svg).not.toContain("締切後に公開");
    expect(svg).not.toContain("投票者数");
  });

  it("keeps admin_only results private in the share image even after closing", async () => {
    const t = await createTenant("共有画像・非公開終了後");
    const poll = await createPoll(t, {
      question: "終了後も内緒",
      results_visibility: "admin_only",
      options: [{ label: "はい" }, { label: "いいえ" }],
    });
    await publish(t, poll.id);
    const close = await SELF.fetch(`${BASE}/api/v1/tenants/${t.id}/polls/${poll.id}/status`, {
      method: "POST",
      headers: auth(t),
      body: JSON.stringify({ status: "closed" }),
    });
    expect(close.status).toBe(200);
    const svg = await ogSvg(poll.id);
    expect(svg).toContain("結果は非公開です");
    expect(svg).not.toContain("締切後に公開");
    expect(svg).not.toContain("投票者数");
  });

  it("keeps the 'revealed after close' note for after_close polls still open", async () => {
    const t = await createTenant("共有画像・締切後公開");
    const poll = await createPoll(t, {
      question: "締切後に見せます",
      results_visibility: "after_close",
      closes_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      options: [{ label: "はい" }, { label: "いいえ" }],
    });
    await publish(t, poll.id);
    const svg = await ogSvg(poll.id);
    expect(svg).toContain("結果は締切後に公開されます");
    expect(svg).not.toContain("結果は非公開です");
    expect(svg).not.toContain("投票者数");
  });

  it("darkens the light-scheme accent on branded pages (results-page bars/buttons)", async () => {
    const t = await createTenant("共有画像・白ブランド画面");
    await SELF.fetch(`${BASE}/api/v1/tenants/${t.id}/branding`, {
      method: "PATCH",
      headers: auth(t),
      body: JSON.stringify({ brand_color: "#ffffff" }),
    });
    const poll = await createPoll(t, {
      question: "あき どっち？",
      options: [{ label: "あ" }, { label: "き" }],
    });
    await publish(t, poll.id);
    const page = await SELF.fetch(`${BASE}/polls/${poll.id}/results-page`);
    expect(page.status).toBe(200);
    const html = await page.text();
    const accent = html.match(/--accent:light-dark\((#[0-9a-f]{6}),#ffffff\)/);
    expect(accent).not.toBeNull();
    expect(accent?.[1]).not.toBe("#ffffff");
    expect(contrastRatio(accent?.[1] ?? "#ffffff", "#ffffff")).toBeGreaterThanOrEqual(3);
  });
});
