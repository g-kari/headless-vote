import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

const BASE = "https://vote.example.com";

describe("brand assets", () => {
  it("serves the favicon set and OGP image with the right content types", async () => {
    const svg = await SELF.fetch(`${BASE}/favicon.svg`);
    expect(svg.status).toBe(200);
    expect(svg.headers.get("content-type")).toContain("image/svg+xml");

    const png32 = await SELF.fetch(`${BASE}/favicon-32x32.png`);
    expect(png32.status).toBe(200);
    expect(png32.headers.get("content-type")).toContain("image/png");

    const apple = await SELF.fetch(`${BASE}/apple-touch-icon.png`);
    expect(apple.status).toBe(200);
    expect(apple.headers.get("content-type")).toContain("image/png");

    const ogp = await SELF.fetch(`${BASE}/ogp.png`);
    expect(ogp.status).toBe(200);
    expect(ogp.headers.get("content-type")).toContain("image/png");
  });

  it("landing page head references the favicon and OGP image", async () => {
    const res = await SELF.fetch(`${BASE}/`);
    const html = await res.text();
    expect(html).toContain('href="/favicon.svg"');
    expect(html).toContain('href="/apple-touch-icon.png"');
    expect(html).toContain("/ogp.png");
    expect(html).toContain('name="color-scheme"');
  });
});
