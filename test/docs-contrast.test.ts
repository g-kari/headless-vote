import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { applySchema } from "./fixtures";

const BASE = "https://vote.test";

beforeAll(async () => {
  await applySchema(env.DB);
});

// jsdom/miniflare cannot judge how a page looks, so these assertions check
// the delivered color VALUES themselves: the /docs page once shipped with
// `color-scheme: light dark` and no explicit body background, which made
// dark-mode browsers paint a near-black canvas under Redoc's dark text.
// The guards below keep the declared foreground/background pairs at
// WCAG AA contrast (>= 4.5:1 for normal text).

function luminance(hex: string): number {
  let h = hex.trim().replace(/^#/, "");
  if (/^[0-9a-f]{3}$/i.test(h)) h = h.replace(/./g, (ch) => ch + ch);
  if (!/^[0-9a-f]{6}$/i.test(h)) throw new Error(`not a hex color: ${hex}`);
  const n = parseInt(h, 16);
  const channel = (v: number) => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  };
  return (
    0.2126 * channel((n >> 16) & 0xff) +
    0.7152 * channel((n >> 8) & 0xff) +
    0.0722 * channel(n & 0xff)
  );
}

function contrastRatio(a: string, b: string): number {
  const la = luminance(a);
  const lb = luminance(b);
  const [hi, lo] = la >= lb ? [la, lb] : [lb, la];
  return (hi + 0.05) / (lo + 0.05);
}

// Extract one declaration value from the rule for an exact selector in the
// served <style> block (e.g. decl(css, "body", "background")).
function decl(css: string, selector: string, property: string): string | null {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const rule = new RegExp(`(?:^|[}])\\s*${escaped}\\s*\\{([^}]*)\\}`).exec(css);
  if (!rule || rule[1] === undefined) return null;
  const d = new RegExp(`(?:^|;)\\s*${property}\\s*:\\s*([^;]+)`).exec(rule[1]);
  return d && d[1] !== undefined ? d[1].trim() : null;
}

function hexOf(value: string | null): string {
  const m = value ? /#[0-9a-f]{6}\b|#[0-9a-f]{3}\b/i.exec(value) : null;
  if (!m) throw new Error(`no hex color in: ${value}`);
  return m[0];
}

function normalizeHex(hex: string): string {
  let h = hex.trim().replace(/^#/, "").toLowerCase();
  if (/^[0-9a-f]{3}$/.test(h)) h = h.replace(/./g, (ch) => ch + ch);
  return `#${h}`;
}

describe("docs page contrast", () => {
  it("pins /docs to the light scheme with explicit, AA-contrast body colors", async () => {
    const res = await SELF.fetch(`${BASE}/docs`);
    expect(res.status).toBe(200);
    const html = await res.text();

    // The page is light-only: it must not opt into the dark scheme, or a
    // dark-mode browser will paint the canvas dark under dark text again.
    expect(html).toContain('<meta name="color-scheme" content="light">');
    expect(html).not.toContain('name="color-scheme" content="light dark"');

    const style = /<style[^>]*>([\s\S]*?)<\/style>/.exec(html)?.[1] ?? "";
    expect(style).not.toBe("");

    // Body declares both background and text color, and the pair is AA.
    const bodyBg = hexOf(decl(style, "body", "background"));
    const bodyColor = hexOf(decl(style, "body", "color"));
    expect(contrastRatio(bodyColor, bodyBg)).toBeGreaterThanOrEqual(4.5);

    // Panel note text also meets AA against the body background.
    const noteColor = hexOf(decl(style, ".try-note", "color"));
    expect(contrastRatio(noteColor, bodyBg)).toBeGreaterThanOrEqual(4.5);

    // Error status text meets AA against the body background.
    const errColor = hexOf(decl(style, ".try-status.err", "color"));
    expect(contrastRatio(errColor, bodyBg)).toBeGreaterThanOrEqual(4.5);

    // The Redoc container itself sits on the same light background.
    const redocBg = hexOf(decl(style, "#redoc", "background"));
    expect(normalizeHex(redocBg)).toBe(normalizeHex(bodyBg));

    // The Redoc theme pairs configured in the init call (sidebar text on
    // sidebar background) also meet AA — no dark-on-dark combination.
    const sidebarBg = /sidebar:\s*\{\s*backgroundColor:\s*"(#[0-9a-f]{6})"/i.exec(html)?.[1];
    const sidebarText = /sidebar:\s*\{[^}]*textColor:\s*"(#[0-9a-f]{6})"/i.exec(html)?.[1];
    expect(sidebarBg).toBeTruthy();
    expect(sidebarText).toBeTruthy();
    expect(contrastRatio(sidebarText!, sidebarBg!)).toBeGreaterThanOrEqual(4.5);

    // Panel placeholders carry an explicit color (the UA default is too
    // pale) and it meets AA against the body background.
    const phColor = hexOf(decl(style, ".try input::placeholder,.try textarea::placeholder", "color"));
    expect(contrastRatio(phColor, bodyBg)).toBeGreaterThanOrEqual(4.5);
  });
});

describe("shared layout auxiliary text contrast", () => {
  it("keeps --muted and placeholder colors at AA against the page background", async () => {
    const res = await SELF.fetch(`${BASE}/`);
    expect(res.status).toBe(200);
    const html = await res.text();
    const style = /<style[^>]*>([\s\S]*?)<\/style>/.exec(html)?.[1] ?? "";
    expect(style).not.toBe("");

    // Light-side values of the light-dark() pairs drive the light theme.
    const lightOf = (name: string): string => {
      const m = new RegExp(`${name}:light-dark\\((#[0-9a-f]{3,6})`, "i").exec(style);
      if (!m || !m[1]) throw new Error(`${name} light-dark() value not found`);
      return m[1];
    };
    const bg = lightOf("--bg");
    const muted = lightOf("--muted");
    // Auxiliary text (lead paragraphs, hints, .muted) is readable: AA.
    expect(contrastRatio(muted, bg)).toBeGreaterThanOrEqual(4.5);

    // Placeholders have an explicit rule resolving to an AA color.
    const ph = decl(style, "::placeholder", "color");
    expect(ph).toBeTruthy();
    const phHex = ph!.includes("var(--muted)") ? muted : hexOf(ph);
    expect(contrastRatio(phHex, bg)).toBeGreaterThanOrEqual(4.5);
  });
});
