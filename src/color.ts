/**
 * Contrast helpers for the places that paint a tenant-chosen brand color:
 * the share image (og.svg) and the page accent variables. A brand color is
 * free-form (#RRGGBB), so a very light color could otherwise end up painting
 * white text / white bars on a white background and make content invisible.
 */

export function parseHexColor(hex: string): { r: number; g: number; b: number } | null {
  const m = /^#([0-9a-fA-F]{6})$/.exec(hex);
  if (!m) return null;
  const n = parseInt(m[1]!, 16);
  return { r: (n >> 16) & 0xff, g: (n >> 8) & 0xff, b: n & 0xff };
}

function toHex(r: number, g: number, b: number): string {
  const p = (v: number) =>
    Math.max(0, Math.min(255, Math.round(v)))
      .toString(16)
      .padStart(2, "0");
  return `#${p(r)}${p(g)}${p(b)}`;
}

function channelLuminance(v: number): number {
  const s = v / 255;
  return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
}

/** WCAG relative luminance of a #RRGGBB color. */
export function relativeLuminance(hex: string): number {
  const c = parseHexColor(hex);
  if (!c) return 0;
  return (
    0.2126 * channelLuminance(c.r) +
    0.7152 * channelLuminance(c.g) +
    0.0722 * channelLuminance(c.b)
  );
}

/** WCAG contrast ratio between two #RRGGBB colors (1..21). */
export function contrastRatio(a: string, b: string): number {
  const la = relativeLuminance(a);
  const lb = relativeLuminance(b);
  const hi = Math.max(la, lb);
  const lo = Math.min(la, lb);
  return (hi + 0.05) / (lo + 0.05);
}

/** Blend a hex color toward black by t (0..1). */
export function darken(hex: string, t: number): string {
  const c = parseHexColor(hex);
  if (!c) return hex;
  const k = Math.max(0, Math.min(1, t));
  return toHex(c.r * (1 - k), c.g * (1 - k), c.b * (1 - k));
}

/**
 * Return the color darkened just enough to stay visible on a white
 * background (chart bars, light-scheme accents). Colors that already
 * contrast with white are returned unchanged.
 */
export function readableOnWhite(hex: string, minRatio = 3): string {
  if (!parseHexColor(hex)) return hex;
  if (contrastRatio(hex, "#ffffff") >= minRatio) return hex.toLowerCase();
  for (const t of [0.2, 0.35, 0.5, 0.65, 0.8]) {
    const candidate = darken(hex, t);
    if (contrastRatio(candidate, "#ffffff") >= minRatio) return candidate;
  }
  return darken(hex, 0.85);
}

/** Pick whichever of the two candidate text colors reads better on `bg`. */
export function bestTextOn(bg: string, light = "#ffffff", dark = "#222222"): string {
  return contrastRatio(light, bg) >= contrastRatio(dark, bg) ? light : dark;
}
