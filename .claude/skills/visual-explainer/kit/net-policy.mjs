// The kit's network policy (KAZAMI-306 #8): a page the kit renders or checks
// makes no network requests. The only http(s) requests a browser may complete
// while a page is being looked at are the ones vendor/fetch-vendor.mjs pinned
// ahead of time — the Google Fonts stylesheets and font files the renderers
// emit, and the pinned three.js build the motion reference documents — and
// those are answered from the vendored copies on disk, never from the
// network. Every other http(s) request is aborted and reported, so a page
// that reaches for an unpinned asset fails its check instead of silently
// phoning out. file:, data:, blob: and about: URLs are the page itself and
// always pass.
//
// The manifest records a sha256 for every pinned file; a file whose bytes no
// longer match its pin is refused (treated as unpinned), so a tampered or
// half-refreshed vendor tree cannot serve different bytes than were pinned.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const VENDOR = join(dirname(fileURLToPath(import.meta.url)), "vendor");

let cache = null;

/** The pinned assets, as { url: { file, sha256, contentType } }. Throws when the vendor tree was never fetched. */
export function vendorManifest() {
  if (cache) return cache;
  let raw;
  try {
    raw = readFileSync(join(VENDOR, "manifest.json"), "utf8");
  } catch {
    throw new Error("kit/vendor/manifest.json is missing; run node kit/vendor/fetch-vendor.mjs once to pin the kit's external assets");
  }
  cache = JSON.parse(raw);
  return cache;
}

const sha256 = (body) => createHash("sha256").update(body).digest("hex");

/** Recomputes every pin. Returns { checked, errors } — errors names each missing or mismatched file. */
export function verifyVendor() {
  const manifest = vendorManifest();
  const errors = [];
  let checked = 0;
  for (const [url, pin] of Object.entries(manifest)) {
    let body;
    try {
      body = readFileSync(join(VENDOR, pin.file));
    } catch {
      errors.push(`${pin.file} (for ${url}) is missing`);
      continue;
    }
    checked++;
    if (sha256(body) !== pin.sha256) errors.push(`${pin.file} (for ${url}) does not match its pinned sha256`);
  }
  return { checked, errors };
}

// Bodies are read once and kept: a check opens the same fonts at two widths.
const bodies = new Map();
function pinnedBody(url) {
  if (bodies.has(url)) return bodies.get(url);
  const pin = vendorManifest()[url];
  let out = null;
  if (pin) {
    const body = readFileSync(join(VENDOR, pin.file));
    if (sha256(body) === pin.sha256) out = { status: 200, contentType: pin.contentType, body };
  }
  bodies.set(url, out);
  return out;
}

/**
 * Applies the policy to a Playwright page or browser context. Returns a live
 * record: `served` lists each pinned URL answered locally (once per URL) and
 * `blocked` lists each other http(s) URL that was aborted (once per URL).
 * A blocked request also fails the page's load of that asset, exactly as an
 * offline reader would see it.
 */
export async function installNetPolicy(page) {
  const record = { served: [], blocked: [] };
  const seenServed = new Set(), seenBlocked = new Set();
  await page.route("**/*", async (route) => {
    const url = route.request().url();
    if (!/^https?:/i.test(url)) return route.continue();
    const pinned = pinnedBody(url);
    if (pinned) {
      if (!seenServed.has(url)) { seenServed.add(url); record.served.push(url); }
      return route.fulfill(pinned);
    }
    if (!seenBlocked.has(url)) { seenBlocked.add(url); record.blocked.push(url); }
    return route.abort("blockedbyclient");
  });
  return record;
}
