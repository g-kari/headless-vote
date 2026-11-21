// Fetch and pin the kit's external assets (KAZAMI-306 #8).
//
// This is the ONLY kit script that uses the network, and it is run by hand, never
// during a render or a check. It downloads the exact assets the kit's pages point
// at — the Google Fonts stylesheets the renderers emit (and the font files those
// stylesheets reference), and the pinned three.js build the motion reference
// documents — verifies nothing but records a sha256 for every file in
// manifest.json. At check/render time kit/net-policy.mjs serves these files
// locally and blocks every other network request.
//
// Run: node kit/vendor/fetch-vendor.mjs   (re-run to refresh; the manifest is rewritten)
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

// The stylesheets kit/render.mjs (FONTS registers), plan/render.mjs and the two
// templates emit, verbatim — the browser requests these exact URLs.
const FONT_CSS = [
  "https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&family=Geist+Mono:wght@400;500;600&display=swap",
  "https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500;600&display=swap",
  "https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap",
  "https://fonts.googleapis.com/css2?family=Newsreader:opsz,wght@6..72,400..600&family=Atkinson+Hyperlegible+Next:wght@400;600&family=Atkinson+Hyperlegible+Mono:wght@400;500;600&display=swap",
  "https://fonts.googleapis.com/css2?family=Instrument+Serif&family=Instrument+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;500;600&display=swap",
  "https://fonts.googleapis.com/css2?family=Instrument+Sans:wght@400;500;600&family=Instrument+Serif&family=JetBrains+Mono:wght@500;600&display=swap",
];

// The importmap in references/motion.md pins three@0.186. The core build plus the
// one addon the kit's references name, with its in-package imports followed.
const THREE_BASE = "https://cdn.jsdelivr.net/npm/three@0.186";
const THREE_SEEDS = [`${THREE_BASE}/build/three.module.js`, `${THREE_BASE}/examples/jsm/interaction/InteractionManager.js`];

const TYPES = { css: "text/css; charset=utf-8", js: "text/javascript; charset=utf-8", woff2: "font/woff2", woff: "font/woff" };
const manifest = {};
let total = 0;

const localFile = (url) => {
  const u = new URL(url);
  let p = join(HERE, u.hostname, u.pathname.replace(/^\/+/, ""));
  if (u.search) p += `@${createHash("sha256").update(u.search).digest("hex").slice(0, 10)}`;
  if (!/\.[a-z0-9]+$/i.test(p)) p += url.includes("css2") ? ".css" : ".bin";
  return p;
};

async function grab(url, kind) {
  if (manifest[url]) return;
  const res = await fetch(url, { headers: { "user-agent": UA } });
  if (!res.ok) throw new Error(`fetch ${url}: HTTP ${res.status}`);
  const body = Buffer.from(await res.arrayBuffer());
  const file = localFile(url);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, body);
  manifest[url] = {
    file: file.slice(HERE.length + 1).split("\\").join("/"),
    sha256: createHash("sha256").update(body).digest("hex"),
    contentType: TYPES[kind],
  };
  total += body.length;
  if (kind === "css") {
    // the stylesheet stays as served (its font URLs are absolute); pin every file it names
    for (const m of body.toString("utf8").matchAll(/url\((https:[^)]+)\)/g)) await grab(m[1], "woff2");
  }
  if (kind === "js") {
    for (const m of body.toString("utf8").matchAll(/(?:from\s+|import\s+)["']([^"']+)["']/g)) {
      const spec = m[1];
      const next = spec === "three" ? `${THREE_BASE}/build/three.module.js`
        : spec.startsWith("three/addons/") ? `${THREE_BASE}/examples/jsm/${spec.slice("three/addons/".length)}`
        : spec.startsWith(".") ? new URL(spec, url).href
        : null;
      if (next?.startsWith(THREE_BASE)) await grab(next, "js");
    }
  }
}

for (const url of FONT_CSS) await grab(url, "css");
for (const url of THREE_SEEDS) await grab(url, "js");

const sorted = Object.fromEntries(Object.entries(manifest).sort(([a], [b]) => (a < b ? -1 : 1)));
writeFileSync(join(HERE, "manifest.json"), `${JSON.stringify(sorted, null, 2)}\n`);
console.log(`pinned ${Object.keys(sorted).length} assets, ${(total / 1024).toFixed(0)} KiB, manifest.json written`);
