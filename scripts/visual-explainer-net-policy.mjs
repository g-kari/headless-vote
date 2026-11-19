// KAZAMI-306 #8 regression: the visual-explainer kit's external assets are
// pinned by sha256, the net policy serves only those and blocks everything
// else, and the /docs page itself references no external asset.
// No browser or network is used: the policy's route handler is driven with a
// fake route, the way scripts/visual-explainer-*-security.mjs drive theirs.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const kit = new URL("../.claude/skills/visual-explainer/kit/", import.meta.url);
const { vendorManifest, verifyVendor, installNetPolicy } = await import(new URL("net-policy.mjs", kit));

// 1. Every pinned file is present and matches its sha256.
const manifest = vendorManifest();
const { checked, errors } = verifyVendor();
assert.deepEqual(errors, [], `vendor tree must match its pins:\n${errors.join("\n")}`);
assert.ok(checked >= 61, `expected at least 61 pinned assets, checked ${checked}`);

// 2. The assets the kit actually emits are pinned: the six Google Fonts
// stylesheets (kit/render.mjs registers, plan/render.mjs, the two templates)
// and the three@0.186 build plus the addon the motion reference names.
const FONT_CSS = [
  "https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&family=Geist+Mono:wght@400;500;600&display=swap",
  "https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500;600&display=swap",
  "https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap",
  "https://fonts.googleapis.com/css2?family=Newsreader:opsz,wght@6..72,400..600&family=Atkinson+Hyperlegible+Next:wght@400;600&family=Atkinson+Hyperlegible+Mono:wght@400;500;600&display=swap",
  "https://fonts.googleapis.com/css2?family=Instrument+Serif&family=Instrument+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;500;600&display=swap",
  "https://fonts.googleapis.com/css2?family=Instrument+Sans:wght@400;500;600&family=Instrument+Serif&family=JetBrains+Mono:wght@500;600&display=swap",
];
for (const url of FONT_CSS) assert.ok(manifest[url], `font stylesheet is not pinned: ${url}`);
for (const url of [
  "https://cdn.jsdelivr.net/npm/three@0.186/build/three.module.js",
  "https://cdn.jsdelivr.net/npm/three@0.186/examples/jsm/interaction/InteractionManager.js",
]) assert.ok(manifest[url], `three.js asset is not pinned: ${url}`);
// Every stylesheet's font files are pinned too (no dangling external url()).
for (const url of FONT_CSS) {
  const css = readFileSync(new URL(`vendor/${manifest[url].file}`, kit), "utf8");
  for (const m of css.matchAll(/url\((https:[^)]+)\)/g)) assert.ok(manifest[m[1]], `font file is not pinned: ${m[1]}`);
}

// 3. The route handler: pinned → fulfilled locally, other http(s) → aborted,
// the page's own schemes → continued.
let handler;
const fakePage = { route: async (_pattern, h) => { handler = h; } };
const record = await installNetPolicy(fakePage);
const drive = async (url) => {
  const calls = [];
  await handler({
    request: () => ({ url: () => url }),
    fulfill: (res) => calls.push(["fulfill", res.status, res.contentType]),
    abort: (code) => calls.push(["abort", code]),
    continue: () => calls.push(["continue"]),
  });
  return calls;
};
const [fontCall] = await drive(FONT_CSS[0]);
assert.equal(fontCall[0], "fulfill", "a pinned font stylesheet must be served locally");
assert.equal(fontCall[2], "text/css; charset=utf-8");
const [threeCall] = await drive("https://cdn.jsdelivr.net/npm/three@0.186/build/three.module.js");
assert.equal(threeCall[0], "fulfill", "pinned three.js must be served locally");
assert.deepEqual(await drive("https://example.com/evil.js"), [["abort", "blockedbyclient"]], "an unpinned external request must be blocked");
assert.deepEqual(await drive("file:///tmp/page.html"), [["continue"]], "the page itself must pass");
assert.equal(record.served.length, 2);
assert.deepEqual(record.blocked, ["https://example.com/evil.js"]);

// 4. The /docs page (the Worker's one static explainer surface) references
// no external asset: its handler in src/routes/ui.ts loads only same-origin
// files, and its CSP variant in src/security.ts keeps connect-src 'self'.
const ui = readFileSync(new URL("../src/routes/ui.ts", import.meta.url), "utf8");
const docs = ui.slice(ui.indexOf('ui.get("/docs"'));
assert.ok(docs.length > 0, "/docs handler not found");
assert.ok(!/https?:\/\//.test(docs.split("ui.get(")[0]), "/docs must not reference an external URL");
const security = readFileSync(new URL("../src/security.ts", import.meta.url), "utf8");
assert.ok(security.includes('"connect-src \'self\'"'), "/docs CSP must keep connect-src 'self'");

console.log(`PASS net policy: ${checked} pinned assets verified, pinned requests served locally, unpinned external requests blocked, /docs references no external asset`);
