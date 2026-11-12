/** Request hardening: headers, fetch metadata, rate limits, bounded bodies. */

import { hmacSha256Base64Url, timingSafeEqual } from "./crypto";
import { badRequest, forbidden, payloadTooLarge, tooManyRequests } from "./errors";
import type { AppContext, Env } from "./types";

export const ASSET_PATHS = new Set([
  "/favicon.svg",
  "/favicon-16x16.png",
  "/favicon-32x32.png",
  "/favicon.ico",
  "/apple-touch-icon.png",
  "/logo.svg",
  "/ogp.png",
]);

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function normalizeUuid(value: string): string | null {
  const v = value.trim().toLowerCase();
  return UUID_RE.test(v) ? v : null;
}

export function isSafeImageKey(key: string, tenantId: string): boolean {
  const match =
    /^t\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.(png|jpg|webp|gif)$/.exec(
      key,
    );
  if (!match) return false;
  const tenant = match[1];
  const file = match[2];
  if (!tenant || !file) return false;
  return tenant === tenantId && normalizeUuid(file) === file;
}

export function imageContentType(ext: string): string | null {
  switch (ext) {
    case "png":
      return "image/png";
    case "jpg":
      return "image/jpeg";
    case "webp":
      return "image/webp";
    case "gif":
      return "image/gif";
    default:
      return null;
  }
}

const BIDI =
  /[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C\uFEFF]/;

/** Reject ASCII controls and bidi overrides. Newlines are opt-in. */
export function assertPlainText(
  value: string,
  opts: { newlines?: boolean } = {},
): void {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    const newline = code === 0x0a || code === 0x0d || code === 0x09;
    if ((code < 0x20 || code === 0x7f) && !(opts.newlines && newline)) {
      throw badRequest("Text contains unsupported control characters");
    }
  }
  if (BIDI.test(value)) {
    throw badRequest("Text contains unsupported directional characters");
  }
}

export async function readBodyLimited(
  source: { body: ReadableStream<Uint8Array> | null; headers: Headers },
  max: number,
): Promise<Uint8Array> {
  const declared = source.headers.get("content-length");
  if (declared !== null) {
    if (!/^\d+$/.test(declared)) throw payloadTooLarge("Request body is too large");
    const n = Number(declared);
    if (!Number.isFinite(n) || n > max) {
      throw payloadTooLarge("Request body is too large");
    }
  }
  const reader = source.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      throw payloadTooLarge("Request body is too large");
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

export async function readUrlEncodedForm(c: AppContext): Promise<URLSearchParams> {
  const media = (c.req.header("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
  if (media !== "application/x-www-form-urlencoded") {
    throw badRequest("Expected a form submission");
  }
  const bytes = await readBodyLimited(c.req.raw, 16 * 1024);
  return new URLSearchParams(new TextDecoder().decode(bytes));
}

const IMAGE_TYPES: Record<string, string> = {
  "image/png": "png",
  "image/jpeg": "jpg",
  "image/webp": "webp",
  "image/gif": "gif",
};

function startsWith(bytes: Uint8Array, sig: number[]): boolean {
  if (bytes.length < sig.length) return false;
  for (let i = 0; i < sig.length; i++) {
    if (bytes[i] !== sig[i]) return false;
  }
  return true;
}

/** Detect a real image and require the declared Content-Type to match. */
export function sniffImage(
  bytes: Uint8Array,
  declaredType: string,
): { ext: string; contentType: string } | null {
  const declared = IMAGE_TYPES[declaredType];
  if (!declared) return null;
  let detected: { ext: string; contentType: string } | null = null;
  if (startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) {
    detected = { ext: "png", contentType: "image/png" };
  } else if (startsWith(bytes, [0xff, 0xd8, 0xff])) {
    detected = { ext: "jpg", contentType: "image/jpeg" };
  } else if (
    bytes.length >= 6 &&
    bytes[0] === 0x47 &&
    bytes[1] === 0x49 &&
    bytes[2] === 0x46 &&
    bytes[3] === 0x38 &&
    (bytes[4] === 0x37 || bytes[4] === 0x39) &&
    bytes[5] === 0x61
  ) {
    detected = { ext: "gif", contentType: "image/gif" };
  } else if (
    bytes.length >= 12 &&
    bytes[0] === 0x52 &&
    bytes[1] === 0x49 &&
    bytes[2] === 0x46 &&
    bytes[3] === 0x46 &&
    bytes[8] === 0x57 &&
    bytes[9] === 0x45 &&
    bytes[10] === 0x42 &&
    bytes[11] === 0x50
  ) {
    detected = { ext: "webp", contentType: "image/webp" };
  }
  if (!detected || detected.ext !== declared) return null;
  return detected;
}

/**
 * Block cross-site (and same-site) subresource requests.
 * `allow` opts specific public embed routes back in.
 * Top-level GET navigations stay open so links and the OAuth callback work.
 */
export function shouldBlockCrossSite(
  request: Request,
  allow: (pathname: string, method: string) => boolean,
): boolean {
  const site = request.headers.get("sec-fetch-site");
  if (!site || site === "same-origin" || site === "none") return false;
  if (site !== "cross-site" && site !== "same-site") return false;
  const url = new URL(request.url);
  const method = request.method.toUpperCase();
  if (allow(url.pathname, method)) return false;
  const mode = request.headers.get("sec-fetch-mode");
  const dest = request.headers.get("sec-fetch-dest");
  if (
    method === "GET" &&
    mode === "navigate" &&
    dest !== "object" &&
    dest !== "embed" &&
    dest !== "iframe"
  ) {
    return false;
  }
  return true;
}

/** Cookie-authenticated mutations must come from this host. */
export function assertSameOriginMutation(c: AppContext): void {
  const site = c.req.header("sec-fetch-site");
  if (site && site !== "same-origin" && site !== "none") {
    throw forbidden("Cross-site request blocked");
  }
  const origin = c.req.header("origin");
  if (!origin) return;
  if (origin === "null") throw forbidden("Cross-site request blocked");
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    throw forbidden("Cross-site request blocked");
  }
  const expected = new URL(c.req.url).origin;
  if (parsed.origin === "null" || parsed.origin !== expected) {
    throw forbidden("Cross-site request blocked");
  }
}

/**
 * Origin of this request when it is allowed to start OAuth.
 * Production sets APP_ORIGIN (https://vote.0g0.xyz). Localhost http is
 * allowed in addition so `wrangler dev` still works.
 */
export function requireRequestOrigin(env: Env, requestUrl: string): string {
  let origin: string;
  try {
    origin = new URL(requestUrl).origin;
  } catch {
    throw forbidden("This host is not allowed");
  }
  if (origin === "null") throw forbidden("This host is not allowed");
  const configured = env.APP_ORIGIN?.replace(/\/+$/, "");
  if (!configured) return origin;
  if (origin === configured) return origin;
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    throw forbidden("This host is not allowed");
  }
  const host = url.hostname;
  const local = host === "localhost" || host === "127.0.0.1" || host === "::1";
  if (url.protocol === "http:" && local) return origin;
  throw forbidden("This host is not allowed");
}

export function stringsEqual(a: string, b: string): boolean {
  return timingSafeEqual(a, b);
}

export async function rateLimit(
  env: Env,
  bucket: string,
  limit: number,
  windowSec: number,
): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  const resetAt = now + windowSec;
  await env.DB.prepare("DELETE FROM rate_limits WHERE reset_at < ?1")
    .bind(now - 86_400)
    .run();
  await env.DB.prepare(
    `INSERT INTO rate_limits (bucket, hits, reset_at) VALUES (?1, 1, ?2)
     ON CONFLICT(bucket) DO UPDATE SET
       hits = CASE WHEN rate_limits.reset_at <= ?3 THEN 1 ELSE rate_limits.hits + 1 END,
       reset_at = CASE WHEN rate_limits.reset_at <= ?3 THEN ?2 ELSE rate_limits.reset_at END`,
  )
    .bind(bucket, resetAt, now)
    .run();
  const row = await env.DB.prepare(
    "SELECT hits, reset_at FROM rate_limits WHERE bucket = ?1",
  )
    .bind(bucket)
    .first<{ hits: number; reset_at: number }>();
  const hits = Number(row?.hits ?? 0);
  if (hits > limit) {
    const retry = Math.max(1, Number(row?.reset_at ?? resetAt) - now);
    throw tooManyRequests(retry);
  }
}

export async function rateLimitByIp(
  c: AppContext,
  action: string,
  limit: number,
  windowSec: number,
): Promise<void> {
  const ip = c.req.header("cf-connecting-ip") ?? "";
  const pepper = c.env.VOTER_KEY_SECRET || c.env.SESSION_SECRET || "rate-limit";
  const hashed = await hmacSha256Base64Url(pepper, `rate/${action}/${ip}`);
  await rateLimit(c.env, `${action}:${hashed}`, limit, windowSec);
}

export function newCspNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function applySecurityHeaders(c: AppContext, opts?: { html?: boolean }): void {
  const path = new URL(c.req.url).pathname;
  const nonce = c.get("cspNonce") ?? "";
  const html =
    opts?.html ??
    (c.res.headers.get("content-type") ?? "").includes("text/html");
  const embed = isEmbedPath(path);
  c.header("X-Content-Type-Options", "nosniff");
  c.header("Referrer-Policy", "strict-origin-when-cross-origin");
  c.header(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  );
  c.header("X-Frame-Options", "DENY");
  c.header("X-Permitted-Cross-Domain-Policies", "none");
  if (new URL(c.req.url).protocol === "https:") {
    c.header("Strict-Transport-Security", "max-age=31536000");
  }
  c.header("Content-Security-Policy", contentSecurityPolicy(nonce, html));
  c.header(
    "Cross-Origin-Resource-Policy",
    embed || ASSET_PATHS.has(path) ? "cross-origin" : "same-origin",
  );
  if (html) {
    c.header("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
  }
  c.header(
    "Vary",
    embed
      ? "Origin, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site"
      : "Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site",
  );
  if (!path.startsWith("/images/") && !ASSET_PATHS.has(path)) {
    c.header("Cache-Control", "no-store");
  }
}

function isEmbedPath(pathname: string): boolean {
  return (
    /^\/api\/v1\/polls\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:\/(?:results|vote))?$/.test(
      pathname,
    ) ||
    /^\/images\/t\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.(png|jpg|webp|gif)$/.test(
      pathname,
    )
  );
}

function contentSecurityPolicy(nonce: string, html: boolean): string {
  if (!html) {
    return "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
  }
  const script = nonce
    ? `script-src 'nonce-${nonce}' 'strict-dynamic'`
    : "script-src 'none'";
  const style = nonce ? `style-src 'nonce-${nonce}'` : "style-src 'none'";
  // style-src-attr stays permissive so server-rendered bar widths and
  // layout attributes keep working. Script execution does not.
  return [
    "default-src 'none'",
    script,
    style,
    "style-src-attr 'unsafe-inline'",
    "img-src 'self'",
    "connect-src 'self'",
    "form-action 'self'",
    "base-uri 'none'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "require-trusted-types-for 'script'",
  ]
    .filter((part) => part.length > 0)
    .join("; ");
}
