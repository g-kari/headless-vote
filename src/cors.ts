/**
 * Per-workspace browser embed allowlist.
 * Origins are stored in D1 and edited from the admin settings screen.
 * Public poll and image responses echo Access-Control-Allow-Origin only
 * when the request Origin is an exact match for that workspace's list.
 */

import { badRequest } from "./errors";
import { getPollRow } from "./domain";
import type { AppContext, Env } from "./types";

export const MAX_ORIGINS = 20;
const MAX_ORIGIN_LENGTH = 200;

const POLL_PATH =
  /^\/api\/v1\/polls\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\/(?:results|vote|ballot|qr\.svg|og\.svg))?$/;
const IMAGE_PATH =
  /^\/images\/t\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.(png|jpg|webp|gif)$/;

export function isPublicEmbedPath(pathname: string): boolean {
  return POLL_PATH.test(pathname) || IMAGE_PATH.test(pathname);
}

/** Cross-site browser calls that the embed allowlist is allowed to make. */
export function allowsCrossSiteEmbed(pathname: string, method: string): boolean {
  const m = method.toUpperCase();
  if (IMAGE_PATH.test(pathname)) return m === "GET" || m === "HEAD" || m === "OPTIONS";
  if (!POLL_PATH.test(pathname)) return false;
  if (pathname.endsWith("/vote")) return m === "POST" || m === "OPTIONS";
  return m === "GET" || m === "HEAD" || m === "OPTIONS";
}

function isLocalHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
}

function isIpv4(hostname: string): boolean {
  const parts = hostname.split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    const n = Number(part);
    return n >= 0 && n <= 255 && String(n) === String(Number(part));
  });
}

function isDnsName(hostname: string): boolean {
  if (hostname.length > 253 || hostname.includes("..")) return false;
  if (hostname.startsWith(".") || hostname.endsWith(".")) return false;
  const labels = hostname.split(".");
  if (labels.length < 2) return false;
  return labels.every((label) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}

/**
 * Normalize a user-entered origin to the canonical `scheme://host[:port]`
 * form, or throw 400. https only, except localhost / 127.0.0.1 / ::1.
 * No wildcards, credentials, paths, queries, or hashes.
 */
export function parseAllowedOrigin(input: string): string {
  const trimmed = input.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_ORIGIN_LENGTH) {
    throw badRequest('"origin" must be an https origin');
  }
  if (/[\u0000-\u0020]/.test(trimmed) || trimmed.includes("*") || trimmed.includes("\\")) {
    throw badRequest('"origin" must not contain whitespace or wildcards');
  }
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw badRequest('"origin" must be an https origin');
  }
  if (url.username || url.password) {
    throw badRequest('"origin" must not include credentials');
  }
  if (url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) {
    throw badRequest('"origin" must not include a path, query, or hash');
  }
  if (url.origin === "null") throw badRequest('"origin" must be an https origin');
  const local = isLocalHost(url.hostname);
  if (url.protocol === "http:") {
    if (!local) throw badRequest("http origins are only allowed for localhost");
  } else if (url.protocol !== "https:") {
    throw badRequest('"origin" must use https');
  }
  if (!local && !isIpv4(url.hostname) && !isDnsName(url.hostname)) {
    throw badRequest('"origin" hostname is not allowed');
  }
  return url.origin;
}

export async function listTenantOrigins(env: Env, tenantId: string): Promise<string[]> {
  const res = await env.DB.prepare(
    "SELECT origin FROM tenant_origins WHERE tenant_id = ?1 ORDER BY created_at ASC, origin ASC",
  )
    .bind(tenantId)
    .all<{ origin: string }>();
  return res.results.map((row) => row.origin);
}

export async function addTenantOrigin(
  env: Env,
  tenantId: string,
  raw: string,
): Promise<{ origin: string; created: boolean }> {
  const origin = parseAllowedOrigin(raw);
  const existing = await env.DB.prepare(
    "SELECT 1 AS ok FROM tenant_origins WHERE tenant_id = ?1 AND origin = ?2",
  )
    .bind(tenantId, origin)
    .first<{ ok: number }>();
  if (existing) return { origin, created: false };
  const count = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM tenant_origins WHERE tenant_id = ?1",
  )
    .bind(tenantId)
    .first<{ n: number }>();
  if (Number(count?.n ?? 0) >= MAX_ORIGINS) {
    throw badRequest(`A workspace can have at most ${MAX_ORIGINS} allowed origins`);
  }
  const inserted = await env.DB.prepare(
    `INSERT INTO tenant_origins (tenant_id, origin, created_at) VALUES (?1, ?2, ?3)
     ON CONFLICT(tenant_id, origin) DO NOTHING`,
  )
    .bind(tenantId, origin, new Date().toISOString())
    .run();
  return { origin, created: Number(inserted.meta.changes ?? 0) > 0 };
}

export async function removeTenantOrigin(
  env: Env,
  tenantId: string,
  raw: string,
): Promise<boolean> {
  const origin = parseAllowedOrigin(raw);
  const res = await env.DB.prepare(
    "DELETE FROM tenant_origins WHERE tenant_id = ?1 AND origin = ?2",
  )
    .bind(tenantId, origin)
    .run();
  return Number(res.meta.changes ?? 0) > 0;
}

/** Exact string match against the stored canonical origin. */
export async function isAllowedTenantOrigin(
  env: Env,
  tenantId: string,
  originHeader: string,
): Promise<boolean> {
  if (!originHeader || originHeader === "null") return false;
  const row = await env.DB.prepare(
    "SELECT 1 AS ok FROM tenant_origins WHERE tenant_id = ?1 AND origin = ?2",
  )
    .bind(tenantId, originHeader)
    .first<{ ok: number }>();
  return row !== null;
}

async function tenantIdForEmbed(c: AppContext, pathname: string): Promise<string | null> {
  const image = IMAGE_PATH.exec(pathname);
  if (image?.[1]) return image[1];
  const pollMatch = POLL_PATH.exec(pathname);
  const pollId = pollMatch?.[1];
  if (!pollId) return null;
  const poll = await getPollRow(c.env, pollId);
  if (!poll || poll.status === "draft") return null;
  return poll.tenant_id;
}

/**
 * Reflect CORS headers for an allowlisted Origin. Never uses `*`.
 * Non-matching and missing Origin values get no CORS headers.
 * Admin routes are not embed paths, so they never receive these headers.
 */
export async function applyPublicCors(c: AppContext): Promise<void> {
  const pathname = new URL(c.req.url).pathname;
  if (!isPublicEmbedPath(pathname)) return;
  const origin = c.req.header("origin");
  if (!origin) return;
  const tenantId = await tenantIdForEmbed(c, pathname);
  if (!tenantId) return;
  if (!(await isAllowedTenantOrigin(c.env, tenantId, origin))) return;
  c.header("Access-Control-Allow-Origin", origin);
  c.header("Access-Control-Allow-Credentials", "true");
  c.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  c.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  c.header("Access-Control-Max-Age", "60");
  // Credentialed responses must not sit in a shared cache.
  c.header("Cache-Control", "private, no-store");
}
