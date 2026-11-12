/**
 * D1-backed fixed-window rate limiting.
 *
 * Each (scope, identifier) pair gets a counter bucket per time window.
 * Identifiers (IP addresses, tenant ids, user subs) are SHA-256 hashed
 * before storage so the buckets table never holds raw identifiers.
 * Counters live in D1 (rate_limit_buckets), so limits hold across
 * Worker isolates.
 */
import { sha256Hex } from "./crypto";
import { tooManyRequests } from "./errors";
import type { AppContext, Env } from "./types";

/** Client IP as seen by Cloudflare (set on every production request). */
export function clientIp(c: AppContext): string {
  return c.req.header("cf-connecting-ip") ?? "unknown";
}

export interface RateLimitOutcome {
  allowed: boolean;
  retryAfterSeconds: number;
}

/** Consume one token from the (scope, identifier) bucket for this window. */
export async function consumeRateLimit(
  env: Env,
  scope: string,
  identifier: string,
  limit: number,
  windowSeconds: number,
): Promise<RateLimitOutcome> {
  const now = Math.floor(Date.now() / 1000);
  const windowStart = Math.floor(now / windowSeconds) * windowSeconds;
  const bucket = await sha256Hex(`rl:${scope}:${identifier}`);
  const row = await env.DB.prepare(
    `INSERT INTO rate_limit_buckets (bucket, window_start, count)
     VALUES (?1, ?2, 1)
     ON CONFLICT (bucket, window_start) DO UPDATE SET count = count + 1
     RETURNING count`,
  )
    .bind(bucket, windowStart)
    .first<{ count: number }>();
  const count = row?.count ?? 1;
  return {
    allowed: count <= limit,
    retryAfterSeconds: windowStart + windowSeconds - now,
  };
}

/** Throw a 429 ApiError when the bucket for this window is exhausted. */
export async function enforceRateLimit(
  env: Env,
  scope: string,
  identifier: string,
  limit: number,
  windowSeconds: number,
): Promise<void> {
  const outcome = await consumeRateLimit(env, scope, identifier, limit, windowSeconds);
  if (!outcome.allowed) {
    throw tooManyRequests(
      "Too many requests. Please wait and try again.",
      outcome.retryAfterSeconds,
    );
  }
}

export const HOUR = 3600;

/** Agreed limits (see PR description for the rationale). */
export const LIMITS = {
  tenantCreatePerIpPerHour: 30,
  workspaceCreatePerUserPerHour: 30,
  loginStartPerIpPerHour: 60,
  votePerPollIpPerHour: 600,
  imageUploadPerTenantPerHour: 120,
  rotateKeyPerTenantPerHour: 30,
} as const;
