import { tooManyRequests } from "../errors";
import type { Env } from "../types";
import type { RateLimitStore } from "./ports";

export function createD1RateLimitStore(env: Env): RateLimitStore {
  return {
    id: "d1",
    async hit(bucket, limit, windowSec) {
      const now = Math.floor(Date.now() / 1000);
      const resetAt = now + windowSec;
      await env.DB.prepare("DELETE FROM rate_limits WHERE reset_at < ?1").bind(now - 86_400).run();
      await env.DB.prepare(
        `INSERT INTO rate_limits (bucket, hits, reset_at) VALUES (?1, 1, ?2)
         ON CONFLICT(bucket) DO UPDATE SET
           hits = CASE WHEN rate_limits.reset_at <= ?3 THEN 1 ELSE rate_limits.hits + 1 END,
           reset_at = CASE WHEN rate_limits.reset_at <= ?3 THEN ?2 ELSE rate_limits.reset_at END`,
      )
        .bind(bucket, resetAt, now)
        .run();
      const row = await env.DB.prepare("SELECT hits, reset_at FROM rate_limits WHERE bucket = ?1")
        .bind(bucket)
        .first<{ hits: number; reset_at: number }>();
      const hits = Number(row?.hits ?? 0);
      if (hits > limit) {
        throw tooManyRequests(Math.max(1, Number(row?.reset_at ?? resetAt) - now));
      }
    },
  };
}

/** Process-local limiter. Suitable for tests and a single process, not for multiple isolates. */
export class MemoryRateLimitStore implements RateLimitStore {
  readonly id = "memory";
  private readonly buckets = new Map<string, { hits: number; resetAt: number }>();

  async hit(bucket: string, limit: number, windowSec: number): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    const current = this.buckets.get(bucket);
    if (!current || current.resetAt <= now) {
      this.buckets.set(bucket, { hits: 1, resetAt: now + windowSec });
      return;
    }
    current.hits += 1;
    if (current.hits > limit) throw tooManyRequests(Math.max(1, current.resetAt - now));
  }
}

let sharedMemoryLimits: MemoryRateLimitStore | null = null;

export function createRateLimitStore(env: Env): RateLimitStore {
  const name = (env.RATE_LIMIT_STORE || "d1").toLowerCase();
  if (name === "d1") return createD1RateLimitStore(env);
  if (name === "memory") {
    sharedMemoryLimits ??= new MemoryRateLimitStore();
    return sharedMemoryLimits;
  }
  throw new Error(`Unknown RATE_LIMIT_STORE "${name}"`);
}
