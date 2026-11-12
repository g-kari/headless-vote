import { randomId } from "../crypto";
import type { Env } from "../types";
import type { AnalyticsStore, DayCount } from "./ports";

function windowStart(days: number): Date {
  const start = new Date();
  start.setUTCHours(0, 0, 0, 0);
  start.setUTCDate(start.getUTCDate() - (days - 1));
  return start;
}

export function bucketCounts(rows: { created_at: string }[], days: number): DayCount[] {
  const start = windowStart(days);
  const counts = new Map<string, number>();
  for (let i = 0; i < days; i++) {
    const day = new Date(start);
    day.setUTCDate(start.getUTCDate() + i);
    counts.set(day.toISOString().slice(0, 10), 0);
  }
  for (const row of rows) {
    const key = row.created_at.slice(0, 10);
    if (counts.has(key)) counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return [...counts.entries()].map(([date, count]) => ({ date, count }));
}

export function createD1AnalyticsStore(env: Env): AnalyticsStore {
  return {
    id: "d1",
    async record(pollId, at) {
      await env.DB.prepare("INSERT INTO vote_events (id, poll_id, created_at) VALUES (?1, ?2, ?3)")
        .bind(randomId(), pollId, at)
        .run();
    },
    async pollSeries(pollId, days) {
      const start = windowStart(days);
      const res = await env.DB.prepare(
        "SELECT created_at FROM vote_events WHERE poll_id = ?1 AND created_at >= ?2",
      )
        .bind(pollId, start.toISOString())
        .all<{ created_at: string }>();
      return bucketCounts(res.results, days);
    },
    async workspaceSeries(tenantId, days) {
      const start = windowStart(days);
      const res = await env.DB.prepare(
        `SELECT e.created_at FROM vote_events AS e
         JOIN polls AS p ON p.id = e.poll_id
         WHERE p.tenant_id = ?1 AND e.created_at >= ?2`,
      )
        .bind(tenantId, start.toISOString())
        .all<{ created_at: string }>();
      return bucketCounts(res.results, days);
    },
  };
}

export class MemoryAnalyticsStore implements AnalyticsStore {
  readonly id = "memory";
  readonly events: { pollId: string; tenantId: string; at: string }[] = [];

  async record(pollId: string, at: string): Promise<void> {
    this.events.push({ pollId, tenantId: "", at });
  }

  async pollSeries(pollId: string, days: number): Promise<DayCount[]> {
    return bucketCounts(
      this.events.filter((event) => event.pollId === pollId).map((event) => ({ created_at: event.at })),
      days,
    );
  }

  async workspaceSeries(tenantId: string, days: number): Promise<DayCount[]> {
    return bucketCounts(
      this.events.filter((event) => event.tenantId === tenantId).map((event) => ({ created_at: event.at })),
      days,
    );
  }
}

let sharedMemoryAnalytics: MemoryAnalyticsStore | null = null;

export function createAnalyticsStore(env: Env): AnalyticsStore {
  const name = (env.ANALYTICS_STORE || "d1").toLowerCase();
  if (name === "d1") return createD1AnalyticsStore(env);
  if (name === "memory") {
    sharedMemoryAnalytics ??= new MemoryAnalyticsStore();
    return sharedMemoryAnalytics;
  }
  throw new Error(`Unknown ANALYTICS_STORE "${name}"`);
}
