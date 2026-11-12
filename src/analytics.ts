import type { Env } from "./types";

export interface DayCount {
  date: string;
  count: number;
}

function windowStart(days: number): Date {
  const start = new Date();
  start.setUTCHours(0, 0, 0, 0);
  start.setUTCDate(start.getUTCDate() - (days - 1));
  return start;
}

function bucket(rows: { created_at: string }[], days: number): DayCount[] {
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

/** Submission events, not unique people. A replacement ballot is another event. */
export async function pollSubmissionSeries(env: Env, pollId: string, days = 14): Promise<DayCount[]> {
  const start = windowStart(days);
  const res = await env.DB.prepare(
    "SELECT created_at FROM vote_events WHERE poll_id = ?1 AND created_at >= ?2",
  )
    .bind(pollId, start.toISOString())
    .all<{ created_at: string }>();
  return bucket(res.results, days);
}

export async function workspaceSubmissionSeries(
  env: Env,
  tenantId: string,
  days = 14,
): Promise<DayCount[]> {
  const start = windowStart(days);
  const res = await env.DB.prepare(
    `SELECT e.created_at FROM vote_events AS e
     JOIN polls AS p ON p.id = e.poll_id
     WHERE p.tenant_id = ?1 AND e.created_at >= ?2`,
  )
    .bind(tenantId, start.toISOString())
    .all<{ created_at: string }>();
  return bucket(res.results, days);
}
