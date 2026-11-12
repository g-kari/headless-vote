import { tooManyRequests } from "./errors";
import { createAnalyticsStore } from "./platform/analytics-store";
import type { Env } from "./types";

export interface Quotas {
  plan: string;
  polls: number;
  keys: number;
  webhooks: number;
  votesPerDay: number;
}

const DEFAULTS: Quotas = {
  plan: "free",
  polls: 100,
  keys: 10,
  webhooks: 5,
  votesPerDay: 5000,
};

export async function tenantQuotas(env: Env, tenantId: string): Promise<Quotas> {
  const row = await env.DB.prepare(
    `SELECT plan, quota_polls AS polls, quota_keys AS keys, quota_webhooks AS webhooks,
            quota_votes_per_day AS votes_per_day
     FROM tenants WHERE id = ?1`,
  )
    .bind(tenantId)
    .first<{ plan: string; polls: number; keys: number; webhooks: number; votes_per_day: number }>();
  if (!row) return DEFAULTS;
  return {
    plan: row.plan || DEFAULTS.plan,
    polls: Number(row.polls ?? DEFAULTS.polls),
    keys: Number(row.keys ?? DEFAULTS.keys),
    webhooks: Number(row.webhooks ?? DEFAULTS.webhooks),
    votesPerDay: Number(row.votes_per_day ?? DEFAULTS.votesPerDay),
  };
}

export async function assertDailyVoteQuota(env: Env, tenantId: string): Promise<void> {
  const quotas = await tenantQuotas(env, tenantId);
  const start = new Date();
  start.setUTCHours(0, 0, 0, 0);
  const row = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM vote_events AS e
     JOIN polls AS p ON p.id = e.poll_id
     WHERE p.tenant_id = ?1 AND e.created_at >= ?2`,
  )
    .bind(tenantId, start.toISOString())
    .first<{ n: number }>();
  if (Number(row?.n ?? 0) >= quotas.votesPerDay) {
    throw tooManyRequests(3600);
  }
}

export async function recordVoteEvent(env: Env, pollId: string): Promise<void> {
  await createAnalyticsStore(env).record(pollId, new Date().toISOString());
}
