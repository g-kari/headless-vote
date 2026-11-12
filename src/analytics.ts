import { createAnalyticsStore } from "./platform/analytics-store";
import type { DayCount } from "./platform/ports";
import type { Env } from "./types";

export type { DayCount };

/** Submission events, not unique people. A replacement ballot is another event. */
export async function pollSubmissionSeries(env: Env, pollId: string, days = 14): Promise<DayCount[]> {
  return createAnalyticsStore(env).pollSeries(pollId, days);
}

export async function workspaceSubmissionSeries(
  env: Env,
  tenantId: string,
  days = 14,
): Promise<DayCount[]> {
  return createAnalyticsStore(env).workspaceSeries(tenantId, days);
}
