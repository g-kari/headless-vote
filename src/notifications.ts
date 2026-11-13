import { randomId } from "./crypto";
import { dispatchWebhooks } from "./webhooks";
import type { Env } from "./types";

/**
 * Daily cron job: polls closing within the next 48 hours get one in-app
 * notification and one poll.closing_soon webhook per poll. The
 * notification row doubles as the dedupe record.
 */
export async function notifyClosingSoon(env: Env): Promise<number> {
  const now = new Date();
  const horizon = new Date(now.getTime() + 48 * 3600 * 1000).toISOString();
  const res = await env.DB.prepare(
    `SELECT id, tenant_id, question, closes_at FROM polls
     WHERE status = 'published' AND closes_at IS NOT NULL
       AND closes_at > ?1 AND closes_at <= ?2
       AND NOT EXISTS (
         SELECT 1 FROM app_notifications
         WHERE poll_id = polls.id AND kind = 'closing_soon'
       )`,
  )
    .bind(now.toISOString(), horizon)
    .all<{ id: string; tenant_id: string; question: string; closes_at: string }>();
  let sent = 0;
  for (const poll of res.results) {
    // Recheck and claim in a single write: concurrent cron runs can have
    // selected the same poll before either one inserted its notification.
    const claimed = await env.DB.prepare(
      `INSERT INTO app_notifications (id, tenant_id, poll_id, kind, message, created_at)
       SELECT ?1, ?2, ?3, 'closing_soon', ?4, ?5
       WHERE NOT EXISTS (
         SELECT 1 FROM app_notifications WHERE poll_id = ?3 AND kind = 'closing_soon'
       )`,
    )
      .bind(
        randomId(),
        poll.tenant_id,
        poll.id,
        `投票「${poll.question}」の締切が近づいています（締切: ${poll.closes_at}）`,
        now.toISOString(),
      )
      .run();
    if (Number(claimed.meta.changes ?? 0) !== 1) continue;
    await dispatchWebhooks(env, poll.tenant_id, "poll.closing_soon", {
      poll_id: poll.id,
      closes_at: poll.closes_at,
    });
    sent++;
  }
  return sent;
}
