/** One stored ballot per voter. The raw token or sub is HMAC'd at rest. */

import { hmacSha256Base64Url, randomId } from "./crypto";
import { conflict } from "./errors";
import { recordVoteEvent } from "./quotas";
import type { Env, PollRow } from "./types";

function pepper(env: Env): string {
  return env.VOTER_KEY_SECRET || env.SESSION_SECRET;
}

export async function hashVoterKey(env: Env, raw: string): Promise<string> {
  const secret = pepper(env);
  const mac = await hmacSha256Base64Url(secret, `headless-vote/voter/v1\0${raw}`);
  return `v1.${mac}`;
}

/**
 * Re-key ballots that were stored before HMAC (plaintext `user:` / `anon:`).
 * Idempotent. New votes are written already hashed, so this is a no-op
 * once `app_meta.voter_hmac_v1` is done.
 */
export async function ensureVoterKeysHashed(env: Env): Promise<void> {
  const flag = await env.DB.prepare("SELECT value FROM app_meta WHERE key = 'voter_hmac_v1'")
    .first<{ value: string }>();
  if (flag?.value === "done") return;
  for (let i = 0; i < 100; i++) {
    const rows = await env.DB.prepare(
      `SELECT poll_id, voter_key, option_ids, updated_at
       FROM vote_ballots
       WHERE substr(voter_key, 1, 3) != 'v1.'
       LIMIT 100`,
    ).all<{
      poll_id: string;
      voter_key: string;
      option_ids: string;
      updated_at: string;
    }>();
    if (rows.results.length === 0) {
      await env.DB.prepare(
        `INSERT INTO app_meta (key, value) VALUES ('voter_hmac_v1', 'done')
         ON CONFLICT(key) DO UPDATE SET value = 'done'`,
      ).run();
      return;
    }
    const stmts = [];
    for (const row of rows.results) {
      const hashed = await hashVoterKey(env, row.voter_key);
      stmts.push(
        env.DB.prepare(
          `INSERT INTO vote_ballots (poll_id, voter_key, option_ids, updated_at)
           VALUES (?1, ?2, ?3, ?4)
           ON CONFLICT(poll_id, voter_key) DO NOTHING`,
        ).bind(row.poll_id, hashed, row.option_ids, row.updated_at),
      );
      stmts.push(
        env.DB.prepare(
          "DELETE FROM vote_ballots WHERE poll_id = ?1 AND voter_key = ?2",
        ).bind(row.poll_id, row.voter_key),
      );
    }
    await env.DB.batch(stmts);
  }
}

/* Remove one voter's ballot (folds an anonymous ballot into a login ballot). */
export async function deleteBallot(env: Env, pollId: string, rawVoterKey: string): Promise<void> {
  await ensureVoterKeysHashed(env);
  const stored = await hashVoterKey(env, rawVoterKey);
  await env.DB.prepare("DELETE FROM vote_ballots WHERE poll_id = ?1 AND voter_key = ?2")
    .bind(pollId, stored)
    .run();
}

export async function ballotCount(env: Env, pollId: string): Promise<number> {
  await ensureVoterKeysHashed(env);
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM vote_ballots WHERE poll_id = ?1",
  )
    .bind(pollId)
    .first<{ n: number }>();
  return Number(row?.n ?? 0);
}

/** Replace this voter's selection in one statement (no delete/insert race). */
export async function upsertBallot(
  env: Env, poll: PollRow, rawVoterKey: string, document: string, authenticated: boolean,
): Promise<void> {
  await ensureVoterKeysHashed(env);
  const stored = await hashVoterKey(env, rawVoterKey);
  const eventId = randomId();
  const now = new Date().toISOString();
  const start = `${now.slice(0, 10)}T00:00:00.000Z`;
  const [reservation] = await env.DB.batch([
    env.DB.prepare(`INSERT INTO vote_events (id, poll_id, created_at)
      SELECT ?1, p.id, ?2 FROM polls p JOIN tenants t ON t.id = p.tenant_id
      WHERE p.id = ?3 AND p.revision = ?4 AND p.status = 'published'
      AND (p.opens_at IS NULL OR p.opens_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      AND (p.closes_at IS NULL OR p.closes_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      AND (p.require_login = 0 OR ?5 = 1)
      AND (SELECT COUNT(*) FROM vote_events e JOIN polls ep ON ep.id = e.poll_id
        WHERE ep.tenant_id = p.tenant_id AND e.created_at >= ?6) < t.quota_votes_per_day`)
      .bind(eventId, now, poll.id, poll.revision, authenticated ? 1 : 0, start),
    env.DB.prepare(`INSERT INTO vote_ballots (poll_id, voter_key, option_ids, updated_at)
      SELECT ?1, ?2, ?3, ?4 WHERE EXISTS (SELECT 1 FROM vote_events WHERE id = ?5)
      ON CONFLICT(poll_id, voter_key) DO UPDATE SET
        option_ids = excluded.option_ids, updated_at = excluded.updated_at`)
      .bind(poll.id, stored, document, now, eventId),
  ]);
  if (Number(reservation?.meta.changes ?? 0) !== 1) {
    throw conflict("VOTE_STATE_CHANGED", "Voting state or quota changed. Reload and try again.");
  }
  // D1 is the durable quota ledger even when analytics uses another adapter.
  await recordVoteEvent(env, poll.id, now);
}
