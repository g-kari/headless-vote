/**
 * Voter identity keys stored in votes.voter_key.
 *
 * - Logged-in voters: `user:<0g0-id sub>` (the sub is an identifier, not
 *   a secret, and pairwise per client).
 * - Anonymous voters: `anonh:<HMAC-SHA256(SESSION_SECRET, token)>`.
 *   The raw voter_token is never stored, so a database leak does not
 *   hand out tokens that could overwrite other people's votes.
 *
 * Rows written before the HMAC change used `anon:<raw token>`. They are
 * migrated in place by migrateLegacyAnonVoterKeys(), which runs before
 * votes are cast or counted for that poll, so existing ballots keep
 * counting for the same voter.
 */
import { hmacSha256Hex } from "./crypto";
import type { Env } from "./types";

export const ANON_KEY_PREFIX = "anonh:";
export const LEGACY_ANON_KEY_PREFIX = "anon:";

export async function anonVoterKey(secret: string, voterToken: string): Promise<string> {
  const digest = await hmacSha256Hex(secret, `anon-voter:${voterToken}`);
  return `${ANON_KEY_PREFIX}${digest}`;
}

export function userVoterKey(sub: string): string {
  return `user:${sub}`;
}

/**
 * In-place migration of one poll's legacy `anon:<token>` voter keys to
 * the HMAC form. When both a legacy row set and an already-migrated row
 * set exist for the same voter, the set with the newest updated_at wins
 * (it reflects the voter's latest ballot).
 *
 * Idempotent and safe to call before every vote/results read for the
 * poll: once a poll has no legacy rows it is a single indexed SELECT.
 * It is deliberately not guarded by a one-time flag, so legacy rows
 * written by an older Worker version during a rollout are picked up
 * too.
 */
export async function migrateLegacyAnonVoterKeys(env: Env, pollId: string): Promise<void> {
  const legacy = await env.DB.prepare(
    "SELECT DISTINCT voter_key FROM votes WHERE poll_id = ?1 AND voter_key LIKE 'anon:%'",
  ).bind(pollId).all<{ voter_key: string }>();

  for (const row of legacy.results) {
    const token = row.voter_key.slice(LEGACY_ANON_KEY_PREFIX.length);
    const canonical = await anonVoterKey(env.SESSION_SECRET, token);
    // Discovery above can be stale. All winner decisions use live rows in
    // one transaction, so a delayed migration cannot erase a later ballot.
    // Ties keep the canonical set, matching the original migration policy.
    await env.DB.batch([
      env.DB.prepare(`DELETE FROM votes
        WHERE poll_id = ?1 AND voter_key = ?2
          AND EXISTS (SELECT 1 FROM votes WHERE poll_id = ?1 AND voter_key = ?3)
          AND (SELECT MAX(updated_at) FROM votes WHERE poll_id = ?1 AND voter_key = ?3)
            >= (SELECT MAX(updated_at) FROM votes WHERE poll_id = ?1 AND voter_key = ?2)`)
        .bind(pollId, row.voter_key, canonical),
      // A surviving legacy set is strictly newer, or has no competitor.
      // If another migration already consumed it, this is a no-op.
      env.DB.prepare(`DELETE FROM votes
        WHERE poll_id = ?1 AND voter_key = ?3
          AND EXISTS (SELECT 1 FROM votes WHERE poll_id = ?1 AND voter_key = ?2)`)
        .bind(pollId, row.voter_key, canonical),
      env.DB.prepare("UPDATE votes SET voter_key = ?3 WHERE poll_id = ?1 AND voter_key = ?2")
        .bind(pollId, row.voter_key, canonical),
    ]);
  }
}
