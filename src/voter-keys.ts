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
  try {
    const legacy = await env.DB.prepare(
      "SELECT DISTINCT voter_key FROM votes WHERE poll_id = ?1 AND voter_key LIKE 'anon:%'",
    )
      .bind(pollId)
      .all<{ voter_key: string }>();

    for (const row of legacy.results) {
      const token = row.voter_key.slice(LEGACY_ANON_KEY_PREFIX.length);
      const canonical = await anonVoterKey(env.SESSION_SECRET, token);
      const legacyRows = await env.DB.prepare(
        "SELECT updated_at FROM votes WHERE poll_id = ?1 AND voter_key = ?2",
      )
        .bind(pollId, row.voter_key)
        .all<{ updated_at: string }>();
      const canonicalRows = await env.DB.prepare(
        "SELECT updated_at FROM votes WHERE poll_id = ?1 AND voter_key = ?2",
      )
        .bind(pollId, canonical)
        .all<{ updated_at: string }>();
      const newest = (rows: { updated_at: string }[]) =>
        rows.reduce((max, r) => (r.updated_at > max ? r.updated_at : max), "");

      if (
        canonicalRows.results.length > 0 &&
        newest(canonicalRows.results) >= newest(legacyRows.results)
      ) {
        // The migrated set is at least as new: drop the legacy rows.
        await env.DB.prepare(
          "DELETE FROM votes WHERE poll_id = ?1 AND voter_key = ?2",
        )
          .bind(pollId, row.voter_key)
          .run();
      } else {
        if (canonicalRows.results.length > 0) {
          await env.DB.prepare(
            "DELETE FROM votes WHERE poll_id = ?1 AND voter_key = ?2",
          )
            .bind(pollId, canonical)
            .run();
        }
        await env.DB.prepare(
          "UPDATE votes SET voter_key = ?1 WHERE poll_id = ?2 AND voter_key = ?3",
        )
          .bind(canonical, pollId, row.voter_key)
          .run();
      }
    }
  } catch {
    // Schema not applied yet (e.g. a database without migrations):
    // skip quietly and retry on a later request.
  }
}
