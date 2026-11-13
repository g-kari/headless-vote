import { randomId } from "./crypto";
import type { Env } from "./types";

/**
 * Internal account identities.
 *
 * The identity provider's `sub` claim is an external identifier: it is kept
 * only in this module's mapping table (`accounts.subject`) and in the login
 * flow that resolves it. Everywhere else in Hyo — memberships, sessions,
 * audit logs, API responses, screens — a person is referenced by the
 * Hyo-internal account id (a random UUID minted here), never by the sub.
 */

export interface AccountRecord {
  id: string;
  /** IdP subject. Server-side only: never put this in a response or a log. */
  subject: string;
  email: string | null;
  name: string | null;
  created_at: string;
}

/** The shape of an account that is safe to show to clients. */
export interface PublicAccount {
  id: string;
  email: string | null;
  name: string | null;
  created_at: string;
}

interface AccountRow {
  id: string;
  subject: string;
  email: string | null;
  name: string | null;
  created_at: string;
}

function toRecord(row: AccountRow): AccountRecord {
  return {
    id: row.id,
    subject: row.subject,
    email: row.email,
    name: row.name,
    created_at: row.created_at,
  };
}

export function toPublicAccount(account: AccountRecord): PublicAccount {
  return {
    id: account.id,
    email: account.email,
    name: account.name,
    created_at: account.created_at,
  };
}

export function normalizeEmail(raw: string): string {
  return raw.trim().toLowerCase();
}

async function selectBySubject(env: Env, subject: string): Promise<AccountRecord | null> {
  const row = await env.DB.prepare(
    "SELECT id, subject, email, name, created_at FROM accounts WHERE subject = ?1",
  )
    .bind(subject)
    .first<AccountRow>();
  return row ? toRecord(row) : null;
}

/** Look up the account for an IdP subject without creating one. */
export async function accountBySubject(env: Env, subject: string): Promise<AccountRecord | null> {
  return selectBySubject(env, subject);
}

/** Look up an account by its Hyo-internal id. */
export async function accountById(env: Env, id: string): Promise<AccountRecord | null> {
  const row = await env.DB.prepare(
    "SELECT id, subject, email, name, created_at FROM accounts WHERE id = ?1",
  )
    .bind(id)
    .first<AccountRow>();
  return row ? toRecord(row) : null;
}

/** The IdP subject for an account id (internal use only, e.g. local-account deletion). */
export async function subjectForAccount(env: Env, accountId: string): Promise<string | null> {
  const account = await accountById(env, accountId);
  return account?.subject ?? null;
}

/** Public view of an account by internal id (no subject). */
export async function publicAccountById(env: Env, id: string): Promise<PublicAccount | null> {
  const account = await accountById(env, id);
  return account ? toPublicAccount(account) : null;
}

/** Find an account by its last known email (used to invite by email). */
export async function findAccountByEmail(env: Env, email: string): Promise<PublicAccount | null> {
  const row = await env.DB.prepare(
    `SELECT id, subject, email, name, created_at FROM accounts
     WHERE email = ?1 ORDER BY last_seen_at DESC LIMIT 1`,
  )
    .bind(normalizeEmail(email))
    .first<AccountRow>();
  return row ? toPublicAccount(toRecord(row)) : null;
}

/**
 * Resolve the account for a login: return the existing mapping for the
 * subject or mint a new internal id. Profile claims (email/name) refresh
 * the stored copy so member lists can show something human-readable.
 * Also claims any pending workspace invites addressed to the account email.
 */
export async function resolveAccount(
  env: Env,
  subject: string,
  profile?: { email?: string | null; name?: string | null },
): Promise<AccountRecord> {
  const now = new Date().toISOString();
  const email = profile?.email ? normalizeEmail(profile.email) : null;
  const name = profile?.name?.trim() ? profile.name.trim() : null;
  await env.DB.prepare(
    `INSERT INTO accounts (id, subject, email, name, created_at, last_seen_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?5)
     ON CONFLICT(subject) DO NOTHING`,
  )
    .bind(randomId(), subject, email, name, now)
    .run();
  let account = await selectBySubject(env, subject);
  if (!account) throw new Error("account resolution failed");
  if ((email && email !== account.email) || (name && name !== account.name)) {
    await env.DB.prepare(
      `UPDATE accounts SET email = COALESCE(?2, email), name = COALESCE(?3, name),
       last_seen_at = ?4 WHERE id = ?1`,
    )
      .bind(account.id, email, name, now)
      .run();
    account = (await selectBySubject(env, subject)) ?? account;
  } else {
    await env.DB.prepare("UPDATE accounts SET last_seen_at = ?2 WHERE id = ?1")
      .bind(account.id, now)
      .run();
  }
  await claimMemberInvites(env, account);
  return account;
}

/**
 * Convert pending email invites for this account into memberships.
 * Runs at login (account resolution), so an invite issued before the
 * person's first login takes effect as soon as they sign in.
 */
export async function claimMemberInvites(env: Env, account: AccountRecord): Promise<void> {
  if (!account.email) return;
  const invites = await env.DB.prepare(
    "SELECT tenant_id, role FROM member_invites WHERE email = ?1",
  )
    .bind(account.email)
    .all<{ tenant_id: string; role: string }>();
  if (invites.results.length === 0) return;
  const now = new Date().toISOString();
  const stmts: D1PreparedStatement[] = [];
  for (const invite of invites.results) {
    stmts.push(
      env.DB.prepare(
        `INSERT INTO tenant_members (tenant_id, account_id, role, created_at)
         VALUES (?1, ?2, ?3, ?4) ON CONFLICT(tenant_id, account_id) DO NOTHING`,
      ).bind(invite.tenant_id, account.id, invite.role === "owner" ? "owner" : "member", now),
    );
  }
  stmts.push(
    env.DB.prepare("DELETE FROM member_invites WHERE email = ?1").bind(account.email),
  );
  await env.DB.batch(stmts);
}
