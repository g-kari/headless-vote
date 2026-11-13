import {
  findAccountByEmail,
  normalizeEmail,
  publicAccountById,
} from "./accounts";
import { actorLabel, recordAudit } from "./audit";
import { badRequest, conflict, notFound } from "./errors";
import { assertPlainText, normalizeUuid } from "./security";
import type { AdminPrincipal, Env } from "./types";

/**
 * Workspace membership, keyed by the Hyo-internal account id.
 * The IdP subject never reaches this module: members are added by
 * internal account id or by email (resolved server-side, or held as a
 * pending invite until that person first signs in).
 */

export interface MemberRow {
  account_id: string;
  email: string | null;
  name: string | null;
  role: "owner" | "member";
  created_at: string;
}

export interface InviteRow {
  email: string;
  role: "owner" | "member";
  created_at: string;
}

export async function listMembers(env: Env, tenantId: string): Promise<MemberRow[]> {
  const res = await env.DB.prepare(
    `SELECT m.account_id, a.email, a.name, m.role, m.created_at
     FROM tenant_members AS m LEFT JOIN accounts AS a ON a.id = m.account_id
     WHERE m.tenant_id = ?1 ORDER BY m.created_at ASC`,
  )
    .bind(tenantId)
    .all<{ account_id: string; email: string | null; name: string | null; role: string; created_at: string }>();
  return res.results.map((row) => ({
    account_id: row.account_id,
    email: row.email,
    name: row.name,
    role: row.role === "owner" ? "owner" : "member",
    created_at: row.created_at,
  }));
}

export async function listInvites(env: Env, tenantId: string): Promise<InviteRow[]> {
  const res = await env.DB.prepare(
    "SELECT email, role, created_at FROM member_invites WHERE tenant_id = ?1 ORDER BY created_at ASC",
  )
    .bind(tenantId)
    .all<{ email: string; role: string; created_at: string }>();
  return res.results.map((row) => ({
    email: row.email,
    role: row.role === "owner" ? "owner" : "member",
    created_at: row.created_at,
  }));
}

function parseAccountId(raw: string): string {
  assertPlainText(raw);
  const id = normalizeUuid(raw.trim());
  if (!id) throw badRequest('"account_id" must be an account id (UUID)');
  return id;
}

export function parseEmail(raw: string): string {
  assertPlainText(raw);
  const email = normalizeEmail(raw);
  if (email.length < 3 || email.length > 200 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw badRequest('"email" must be a valid email address');
  }
  return email;
}

function parseRole(raw: unknown): "owner" | "member" {
  if (raw !== "owner" && raw !== "member") throw badRequest('"role" must be owner or member');
  return raw;
}

async function insertMember(
  env: Env,
  tenantId: string,
  accountId: string,
  role: "owner" | "member",
): Promise<MemberRow> {
  const account = await publicAccountById(env, accountId);
  if (!account) throw notFound("Account not found");
  const existing = await env.DB.prepare(
    "SELECT account_id FROM tenant_members WHERE tenant_id = ?1 AND account_id = ?2",
  )
    .bind(tenantId, accountId)
    .first();
  if (existing) throw conflict("ALREADY_MEMBER", "That user is already a member");
  const createdAt = new Date().toISOString();
  await env.DB.prepare(
    "INSERT INTO tenant_members (tenant_id, account_id, role, created_at) VALUES (?1, ?2, ?3, ?4)",
  )
    .bind(tenantId, accountId, role, createdAt)
    .run();
  return {
    account_id: accountId,
    email: account.email,
    name: account.name,
    role,
    created_at: createdAt,
  };
}

/** Add a member by Hyo-internal account id. */
export async function addMember(
  env: Env,
  tenantId: string,
  accountIdRaw: string,
  roleRaw: unknown,
  actor: AdminPrincipal,
): Promise<MemberRow> {
  const accountId = parseAccountId(accountIdRaw);
  const role = parseRole(roleRaw);
  const member = await insertMember(env, tenantId, accountId, role);
  await recordAudit(env, {
    tenantId,
    actor: actorLabel(actor),
    action: "member.add",
    target: member.account_id,
    detail: role,
  });
  return member;
}

export type InviteOutcome =
  | { kind: "member"; member: MemberRow }
  | { kind: "invite"; invite: InviteRow };

/**
 * Invite by email. When the address already belongs to a Hyo account the
 * person becomes a member immediately; otherwise a pending invite is
 * stored and claimed automatically at their first login.
 */
export async function inviteMemberByEmail(
  env: Env,
  tenantId: string,
  emailRaw: string,
  roleRaw: unknown,
  actor: AdminPrincipal,
): Promise<InviteOutcome> {
  const email = parseEmail(emailRaw);
  const role = parseRole(roleRaw);
  const account = await findAccountByEmail(env, email);
  if (account) {
    const member = await insertMember(env, tenantId, account.id, role);
    await recordAudit(env, {
      tenantId,
      actor: actorLabel(actor),
      action: "member.add",
      target: member.account_id,
      detail: role,
    });
    return { kind: "member", member };
  }
  const existingInvite = await env.DB.prepare(
    "SELECT email FROM member_invites WHERE tenant_id = ?1 AND email = ?2",
  )
    .bind(tenantId, email)
    .first();
  if (existingInvite) throw conflict("ALREADY_INVITED", "That email is already invited");
  const createdAt = new Date().toISOString();
  await env.DB.prepare(
    "INSERT INTO member_invites (tenant_id, email, role, created_at) VALUES (?1, ?2, ?3, ?4)",
  )
    .bind(tenantId, email, role, createdAt)
    .run();
  await recordAudit(env, {
    tenantId,
    actor: actorLabel(actor),
    action: "member.invite",
    target: email,
    detail: role,
  });
  return { kind: "invite", invite: { email, role, created_at: createdAt } };
}

export async function cancelInvite(
  env: Env,
  tenantId: string,
  emailRaw: string,
  actor: AdminPrincipal,
): Promise<void> {
  const email = parseEmail(emailRaw);
  const removed = await env.DB.prepare(
    "DELETE FROM member_invites WHERE tenant_id = ?1 AND email = ?2",
  )
    .bind(tenantId, email)
    .run();
  if (removed.meta.changes !== 1) throw notFound("Invite not found");
  await recordAudit(env, {
    tenantId,
    actor: actorLabel(actor),
    action: "member.invite.cancel",
    target: email,
  });
}

export async function setMemberRole(
  env: Env,
  tenantId: string,
  accountIdRaw: string,
  roleRaw: unknown,
  actor: AdminPrincipal,
): Promise<void> {
  const accountId = parseAccountId(accountIdRaw);
  const role = parseRole(roleRaw);
  const current = await env.DB.prepare(
    "SELECT role FROM tenant_members WHERE tenant_id = ?1 AND account_id = ?2",
  )
    .bind(tenantId, accountId)
    .first<{ role: string }>();
  if (!current) throw notFound("Member not found");
  const updated = await env.DB.prepare(
    `UPDATE tenant_members SET role = ?1
     WHERE tenant_id = ?2 AND account_id = ?3 AND role = ?4
       AND (role <> 'owner' OR ?1 = 'owner' OR
         (SELECT COUNT(*) FROM tenant_members WHERE tenant_id = ?2 AND role = 'owner') > 1)`,
  )
    .bind(role, tenantId, accountId, current.role)
    .run();
  if (updated.meta.changes !== 1) {
    throw conflict("LAST_OWNER", "Member changed or the last owner cannot be demoted");
  }
  await recordAudit(env, {
    tenantId,
    actor: actorLabel(actor),
    action: "member.role",
    target: accountId,
    detail: role,
  });
}

export async function removeMember(
  env: Env,
  tenantId: string,
  accountIdRaw: string,
  actor: AdminPrincipal,
): Promise<void> {
  const accountId = parseAccountId(accountIdRaw);
  const current = await env.DB.prepare(
    "SELECT role FROM tenant_members WHERE tenant_id = ?1 AND account_id = ?2",
  )
    .bind(tenantId, accountId)
    .first<{ role: string }>();
  if (!current) throw notFound("Member not found");
  const removed = await env.DB.prepare(
    `DELETE FROM tenant_members
     WHERE tenant_id = ?1 AND account_id = ?2 AND role = ?3
       AND (role <> 'owner' OR
         (SELECT COUNT(*) FROM tenant_members WHERE tenant_id = ?1 AND role = 'owner') > 1)`,
  )
    .bind(tenantId, accountId, current.role)
    .run();
  if (removed.meta.changes !== 1) {
    throw conflict("LAST_OWNER", "Member changed or the last owner cannot be removed");
  }
  await recordAudit(env, {
    tenantId,
    actor: actorLabel(actor),
    action: "member.remove",
    target: accountId,
  });
}
