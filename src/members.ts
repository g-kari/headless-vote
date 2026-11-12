import { actorLabel, recordAudit } from "./audit";
import { badRequest, conflict, notFound } from "./errors";
import { assertPlainText } from "./security";
import type { AdminPrincipal, Env } from "./types";

export interface MemberRow {
  user_sub: string;
  role: "owner" | "member";
  created_at: string;
}

export async function listMembers(env: Env, tenantId: string): Promise<MemberRow[]> {
  const res = await env.DB.prepare(
    "SELECT user_sub, role, created_at FROM tenant_members WHERE tenant_id = ?1 ORDER BY created_at ASC",
  )
    .bind(tenantId)
    .all<{ user_sub: string; role: string; created_at: string }>();
  return res.results.map((row) => ({
    user_sub: row.user_sub,
    role: row.role === "owner" ? "owner" : "member",
    created_at: row.created_at,
  }));
}

function parseSub(raw: string): string {
  assertPlainText(raw);
  const sub = raw.trim();
  if (sub.length < 1 || sub.length > 256) throw badRequest('"user_sub" must be 1-256 characters');
  return sub;
}

function parseRole(raw: unknown): "owner" | "member" {
  if (raw !== "owner" && raw !== "member") throw badRequest('"role" must be owner or member');
  return raw;
}

export async function addMember(
  env: Env,
  tenantId: string,
  userSub: string,
  roleRaw: unknown,
  actor: AdminPrincipal,
): Promise<MemberRow> {
  const sub = parseSub(userSub);
  const role = parseRole(roleRaw);
  const existing = await env.DB.prepare(
    "SELECT user_sub FROM tenant_members WHERE tenant_id = ?1 AND user_sub = ?2",
  )
    .bind(tenantId, sub)
    .first();
  if (existing) throw conflict("ALREADY_MEMBER", "That user is already a member");
  const createdAt = new Date().toISOString();
  await env.DB.prepare(
    "INSERT INTO tenant_members (tenant_id, user_sub, role, created_at) VALUES (?1, ?2, ?3, ?4)",
  )
    .bind(tenantId, sub, role, createdAt)
    .run();
  await recordAudit(env, {
    tenantId,
    actor: actorLabel(actor),
    action: "member.add",
    target: sub.slice(0, 80),
    detail: role,
  });
  return { user_sub: sub, role, created_at: createdAt };
}

export async function setMemberRole(
  env: Env,
  tenantId: string,
  userSub: string,
  roleRaw: unknown,
  actor: AdminPrincipal,
): Promise<void> {
  const sub = parseSub(userSub);
  const role = parseRole(roleRaw);
  const current = await env.DB.prepare(
    "SELECT role FROM tenant_members WHERE tenant_id = ?1 AND user_sub = ?2",
  )
    .bind(tenantId, sub)
    .first<{ role: string }>();
  if (!current) throw notFound("Member not found");
  const updated = await env.DB.prepare(
    `UPDATE tenant_members SET role = ?1
     WHERE tenant_id = ?2 AND user_sub = ?3 AND role = ?4
       AND (role <> 'owner' OR ?1 = 'owner' OR
         (SELECT COUNT(*) FROM tenant_members WHERE tenant_id = ?2 AND role = 'owner') > 1)`,
  )
    .bind(role, tenantId, sub, current.role)
    .run();
  if (updated.meta.changes !== 1) {
    throw conflict("LAST_OWNER", "Member changed or the last owner cannot be demoted");
  }
  await recordAudit(env, {
    tenantId,
    actor: actorLabel(actor),
    action: "member.role",
    target: sub.slice(0, 80),
    detail: role,
  });
}

export async function removeMember(
  env: Env,
  tenantId: string,
  userSub: string,
  actor: AdminPrincipal,
): Promise<void> {
  const sub = parseSub(userSub);
  const current = await env.DB.prepare(
    "SELECT role FROM tenant_members WHERE tenant_id = ?1 AND user_sub = ?2",
  )
    .bind(tenantId, sub)
    .first<{ role: string }>();
  if (!current) throw notFound("Member not found");
  const removed = await env.DB.prepare(
    `DELETE FROM tenant_members
     WHERE tenant_id = ?1 AND user_sub = ?2 AND role = ?3
       AND (role <> 'owner' OR
         (SELECT COUNT(*) FROM tenant_members WHERE tenant_id = ?1 AND role = 'owner') > 1)`,
  )
    .bind(tenantId, sub, current.role)
    .run();
  if (removed.meta.changes !== 1) {
    throw conflict("LAST_OWNER", "Member changed or the last owner cannot be removed");
  }
  await recordAudit(env, {
    tenantId,
    actor: actorLabel(actor),
    action: "member.remove",
    target: sub.slice(0, 80),
  });
}
