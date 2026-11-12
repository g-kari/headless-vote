import type { Env } from "./types";

export async function listMemberships(env: Env, sub: string) {
  const res = await env.DB.prepare(
    `SELECT t.id, t.name, t.plan, t.created_at, m.role
     FROM tenant_members AS m
     JOIN tenants AS t ON t.id = m.tenant_id
     WHERE m.user_sub = ?1
     ORDER BY t.created_at ASC`,
  )
    .bind(sub)
    .all<{ id: string; name: string; plan: string; created_at: string; role: string }>();
  return res.results;
}

export async function deleteWorkspace(env: Env, tenantId: string): Promise<void> {
  await env.DB.batch([
    env.DB.prepare(
      "DELETE FROM vote_events WHERE poll_id IN (SELECT id FROM polls WHERE tenant_id = ?1)",
    ).bind(tenantId),
    env.DB.prepare(
      "DELETE FROM webhook_deliveries WHERE webhook_id IN (SELECT id FROM webhooks WHERE tenant_id = ?1)",
    ).bind(tenantId),
    env.DB.prepare("DELETE FROM audit_events WHERE tenant_id = ?1").bind(tenantId),
    env.DB.prepare("DELETE FROM tenants WHERE id = ?1").bind(tenantId),
  ]);
}

/**
 * Removes this app's copy of the person's memberships.
 * A workspace is deleted only when they are its sole owner.
 * The 0g0-id account itself is not deleted.
 */
export async function deleteAccountData(env: Env, sub: string): Promise<{ deleted_workspaces: string[] }> {
  const memberships = await listMemberships(env, sub);
  const deleted: string[] = [];
  for (const membership of memberships) {
    if (membership.role === "owner") {
      const owners = await env.DB.prepare(
        "SELECT COUNT(*) AS n FROM tenant_members WHERE tenant_id = ?1 AND role = 'owner'",
      )
        .bind(membership.id)
        .first<{ n: number }>();
      if (Number(owners?.n ?? 0) <= 1) {
        await deleteWorkspace(env, membership.id);
        deleted.push(membership.id);
        continue;
      }
    }
    await env.DB.prepare("DELETE FROM tenant_members WHERE tenant_id = ?1 AND user_sub = ?2")
      .bind(membership.id, sub)
      .run();
  }
  return { deleted_workspaces: deleted };
}
