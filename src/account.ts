import { deleteLocalAccount } from "./platform/auth-local";
import { drainObjectCleanup } from "./object-cleanup";
import type { Env } from "./types";

export async function listMemberships(env: Env, sub: string) {
  const res = await env.DB.prepare(
    `SELECT t.id, t.name, t.plan, t.created_at, m.role
     FROM tenant_members AS m JOIN tenants AS t ON t.id = m.tenant_id
     WHERE m.user_sub = ?1 ORDER BY t.created_at ASC`,
  ).bind(sub).all<{ id: string; name: string; plan: string; created_at: string; role: string }>();
  return res.results;
}

function deletedWorkspaceCleanup(env: Env, tenantId: string): D1PreparedStatement[] {
  // These statements run before removing tenants; predicates are supplied by
  // callers by using the conditional deleted-tenant marker within one batch.
  return [
    env.DB.prepare(`DELETE FROM vote_events WHERE poll_id IN
      (SELECT id FROM polls WHERE tenant_id = ?1)
      AND EXISTS (SELECT 1 FROM object_cleanup WHERE tenant_id = ?1)`).bind(tenantId),
    env.DB.prepare(`DELETE FROM webhook_deliveries WHERE webhook_id IN
      (SELECT id FROM webhooks WHERE tenant_id = ?1)
      AND EXISTS (SELECT 1 FROM object_cleanup WHERE tenant_id = ?1)`).bind(tenantId),
    env.DB.prepare(`DELETE FROM audit_events WHERE tenant_id = ?1
      AND EXISTS (SELECT 1 FROM object_cleanup WHERE tenant_id = ?1)`).bind(tenantId),
    env.DB.prepare(`DELETE FROM tenants WHERE id = ?1
      AND EXISTS (SELECT 1 FROM object_cleanup WHERE tenant_id = ?1)`).bind(tenantId),
  ];
}

export async function deleteWorkspace(env: Env, tenantId: string): Promise<void> {
  await env.DB.batch([
    env.DB.prepare("INSERT INTO object_cleanup (tenant_id, created_at, generation) VALUES (?1, ?2, lower(hex(randomblob(16)))) ON CONFLICT(tenant_id) DO UPDATE SET generation = excluded.generation")
      .bind(tenantId, new Date().toISOString()),
    ...deletedWorkspaceCleanup(env, tenantId),
  ]);
  await drainObjectCleanup(env);
}

/** Delete only workspaces for which this user is still the sole owner. */
export async function deleteAccountData(env: Env, sub: string): Promise<{ deleted_workspaces: string[] }> {
  const memberships = await listMemberships(env, sub);
  const deleted: string[] = [];
  for (const membership of memberships) {
    const results = await env.DB.batch([
      env.DB.prepare(`INSERT INTO object_cleanup (tenant_id, created_at, generation)
        SELECT id, ?3, lower(hex(randomblob(16))) FROM tenants WHERE id = ?1
        AND EXISTS (SELECT 1 FROM tenant_members WHERE tenant_id = ?1 AND user_sub = ?2 AND role = 'owner')
        AND NOT EXISTS (SELECT 1 FROM tenant_members WHERE tenant_id = ?1 AND user_sub != ?2 AND role = 'owner')
        ON CONFLICT(tenant_id) DO UPDATE SET generation = excluded.generation`)
        .bind(membership.id, sub, new Date().toISOString()),
      ...deletedWorkspaceCleanup(env, membership.id),
      env.DB.prepare(`DELETE FROM tenant_members WHERE tenant_id = ?1 AND user_sub = ?2
        AND (role != 'owner' OR EXISTS (SELECT 1 FROM tenant_members AS other
          WHERE other.tenant_id = ?1 AND other.user_sub != ?2 AND other.role = 'owner'))`)
        .bind(membership.id, sub),
    ]);
    if (Number(results[4]?.meta.changes ?? 0) === 1) deleted.push(membership.id);
  }
  await deleteLocalAccount(env, sub);
  await drainObjectCleanup(env);
  return { deleted_workspaces: deleted };
}
