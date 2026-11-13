import { randomId } from "./crypto";
import type { AdminPrincipal, Env } from "./types";

export function actorLabel(principal: AdminPrincipal): string {
  // Session actors are labelled with the Hyo-internal account id. The IdP
  // subject is never written to the audit log.
  if (principal.kind === "session") return `session:${principal.accountId}`;
  return `key:${principal.prefix}`;
}

export async function recordAudit(
  env: Env,
  event: {
    tenantId: string;
    actor: string;
    action: string;
    target?: string | null;
    detail?: string;
  },
): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO audit_events (id, tenant_id, actor, action, target, detail, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`,
  )
    .bind(
      randomId(),
      event.tenantId,
      event.actor.slice(0, 120),
      event.action.slice(0, 64),
      event.target ?? null,
      (event.detail ?? "").slice(0, 300),
      new Date().toISOString(),
    )
    .run();
}

export interface AuditEventRow {
  id: string;
  tenant_id: string;
  actor: string;
  action: string;
  target: string | null;
  detail: string;
  created_at: string;
}

export async function listAuditEvents(env: Env, tenantId: string, limit = 100): Promise<AuditEventRow[]> {
  const res = await env.DB.prepare(
    `SELECT * FROM audit_events WHERE tenant_id = ?1
     ORDER BY created_at DESC LIMIT ?2`,
  )
    .bind(tenantId, limit)
    .all<AuditEventRow>();
  return res.results;
}
