import { actorLabel, recordAudit } from "./audit";
import { randomId, randomToken, sha256Hex } from "./crypto";
import { badRequest, notFound, unauthorized } from "./errors";
import { tenantQuotas } from "./quotas";
import { assertPlainText, rateLimit } from "./security";
import type { AdminPrincipal, ApiScope, Env, TenantRow } from "./types";
export type { ApiScope };

export interface ApiKeyRow {
  id: string;
  tenant_id: string;
  name: string;
  key_hash: string;
  key_prefix: string;
  scope: ApiScope;
  created_at: string;
  revoked_at: string | null;
  last_used_at: string | null;
}

export function keyPrefix(token: string): string {
  return token.slice(0, 12);
}

export function publicKey(row: ApiKeyRow) {
  return {
    id: row.id,
    name: row.name,
    prefix: row.key_prefix,
    scope: row.scope,
    created_at: row.created_at,
    revoked_at: row.revoked_at,
    last_used_at: row.last_used_at,
  };
}

export async function findActiveApiKey(
  env: Env,
  token: string,
): Promise<{ tenant: TenantRow; key: ApiKeyRow } | null> {
  const hash = await sha256Hex(token);
  const row = await env.DB.prepare(
    `SELECT k.id, k.tenant_id, k.name, k.key_hash, k.key_prefix, k.scope,
            k.created_at, k.revoked_at, k.last_used_at,
            t.name AS tenant_name, t.api_key_hash, t.created_at AS tenant_created_at
     FROM api_keys AS k
     JOIN tenants AS t ON t.id = k.tenant_id
     WHERE k.key_hash = ?1`,
  )
    .bind(hash)
    .first<
      ApiKeyRow & {
        tenant_name: string;
        api_key_hash: string;
        tenant_created_at: string;
      }
    >();
  if (row) {
    if (row.revoked_at) return null;
    return {
      tenant: {
        id: row.tenant_id,
        name: row.tenant_name,
        api_key_hash: row.api_key_hash,
        created_at: row.tenant_created_at,
        brand_color: null,
        brand_logo_key: null,
      },
      key: {
        id: row.id,
        tenant_id: row.tenant_id,
        name: row.name,
        key_hash: row.key_hash,
        key_prefix: row.key_prefix,
        scope: row.scope,
        created_at: row.created_at,
        revoked_at: row.revoked_at,
        last_used_at: row.last_used_at,
      },
    };
  }
  const tenant = await env.DB.prepare("SELECT * FROM tenants WHERE api_key_hash = ?1")
    .bind(hash)
    .first<TenantRow>();
  if (!tenant) return null;
  const now = new Date().toISOString();
  return {
    tenant,
    key: {
      id: "legacy",
      tenant_id: tenant.id,
      name: "legacy",
      key_hash: hash,
      key_prefix: "hvk_",
      scope: "write",
      created_at: tenant.created_at,
      revoked_at: null,
      last_used_at: now,
    },
  };
}

export async function touchApiKey(env: Env, keyId: string): Promise<void> {
  if (keyId === "legacy") return;
  await env.DB.prepare("UPDATE api_keys SET last_used_at = ?1 WHERE id = ?2")
    .bind(new Date().toISOString(), keyId)
    .run();
}

export async function provisionTenant(
  env: Env,
  name: string,
  ownerAccountId: string | null,
): Promise<{ tenantId: string; apiKey: string }> {
  assertPlainText(name);
  // Shared by API and UI provisioning; keep the global abuse ceiling from main.
  await rateLimit(env, await sha256Hex("rl:tenant-create-global:all"), 1000, 86_400);
  const tenantId = randomId();
  const apiKey = randomToken("hvk");
  const now = new Date().toISOString();
  const hash = await sha256Hex(apiKey);
  const stmts = [
    env.DB.prepare(
      "INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
    ).bind(tenantId, name, hash, now),
    env.DB.prepare(
      `INSERT INTO api_keys (id, tenant_id, name, key_hash, key_prefix, scope, created_at)
       VALUES (?1, ?2, '初期キー', ?3, ?4, 'write', ?5)`,
    ).bind(randomId(), tenantId, hash, keyPrefix(apiKey), now),
  ];
  if (ownerAccountId) {
    stmts.push(
      env.DB.prepare(
        "INSERT INTO tenant_members (tenant_id, account_id, role, created_at) VALUES (?1, ?2, 'owner', ?3)",
      ).bind(tenantId, ownerAccountId, now),
    );
  }
  await env.DB.batch(stmts);
  await recordAudit(env, {
    tenantId,
    actor: ownerAccountId ? `session:${ownerAccountId}` : "bootstrap",
    action: "tenant.create",
    detail: name.slice(0, 80),
  });
  return { tenantId, apiKey };
}

export async function listApiKeys(env: Env, tenantId: string): Promise<ApiKeyRow[]> {
  const res = await env.DB.prepare(
    `SELECT * FROM api_keys WHERE tenant_id = ?1
     ORDER BY created_at ASC`,
  )
    .bind(tenantId)
    .all<ApiKeyRow>();
  return res.results;
}

export async function issueApiKey(
  env: Env,
  tenantId: string,
  name: string,
  scope: ApiScope,
  actor: AdminPrincipal,
): Promise<{ apiKey: string; key: ReturnType<typeof publicKey> }> {
  assertPlainText(name);
  if (name.length < 1 || name.length > 80) throw badRequest('"name" must be 1-80 characters');
  if (scope !== "read" && scope !== "write") throw badRequest('"scope" must be read or write');
  const quotas = await tenantQuotas(env, tenantId);
  const apiKey = randomToken("hvk");
  const now = new Date().toISOString();
  const row: ApiKeyRow = {
    id: randomId(),
    tenant_id: tenantId,
    name,
    key_hash: await sha256Hex(apiKey),
    key_prefix: keyPrefix(apiKey),
    scope,
    created_at: now,
    revoked_at: null,
    last_used_at: null,
  };
  // Count and insert in one statement: concurrent issuers cannot overrun the quota.
  const inserted = await env.DB.prepare(
    `INSERT INTO api_keys (id, tenant_id, name, key_hash, key_prefix, scope, created_at)
     SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7
     WHERE (SELECT COUNT(*) FROM api_keys WHERE tenant_id = ?2 AND revoked_at IS NULL)
       < (SELECT COALESCE(quota_keys, 10) FROM tenants WHERE id = ?2)`,
  )
    .bind(row.id, row.tenant_id, row.name, row.key_hash, row.key_prefix, row.scope, row.created_at)
    .run();
  if (inserted.meta.changes !== 1) {
    throw badRequest(`A workspace can have at most ${quotas.keys} active API keys`);
  }
  await recordAudit(env, {
    tenantId,
    actor: actorLabel(actor),
    action: "key.create",
    target: row.id,
    detail: `${row.name} (${row.scope})`,
  });
  return { apiKey, key: publicKey(row) };
}

export async function revokeApiKey(
  env: Env,
  tenantId: string,
  keyId: string,
  actor: AdminPrincipal,
): Promise<void> {
  const row = await env.DB.prepare(
    "SELECT * FROM api_keys WHERE id = ?1 AND tenant_id = ?2",
  )
    .bind(keyId, tenantId)
    .first<ApiKeyRow>();
  if (!row || row.revoked_at) throw notFound("API key not found");
  const now = new Date().toISOString();
  await env.DB.prepare("UPDATE api_keys SET revoked_at = ?1 WHERE id = ?2")
    .bind(now, row.id)
    .run();
  await env.DB.prepare(
    `UPDATE tenants SET api_key_hash = ?1
     WHERE id = ?2 AND api_key_hash = ?3`,
  )
    .bind(await sha256Hex(randomToken("revoked")), tenantId, row.key_hash)
    .run();
  await recordAudit(env, {
    tenantId,
    actor: actorLabel(actor),
    action: "key.revoke",
    target: row.id,
    detail: row.key_prefix,
  });
}

/** Call only after proving ownership or authenticating a write key. */
export async function limitKeyRotation(env: Env, tenantId: string): Promise<void> {
  await rateLimit(env, await sha256Hex(`rl:rotate-key:${tenantId}`), 30, 3600);
}

/** Revoke the presented key and issue a replacement write key. */
export async function rotatePresentedKey(
  env: Env,
  tenantId: string,
  presented: { tenant: TenantRow; key: ApiKeyRow },
): Promise<string> {
  const apiKey = randomToken("hvk");
  const now = new Date().toISOString();
  const hash = await sha256Hex(apiKey);
  const successorId = randomId();
  if (presented.tenant.id !== tenantId || presented.key.tenant_id !== tenantId ||
      presented.key.scope !== "write") {
    throw unauthorized("INVALID_API_KEY", "API key cannot be rotated");
  }
  const legacy = presented.key.id === "legacy";
  // D1 batches are transactional. Only the first transaction observing a live
  // predecessor inserts a successor; all subsequent writes depend on that insert.
  // Never trust the authentication snapshot after awaiting another request.
  const insert = legacy
    ? env.DB.prepare(
      `INSERT INTO api_keys (id, tenant_id, name, key_hash, key_prefix, scope, created_at)
       SELECT ?1, ?2, '再発行', ?3, ?4, 'write', ?5
       FROM tenants WHERE id = ?2 AND api_key_hash = ?6
         AND NOT EXISTS (SELECT 1 FROM api_keys WHERE key_hash = ?6)
         AND (SELECT COUNT(*) FROM api_keys WHERE tenant_id = ?2 AND revoked_at IS NULL)
           < COALESCE(quota_keys, 10)`,
    ).bind(successorId, tenantId, hash, keyPrefix(apiKey), now, presented.key.key_hash)
    : env.DB.prepare(
      `INSERT INTO api_keys (id, tenant_id, name, key_hash, key_prefix, scope, created_at)
       SELECT ?1, ?2, '再発行', ?3, ?4, 'write', ?5
       FROM api_keys WHERE id = ?6 AND tenant_id = ?2 AND key_hash = ?7
         AND revoked_at IS NULL AND scope = 'write'
         AND (SELECT COUNT(*) FROM api_keys WHERE tenant_id = ?2 AND revoked_at IS NULL)
           <= (SELECT COALESCE(quota_keys, 10) FROM tenants WHERE id = ?2)`,
    ).bind(successorId, tenantId, hash, keyPrefix(apiKey), now,
      presented.key.id, presented.key.key_hash);
  const stmts = [insert];
  if (!legacy) {
    stmts.push(env.DB.prepare(
      `UPDATE api_keys SET revoked_at = ?1
       WHERE id = ?2 AND tenant_id = ?3 AND key_hash = ?4 AND revoked_at IS NULL
         AND EXISTS (SELECT 1 FROM api_keys WHERE id = ?5 AND tenant_id = ?3)`,
    ).bind(now, presented.key.id, tenantId, presented.key.key_hash, successorId));
  }
  stmts.push(env.DB.prepare(
    `UPDATE tenants SET api_key_hash = ?1
     WHERE id = ?2 AND api_key_hash = ?3
       AND EXISTS (SELECT 1 FROM api_keys WHERE id = ?4 AND tenant_id = ?2)`,
  ).bind(hash, tenantId, presented.key.key_hash, successorId));
  const results = await env.DB.batch(stmts);
  if (results[0]?.meta.changes !== 1) {
    throw unauthorized("INVALID_API_KEY", "API key is no longer active or key quota is exhausted");
  }
  await recordAudit(env, {
    tenantId,
    actor: `key:${presented.key.key_prefix}`,
    action: "key.rotate",
    target: presented.key.id,
  });
  return apiKey;
}
