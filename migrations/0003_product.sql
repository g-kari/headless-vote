-- Product features: open time, multiple API keys, admin audit log.
-- Applied after 0002.

ALTER TABLE polls ADD COLUMN opens_at TEXT;

CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  key_prefix TEXT NOT NULL,
  scope TEXT NOT NULL CHECK (scope IN ('read', 'write')),
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);

-- Keep keys that already exist on the tenant row usable after this migration.
INSERT INTO api_keys (id, tenant_id, name, key_hash, key_prefix, scope, created_at)
SELECT id, id, '初期キー', api_key_hash, 'hvk_', 'write', created_at
FROM tenants
WHERE NOT EXISTS (
  SELECT 1 FROM api_keys AS k WHERE k.key_hash = tenants.api_key_hash
);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT,
  detail TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_events(tenant_id, created_at);
