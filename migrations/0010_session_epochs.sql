-- Session epochs for OIDC users (revoke-all for stateless session
-- cookies) and the per-tenant image usage ledger. tenant_image_usage
-- is already created by 0002_security.sql on databases that applied
-- it; IF NOT EXISTS keeps this migration a no-op there.
CREATE TABLE IF NOT EXISTS session_epochs (
  sub TEXT PRIMARY KEY,
  epoch INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS tenant_image_usage (
  tenant_id TEXT PRIMARY KEY,
  image_count INTEGER NOT NULL,
  total_bytes INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);
