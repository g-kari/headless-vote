-- Security hardening (review follow-up):
-- - sessions: server-side admin sessions so a session can be revoked
--   (logout / revoke-all) instead of living until the cookie signature
--   expires.
-- - rate_limit_buckets: fixed-window counters for the Worker-side rate
--   limits (identifiers are stored SHA-256 hashed).
-- - tenant_image_usage: per-tenant image count / total-bytes quota
--   bookkeeping for R2 uploads.
-- - app_migrations: bookkeeping table for Worker-applied data
--   migrations (reserved; the voter-key rewrite is idempotent and
--   poll-scoped, so it does not depend on this table).
CREATE TABLE IF NOT EXISTS sessions (
  id_hash TEXT PRIMARY KEY,
  user_sub TEXT NOT NULL,
  name TEXT,
  email TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_sub);

CREATE TABLE IF NOT EXISTS rate_limit_buckets (
  bucket TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (bucket, window_start)
);

CREATE TABLE IF NOT EXISTS tenant_image_usage (
  tenant_id TEXT PRIMARY KEY,
  image_count INTEGER NOT NULL,
  total_bytes INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_migrations (
  name TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL
);
