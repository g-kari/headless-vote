/**
 * Database schema: the union of migrations/0001_init.sql and
 * migrations/0002_security.sql and 0003_main_security.sql. Tests apply SCHEMA_SQL directly to a
 * fresh D1 database.
 */
export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  api_key_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_members (
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_sub TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'owner',
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, user_sub)
);

CREATE TABLE IF NOT EXISTS polls (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  revision INTEGER NOT NULL DEFAULT 0,
  question TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  image_key TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'closed')),
  allow_multiple INTEGER NOT NULL DEFAULT 0,
  require_login INTEGER NOT NULL DEFAULT 0,
  closes_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_polls_tenant ON polls(tenant_id);

CREATE TABLE IF NOT EXISTS options (
  id TEXT PRIMARY KEY,
  poll_id TEXT NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  image_key TEXT,
  position INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_options_poll ON options(poll_id);

CREATE TABLE IF NOT EXISTS votes (
  id TEXT PRIMARY KEY,
  poll_id TEXT NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
  option_id TEXT NOT NULL REFERENCES options(id) ON DELETE CASCADE,
  voter_key TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (poll_id, voter_key, option_id)
);
CREATE INDEX IF NOT EXISTS idx_votes_poll ON votes(poll_id);

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

CREATE TABLE IF NOT EXISTS poll_mutation_guards (
  id TEXT PRIMARY KEY,
  valid INTEGER NOT NULL CONSTRAINT poll_mutation_allowed CHECK (valid = 1)
);
CREATE INDEX IF NOT EXISTS idx_rate_limit_expiry ON rate_limit_buckets(window_start);

CREATE TABLE IF NOT EXISTS app_migrations (
  name TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL
);
`;

/** Split a multi-statement SQL script into individual statements. */
export function schemaStatements(): string[] {
  return SCHEMA_SQL.split(";")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}
