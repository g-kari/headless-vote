/**
 * Full database schema for a fresh database (what tests apply).
 * Production upgrades go through migrations/ (0001, then 0002, ...).
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
  question TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  image_key TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'closed')),
  allow_multiple INTEGER NOT NULL DEFAULT 0,
  require_login INTEGER NOT NULL DEFAULT 0,
  closes_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revision TEXT NOT NULL DEFAULT ''
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

CREATE TABLE IF NOT EXISTS vote_ballots (
  poll_id TEXT NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
  voter_key TEXT NOT NULL,
  option_ids TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (poll_id, voter_key)
);

CREATE TABLE IF NOT EXISTS tenant_origins (
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  origin TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, origin)
);

CREATE TABLE IF NOT EXISTS rate_limits (
  bucket TEXT PRIMARY KEY,
  hits INTEGER NOT NULL,
  reset_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS app_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_states (
  state_hash TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
`;

/** Split a multi-statement SQL script into individual statements. */
export function schemaStatements(): string[] {
  return SCHEMA_SQL.split(";")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}
