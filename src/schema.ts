/**
 * Full database schema for a fresh database (what tests apply).
 * Production upgrades go through migrations/ (0001, then 0002, ...).
 */
export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  api_key_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'free',
  quota_polls INTEGER NOT NULL DEFAULT 100,
  quota_keys INTEGER NOT NULL DEFAULT 10,
  quota_webhooks INTEGER NOT NULL DEFAULT 5,
  quota_votes_per_day INTEGER NOT NULL DEFAULT 5000,
  brand_color TEXT,
  brand_logo_key TEXT
);

CREATE TABLE IF NOT EXISTS poll_templates (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  payload TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_poll_templates_tenant ON poll_templates(tenant_id);

CREATE TABLE IF NOT EXISTS app_notifications (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  poll_id TEXT,
  kind TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at TEXT NOT NULL,
  read_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_app_notifications_tenant ON app_notifications(tenant_id, read_at);

CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  subject TEXT NOT NULL UNIQUE,
  email TEXT,
  name TEXT,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_accounts_email ON accounts(email);

CREATE TABLE IF NOT EXISTS tenant_members (
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'owner',
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, account_id)
);

CREATE TABLE IF NOT EXISTS member_invites (
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'member',
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, email)
);
CREATE INDEX IF NOT EXISTS idx_member_invites_email ON member_invites(email);

CREATE TABLE IF NOT EXISTS polls (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  question TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  image_key TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'closed')),
  allow_multiple INTEGER NOT NULL DEFAULT 0,
  require_login INTEGER NOT NULL DEFAULT 0,
  opens_at TEXT,
  closes_at TEXT,
  results_visibility TEXT NOT NULL DEFAULT 'public',
  ip_single_vote INTEGER NOT NULL DEFAULT 0,
  confirm_required INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revision TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_polls_tenant ON polls(tenant_id);

CREATE TABLE IF NOT EXISTS questions (
  id TEXT PRIMARY KEY,
  poll_id TEXT NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
  prompt TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  image_key TEXT,
  kind TEXT NOT NULL CHECK (kind IN ('single', 'multiple', 'text', 'short_text', 'ranking', 'score', 'number', 'date', 'scale', 'slider', 'allocation')),
  required INTEGER NOT NULL DEFAULT 1,
  position INTEGER NOT NULL DEFAULT 0,
  show_if_question_id TEXT,
  show_if_option_id TEXT,
  config TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_questions_poll ON questions(poll_id);

CREATE TABLE IF NOT EXISTS options (
  id TEXT PRIMARY KEY,
  poll_id TEXT NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
  question_id TEXT NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  image_key TEXT,
  position INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_options_poll ON options(poll_id);
CREATE INDEX IF NOT EXISTS idx_options_question ON options(question_id);

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

CREATE TABLE IF NOT EXISTS tenant_admin_ip_rules (
  tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  entries_enc TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_limits (
  bucket TEXT PRIMARY KEY,
  hits INTEGER NOT NULL,
  reset_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_expiry ON rate_limits(reset_at);

CREATE TABLE IF NOT EXISTS app_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_states (
  state_hash TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);

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

CREATE TABLE IF NOT EXISTS webhooks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  secret_enc TEXT NOT NULL,
  events TEXT NOT NULL,
  created_at TEXT NOT NULL,
  disabled_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_webhooks_tenant ON webhooks(tenant_id);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id TEXT PRIMARY KEY,
  webhook_id TEXT NOT NULL,
  event TEXT NOT NULL,
  status INTEGER,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_hook ON webhook_deliveries(webhook_id, created_at);

CREATE TABLE IF NOT EXISTS vote_events (
  id TEXT PRIMARY KEY,
  poll_id TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vote_events_poll ON vote_events(poll_id, created_at);

CREATE TABLE IF NOT EXISTS local_users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  session_version INTEGER NOT NULL DEFAULT 0,
  name TEXT,
  email_verified_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS local_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  purpose TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS object_cleanup (
  tenant_id TEXT PRIMARY KEY,
  generation TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS session_epochs (
  account_id TEXT PRIMARY KEY,
  epoch INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS tenant_image_usage (
  tenant_id TEXT PRIMARY KEY,
  image_count INTEGER NOT NULL,
  total_bytes INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS email_outbox (
  id TEXT PRIMARY KEY,
  recipient TEXT NOT NULL,
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL
);
-- IP addresses enforce uniqueness, never ballot ownership. Only HMACs are stored.
-- Legacy IP-key ballots cannot be assigned to a token retroactively. Preserve
-- them and fail closed for their IP. Never return their answers via IP lookup.
CREATE TABLE IF NOT EXISTS poll_ip_ballot_owners (
  poll_id TEXT NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
  ip_key TEXT NOT NULL,
  owner_key TEXT NOT NULL,
  PRIMARY KEY (poll_id, ip_key)
);
CREATE INDEX IF NOT EXISTS idx_poll_ip_ballot_owner ON poll_ip_ballot_owners(poll_id, owner_key);

-- Survive tenant deletion: uncertain uploads must keep cleanup retryable.
CREATE TABLE IF NOT EXISTS image_upload_intents (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_image_upload_intents_tenant ON image_upload_intents(tenant_id);
`;

/** Split a multi-statement SQL script into individual statements. */
export function schemaStatements(): string[] {
  return SCHEMA_SQL.split(";")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}
