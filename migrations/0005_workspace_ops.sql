-- Quotas, signed webhooks, vote events for analytics, and member roles.
-- Existing members stay owners. Existing ballots become one analytics event each.

ALTER TABLE tenants ADD COLUMN plan TEXT NOT NULL DEFAULT 'free';
ALTER TABLE tenants ADD COLUMN quota_polls INTEGER NOT NULL DEFAULT 100;
ALTER TABLE tenants ADD COLUMN quota_keys INTEGER NOT NULL DEFAULT 10;
ALTER TABLE tenants ADD COLUMN quota_webhooks INTEGER NOT NULL DEFAULT 5;
ALTER TABLE tenants ADD COLUMN quota_votes_per_day INTEGER NOT NULL DEFAULT 5000;

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

INSERT INTO vote_events (id, poll_id, created_at)
SELECT lower(hex(randomblob(16))), poll_id, updated_at
FROM vote_ballots
WHERE NOT EXISTS (
  SELECT 1 FROM vote_events AS e WHERE e.poll_id = vote_ballots.poll_id AND e.created_at = vote_ballots.updated_at
);
