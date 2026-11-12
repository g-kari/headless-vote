-- Security and embed-origin settings.
-- Applied after 0001. Safe on databases that already have votes.

ALTER TABLE polls ADD COLUMN revision TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS vote_ballots (
  poll_id TEXT NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
  voter_key TEXT NOT NULL,
  option_ids TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (poll_id, voter_key)
);

-- One row per voter. Existing per-option rows are folded in so a deploy
-- does not let those voters vote a second time under a new table.
INSERT INTO vote_ballots (poll_id, voter_key, option_ids, updated_at)
SELECT poll_id, voter_key, json_group_array(option_id), MAX(updated_at)
FROM votes
GROUP BY poll_id, voter_key;

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
