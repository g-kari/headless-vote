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
