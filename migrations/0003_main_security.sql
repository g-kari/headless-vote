-- Preserve 0002: this is an additive migration for existing deployments.
ALTER TABLE polls ADD COLUMN revision INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS poll_mutation_guards (
  id TEXT PRIMARY KEY,
  valid INTEGER NOT NULL CONSTRAINT poll_mutation_allowed CHECK (valid = 1)
);
CREATE INDEX IF NOT EXISTS idx_rate_limit_expiry ON rate_limit_buckets(window_start);
