-- Bound global expiry cleanup for one-off rate limit identifiers.
CREATE INDEX IF NOT EXISTS idx_rate_limits_expiry ON rate_limits(reset_at);
