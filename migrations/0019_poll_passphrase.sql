-- Optional per-poll passphrase. Only a salted HMAC of the passphrase is
-- stored (see src/passphrase.ts); the passphrase itself never persists.
ALTER TABLE polls ADD COLUMN passphrase_hash TEXT;
