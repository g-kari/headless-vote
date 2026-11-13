-- Per-workspace admin IP allowlist. The entries themselves are stored only
-- as AES-GCM ciphertext (entries_enc) under the IP_LIST_ENCRYPTION_KEY
-- Worker secret; plaintext IP addresses never touch the database.
CREATE TABLE IF NOT EXISTS tenant_admin_ip_rules (
  tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  entries_enc TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
