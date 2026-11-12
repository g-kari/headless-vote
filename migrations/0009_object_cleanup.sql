CREATE TABLE IF NOT EXISTS object_cleanup (
  tenant_id TEXT PRIMARY KEY,
  generation TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
