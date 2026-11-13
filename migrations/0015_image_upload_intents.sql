-- Survive tenant deletion: uncertain uploads must keep cleanup retryable.
CREATE TABLE IF NOT EXISTS image_upload_intents (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_image_upload_intents_tenant ON image_upload_intents(tenant_id);
