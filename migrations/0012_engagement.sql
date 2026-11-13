-- Branding, poll templates, and in-app notifications (2026-11-13).
ALTER TABLE tenants ADD COLUMN brand_color TEXT;
ALTER TABLE tenants ADD COLUMN brand_logo_key TEXT;

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
