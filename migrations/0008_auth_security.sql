-- Revoke local sessions after password recovery. Existing local cookies must log in again.
ALTER TABLE local_users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0;
