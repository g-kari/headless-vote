-- Internal account ids: Hyo no longer keys accounts by the identity
-- provider's `sub`. A server-side mapping table (accounts) links each
-- subject to a random internal id; memberships, session epochs, and audit
-- actors move to the internal id, and historical audit rows that embedded
-- a subject are rewritten to the internal id.

CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  subject TEXT NOT NULL UNIQUE,
  email TEXT,
  name TEXT,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_accounts_email ON accounts(email);

CREATE TABLE IF NOT EXISTS member_invites (
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'member',
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, email)
);
CREATE INDEX IF NOT EXISTS idx_member_invites_email ON member_invites(email);

-- Backfill the mapping from every place a subject was used as a key.
INSERT OR IGNORE INTO accounts (id, subject, email, name, created_at, last_seen_at)
SELECT
  lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' ||
  substr(lower(hex(randomblob(2))), 2) || '-' ||
  substr('89ab', 1 + (abs(random()) % 4), 1) || substr(lower(hex(randomblob(2))), 2) || '-' ||
  lower(hex(randomblob(6))),
  user_sub, NULL, NULL, MIN(created_at), MIN(created_at)
FROM tenant_members GROUP BY user_sub;

INSERT OR IGNORE INTO accounts (id, subject, email, name, created_at, last_seen_at)
SELECT
  lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' ||
  substr(lower(hex(randomblob(2))), 2) || '-' ||
  substr('89ab', 1 + (abs(random()) % 4), 1) || substr(lower(hex(randomblob(2))), 2) || '-' ||
  lower(hex(randomblob(6))),
  'local:' || id, lower(email), name, created_at, created_at
FROM local_users;

INSERT OR IGNORE INTO accounts (id, subject, email, name, created_at, last_seen_at)
SELECT
  lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' ||
  substr(lower(hex(randomblob(2))), 2) || '-' ||
  substr('89ab', 1 + (abs(random()) % 4), 1) || substr(lower(hex(randomblob(2))), 2) || '-' ||
  lower(hex(randomblob(6))),
  sub, NULL, NULL, '1970-01-01T00:00:00.000Z', '1970-01-01T00:00:00.000Z'
FROM session_epochs;

INSERT OR IGNORE INTO accounts (id, subject, email, name, created_at, last_seen_at)
SELECT
  lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' ||
  substr(lower(hex(randomblob(2))), 2) || '-' ||
  substr('89ab', 1 + (abs(random()) % 4), 1) || substr(lower(hex(randomblob(2))), 2) || '-' ||
  lower(hex(randomblob(6))),
  substr(actor, 9), NULL, NULL, '1970-01-01T00:00:00.000Z', '1970-01-01T00:00:00.000Z'
FROM audit_events WHERE actor LIKE 'session:%';

-- tenant_members: user_sub -> account_id (table rebuild).
ALTER TABLE tenant_members ADD COLUMN account_id TEXT;
UPDATE tenant_members
SET account_id = (SELECT id FROM accounts WHERE accounts.subject = tenant_members.user_sub);

CREATE TABLE tenant_members_migrated (
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'owner',
  created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, account_id)
);
INSERT INTO tenant_members_migrated (tenant_id, account_id, role, created_at)
SELECT tenant_id, account_id, role, created_at FROM tenant_members WHERE account_id IS NOT NULL;
DROP TABLE tenant_members;
ALTER TABLE tenant_members_migrated RENAME TO tenant_members;

-- session_epochs: sub -> account_id (table rebuild).
ALTER TABLE session_epochs ADD COLUMN account_id TEXT;
UPDATE session_epochs
SET account_id = (SELECT id FROM accounts WHERE accounts.subject = session_epochs.sub);

CREATE TABLE session_epochs_migrated (
  account_id TEXT PRIMARY KEY,
  epoch INTEGER NOT NULL DEFAULT 0
);
INSERT INTO session_epochs_migrated (account_id, epoch)
SELECT account_id, epoch FROM session_epochs WHERE account_id IS NOT NULL;
DROP TABLE session_epochs;
ALTER TABLE session_epochs_migrated RENAME TO session_epochs;

-- Scrub historical audit rows: actors and member-operation targets that
-- embedded a raw subject are rewritten to the internal account id.
UPDATE audit_events
SET actor = 'session:' || (SELECT id FROM accounts WHERE accounts.subject = substr(audit_events.actor, 9))
WHERE actor LIKE 'session:%'
  AND EXISTS (SELECT 1 FROM accounts WHERE accounts.subject = substr(audit_events.actor, 9));

UPDATE audit_events
SET target = (SELECT id FROM accounts WHERE accounts.subject = audit_events.target)
WHERE action IN ('member.add', 'member.role', 'member.remove')
  AND target IS NOT NULL
  AND EXISTS (SELECT 1 FROM accounts WHERE accounts.subject = audit_events.target);
