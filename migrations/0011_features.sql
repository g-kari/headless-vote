-- Poll capability flags (additive, defaults keep current behaviour).
ALTER TABLE polls ADD COLUMN results_visibility TEXT NOT NULL DEFAULT 'public';
ALTER TABLE polls ADD COLUMN ip_single_vote INTEGER NOT NULL DEFAULT 0;
ALTER TABLE polls ADD COLUMN confirm_required INTEGER NOT NULL DEFAULT 0;

-- questions: widen the kind CHECK to include ranking/score and add the
-- conditional-display columns. SQLite cannot alter a CHECK in place, so the
-- table is rebuilt. options rows are backed up first because
-- options.question_id REFERENCES questions(id) ON DELETE CASCADE.
CREATE TABLE IF NOT EXISTS options_backup_0011 AS SELECT * FROM options WHERE 1 = 0;
INSERT INTO options_backup_0011 SELECT * FROM options;

CREATE TABLE questions_new_0011 (
  id TEXT PRIMARY KEY,
  poll_id TEXT NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
  prompt TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  image_key TEXT,
  kind TEXT NOT NULL CHECK (kind IN ('single', 'multiple', 'text', 'ranking', 'score')),
  required INTEGER NOT NULL DEFAULT 1,
  position INTEGER NOT NULL DEFAULT 0,
  show_if_question_id TEXT,
  show_if_option_id TEXT,
  created_at TEXT NOT NULL
);
INSERT INTO questions_new_0011 (id, poll_id, prompt, description, image_key, kind, required, position, show_if_question_id, show_if_option_id, created_at)
  SELECT id, poll_id, prompt, description, image_key, kind, required, position, NULL, NULL, created_at FROM questions;
DROP TABLE questions;
ALTER TABLE questions_new_0011 RENAME TO questions;
CREATE INDEX IF NOT EXISTS idx_questions_poll ON questions(poll_id);

-- Restore any options rows removed by the cascade during the drop, then
-- remove the backup. Rows that survived are kept as-is (INSERT OR IGNORE).
INSERT OR IGNORE INTO options SELECT * FROM options_backup_0011;
DROP TABLE options_backup_0011;
