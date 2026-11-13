-- New question kinds (short_text, number, date, scale, slider, allocation)
-- and a per-question config column (JSON). SQLite cannot alter a CHECK in
-- place, so the table is rebuilt following the 0011 pattern: options rows
-- are backed up first because options.question_id REFERENCES questions(id)
-- ON DELETE CASCADE.

CREATE TABLE IF NOT EXISTS options_backup_0018 AS SELECT * FROM options WHERE 1 = 0;
INSERT INTO options_backup_0018 SELECT * FROM options;

CREATE TABLE questions_new_0018 (
  id TEXT PRIMARY KEY,
  poll_id TEXT NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
  prompt TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  image_key TEXT,
  kind TEXT NOT NULL CHECK (kind IN ('single', 'multiple', 'text', 'short_text', 'ranking', 'score', 'number', 'date', 'scale', 'slider', 'allocation')),
  required INTEGER NOT NULL DEFAULT 1,
  position INTEGER NOT NULL DEFAULT 0,
  show_if_question_id TEXT,
  show_if_option_id TEXT,
  config TEXT,
  created_at TEXT NOT NULL
);

INSERT INTO questions_new_0018 (id, poll_id, prompt, description, image_key, kind, required, position, show_if_question_id, show_if_option_id, config, created_at)
  SELECT id, poll_id, prompt, description, image_key, kind, required, position, show_if_question_id, show_if_option_id, NULL, created_at FROM questions;
DROP TABLE questions;
ALTER TABLE questions_new_0018 RENAME TO questions;
CREATE INDEX IF NOT EXISTS idx_questions_poll ON questions(poll_id);

-- Restore any options rows removed by the cascade during the drop, then
-- remove the backup. Rows that survived are kept as-is (INSERT OR IGNORE).
INSERT OR IGNORE INTO options SELECT * FROM options_backup_0018;
DROP TABLE options_backup_0018;
