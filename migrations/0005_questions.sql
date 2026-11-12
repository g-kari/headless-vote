-- Multiple questions per poll. Existing polls become one question, and
-- their options and ballots stay attached to that question.

CREATE TABLE IF NOT EXISTS questions (
  id TEXT PRIMARY KEY,
  poll_id TEXT NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
  prompt TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  image_key TEXT,
  kind TEXT NOT NULL CHECK (kind IN ('single', 'multiple', 'text')),
  required INTEGER NOT NULL DEFAULT 1,
  position INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_questions_poll ON questions(poll_id);

INSERT INTO questions (id, poll_id, prompt, description, image_key, kind, required, position, created_at)
SELECT id, id, question, '', image_key,
       CASE WHEN allow_multiple = 1 THEN 'multiple' ELSE 'single' END,
       1, 0, created_at
FROM polls
WHERE NOT EXISTS (SELECT 1 FROM questions AS q WHERE q.poll_id = polls.id);

ALTER TABLE options ADD COLUMN question_id TEXT;

UPDATE options SET question_id = poll_id WHERE question_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_options_question ON options(question_id);

-- Wrap legacy ballots (a JSON array of option ids) as an answer to the
-- migrated question. The question id equals the poll id for those rows.
UPDATE vote_ballots
SET option_ids = json_object(
  'v', 2,
  'answers', json_array(
    json_object('question_id', poll_id, 'option_ids', json(option_ids))
  )
)
WHERE json_valid(option_ids) AND json_type(option_ids) = 'array';
