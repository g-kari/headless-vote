-- Per-poll deadline reminder: when enabled, the scheduled job emits one
-- admin notification and one poll.deadline_reminder webhook once the poll
-- is within reminder_lead_hours of its deadline.
ALTER TABLE polls ADD COLUMN reminder_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE polls ADD COLUMN reminder_lead_hours INTEGER NOT NULL DEFAULT 24;
