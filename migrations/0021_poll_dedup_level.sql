-- Per-poll anonymous-vote dedup level (KAZAMI-306 #11). Anonymous voting
-- stays token-based by default; the organizer picks how strongly repeat
-- ballots from the same person are rejected:
--   token   = one ballot per voter token (browser-held), the historical default
--   ip      = one ballot per client IP (the former ip_single_vote = 1)
--   browser = one ballot per client IP + browser (User-Agent) pair
-- Strict one-person-one-vote remains the job of require_login polls.
-- ip_single_vote is kept in sync (1 for ip/browser, 0 for token) so existing
-- readers keep working; existing IP-restricted polls become level 'ip'.
ALTER TABLE polls ADD COLUMN dedup_level TEXT NOT NULL DEFAULT 'token';
UPDATE polls SET dedup_level = 'ip' WHERE ip_single_vote = 1;
