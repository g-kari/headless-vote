# Anonymous-vote dedup levels

Anonymous polls historically deduplicated by voter token only: one token,
one ballot. That is not one person, one vote, and the only stronger tool was
the boolean `ip_single_vote`. Polls now carry a `dedup_level`
(KAZAMI-306 #11, migration 0021) that the organizer picks per poll:

- `token` (default): one ballot per voter token, the historical behavior.
- `ip`: one ballot per client IP — the former `ip_single_vote = 1`.
- `browser`: one ballot per client IP + browser (User-Agent) pair, so people
  sharing a network can still vote from different browsers.

The level is settable on create, CSV import, and update (API
`dedup_level`, or the level selector in the admin editor), is carried over
by duplication and templates, and is locked once a ballot has been cast
(`RULES_LOCKED`, like the other voting rules). The legacy `ip_single_vote`
flag stays in sync (true for `ip`/`browser`) so existing readers keep
working, and an explicit `dedup_level` wins over the flag on write.

Enforcement reuses the IP-ownership machinery: at the `browser` level the
ownership slot key is the HMAC of the poll id, IP, and User-Agent instead of
the IP alone. Addresses and agent strings are never stored — only HMACs, as
before — and an IP still never grants ownership of a ballot. Strict
one-person-one-vote remains the job of `require_login` polls, where the
voter key is the account.

Validation: `test/dedup-level.test.ts` covers the default token behavior,
per-IP and per-IP+browser rejection and allowance, the legacy flag mapping,
invalid values (400), level updates before voting, the post-vote lock, and
the editor rendering the selector with the current level checked.
