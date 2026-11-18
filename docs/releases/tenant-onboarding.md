# Tenant onboarding: login required and a total cap

Creating a workspace through `POST /api/v1/tenants` used to be open to any
anonymous caller: the only brakes were rate limits, and the new tenant had no
owner until someone claimed it. Two changes close that (KAZAMI-306 #10).

Creation now requires a verified login session, and the creator is recorded
as the workspace owner in `tenant_members`. Because the endpoint now relies
on the session cookie, it also applies the same-origin mutation check, so a
cross-site request is rejected with 403 even when a session cookie rides
along. The response shape is unchanged (tenant id plus the one-time API key).

Provisioning also enforces a hard cap on the total number of tenants,
independent of the daily creation rate limit. The cap defaults to 1000 and
can be set with the `MAX_TENANTS` variable. The gate is a conditional insert
inside `provisionTenant`, so concurrent requests cannot slip past it, and a
rejected attempt (503 `TENANT_LIMIT_REACHED`) writes no tenant, key, or
membership rows.

Validation: `test/tenant-onboarding.test.ts` covers anonymous rejection
(401, nothing written), cross-site rejection with a session (403), owner
recording for the creator, and the cap boundary (no partial rows at the cap,
exactly one more tenant allowed when the cap leaves room for one). The
tenant-creation fixtures across the suite now log in through the shared
helper in `test/session.ts`.
