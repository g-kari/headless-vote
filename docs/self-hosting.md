# Self-hosting

This repository does not name a production hostname, identity provider, or client id. Those belong in your own config. See `config/example.env` and `config/wrangler.example.toml`. Neither file contains a secret.

## 1. Database and images

Create a SQL database and apply `migrations/` in order (`0001` through `0006`). On Cloudflare that is D1 plus the `DB` binding, and an R2 bucket on the `IMAGES` binding. Another host can supply a D1-shaped binding and an `ObjectStore` (see `docs/adapters.md`).

## 2. Secrets

Set `SESSION_SECRET` to a long random value in the host's secret store. Optionally set `VOTER_KEY_SECRET` so you can rotate the session secret without changing voter identity. Do not commit either value.

## 3. Choose auth

OIDC (default):

```
AUTH_PROVIDER=oidc
OIDC_ISSUER=https://idp.example.com
OIDC_CLIENT_ID=your-public-client-id
OIDC_SCOPES=openid profile email
APP_ORIGIN=https://vote.example.com
```

The issuer must be `https` with no path. Discovery URLs must stay on that origin. Register the redirect URI `https://vote.example.com/auth/callback`. If the issuer supports dynamic registration:

```bash
OIDC_ISSUER=https://idp.example.com \
REDIRECT_URI=https://vote.example.com/auth/callback \
node scripts/register-oidc-client.mjs
```

Local passwords:

```
AUTH_PROVIDER=local
EMAIL_PROVIDER=http
EMAIL_HTTP_URL=https://mail.example.com/send
APP_ORIGIN=https://vote.example.com
```

`EMAIL_PROVIDER=outbox` stores messages in the `email_outbox` table so you can develop without a mail server. Point `EMAIL_PROVIDER` at `http`, or replace `createEmailSender`, before you rely on verification mail.

## 4. Hostname

Set `APP_ORIGIN` to the origin users actually open. Add that hostname in your host's routing config (`routes` in `wrangler.toml` on Cloudflare). `workers_dev` stays false so a second hostname cannot bypass the origin check.

## 5. Other adapters

Leave the defaults (`RATE_LIMIT_STORE=d1`, `ANALYTICS_STORE=d1`, `OBJECT_STORE=r2`, `WEBHOOK_TRANSPORT=fetch`) unless you have implemented a replacement. `memory` stores do not survive another isolate and are not a production setting.

## 6. Run

```bash
npm install --legacy-peer-deps
npm test
npm run dev
```

No license file is shipped. Publishing or redistributing this code needs a license decision from the repository owner. See `CONTRIBUTING.md`.
