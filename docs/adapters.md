# Adapters

A self-hoster selects a built-in adapter with an environment variable, or adds one in `src/platform` and registers it in `createPlatform` / `selectAuthProvider`.

## AuthProvider

```ts
interface AuthProvider {
  id: string;
  label(env): string;
  capabilities: { localPasswords: boolean; emailVerification: boolean };
  verifyAccessToken(env, token): Promise<{ sub: string }>;
}
```

| `AUTH_PROVIDER` | Adapter | Behavior |
|---|---|---|
| `oidc` (default) | `oidcAuthProvider` | Authorization code + PKCE for the admin UI. Voting accepts an ID token from `OIDC_ISSUER`. No password is stored. |
| `local` | `localAuthProvider` | Email and password in `local_users` (PBKDF2-SHA-256). Verification and reset links go through the email adapter. The session subject is `local:<id>`. Bearer tokens are rejected. |

The login route (`GET /admin/login`) asks the selected provider which flow to start. Poll code calls `verifyAccessToken` and does not import an identity provider.

To add a provider: implement `AuthProvider`, add a branch in `selectAuthProvider`, and branch `GET /admin/login` if the provider needs its own browser flow.

## EmailSender

| `EMAIL_PROVIDER` | Behavior |
|---|---|
| `outbox` (default) | Inserts the message into `email_outbox`. Useful for development. Do not use it as the only production mail path. |
| `http` | `POST` JSON `{ to, subject, text }` to `EMAIL_HTTP_URL`. The URL must be `https` and must not contain credentials. Redirects are not followed. |
| `noop` | Discards the message. |

`registerLocalUser` and `requestPasswordReset` take an `EmailSender`. They do not know which one is configured.

## ObjectStore

`r2` uses the `IMAGES` binding. `memory` keeps bytes in the isolate and is for tests or a single process. Image upload, existence checks, and public image reads go through this interface.

## RateLimitStore

`d1` uses the `rate_limits` table. `memory` counts inside one isolate and is not shared across isolates. `rateLimitByIp` hashes the client address and calls `hit`. The vote and login handlers do not talk to the table themselves.

## WebhookTransport

`fetch` POSTs the signed body and returns the status, or `0` if the call fails. It does not follow redirects. `dispatchWebhooks` builds the payload and signature, then calls `post`. A test double implements the same `post` method and records the body. The signature header is `X-Headless-Vote-Signature: v1=<hex>`.

## AnalyticsStore

`d1` appends `vote_events` and reads the last 14 days. `memory` keeps the same events in the isolate. `recordVoteEvent` and the analytics routes call the store. Counts are submissions, not unique people. The store must not record a voter token.

## What stays in the core

Question validation, ballot documents, API-key hashing, member roles, quotas, and the audit log stay in the domain modules. They receive an `Env` for D1. Replacing D1 means providing an object with the same `prepare` / `batch` methods; the SQL itself is the product schema in `migrations/`.
