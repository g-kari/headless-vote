export interface Env {
  DB: D1Database;
  IMAGES: R2Bucket;
  /** Static assets (public/). Present when the [assets] binding is set. */
  ASSETS?: Fetcher;
  /** OIDC issuer origin, configured per deployment. Required when AUTH_PROVIDER=oidc. */
  OIDC_ISSUER: string;
  /** Registered public or confidential client_id at the issuer. */
  OIDC_CLIENT_ID: string;
  /** Which AuthProvider to use: "oidc" (default) or "local". */
  AUTH_PROVIDER?: string;
  /** Name shown on the login button. Defaults to the provider's own label. */
  AUTH_LABEL?: string;
  /** "outbox" (default, stores mail in D1), "http", or "noop". */
  EMAIL_PROVIDER?: string;
  /** HTTPS endpoint used when EMAIL_PROVIDER=http. No credentials in the URL. */
  EMAIL_HTTP_URL?: string;
  /** "d1" (default) or "memory". Memory does not span isolates. */
  RATE_LIMIT_STORE?: string;
  /** "fetch" (default). */
  WEBHOOK_TRANSPORT?: string;
  /** "d1" (default) or "memory". */
  ANALYTICS_STORE?: string;
  /** "r2" (default) or "memory". */
  OBJECT_STORE?: string;
  /** Optional client secret (confidential client). Leave empty for public client + PKCE. */
  OIDC_CLIENT_SECRET?: string;
  /** Space-separated scopes for the admin login. */
  OIDC_SCOPES?: string;
  /** HMAC secret for session / flow cookies. Set with `wrangler secret put`. */
  SESSION_SECRET: string;
  /**
   * Optional pepper for voter-key HMAC. When unset, SESSION_SECRET is used.
   * Set this if you want to rotate the session secret without resetting
   * one-person-one-vote identity. `wrangler secret put VOTER_KEY_SECRET`.
   */
  VOTER_KEY_SECRET?: string;
  /**
   * Canonical origin of this deployment, for example "https://vote.example.com".
   * Login is rejected on any other host (http localhost is still allowed).
   */
  APP_ORIGIN?: string;
  /** Test-only override: inline JWKS JSON used instead of fetching jwks_uri. */
  OIDC_JWKS_JSON?: string;
  /** Test-only override for the token endpoint. */
  OIDC_TOKEN_ENDPOINT?: string;
  /** Test-only override for the authorization endpoint. */
  OIDC_AUTHORIZATION_ENDPOINT?: string;
  /** Test-only override for the JWKS URI. */
  OIDC_JWKS_URI?: string;
}

export interface TenantRow {
  id: string;
  name: string;
  api_key_hash: string;
  created_at: string;
}

export interface PollRow {
  id: string;
  tenant_id: string;
  question: string;
  description: string;
  image_key: string | null;
  status: "draft" | "published" | "closed";
  allow_multiple: number;
  require_login: number;
  opens_at: string | null;
  closes_at: string | null;
  created_at: string;
  updated_at: string;
  /** Optimistic concurrency token. Changes on every successful edit. */
  revision: string;
}

export type QuestionKind = "single" | "multiple" | "text";

export interface QuestionRow {
  id: string;
  poll_id: string;
  prompt: string;
  description: string;
  image_key: string | null;
  kind: QuestionKind;
  required: number;
  position: number;
  created_at: string;
}

export interface OptionRow {
  id: string;
  poll_id: string;
  question_id: string;
  label: string;
  image_key: string | null;
  position: number;
  created_at: string;
}

/** Authenticated principal for admin operations (exactly one of the two). */
export type ApiScope = "read" | "write";

export type AdminPrincipal =
  | { kind: "api_key"; tenantId: string; keyId: string; prefix: string; scope: ApiScope }
  | { kind: "session"; tenantId: string; sub: string; role: "owner" | "member" };

/** A signed-in user (admin UI session). The subject comes from the configured auth provider. */
export interface SessionUser {
  kind: "session";
  sessionVersion?: number;
  authProvider?: "local" | "oidc";
  sub: string;
  name?: string;
  email?: string;
  exp: number;
}

export type Variables = {
  admin?: AdminPrincipal;
  sessionUser?: SessionUser;
  cspNonce?: string;
};

/** Hono context type used across the app. */
export type AppContext = import("hono").Context<{
  Bindings: Env;
  Variables: Variables;
}>;
