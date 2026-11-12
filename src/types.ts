export interface Env {
  DB: D1Database;
  IMAGES: R2Bucket;
  /** Static assets (public/). Present when the [assets] binding is set. */
  ASSETS?: Fetcher;
  /** OIDC issuer, e.g. "https://id.0g0.xyz" */
  OIDC_ISSUER: string;
  /** Registered client_id at the issuer (set after registration). */
  OIDC_CLIENT_ID: string;
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
   * Canonical origin of this deployment, e.g. "https://vote.0g0.xyz".
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
  | { kind: "session"; tenantId: string; sub: string };

/** A signed-in 0g0-id user (admin UI session). */
export interface SessionUser {
  kind: "session";
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
