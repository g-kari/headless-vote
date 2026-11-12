/**
 * Ports for everything that depends on the host environment.
 * Domain code talks to these interfaces. `createPlatform` picks an adapter
 * from configuration. A self-hosted build swaps an adapter by implementing
 * the same interface and selecting it in `createPlatform`.
 */

export interface AuthIdentity {
  sessionVersion?: number;
  sub: string;
  email?: string;
  name?: string;
}

export interface AuthCapabilities {
  /** This deployment stores passwords and can reset them. */
  localPasswords: boolean;
  /** This deployment can mark an email address verified. */
  emailVerification: boolean;
}

export interface AuthProvider {
  readonly id: string;
  label(env: { AUTH_LABEL?: string }): string;
  readonly capabilities: AuthCapabilities;
  /**
   * Verify a bearer token presented to the voting API.
   * Throws when the token is present but not valid. Providers that do not
   * use bearer tokens throw for every token.
   */
  verifyAccessToken(env: import("../types").Env, token: string): Promise<AuthIdentity>;
}

export interface EmailMessage {
  to: string;
  subject: string;
  text: string;
}

export interface EmailSender {
  readonly id: string;
  send(message: EmailMessage): Promise<void>;
}

export interface StoredObject {
  body: ReadableStream | null;
  httpEtag: string;
  contentType: string | null;
}

export interface ObjectStore {
  /** Delete one bounded page; repeat with the returned cursor until null. */
  deletePrefix(prefix: string, cursor?: string): Promise<string | null>;
  readonly id: string;
  put(key: string, body: ArrayBuffer | Uint8Array, contentType: string): Promise<void>;
  get(key: string): Promise<StoredObject | null>;
  head(key: string): Promise<boolean>;
}

export interface RateLimitStore {
  readonly id: string;
  /** Throws 429 when the bucket is over its limit. */
  hit(bucket: string, limit: number, windowSec: number): Promise<void>;
}

export interface WebhookTransport {
  readonly id: string;
  /** Returns the HTTP status, or 0 when the request did not complete. */
  post(url: string, body: string, headers: Record<string, string>): Promise<number>;
}

export interface DayCount {
  date: string;
  count: number;
}

export interface AnalyticsStore {
  readonly id: string;
  record(pollId: string, at: string): Promise<void>;
  pollSeries(pollId: string, days: number): Promise<DayCount[]>;
  workspaceSeries(tenantId: string, days: number): Promise<DayCount[]>;
}

export interface Platform {
  auth: AuthProvider;
  email: EmailSender;
  objects: ObjectStore;
  rateLimits: RateLimitStore;
  webhooks: WebhookTransport;
  analytics: AnalyticsStore;
}
