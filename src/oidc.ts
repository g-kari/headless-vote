/**
 * Generic OIDC client.
 * - Admin UI login: authorization code flow + PKCE S256.
 * - Logged-in voting: verifies JWTs from the configured issuer via JWKS (ES256).
 * The issuer, client id, and endpoints come from the environment, not from this file.
 */
import { base64UrlDecode, timingSafeEqual } from "./crypto";
import { readBodyLimited } from "./security";
import type { Env } from "./types";

const OIDC_BODY_LIMIT = 64 * 1024;
const JWT_MAX_LENGTH = 8192;

export interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  registration_endpoint?: string;
}

/** Clock-skew allowance (seconds) applied to the iat check. */
const CLOCK_SKEW_SECONDS = 60;

let discoveryCache: { issuer: string; doc: OidcDiscovery } | null = null;

/** Issuer and every OIDC URL must be https and on the same origin. */
export function assertPinnedOidcUrl(issuer: string, endpoint: string): void {
  const issuerUrl = new URL(issuer);
  const endpointUrl = new URL(endpoint);
  if (issuerUrl.protocol !== "https:" || endpointUrl.protocol !== "https:") {
    throw new Error("OIDC URLs must use https");
  }
  if (
    issuerUrl.username ||
    issuerUrl.password ||
    endpointUrl.username ||
    endpointUrl.password
  ) {
    throw new Error("OIDC URLs must not include credentials");
  }
  if (issuerUrl.pathname !== "/" && issuerUrl.pathname !== "") {
    throw new Error("OIDC issuer must not include a path");
  }
  if (issuerUrl.origin === "null" || endpointUrl.origin !== issuerUrl.origin) {
    throw new Error("OIDC endpoint is not on the issuer origin");
  }
}

function assertDiscovery(doc: OidcDiscovery): void {
  assertPinnedOidcUrl(doc.issuer, doc.authorization_endpoint);
  assertPinnedOidcUrl(doc.issuer, doc.token_endpoint);
  assertPinnedOidcUrl(doc.issuer, doc.jwks_uri);
}

async function fetchNoRedirect(url: string, init?: RequestInit): Promise<Response> {
  const res = await fetch(url, {
    ...init,
    redirect: "manual",
    signal: AbortSignal.timeout(10_000),
  });
  if (res.status >= 300 && res.status < 400) {
    await res.body?.cancel();
    throw new Error("OIDC endpoint returned a redirect");
  }
  return res;
}

async function readOidcJson(res: Response): Promise<unknown> {
  const bytes = await readBodyLimited(res, OIDC_BODY_LIMIT);
  return JSON.parse(new TextDecoder().decode(bytes));
}

export async function getDiscovery(env: Env): Promise<OidcDiscovery> {
  const issuer = env.OIDC_ISSUER.replace(/\/+$/, "");
  if (env.OIDC_AUTHORIZATION_ENDPOINT && env.OIDC_TOKEN_ENDPOINT && env.OIDC_JWKS_URI) {
    const doc = {
      issuer,
      authorization_endpoint: env.OIDC_AUTHORIZATION_ENDPOINT,
      token_endpoint: env.OIDC_TOKEN_ENDPOINT,
      jwks_uri: env.OIDC_JWKS_URI,
    };
    assertDiscovery(doc);
    return doc;
  }
  if (discoveryCache?.issuer === issuer) return discoveryCache.doc;
  assertPinnedOidcUrl(issuer, `${issuer}/.well-known/openid-configuration`);
  const res = await fetchNoRedirect(`${issuer}/.well-known/openid-configuration`);
  if (!res.ok) {
    await res.body?.cancel();
    throw new Error(`OIDC discovery failed: ${res.status}`);
  }
  const doc = (await readOidcJson(res)) as OidcDiscovery;
  doc.issuer = issuer;
  assertDiscovery(doc);
  discoveryCache = { issuer, doc };
  return doc;
}

interface Jwk {
  kid?: string;
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  n?: string;
  e?: string;
  alg?: string;
  use?: string;
}

let jwksCache: { uri: string; keys: Jwk[]; fetchedAt: number } | null = null;
const JWKS_TTL_MS = 10 * 60 * 1000;

async function getJwks(env: Env): Promise<Jwk[]> {
  if (env.OIDC_JWKS_JSON) {
    return (JSON.parse(env.OIDC_JWKS_JSON) as { keys: Jwk[] }).keys;
  }
  const discovery = await getDiscovery(env);
  const now = Date.now();
  if (jwksCache && jwksCache.uri === discovery.jwks_uri && now - jwksCache.fetchedAt < JWKS_TTL_MS) {
    return jwksCache.keys;
  }
  assertPinnedOidcUrl(discovery.issuer, discovery.jwks_uri);
  const res = await fetchNoRedirect(discovery.jwks_uri);
  if (!res.ok) {
    await res.body?.cancel();
    throw new Error(`JWKS fetch failed: ${res.status}`);
  }
  const doc = (await readOidcJson(res)) as { keys: Jwk[] };
  jwksCache = { uri: discovery.jwks_uri, keys: doc.keys, fetchedAt: now };
  return doc.keys;
}

export interface VerifiedToken {
  sub: string;
  claims: Record<string, unknown>;
}

function decodeJsonPart(part: string): Record<string, unknown> {
  try {
    return JSON.parse(
      new TextDecoder().decode(base64UrlDecode(part)),
    ) as Record<string, unknown>;
  } catch {
    throw new Error("malformed JWT");
  }
}

/**
 * Verify a JWT issued by the configured issuer.
 * - Signature: ES256 against JWKS.
 * - iss must match the issuer exactly.
 * - exp must be in the future (nbf honored when present).
 * - When `audience` is given, aud must contain it.
 * - When `nonce` is given, the nonce claim must match.
 */
export async function verifyJwt(
  env: Env,
  token: string,
  opts: { audience: string; nonce?: string },
): Promise<VerifiedToken> {
  if (!opts.audience) throw new Error("audience is required");
  if (token.length === 0 || token.length > JWT_MAX_LENGTH) throw new Error("malformed JWT");
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed JWT");
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];
  const header = decodeJsonPart(headerPart);
  const claims = decodeJsonPart(payloadPart);

  if (header["alg"] !== "ES256") throw new Error("unexpected JWT alg");
  if (header["crit"] !== undefined) throw new Error("unsupported crit");
  const typ = header["typ"];
  if (typ !== undefined && typ !== "JWT" && typ !== "jwt") throw new Error("unexpected JWT typ");
  const issuer = env.OIDC_ISSUER.replace(/\/+$/, "");
  if (claims["iss"] !== issuer) throw new Error("issuer mismatch");

  const nowSeconds = Math.floor(Date.now() / 1000);
  const exp = claims["exp"];
  if (typeof exp !== "number" || !Number.isFinite(exp) || exp <= nowSeconds) {
    throw new Error("token expired");
  }
  const nbf = claims["nbf"];
  if (nbf !== undefined && (typeof nbf !== "number" || !Number.isFinite(nbf) || nbf > nowSeconds)) {
    throw new Error("token not yet valid");
  }
  // iat is required and must be sane (ported from the PR #4 review fixes):
  // not in the future beyond a small clock-skew allowance, not after exp.
  const iat = claims["iat"];
  if (typeof iat !== "number" || !Number.isFinite(iat)) {
    throw new Error("token has no valid iat");
  }
  if (iat > nowSeconds + CLOCK_SKEW_SECONDS) throw new Error("token issued in the future");
  if (iat > exp) throw new Error("token iat is after exp");

  const aud = claims["aud"];
  const audiences = Array.isArray(aud) ? aud : aud ? [aud] : [];
  if (!audiences.includes(opts.audience)) throw new Error("audience mismatch");
  // With multiple audiences, azp must name the expected audience
  // (OIDC Core 3.1.3.7); a present azp must always match it.
  const azp = claims["azp"];
  if (audiences.length > 1 && azp !== opts.audience) {
    throw new Error("azp mismatch for multi-audience token");
  }
  if (azp !== undefined && azp !== opts.audience) {
    throw new Error("azp mismatch");
  }
  if (opts.nonce !== undefined) {
    const claimNonce = claims["nonce"];
    if (typeof claimNonce !== "string" || !timingSafeEqual(claimNonce, opts.nonce)) {
      throw new Error("nonce mismatch");
    }
  }

  const keys = await getJwks(env);
  if (header["kid"] !== undefined && typeof header["kid"] !== "string") {
    throw new Error("bad kid");
  }
  const kid = typeof header["kid"] === "string" ? header["kid"] : undefined;
  const jwk = keys.find((k) => (kid ? k.kid === kid : true) && k.kty === "EC" && k.crv === "P-256");
  if (!jwk || typeof jwk.x !== "string" || typeof jwk.y !== "string") {
    throw new Error("signing key not found");
  }

  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const signed = new TextEncoder().encode(`${headerPart}.${payloadPart}`);
  let signature: Uint8Array;
  try {
    signature = base64UrlDecode(signaturePart);
  } catch {
    throw new Error("malformed signature");
  }
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    signature as BufferSource,
    signed,
  );
  if (!ok) throw new Error("signature verification failed");

  const sub = claims["sub"];
  if (typeof sub !== "string" || sub.length === 0 || sub.length > 256) throw new Error("missing sub");
  return { sub, claims };
}

/** Exchange an authorization code at the token endpoint. */
export async function exchangeCode(
  env: Env,
  params: { code: string; codeVerifier: string; redirectUri: string },
): Promise<{ idToken: string }> {
  const discovery = await getDiscovery(env);
  assertPinnedOidcUrl(discovery.issuer, discovery.token_endpoint);
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: params.code,
    redirect_uri: params.redirectUri,
    client_id: env.OIDC_CLIENT_ID,
    code_verifier: params.codeVerifier,
  });
  const headers: Record<string, string> = {
    "content-type": "application/x-www-form-urlencoded",
  };
  if (env.OIDC_CLIENT_SECRET) {
    const basic = btoa(`${env.OIDC_CLIENT_ID}:${env.OIDC_CLIENT_SECRET}`);
    headers["authorization"] = `Basic ${basic}`;
  }
  const res = await fetchNoRedirect(discovery.token_endpoint, {
    method: "POST",
    headers,
    body: body.toString(),
  });
  if (!res.ok) {
    await res.body?.cancel();
    throw new Error(`token exchange failed: ${res.status}`);
  }
  const json = (await readOidcJson(res)) as { id_token?: unknown };
  if (typeof json.id_token !== "string" || json.id_token.length === 0 || json.id_token.length > JWT_MAX_LENGTH) {
    throw new Error("token response has no id_token");
  }
  return { idToken: json.id_token };
}
