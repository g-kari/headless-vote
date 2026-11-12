/**
 * Minimal OIDC client/verifier for 0g0-id (issuer https://id.0g0.xyz).
 * - Admin UI login: authorization code flow + PKCE S256.
 * - Logged-in voting: verifies JWTs (id_token) issued by 0g0-id via JWKS (ES256).
 */
import { base64UrlDecode } from "./crypto";
import type { Env } from "./types";

export interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  registration_endpoint?: string;
}

let discoveryCache: { issuer: string; doc: OidcDiscovery } | null = null;

export async function getDiscovery(env: Env): Promise<OidcDiscovery> {
  const issuer = env.OIDC_ISSUER.replace(/\/+$/, "");
  if (env.OIDC_AUTHORIZATION_ENDPOINT && env.OIDC_TOKEN_ENDPOINT && env.OIDC_JWKS_URI) {
    return {
      issuer,
      authorization_endpoint: env.OIDC_AUTHORIZATION_ENDPOINT,
      token_endpoint: env.OIDC_TOKEN_ENDPOINT,
      jwks_uri: env.OIDC_JWKS_URI,
    };
  }
  if (discoveryCache?.issuer === issuer) return discoveryCache.doc;
  const res = await fetch(`${issuer}/.well-known/openid-configuration`);
  if (!res.ok) throw new Error(`OIDC discovery failed: ${res.status}`);
  const doc = (await res.json()) as OidcDiscovery;
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
  const res = await fetch(discovery.jwks_uri);
  if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
  const doc = (await res.json()) as { keys: Jwk[] };
  jwksCache = { uri: discovery.jwks_uri, keys: doc.keys, fetchedAt: now };
  return doc.keys;
}

export interface VerifiedToken {
  sub: string;
  claims: Record<string, unknown>;
}

function decodeJsonPart(part: string): Record<string, unknown> {
  return JSON.parse(
    new TextDecoder().decode(base64UrlDecode(part)),
  ) as Record<string, unknown>;
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
  opts: { audience?: string; nonce?: string } = {},
): Promise<VerifiedToken> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed JWT");
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];
  const header = decodeJsonPart(headerPart);
  const claims = decodeJsonPart(payloadPart);

  if (header["alg"] !== "ES256") throw new Error("unexpected JWT alg");
  const issuer = env.OIDC_ISSUER.replace(/\/+$/, "");
  if (claims["iss"] !== issuer) throw new Error("issuer mismatch");

  const nowSeconds = Math.floor(Date.now() / 1000);
  const exp = claims["exp"];
  if (typeof exp !== "number" || exp <= nowSeconds) throw new Error("token expired");
  const nbf = claims["nbf"];
  if (typeof nbf === "number" && nbf > nowSeconds) throw new Error("token not yet valid");

  if (opts.audience) {
    const aud = claims["aud"];
    const audiences = Array.isArray(aud) ? aud : aud ? [aud] : [];
    if (!audiences.includes(opts.audience)) throw new Error("audience mismatch");
  }
  if (opts.nonce !== undefined && claims["nonce"] !== opts.nonce) {
    throw new Error("nonce mismatch");
  }

  const keys = await getJwks(env);
  const kid = header["kid"];
  const jwk = keys.find((k) => (kid ? k.kid === kid : true) && k.kty === "EC" && k.crv === "P-256");
  if (!jwk) throw new Error("signing key not found");

  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const signed = new TextEncoder().encode(`${headerPart}.${payloadPart}`);
  const signature = base64UrlDecode(signaturePart);
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    signature as BufferSource,
    signed,
  );
  if (!ok) throw new Error("signature verification failed");

  const sub = claims["sub"];
  if (typeof sub !== "string" || sub.length === 0) throw new Error("missing sub");
  return { sub, claims };
}

/** Exchange an authorization code at the token endpoint. */
export async function exchangeCode(
  env: Env,
  params: { code: string; codeVerifier: string; redirectUri: string },
): Promise<{ idToken: string; accessToken?: string }> {
  const discovery = await getDiscovery(env);
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
  const res = await fetch(discovery.token_endpoint, {
    method: "POST",
    headers,
    body: body.toString(),
  });
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`token exchange failed: ${res.status} ${detail.slice(0, 200)}`);
  }
  const json = (await res.json()) as { id_token?: string; access_token?: string };
  if (!json.id_token) throw new Error("token response has no id_token");
  return { idToken: json.id_token, accessToken: json.access_token };
}
