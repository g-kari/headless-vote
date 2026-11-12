/**
 * Test-only OIDC keypair (generated for this repository's test suite).
 * The private key is a fixture: it is NOT used in production and the matching
 * JWKS is injected into tests through the OIDC_JWKS_JSON binding only.
 */
export const TEST_PUBLIC_JWK = {
  kty: "EC",
  x: "vWu4wHhBEXjtTleV2uzkmysDzQIIN9FJTIXmutWmGc4",
  y: "eWy6N3O0ZrgnQe7DGSCNWNGR2_DsZR_pncQZ5_VPXMc",
  crv: "P-256",
  kid: "test-key-1",
  alg: "ES256",
  use: "sig",
} as const;

export const TEST_PRIVATE_JWK = {
  kty: "EC",
  x: "vWu4wHhBEXjtTleV2uzkmysDzQIIN9FJTIXmutWmGc4",
  y: "eWy6N3O0ZrgnQe7DGSCNWNGR2_DsZR_pncQZ5_VPXMc",
  crv: "P-256",
  d: "Gc4Vb4EHFcAU6lX0bptCzh3h_SrMs0kEWvjjNmRjZb0",
} as const;

export const TEST_ISSUER = "https://idp.example.test";
export const TEST_CLIENT_ID = "test-client-id";

import { schemaStatements } from "../src/schema";

/** Apply the app schema to a fresh D1 database (statement by statement). */
export async function applySchema(db: D1Database): Promise<void> {
  await db.batch(schemaStatements().map((stmt) => db.prepare(stmt)));
}

/** TEST-ONLY private JWK (JSON string) for the mock IdP worker. */
export const TEST_PRIVATE_JWK_JSON = JSON.stringify(TEST_PRIVATE_JWK);
export const TEST_JWKS_JSON = JSON.stringify({ keys: [TEST_PUBLIC_JWK] });

function b64url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlJson(value: unknown): string {
  return b64url(new TextEncoder().encode(JSON.stringify(value)));
}

/** Sign a JWT (ES256) with the test keypair, shaped like an OIDC id_token. */
export async function signTestJwt(
  claims: Record<string, unknown>,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "ES256", typ: "JWT", kid: "test-key-1" };
  const payload = {
    iss: TEST_ISSUER,
    aud: TEST_CLIENT_ID,
    iat: now,
    exp: now + 3600,
    ...claims,
  };
  const unsigned = `${b64urlJson(header)}.${b64urlJson(payload)}`;
  const key = await crypto.subtle.importKey(
    "jwk",
    TEST_PRIVATE_JWK,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new TextEncoder().encode(unsigned),
  );
  return `${unsigned}.${b64url(new Uint8Array(signature))}`;
}
