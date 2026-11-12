/**
 * Mock OIDC provider used only by the test suite.
 *
 * The main worker's outbound fetch is routed to this worker (Miniflare
 * `outboundService`), so the app's server-side calls to the token endpoint
 * are answered here instead of reaching the real https://idp.example.test.
 *
 * The authorization "code" the test passes to /auth/callback encodes what
 * this mock should return:  mock:<sub>:<nonce>:<email>
 * The id_token is signed with the test-only keypair from fixtures.ts.
 */

function b64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlJson(value) {
  return b64url(new TextEncoder().encode(JSON.stringify(value)));
}

async function signIdToken(env, claims) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "ES256", typ: "JWT", kid: "test-key-1" };
  const payload = {
    iss: "https://idp.example.test",
    aud: env.CLIENT_ID,
    iat: now,
    exp: now + 3600,
    ...claims,
  };
  const unsigned = `${b64urlJson(header)}.${b64urlJson(payload)}`;
  const key = await crypto.subtle.importKey(
    "jwk",
    JSON.parse(env.PRIVATE_JWK_JSON),
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/.well-known/openid-configuration") {
      return Response.json({
        issuer: "https://idp.example.test",
        authorization_endpoint: "https://idp.example.test/auth/authorize",
        token_endpoint: "https://idp.example.test/api/token",
        jwks_uri: "https://idp.example.test/.well-known/jwks.json",
      });
    }

    if (url.pathname === "/.well-known/jwks.json") {
      return Response.json(JSON.parse(env.JWKS_JSON));
    }

    if (url.pathname === "/api/token" && request.method === "POST") {
      const form = new URLSearchParams(await request.text());
      const code = form.get("code") ?? "";
      const parts = code.split(":");
      if (parts[0] !== "mock" || parts.length < 4) {
        return Response.json(
          { error: "invalid_grant", error_description: "unknown mock code" },
          { status: 400 },
        );
      }
      const [, sub, nonce, email] = parts;
      const idToken = await signIdToken(env, {
        sub,
        nonce,
        email,
        name: "テストユーザー",
      });
      return Response.json({
        id_token: idToken,
        access_token: "mock-access-token",
        token_type: "Bearer",
        expires_in: 3600,
      });
    }

    return new Response("mock-idp: not found", { status: 404 });
  },
};
