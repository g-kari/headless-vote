#!/usr/bin/env node
/**
 * Register headless-vote as an OAuth client via Dynamic Client
 * Registration (RFC 7591), then print the client_id to configure.
 *
 * Usage:
 *   OIDC_ISSUER=https://idp.example.com \
 *   REDIRECT_URI=https://vote.example.com/auth/callback \
 *   node scripts/register-oidc-client.mjs
 *
 * The client is a public client (token_endpoint_auth_method "none");
 * the admin login uses Authorization Code + PKCE (S256), so no client
 * secret is issued or needed. Set the printed client_id as OIDC_CLIENT_ID.
 */
const ISSUER = process.env.OIDC_ISSUER;
const redirectUri = process.env.REDIRECT_URI;

if (!ISSUER || !redirectUri) {
  console.error("OIDC_ISSUER and REDIRECT_URI are required.");
  console.error("Example: OIDC_ISSUER=https://idp.example.com REDIRECT_URI=https://vote.example.com/auth/callback node scripts/register-oidc-client.mjs");
  process.exit(1);
}

let issuerUrl;
let redirectUrl;
try {
  issuerUrl = new URL(ISSUER);
  redirectUrl = new URL(redirectUri);
} catch {
  console.error("OIDC_ISSUER and REDIRECT_URI must be absolute URLs.");
  process.exit(1);
}
if (issuerUrl.protocol !== "https:" || issuerUrl.pathname !== "/" && issuerUrl.pathname !== "") {
  console.error("OIDC_ISSUER must be an https origin with no path.");
  process.exit(1);
}

const res = await fetch(`${issuerUrl.origin}/api/register`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    client_name: "headless-vote",
    redirect_uris: [redirectUrl.toString()],
    grant_types: ["authorization_code"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
    scope: "openid profile email",
  }),
});

if (!res.ok) {
  console.error(`Registration failed: HTTP ${res.status}`);
  console.error(await res.text());
  process.exit(1);
}

const data = await res.json();
console.log("Registered an OAuth client.");
console.log(`  client_id:    ${data.client_id}`);
console.log(`  redirect_uri: ${redirectUrl.toString()}`);
console.log("");
console.log("Next steps:");
console.log("  1. Set OIDC_CLIENT_ID to the client_id above.");
console.log("  2. Set OIDC_ISSUER and APP_ORIGIN for this deployment.");
console.log("  3. Redeploy, then open /admin/login on APP_ORIGIN.");
