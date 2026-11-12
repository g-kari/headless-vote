#!/usr/bin/env node
/**
 * Register headless-vote as an OAuth client of 0g0-id via Dynamic Client
 * Registration (RFC 7591), then print the client_id to configure.
 *
 * Usage:
 *   node scripts/register-oidc-client.mjs
 *   REDIRECT_URI=http://localhost:8787/auth/callback node scripts/register-oidc-client.mjs
 *
 * The client is a public client (token_endpoint_auth_method "none");
 * the admin login uses Authorization Code + PKCE (S256), so no client
 * secret is issued or needed. Set the printed client_id as the
 * OIDC_CLIENT_ID var (wrangler.toml [vars] or the dashboard) and redeploy.
 */
const ISSUER = process.env.OIDC_ISSUER || "https://id.0g0.xyz";
const redirectUri =
  process.env.REDIRECT_URI || "https://vote.0g0.xyz/auth/callback";

const res = await fetch(`${ISSUER}/api/register`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    client_name: "headless-vote",
    redirect_uris: [redirectUri],
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
console.log("Registered with 0g0-id.");
console.log(`  client_id:    ${data.client_id}`);
console.log(`  redirect_uri: ${redirectUri}`);
console.log("");
console.log("Next steps:");
console.log("  1. Set OIDC_CLIENT_ID in wrangler.toml [vars] to the client_id above");
console.log("     (or set it as a var in the Cloudflare dashboard).");
console.log("  2. Redeploy: npx wrangler deploy");
console.log("  3. Open https://vote.0g0.xyz/admin/login and sign in with 0g0-id.");
