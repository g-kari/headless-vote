import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";
import { TEST_JWKS_JSON, TEST_PRIVATE_JWK_JSON } from "./test/fixtures.ts";

// Tests run the real Worker in miniflare (Workers runtime) with D1 + R2.
// Outbound fetch from the app is routed to a mock 0g0-id worker so the
// OIDC login flow and voter-token verification run against real ES256
// signatures without touching the production IdP.
export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        bindings: {
          SESSION_SECRET: "test-session-secret",
          OIDC_CLIENT_ID: "test-client-id",
          APP_ORIGIN: "https://vote.test",
          OIDC_AUTHORIZATION_ENDPOINT: "https://id.0g0.xyz/auth/authorize",
          OIDC_TOKEN_ENDPOINT: "https://id.0g0.xyz/api/token",
          OIDC_JWKS_URI: "https://id.0g0.xyz/.well-known/jwks.json",
          OIDC_JWKS_JSON: TEST_JWKS_JSON,
        },
        outboundService: "mock-idp",
        workers: [
          {
            name: "mock-idp",
            modules: true,
            scriptPath: "./test/mock-idp.js",
            bindings: {
              CLIENT_ID: "test-client-id",
              JWKS_JSON: TEST_JWKS_JSON,
              PRIVATE_JWK_JSON: TEST_PRIVATE_JWK_JSON,
            },
          },
        ],
      },
    }),
  ],
  test: { include: ["test/**/*.test.ts"] },
});
