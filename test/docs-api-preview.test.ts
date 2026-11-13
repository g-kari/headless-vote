import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { applySchema } from "./fixtures";

const BASE = "https://vote.test";

beforeAll(async () => {
  await applySchema(env.DB);
});

describe("docs API preview", () => {
  it("serves the try-it panel on /docs with an in-memory-only API key field", async () => {
    const res = await SELF.fetch(`${BASE}/docs`);
    expect(res.status).toBe(200);
    const html = await res.text();
    // Panel and controls.
    expect(html).toContain('id="api-try"');
    expect(html).toContain("API を試す");
    expect(html).toContain('id="try-endpoint"');
    expect(html).toContain('id="try-tenant"');
    expect(html).toContain('id="try-poll"');
    expect(html).toContain('id="try-path"');
    expect(html).toContain('id="try-body"');
    expect(html).toContain('id="try-response"');
    // The key field is a password input and nothing persists it.
    expect(html).toContain('id="try-key" type="password"');
    expect(html).not.toContain("localStorage");
    expect(html).not.toContain("sessionStorage");
    // Curated endpoints include a public vote call and admin calls.
    expect(html).toContain("/api/v1/polls/{pollId}/vote");
    expect(html).toContain("/api/v1/tenants/{tenantId}/polls");
    // Sample JSON bodies keep their escaped newlines (a raw newline would
    // break the inline script's string literals).
    expect(html).toContain('{\\n  "voter_token": "preview-voter-1"');
    // The Redoc reference viewer still coexists on the same page.
    expect(html).toContain('id="redoc"');
    // The docs CSP variant stays as-is: same-origin fetches are allowed,
    // scripts still require the nonce.
    const csp = res.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("connect-src 'self'");
    expect(csp).toContain("script-src 'nonce-");
  });
});
