import { SELF, env } from "cloudflare:test";
import { applySchema } from "./fixtures";
import { beforeAll, describe, expect, it } from "vitest";


const BASE = "https://vote.test";
const ISSUER = "https://id.0g0.xyz";

beforeAll(async () => {
  await applySchema(env.DB);
  // Outbound fetch from the app is routed to the mock IdP worker
  // (see vitest.config.ts): discovery is short-circuited by endpoint
  // overrides, and the token endpoint answers with a freshly signed
  // id_token for the mock authorization code used below.
});

function getCookie(res: Response, name: string): string | null {
  for (const header of res.headers.getSetCookie()) {
    const [pair] = header.split(";");
    const eq = pair?.indexOf("=") ?? -1;
    if (eq > 0 && pair?.slice(0, eq).trim() === name) {
      return pair.slice(eq + 1).trim() as string;
    }
  }
  return null;
}

function decodeFlowPayload(cookieValue: string): { state: string; nonce: string } {
  const decoded = decodeURIComponent(cookieValue);
  const payloadPart = decoded.split(".")[0] as string;
  const padded = payloadPart.replace(/-/g, "+").replace(/_/g, "/");
  const json = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  return JSON.parse(json) as { state: string; nonce: string };
}

/** Run a full login as the given sub. Returns the session cookie value. */
async function loginAs(sub: string, email: string): Promise<string> {
  const loginRes = await SELF.fetch(`${BASE}/admin/login`, {
    redirect: "manual",
  });
  expect(loginRes.status).toBe(302);
  const location = loginRes.headers.get("location") ?? "";
  expect(location.startsWith(`${ISSUER}/auth/authorize?`)).toBe(true);
  const params = new URL(location).searchParams;
  expect(params.get("code_challenge_method")).toBe("S256");
  expect(params.get("client_id")).toBe("test-client-id");
  expect(params.get("redirect_uri")).toBe(`${BASE}/auth/callback`);

  const flowCookie = getCookie(loginRes, "hv_oidc_flow");
  expect(flowCookie).toBeTruthy();
  const flow = decodeFlowPayload(flowCookie as string);
  expect(params.get("state")).toBe(flow.state);

  // The mock IdP mints an id_token for this code (mock:<sub>:<nonce>:<email>).
  const code = `mock:${sub}:${flow.nonce}:${email}`;
  const callbackRes = await SELF.fetch(
    `${BASE}/auth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(flow.state)}`,
    {
      redirect: "manual",
      headers: { cookie: `hv_oidc_flow=${flowCookie}` },
    },
  );
  expect(callbackRes.status).toBe(302);
  expect(callbackRes.headers.get("location")).toBe("/admin");
  const session = getCookie(callbackRes, "__Host-hv_session");
  expect(session).toBeTruthy();
  return session as string;
}

describe("0g0-id login flow for the admin UI", () => {
  it("logs in, creates a workspace, and isolates it from other users", async () => {
    const session = await loginAs("ui-user-1", "one@example.com");

    const adminRes = await SELF.fetch(`${BASE}/admin`, {
      headers: { cookie: `__Host-hv_session=${session}` },
    });
    expect(adminRes.status).toBe(200);
    const adminHtml = await adminRes.text();
    expect(adminHtml).toContain("ワークスペース");
    const csrf = /name="csrf_token" value="([0-9a-f]{64})"/.exec(adminHtml)?.[1];
    expect(csrf).toBeTruthy();

    const createRes = await SELF.fetch(`${BASE}/admin/workspaces`, {
      method: "POST",
      headers: {
        cookie: `__Host-hv_session=${session}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ name: "私の投票所", csrf_token: csrf as string }).toString(),
    });
    expect(createRes.status).toBe(200);
    const createdHtml = await createRes.text();
    expect(createdHtml).toContain("hvk_");
    const tenantId = /\/admin\/workspaces\/([0-9a-f-]{36})/.exec(createdHtml)?.[1];
    expect(tenantId).toBeTruthy();

    // The owner can open the workspace dashboard.
    const dashRes = await SELF.fetch(`${BASE}/admin/workspaces/${tenantId}`, {
      headers: { cookie: `__Host-hv_session=${session}` },
    });
    expect(dashRes.status).toBe(200);
    expect(await dashRes.text()).toContain("私の投票所");

    // Another logged-in user is not a member and cannot open it.
    const otherSession = await loginAs("ui-user-2", "two@example.com");
    const otherRes = await SELF.fetch(`${BASE}/admin/workspaces/${tenantId}`, {
      headers: { cookie: `__Host-hv_session=${otherSession}` },
      redirect: "manual",
    });
    expect(otherRes.status).toBe(302);
    const otherAdmin = await SELF.fetch(`${BASE}/admin`, {
      headers: { cookie: `__Host-hv_session=${otherSession}` },
    });
    expect(await otherAdmin.text()).not.toContain("私の投票所");
  });

  it("rejects a callback whose state does not match the flow cookie", async () => {
    const loginRes = await SELF.fetch(`${BASE}/admin/login`, {
      redirect: "manual",
    });
    const flowCookie = getCookie(loginRes, "hv_oidc_flow");
    const res = await SELF.fetch(
      `${BASE}/auth/callback?code=test-code&state=bogus-state`,
      {
        redirect: "manual",
        headers: { cookie: `hv_oidc_flow=${flowCookie}` },
      },
    );
    expect(res.status).toBe(400);
  });

  it("serves the admin landing with a login link when logged out", async () => {
    const res = await SELF.fetch(`${BASE}/admin`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("0g0-id でログイン");
    expect(html).toContain('href="/favicon.svg"');
  });
});
