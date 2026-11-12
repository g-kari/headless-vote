import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { applySchema, signTestJwt } from "./fixtures";

const BASE = "https://vote.test";

beforeAll(async () => {
  await applySchema(env.DB);
});

async function createTenantWithPoll(
  overrides: Record<string, unknown> = {},
): Promise<{ pollId: string; optionIds: string[] }> {
  const tRes = await SELF.fetch(`${BASE}/api/v1/tenants`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: "ログイン投票テスト" }),
  });
  const t = (await tRes.json()) as { tenant: { id: string }; api_key: string };
  const pRes = await SELF.fetch(`${BASE}/api/v1/tenants/${t.tenant.id}/polls`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${t.api_key}`,
    },
    body: JSON.stringify({
      question: "ログイン投票のテスト",
      options: [{ label: "賛成" }, { label: "反対" }],
      ...overrides,
    }),
  });
  const p = (await pRes.json()) as {
    poll: { id: string; options: { id: string }[] };
  };
  await SELF.fetch(
    `${BASE}/api/v1/tenants/${t.tenant.id}/polls/${p.poll.id}/status`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${t.api_key}`,
      },
      body: JSON.stringify({ status: "published" }),
    },
  );
  return { pollId: p.poll.id, optionIds: p.poll.options.map((o) => o.id) };
}

async function vote(
  pollId: string,
  body: Record<string, unknown>,
  token?: string,
): Promise<Response> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (token) headers["authorization"] = `Bearer ${token}`;
  return SELF.fetch(`${BASE}/api/v1/polls/${pollId}/vote`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

async function totals(pollId: string) {
  const res = await SELF.fetch(`${BASE}/api/v1/polls/${pollId}/results`);
  const data = (await res.json()) as {
    results: {
      total_voters: number;
      options: { id: string; votes: number }[];
    };
  };
  return data.results;
}

describe("login-required polls", () => {
  it("rejects anonymous votes", async () => {
    const { pollId, optionIds } = await createTenantWithPoll({
      require_login: true,
    });
    const res = await vote(pollId, {
      option_ids: [optionIds[0]],
      voter_token: "token-anon-1",
    });
    expect(res.status).toBe(401);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "LOGIN_REQUIRED",
    );
  });

  it("accepts a logged-in vote keyed by sub, and re-votes overwrite", async () => {
    const { pollId, optionIds } = await createTenantWithPoll({
      require_login: true,
    });
    const jwt = await signTestJwt({ sub: "pairwise-user-1" });
    const first = await vote(pollId, { option_ids: [optionIds[0]] }, jwt);
    expect(first.status).toBe(200);
    const firstData = (await first.json()) as { vote: { voter: string } };
    expect(firstData.vote.voter).toBe("user");

    let r = await totals(pollId);
    expect(r.total_voters).toBe(1);
    expect(r.options.find((o) => o.id === optionIds[0])?.votes).toBe(1);

    // Same sub re-votes: still one voter, choice replaced.
    const second = await vote(pollId, { option_ids: [optionIds[1]] }, jwt);
    expect(second.status).toBe(200);
    r = await totals(pollId);
    expect(r.total_voters).toBe(1);
    expect(r.options.find((o) => o.id === optionIds[0])?.votes).toBe(0);
    expect(r.options.find((o) => o.id === optionIds[1])?.votes).toBe(1);

    // A different sub is a different voter.
    const other = await signTestJwt({ sub: "pairwise-user-2" });
    await vote(pollId, { option_ids: [optionIds[0]] }, other);
    r = await totals(pollId);
    expect(r.total_voters).toBe(2);
  });
});

describe("open polls with optional login", () => {
  it("counts logged-in and anonymous voters as distinct voters", async () => {
    const { pollId, optionIds } = await createTenantWithPoll();
    const jwt = await signTestJwt({ sub: "pairwise-user-9" });
    const loggedIn = await vote(pollId, { option_ids: [optionIds[0]] }, jwt);
    expect(loggedIn.status).toBe(200);
    const anon = await vote(pollId, {
      option_ids: [optionIds[0]],
      voter_token: "token-someone",
    });
    expect(anon.status).toBe(200);
    const r = await totals(pollId);
    expect(r.total_voters).toBe(2);
    expect(r.options.find((o) => o.id === optionIds[0])?.votes).toBe(2);
  });

  it("rejects invalid or expired login tokens instead of downgrading", async () => {
    const { pollId, optionIds } = await createTenantWithPoll();
    const garbage = await vote(pollId, { option_ids: [optionIds[0]] }, "not-a-jwt");
    expect(garbage.status).toBe(401);
    expect(
      ((await garbage.json()) as { error: { code: string } }).error.code,
    ).toBe("INVALID_TOKEN");

    const expired = await signTestJwt({
      sub: "pairwise-user-1",
      exp: Math.floor(Date.now() / 1000) - 60,
    });
    const expiredRes = await vote(pollId, { option_ids: [optionIds[0]] }, expired);
    expect(expiredRes.status).toBe(401);

    const wrongAudience = await signTestJwt({
      sub: "pairwise-user-1",
      aud: "some-other-client",
    });
    const audRes = await vote(pollId, { option_ids: [optionIds[0]] }, wrongAudience);
    expect(audRes.status).toBe(401);
  });
});
