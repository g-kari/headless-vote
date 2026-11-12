import { SELF, env } from "cloudflare:test";
import { applySchema } from "./fixtures";
import { beforeAll, describe, expect, it } from "vitest";


const BASE = "https://vote.test";

beforeAll(async () => {
  await applySchema(env.DB);
});

interface Tenant {
  id: string;
  apiKey: string;
}

async function createTenant(name: string): Promise<Tenant> {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name }),
  });
  expect(res.status).toBe(201);
  const data = (await res.json()) as {
    tenant: { id: string };
    api_key: string;
  };
  return { id: data.tenant.id, apiKey: data.api_key };
}

async function createPoll(
  tenant: Tenant,
  overrides: Record<string, unknown> = {},
): Promise<{ id: string; options: { id: string; label: string }[] }> {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/polls`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${tenant.apiKey}`,
    },
    body: JSON.stringify({
      question: "好きな色は？",
      description: "テスト用の投票です",
      options: [{ label: "赤" }, { label: "青" }, { label: "緑" }],
      ...overrides,
    }),
  });
  expect(res.status).toBe(201);
  const data = (await res.json()) as {
    poll: { id: string; options: { id: string; label: string }[] };
  };
  return data.poll;
}

async function setStatus(
  tenant: Tenant,
  pollId: string,
  status: string,
): Promise<Response> {
  return SELF.fetch(
    `${BASE}/api/v1/tenants/${tenant.id}/polls/${pollId}/status`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${tenant.apiKey}`,
      },
      body: JSON.stringify({ status }),
    },
  );
}

async function vote(
  pollId: string,
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
): Promise<Response> {
  return SELF.fetch(`${BASE}/api/v1/polls/${pollId}/vote`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

async function results(pollId: string) {
  const res = await SELF.fetch(`${BASE}/api/v1/polls/${pollId}/results`);
  expect(res.status).toBe(200);
  const data = (await res.json()) as {
    results: {
      total_voters: number;
      total_votes: number;
      options: { id: string; votes: number }[];
    };
  };
  return data.results;
}

describe("health + tenant onboarding", () => {
  it("health endpoint responds", async () => {
    const res = await SELF.fetch(`${BASE}/api/v1/health`);
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ok: true });
  });

  it("tenant creation returns an API key exactly once", async () => {
    const tenant = await createTenant("テストテナント");
    expect(tenant.id).toBeTruthy();
    expect(tenant.apiKey.startsWith("hvk_")).toBe(true);
  });

  it("rejects an invalid API key", async () => {
    const tenant = await createTenant("キー確認用");
    const res = await SELF.fetch(
      `${BASE}/api/v1/tenants/${tenant.id}/polls`,
      { headers: { authorization: "Bearer hvk_wrong" } },
    );
    expect(res.status).toBe(401);
    const data = (await res.json()) as { error: { code: string } };
    expect(data.error.code).toBe("INVALID_API_KEY");
  });
});

describe("poll lifecycle", () => {
  it("draft polls are invisible to the public API", async () => {
    const tenant = await createTenant("ライフサイクル");
    const poll = await createPoll(tenant);
    const res = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}`);
    expect(res.status).toBe(404);
    const pub = await setStatus(tenant, poll.id, "published");
    expect(pub.status).toBe(200);
    const after = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}`);
    expect(after.status).toBe(200);
    const data = (await after.json()) as {
      poll: { question: string; options: unknown[]; require_login: boolean };
    };
    expect(data.poll.question).toBe("好きな色は？");
    expect(data.poll.options).toHaveLength(3);
    expect(data.poll.require_login).toBe(false);
  });

  it("tenants cannot see or modify each other's polls", async () => {
    const a = await createTenant("テナントA");
    const b = await createTenant("テナントB");
    const poll = await createPoll(a);
    const listRes = await SELF.fetch(`${BASE}/api/v1/tenants/${a.id}/polls`, {
      headers: { authorization: `Bearer ${b.apiKey}` },
    });
    expect(listRes.status).toBe(401);
    const patchRes = await SELF.fetch(
      `${BASE}/api/v1/tenants/${a.id}/polls/${poll.id}`,
      {
        method: "PATCH",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${b.apiKey}`,
        },
        body: JSON.stringify({ question: "乗っ取り" }),
      },
    );
    expect(patchRes.status).toBe(401);
    // B's own list is empty
    const ownList = await SELF.fetch(`${BASE}/api/v1/tenants/${b.id}/polls`, {
      headers: { authorization: `Bearer ${b.apiKey}` },
    });
    const ownData = (await ownList.json()) as { polls: unknown[] };
    expect(ownData.polls).toHaveLength(0);
  });

  it("closed polls and past deadlines reject votes", async () => {
    const tenant = await createTenant("締切");
    const poll = await createPoll(tenant);
    await setStatus(tenant, poll.id, "published");
    await setStatus(tenant, poll.id, "closed");
    const closedVote = await vote(poll.id, {
      option_ids: [poll.options[0]?.id],
      voter_token: "voter-token-1",
    });
    expect(closedVote.status).toBe(409);
    expect(
      ((await closedVote.json()) as { error: { code: string } }).error.code,
    ).toBe("POLL_CLOSED");

    const past = await createPoll(tenant, {
      closes_at: new Date(Date.now() - 60_000).toISOString(),
    });
    await setStatus(tenant, past.id, "published");
    const lateVote = await vote(past.id, {
      option_ids: [past.options[0]?.id],
      voter_token: "voter-token-1",
    });
    expect(lateVote.status).toBe(409);
  });
});

describe("anonymous voting (one person, one vote)", () => {
  it("counts one vote per voter token and lets the voter change it", async () => {
    const tenant = await createTenant("匿名投票");
    const poll = await createPoll(tenant);
    await setStatus(tenant, poll.id, "published");
    const [red, blue] = [poll.options[0] as { id: string }, poll.options[1] as { id: string }];

    const first = await vote(poll.id, {
      option_ids: [red.id],
      voter_token: "token-alice",
    });
    expect(first.status).toBe(200);
    let r = await results(poll.id);
    expect(r.total_voters).toBe(1);
    expect(r.options.find((o) => o.id === red.id)?.votes).toBe(1);

    // Re-vote with the same token replaces the previous choice.
    const second = await vote(poll.id, {
      option_ids: [blue.id],
      voter_token: "token-alice",
    });
    expect(second.status).toBe(200);
    r = await results(poll.id);
    expect(r.total_voters).toBe(1);
    expect(r.options.find((o) => o.id === red.id)?.votes).toBe(0);
    expect(r.options.find((o) => o.id === blue.id)?.votes).toBe(1);

    // A different token is a different voter.
    await vote(poll.id, { option_ids: [red.id], voter_token: "token-bob-1" });
    r = await results(poll.id);
    expect(r.total_voters).toBe(2);
    expect(r.total_votes).toBe(2);
  });

  it("validates the vote payload", async () => {
    const tenant = await createTenant("検証");
    const poll = await createPoll(tenant);
    await setStatus(tenant, poll.id, "published");
    const [o1, o2] = [poll.options[0] as { id: string }, poll.options[1] as { id: string }];

    const noToken = await vote(poll.id, { option_ids: [o1.id] });
    expect(noToken.status).toBe(400);

    const twoChoices = await vote(poll.id, {
      option_ids: [o1.id, o2.id],
      voter_token: "token-carol",
    });
    expect(twoChoices.status).toBe(400);

    const unknown = await vote(poll.id, {
      option_ids: ["00000000-0000-0000-0000-000000000000"],
      voter_token: "token-carol",
    });
    expect(unknown.status).toBe(400);
  });

  it("supports multiple-choice polls and replaces selections on re-vote", async () => {
    const tenant = await createTenant("複数選択");
    const poll = await createPoll(tenant, { allow_multiple: true });
    await setStatus(tenant, poll.id, "published");
    const [o1, o2, o3] = poll.options as { id: string }[];

    const res = await vote(poll.id, {
      option_ids: [o1?.id, o2?.id],
      voter_token: "token-dave-1",
    });
    expect(res.status).toBe(200);
    let r = await results(poll.id);
    expect(r.total_voters).toBe(1);
    expect(r.total_votes).toBe(2);

    await vote(poll.id, { option_ids: [o3?.id], voter_token: "token-dave-1" });
    r = await results(poll.id);
    expect(r.total_voters).toBe(1);
    expect(r.total_votes).toBe(1);
    expect(r.options.find((o) => o.id === o3?.id)?.votes).toBe(1);
  });

  it("locks options after the first vote", async () => {
    const tenant = await createTenant("選択肢ロック");
    const poll = await createPoll(tenant);
    await setStatus(tenant, poll.id, "published");
    await vote(poll.id, {
      option_ids: [poll.options[0]?.id],
      voter_token: "token-erin-1",
    });
    const patch = await SELF.fetch(
      `${BASE}/api/v1/tenants/${tenant.id}/polls/${poll.id}`,
      {
        method: "PATCH",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${tenant.apiKey}`,
        },
        body: JSON.stringify({
          options: [{ label: "新1" }, { label: "新2" }],
        }),
      },
    );
    expect(patch.status).toBe(409);
    expect(
      ((await patch.json()) as { error: { code: string } }).error.code,
    ).toBe("OPTIONS_LOCKED");
  });
});

describe("images (R2)", () => {
  const PNG_BYTES = new Uint8Array([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4,
  ]);

  it("uploads an image and serves it back publicly", async () => {
    const tenant = await createTenant("画像");
    const res = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/images`, {
      method: "POST",
      headers: {
        "content-type": "image/png",
        authorization: `Bearer ${tenant.apiKey}`,
      },
      body: PNG_BYTES,
    });
    expect(res.status).toBe(201);
    const data = (await res.json()) as { key: string; url: string };
    expect(data.key.startsWith(`t/${tenant.id}/`)).toBe(true);

    const served = await SELF.fetch(data.url.replace(/^https:\/\/[^/]+/, BASE));
    expect(served.status).toBe(200);
    expect(served.headers.get("content-type")).toContain("image/png");
    const bytes = new Uint8Array(await served.arrayBuffer());
    expect([...bytes]).toEqual([...PNG_BYTES]);

    // The key can be attached to a poll and shows up as image_url.
    const poll = await createPoll(tenant, { image_key: data.key });
    await setStatus(tenant, poll.id, "published");
    const pub = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}`);
    const pubData = (await pub.json()) as { poll: { image_url: string } };
    expect(pubData.poll.image_url).toBe(data.url.replace(/^https:\/\/[^/]+/, "https://vote.test"));
  });

  it("rejects non-image uploads and cross-tenant image keys", async () => {
    const a = await createTenant("画像A");
    const b = await createTenant("画像B");
    const badType = await SELF.fetch(`${BASE}/api/v1/tenants/${a.id}/images`, {
      method: "POST",
      headers: {
        "content-type": "text/plain",
        authorization: `Bearer ${a.apiKey}`,
      },
      body: "hello",
    });
    expect(badType.status).toBe(400);

    const up = await SELF.fetch(`${BASE}/api/v1/tenants/${a.id}/images`, {
      method: "POST",
      headers: {
        "content-type": "image/png",
        authorization: `Bearer ${a.apiKey}`,
      },
      body: PNG_BYTES,
    });
    const { key } = (await up.json()) as { key: string };
    // Tenant B must not reference tenant A's image.
    const res = await SELF.fetch(`${BASE}/api/v1/tenants/${b.id}/polls`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${b.apiKey}`,
      },
      body: JSON.stringify({
        question: "他人の画像を使う",
        image_key: key,
        options: [{ label: "x" }, { label: "y" }],
      }),
    });
    expect(res.status).toBe(400);
  });
});

describe("API key rotation", () => {
  it("invalidates the old key after rotation", async () => {
    const tenant = await createTenant("ローテーション");
    const res = await SELF.fetch(
      `${BASE}/api/v1/tenants/${tenant.id}/rotate-key`,
      {
        method: "POST",
        headers: { authorization: `Bearer ${tenant.apiKey}` },
      },
    );
    expect(res.status).toBe(200);
    const { api_key: newKey } = (await res.json()) as { api_key: string };
    const oldRes = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/polls`, {
      headers: { authorization: `Bearer ${tenant.apiKey}` },
    });
    expect(oldRes.status).toBe(401);
    const newRes = await SELF.fetch(`${BASE}/api/v1/tenants/${tenant.id}/polls`, {
      headers: { authorization: `Bearer ${newKey}` },
    });
    expect(newRes.status).toBe(200);
  });
});
