import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { applySchema } from "./fixtures";
import { fixtureSessionHeaders } from "./session";

const BASE = "https://vote.test";

beforeAll(async () => {
  await applySchema(env.DB);
});

interface PollJson {
  poll: {
    id: string;
    ip_single_vote: boolean;
    dedup_level: string;
    questions: {
      id: string;
      options: { id: string; label: string }[];
    }[];
  };
}

async function tenant() {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(await fixtureSessionHeaders()) },
    body: JSON.stringify({ name: "重複防止レベル" }),
  });
  expect(res.status).toBe(201);
  const data = (await res.json()) as { tenant: { id: string }; api_key: string };
  return { id: data.tenant.id, apiKey: data.api_key };
}

function auth(owner: { apiKey: string }): Record<string, string> {
  return { "content-type": "application/json", authorization: `Bearer ${owner.apiKey}` };
}

async function createPoll(owner: { id: string; apiKey: string }, body: unknown) {
  return SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls`, {
    method: "POST",
    headers: auth(owner),
    body: JSON.stringify(body),
  });
}

async function publishedPoll(owner: { id: string; apiKey: string }, body: unknown) {
  const created = await createPoll(owner, body);
  expect(created.status).toBe(201);
  const { poll } = (await created.json()) as PollJson;
  const status = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/${poll.id}/status`, {
    method: "POST",
    headers: auth(owner),
    body: JSON.stringify({ status: "published" }),
  });
  expect(status.status).toBe(200);
  return poll;
}

function vote(poll: PollJson["poll"], token: string, ip: string, userAgent?: string) {
  const q = poll.questions[0];
  if (!q) throw new Error("question missing");
  const headers: Record<string, string> = { "content-type": "application/json", "cf-connecting-ip": ip };
  if (userAgent) headers["user-agent"] = userAgent;
  return SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/vote`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      voter_token: token,
      answers: [{ question_id: q.id, option_ids: [q.options[0]?.id] }],
    }),
  });
}

const SIMPLE = { options: [{ label: "A" }, { label: "B" }] };

describe("anonymous-vote dedup levels (KAZAMI-306 #11)", () => {
  it("defaults to token level: the same connection can vote with another token", async () => {
    const owner = await tenant();
    const poll = await publishedPoll(owner, { question: "トークン既定", ...SIMPLE });
    expect(poll.dedup_level).toBe("token");
    expect(poll.ip_single_vote).toBe(false);
    expect((await vote(poll, "token-alpha-1", "203.0.113.1")).status).toBe(200);
    expect((await vote(poll, "token-bravo-2", "203.0.113.1")).status).toBe(200);
    // The same token re-voting still just overwrites its own ballot.
    expect((await vote(poll, "token-alpha-1", "203.0.113.1")).status).toBe(200);
  });

  it("ip level: one ballot per connection, however many tokens", async () => {
    const owner = await tenant();
    const poll = await publishedPoll(owner, { question: "IPレベル", dedup_level: "ip", ...SIMPLE });
    expect(poll.dedup_level).toBe("ip");
    expect(poll.ip_single_vote).toBe(true);
    expect((await vote(poll, "token-alpha-1", "203.0.113.2")).status).toBe(200);
    expect((await vote(poll, "token-bravo-2", "203.0.113.2")).status).toBe(409);
    expect((await vote(poll, "token-bravo-2", "203.0.113.3")).status).toBe(200);
  });

  it("maps the legacy ip_single_vote flag to the ip level, and dedup_level wins", async () => {
    const owner = await tenant();
    const legacy = await createPoll(owner, { question: "旧フラグ", ip_single_vote: true, ...SIMPLE });
    expect(legacy.status).toBe(201);
    expect(((await legacy.json()) as PollJson).poll.dedup_level).toBe("ip");

    const explicit = await createPoll(owner, {
      question: "明示優先",
      ip_single_vote: false,
      dedup_level: "browser",
      ...SIMPLE,
    });
    expect(explicit.status).toBe(201);
    const { poll } = (await explicit.json()) as PollJson;
    expect(poll.dedup_level).toBe("browser");
    expect(poll.ip_single_vote).toBe(true);
  });

  it("browser level: one ballot per connection + browser pair", async () => {
    const owner = await tenant();
    const poll = await publishedPoll(owner, { question: "ブラウザレベル", dedup_level: "browser", ...SIMPLE });
    const ip = "203.0.113.4";
    expect((await vote(poll, "token-alpha-1", ip, "Browser/A")).status).toBe(200);
    // Same connection, same browser, another token: rejected.
    expect((await vote(poll, "token-bravo-2", ip, "Browser/A")).status).toBe(409);
    // Same connection, different browser: allowed.
    expect((await vote(poll, "token-bravo-2", ip, "Browser/B")).status).toBe(200);
    // Same browser, different connection: allowed.
    expect((await vote(poll, "token-charlie", "203.0.113.5", "Browser/A")).status).toBe(200);
    // The original voter can still change their own ballot.
    expect((await vote(poll, "token-alpha-1", ip, "Browser/A")).status).toBe(200);
  });

  it("rejects an unknown dedup_level on create and update", async () => {
    const owner = await tenant();
    const created = await createPoll(owner, { question: "不正なレベル", dedup_level: "strict", ...SIMPLE });
    expect(created.status).toBe(400);

    const ok = await createPoll(owner, { question: "更新対象", ...SIMPLE });
    const { poll } = (await ok.json()) as PollJson;
    const patched = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/${poll.id}`, {
      method: "PATCH",
      headers: auth(owner),
      body: JSON.stringify({ dedup_level: "strict" }),
    });
    expect(patched.status).toBe(400);
  });

  it("updates the level before voting and locks it after a vote", async () => {
    const owner = await tenant();
    const created = await createPoll(owner, { question: "レベル変更", ...SIMPLE });
    const { poll } = (await created.json()) as PollJson;
    const patched = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/${poll.id}`, {
      method: "PATCH",
      headers: auth(owner),
      body: JSON.stringify({ dedup_level: "browser" }),
    });
    expect(patched.status).toBe(200);
    const updated = ((await patched.json()) as PollJson).poll;
    expect(updated.dedup_level).toBe("browser");
    expect(updated.ip_single_vote).toBe(true);

    const status = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/${poll.id}/status`, {
      method: "POST",
      headers: auth(owner),
      body: JSON.stringify({ status: "published" }),
    });
    expect(status.status).toBe(200);
    expect((await vote(updated, "token-alpha-1", "203.0.113.6", "Browser/A")).status).toBe(200);

    const locked = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/${poll.id}`, {
      method: "PATCH",
      headers: auth(owner),
      body: JSON.stringify({ dedup_level: "token" }),
    });
    expect(locked.status).toBe(409);
    const lockedBody = (await locked.json()) as { error: { code: string } };
    expect(lockedBody.error.code).toBe("RULES_LOCKED");
  });

  it("shows the level selector in the poll editor with the current level checked", async () => {
    const owner = await tenant();
    const created = await createPoll(owner, { question: "エディタ確認", dedup_level: "browser", ...SIMPLE });
    const { poll } = (await created.json()) as PollJson;
    const page = await SELF.fetch(`${BASE}/admin/workspaces/${owner.id}/polls/${poll.id}`, {
      headers: { ...(await fixtureSessionHeaders()) },
    });
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain("重複投票の防止レベル");
    expect(html).toContain("IP＋ブラウザ情報でも制限（強い）");
    expect(html).not.toContain("ip-single-vote");
    const browserRadio = /<input type="radio" name="dedup-level" id="dedup-browser" value="browser"[^>]*>/.exec(html)?.[0];
    expect(browserRadio).toContain("checked");
  });
});
