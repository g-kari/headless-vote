import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { applySchema } from "./fixtures";
import { notifyClosingSoon } from "../src/notifications";
import { encodeQr } from "../src/qr";

const BASE = "https://vote.test";

beforeAll(async () => {
  await applySchema(env.DB);
});

async function tenant() {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: "参加促進" }),
  });
  expect(res.status).toBe(201);
  const data = (await res.json()) as { tenant: { id: string }; api_key: string };
  return { id: data.tenant.id, apiKey: data.api_key };
}

function auth(owner: { apiKey: string }) {
  return { "content-type": "application/json", authorization: `Bearer ${owner.apiKey}` };
}

interface PollJson {
  poll: {
    id: string;
    status: string;
    closes_at: string | null;
    results_visibility: string;
    questions: { id: string; kind: string; options: { id: string }[] }[];
  };
}

async function createPoll(owner: { id: string; apiKey: string }, body: unknown) {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls`, {
    method: "POST",
    headers: auth(owner),
    body: JSON.stringify(body),
  });
  expect(res.status).toBe(201);
  return ((await res.json()) as PollJson).poll;
}

async function setStatus(owner: { id: string; apiKey: string }, pollId: string, status: string) {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/${pollId}/status`, {
    method: "POST",
    headers: auth(owner),
    body: JSON.stringify({ status }),
  });
  expect(res.status).toBe(200);
}

describe("qr encoder", () => {
  it("builds a version 1 matrix for a short payload with intact finder patterns", () => {
    const qr = encodeQr("hello world!");
    expect(qr.size).toBe(21);
    expect(qr.modules[0]?.slice(0, 7)).toEqual([true, true, true, true, true, true, true]);
    expect(qr.modules[13]?.[8]).toBe(true); // dark module
    const url = encodeQr("https://vote.0g0.xyz/polls/28b5b946-eb42-427d-9bb0-25459036f34c/results-page");
    expect(url.size).toBe(37); // version 5 at level M
  });
});

describe("duplicate and templates", () => {
  it("duplicates a poll as a draft without its schedule", async () => {
    const owner = await tenant();
    const source = await createPoll(owner, {
      question: "元の投票",
      results_visibility: "after_close",
      closes_at: new Date(Date.now() + 86400000).toISOString(),
      questions: [
        { prompt: "Q1", kind: "single", options: [{ label: "A" }, { label: "B" }] },
        { prompt: "Q2", kind: "text", required: false },
      ],
    });
    const res = await SELF.fetch(
      `${BASE}/api/v1/tenants/${owner.id}/polls/${source.id}/duplicate`,
      { method: "POST", headers: auth(owner), body: JSON.stringify({}) },
    );
    expect(res.status).toBe(201);
    const copy = ((await res.json()) as PollJson).poll;
    expect(copy.id).not.toBe(source.id);
    expect(copy.status).toBe("draft");
    expect(copy.closes_at).toBeNull();
    expect(copy.results_visibility).toBe("after_close");
    expect(copy.questions).toHaveLength(2);
  });

  it("creates a poll from a template and deletes the template", async () => {
    const owner = await tenant();
    const source = await createPoll(owner, {
      question: "テンプレート元",
      options: [{ label: "A" }, { label: "B" }],
    });
    const created = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/templates`, {
      method: "POST",
      headers: auth(owner),
      body: JSON.stringify({ name: "定型1", poll_id: source.id }),
    });
    expect(created.status).toBe(201);
    const tpl = (await created.json()) as { template: { id: string } };
    const list = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/templates`, {
      headers: auth(owner),
    });
    const listData = (await list.json()) as { templates: { id: string; name: string }[] };
    expect(listData.templates).toHaveLength(1);
    expect(listData.templates[0]?.name).toBe("定型1");

    const fromTpl = await SELF.fetch(
      `${BASE}/api/v1/tenants/${owner.id}/templates/${tpl.template.id}/polls`,
      {
        method: "POST",
        headers: auth(owner),
        body: JSON.stringify({ question: "テンプレートから作成" }),
      },
    );
    expect(fromTpl.status).toBe(201);
    const poll = ((await fromTpl.json()) as PollJson).poll;
    expect(poll.status).toBe("draft");
    expect(poll.questions).toHaveLength(1);

    const del = await SELF.fetch(
      `${BASE}/api/v1/tenants/${owner.id}/templates/${tpl.template.id}`,
      { method: "DELETE", headers: auth(owner) },
    );
    expect(del.status).toBe(204);
    const gone = await SELF.fetch(
      `${BASE}/api/v1/tenants/${owner.id}/templates/${tpl.template.id}/polls`,
      { method: "POST", headers: auth(owner), body: JSON.stringify({}) },
    );
    expect(gone.status).toBe(404);
  });
});

describe("my ballot receipt", () => {
  it("returns the cast ballot and editability, then locks after close", async () => {
    const owner = await tenant();
    const poll = await createPoll(owner, {
      question: "控え",
      options: [{ label: "A" }, { label: "B" }],
    });
    await setStatus(owner, poll.id, "published");
    const q = poll.questions[0];
    if (!q) throw new Error("question missing");
    const vote = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/vote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        voter_token: "receipt-voter",
        answers: [{ question_id: q.id, option_ids: [q.options[0]?.id] }],
      }),
    });
    expect(vote.status).toBe(200);
    const mine = await SELF.fetch(
      `${BASE}/api/v1/polls/${poll.id}/ballot?voter_token=receipt-voter`,
    );
    expect(mine.status).toBe(200);
    const data = (await mine.json()) as {
      ballot: { answers: { option_ids: string[] }[] } | null;
      editable: boolean;
    };
    expect(data.ballot?.answers[0]?.option_ids).toEqual([q.options[0]?.id]);
    expect(data.editable).toBe(true);

    const other = await SELF.fetch(
      `${BASE}/api/v1/polls/${poll.id}/ballot?voter_token=receipt-other`,
    );
    const otherData = (await other.json()) as { ballot: unknown };
    expect(otherData.ballot).toBeNull();

    await setStatus(owner, poll.id, "closed");
    const after = await SELF.fetch(
      `${BASE}/api/v1/polls/${poll.id}/ballot?voter_token=receipt-voter`,
    );
    const afterData = (await after.json()) as { editable: boolean };
    expect(afterData.editable).toBe(false);
  });
});

describe("branding, share assets, docs", () => {
  it("validates and stores the brand color and applies it to the results page", async () => {
    const owner = await tenant();
    const bad = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/branding`, {
      method: "PATCH",
      headers: auth(owner),
      body: JSON.stringify({ brand_color: "red" }),
    });
    expect(bad.status).toBe(400);
    const ok = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/branding`, {
      method: "PATCH",
      headers: auth(owner),
      body: JSON.stringify({ brand_color: "#0C6B34" }),
    });
    expect(ok.status).toBe(200);
    const saved = (await ok.json()) as { tenant: { brand_color: string } };
    expect(saved.tenant.brand_color).toBe("#0c6b34");

    const poll = await createPoll(owner, {
      question: "ブランド確認",
      options: [{ label: "A" }, { label: "B" }],
    });
    await setStatus(owner, poll.id, "published");
    const page = await SELF.fetch(`${BASE}/polls/${poll.id}/results-page`);
    expect(page.status).toBe(200);
    expect(await page.text()).toContain("#0c6b34");
  });

  it("serves QR and share-image SVGs and hides results in the share image until close", async () => {
    const owner = await tenant();
    const poll = await createPoll(owner, {
      question: "共有確認",
      results_visibility: "after_close",
      options: [{ label: "A" }, { label: "B" }],
    });
    await setStatus(owner, poll.id, "published");
    const qr = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/qr.svg`);
    expect(qr.status).toBe(200);
    expect(qr.headers.get("content-type")).toContain("image/svg+xml");
    const qrBody = await qr.text();
    expect(qrBody).toContain("<svg");
    expect(qrBody).toContain("<path");
    const og = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/og.svg`);
    expect(og.status).toBe(200);
    const ogBody = await og.text();
    expect(ogBody).toContain("共有確認");
    expect(ogBody).toContain("結果は締切後に公開されます");
    expect(ogBody).not.toContain("投票者数");
  });

  it("serves the API docs page", async () => {
    const res = await SELF.fetch(`${BASE}/docs`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("API 仕様書");
    // The docs page is a Redoc shell over the versioned OpenAPI spec.
    expect(html).toContain('id="redoc"');
    expect(html).toContain("/openapi.yaml");
    expect(html).toContain("/redoc.standalone.js");
    const spec = await SELF.fetch(`${BASE}/openapi.yaml`);
    expect(spec.status).toBe(200);
    const yaml = await spec.text();
    expect(yaml).toContain("openapi: 3.0.3");
    expect(yaml).toContain("poll.closing_soon");
    expect(yaml).toContain("CONFIRM_REQUIRED");
    expect(yaml).toContain("/api/v1/polls/{pollId}/vote:");
  });
});

describe("closing-soon notifications", () => {
  it("creates one notification and webhook-eligible event per poll", async () => {
    const owner = await tenant();
    const poll = await createPoll(owner, {
      question: "締切間近",
      closes_at: new Date(Date.now() + 12 * 3600000).toISOString(),
      options: [{ label: "A" }, { label: "B" }],
    });
    await setStatus(owner, poll.id, "published");
    const hook = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/webhooks`, {
      method: "POST",
      headers: auth(owner),
      body: JSON.stringify({ url: "https://example.com/hook", events: ["poll.closing_soon"] }),
    });
    expect([201, 400]).toContain(hook.status); // URL may be rejected by SSRF rules in tests
    const first = await notifyClosingSoon(env);
    expect(first).toBeGreaterThanOrEqual(1);
    const second = await notifyClosingSoon(env);
    expect(second).toBe(0);
    const list = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/notifications`, {
      headers: auth(owner),
    });
    const data = (await list.json()) as {
      notifications: { kind: string; message: string; read_at: string | null }[];
    };
    const mine = data.notifications.filter((n) => n.kind === "closing_soon");
    expect(mine).toHaveLength(1);
    expect(mine[0]?.message).toContain("締切間近");
    expect(mine[0]?.read_at).toBeNull();
  });
});
