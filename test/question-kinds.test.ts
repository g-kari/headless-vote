import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { applySchema } from "./fixtures";

const BASE = "https://vote.test";

beforeAll(async () => {
  await applySchema(env.DB);
});

interface ErrBody {
  error: { code: string; message: string; details?: Record<string, unknown> };
}

async function tenant() {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: "設問形式" }),
  });
  expect(res.status).toBe(201);
  const data = (await res.json()) as { tenant: { id: string }; api_key: string };
  return { id: data.tenant.id, apiKey: data.api_key };
}

function auth(owner: { apiKey: string }) {
  return {
    "content-type": "application/json",
    authorization: `Bearer ${owner.apiKey}`,
  };
}

async function createPoll(owner: { id: string; apiKey: string }, questions: unknown[]) {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls`, {
    method: "POST",
    headers: auth(owner),
    body: JSON.stringify({ question: "形式テスト", questions }),
  });
  expect(res.status).toBe(201);
  const data = (await res.json()) as {
    poll: {
      id: string;
      questions: {
        id: string;
        kind: string;
        config: Record<string, number> | null;
        options: { id: string; label: string }[];
      }[];
    };
  };
  await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/${data.poll.id}/status`, {
    method: "POST",
    headers: auth(owner),
    body: JSON.stringify({ status: "published" }),
  });
  return data.poll;
}

function vote(pollId: string, token: string, answers: unknown[]) {
  return SELF.fetch(`${BASE}/api/v1/polls/${pollId}/vote`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ voter_token: token, answers }),
  });
}

async function adminResults(owner: { id: string; apiKey: string }, pollId: string) {
  const res = await SELF.fetch(
    `${BASE}/api/v1/tenants/${owner.id}/polls/${pollId}/export?format=json`,
    { headers: auth(owner) },
  );
  expect(res.status).toBe(200);
  return (await res.json()) as {
    results: {
      questions: {
        id: string;
        kind: string;
        response_count: number;
        options: { id: string; label: string; votes: number; points?: number; average_points?: number | null }[];
        texts?: string[];
        values?: number[];
        numeric?: { count: number; average: number | null; min: number | null; max: number | null };
      }[];
    };
  };
}

describe("new question kinds", () => {
  it("number: validates range and aggregates statistics", async () => {
    const owner = await tenant();
    const poll = await createPoll(owner, [
      { prompt: "個数", kind: "number", config: { min: 0, max: 10 } },
    ]);
    const q = poll.questions[0];
    expect(q?.config).toEqual({ min: 0, max: 10 });

    const tooBig = await vote(poll.id, "voter-n-1", [{ question_id: q?.id, value: 11 }]);
    expect(tooBig.status).toBe(400);
    expect(((await tooBig.json()) as ErrBody).error.details?.question_id).toBe(q?.id);

    const notNumber = await vote(poll.id, "voter-n-2", [{ question_id: q?.id, value: "x" }]);
    expect(notNumber.status).toBe(400);

    expect((await vote(poll.id, "voter-n-3", [{ question_id: q?.id, value: 4 }])).status).toBe(200);
    expect((await vote(poll.id, "voter-n-4", [{ question_id: q?.id, value: 8 }])).status).toBe(200);

    const data = await adminResults(owner, poll.id);
    const result = data.results.questions[0];
    expect(result?.numeric).toEqual({ count: 2, average: 6, min: 4, max: 8 });
    expect(result?.values).toEqual([4, 8]);
  });

  it("date: accepts real dates only and exports them as text rows", async () => {
    const owner = await tenant();
    const poll = await createPoll(owner, [{ prompt: "日付", kind: "date" }]);
    const q = poll.questions[0];
    expect((await vote(poll.id, "voter-d-1", [{ question_id: q?.id, text: "2026-02-30" }])).status).toBe(400);
    expect((await vote(poll.id, "voter-d-2", [{ question_id: q?.id, text: "2026/03/01" }])).status).toBe(400);
    expect((await vote(poll.id, "voter-d-3", [{ question_id: q?.id, text: "2026-03-01" }])).status).toBe(200);
    const data = await adminResults(owner, poll.id);
    expect(data.results.questions[0]?.texts).toEqual(["2026-03-01"]);

    const csv = await SELF.fetch(
      `${BASE}/api/v1/tenants/${owner.id}/polls/${poll.id}/export?format=csv`,
      { headers: auth(owner) },
    );
    const body = await csv.text();
    expect(body).toContain("date");
    expect(body).toContain("2026-03-01");
  });

  it("short_text: rejects newlines and overlong answers", async () => {
    const owner = await tenant();
    const poll = await createPoll(owner, [
      { prompt: "一言", kind: "short_text" },
      { prompt: "長文", kind: "text", required: false },
    ]);
    const q = poll.questions[0];
    expect((await vote(poll.id, "voter-s-1", [{ question_id: q?.id, text: "一行目\n二行目" }])).status).toBe(400);
    expect((await vote(poll.id, "voter-s-2", [{ question_id: q?.id, text: "あ".repeat(201) }])).status).toBe(400);
    expect((await vote(poll.id, "voter-s-3", [{ question_id: q?.id, text: "短い一言" }])).status).toBe(200);
    const data = await adminResults(owner, poll.id);
    expect(data.results.questions[0]?.texts).toEqual(["短い一言"]);
  });

  it("scale: validates the step range and synthesizes step options", async () => {
    const owner = await tenant();
    const poll = await createPoll(owner, [
      { prompt: "満足度", kind: "scale", config: { steps: 3 } },
    ]);
    const q = poll.questions[0];
    expect((await vote(poll.id, "voter-sc-1", [{ question_id: q?.id, value: 4 }])).status).toBe(400);
    expect((await vote(poll.id, "voter-sc-2", [{ question_id: q?.id, value: 1.5 }])).status).toBe(400);
    for (const [token, value] of [["voter-sc-3", 1], ["voter-sc-4", 3], ["voter-sc-5", 3]] as const) {
      expect((await vote(poll.id, token, [{ question_id: q?.id, value }])).status).toBe(200);
    }
    const data = await adminResults(owner, poll.id);
    const result = data.results.questions[0];
    expect(result?.options.map((o) => [o.label, o.votes])).toEqual([["1", 1], ["2", 0], ["3", 2]]);
    expect(result?.numeric?.count).toBe(3);
    expect(result?.numeric?.average).toBe(2.33);
  });

  it("slider: enforces range and step alignment", async () => {
    const owner = await tenant();
    const poll = await createPoll(owner, [
      { prompt: "量", kind: "slider", config: { min: 0, max: 10, step: 5 } },
    ]);
    const q = poll.questions[0];
    expect((await vote(poll.id, "voter-sl-1", [{ question_id: q?.id, value: 7 }])).status).toBe(400);
    expect((await vote(poll.id, "voter-sl-2", [{ question_id: q?.id, value: 15 }])).status).toBe(400);
    expect((await vote(poll.id, "voter-sl-3", [{ question_id: q?.id, value: 5 }])).status).toBe(200);
    const data = await adminResults(owner, poll.id);
    expect(data.results.questions[0]?.numeric).toEqual({ count: 1, average: 5, min: 5, max: 5 });
  });

  it("allocation: requires the exact total and reports averages", async () => {
    const owner = await tenant();
    const poll = await createPoll(owner, [
      {
        prompt: "配点",
        kind: "allocation",
        config: { total: 10 },
        options: [{ label: "案A" }, { label: "案B" }],
      },
    ]);
    const q = poll.questions[0];
    const [a, b] = q?.options ?? [];
    const short = await vote(poll.id, "voter-al-1", [
      { question_id: q?.id, scores: { [a?.id as string]: 6, [b?.id as string]: 3 } },
    ]);
    expect(short.status).toBe(400);
    expect(((await short.json()) as ErrBody).error.details?.question_id).toBe(q?.id);
    expect((await vote(poll.id, "voter-al-2", [
      { question_id: q?.id, scores: { [a?.id as string]: 6, [b?.id as string]: 4 } },
    ])).status).toBe(200);
    expect((await vote(poll.id, "voter-al-3", [
      { question_id: q?.id, scores: { [a?.id as string]: 10 } },
    ])).status).toBe(200);
    const data = await adminResults(owner, poll.id);
    const result = data.results.questions[0];
    expect(result?.options[0]?.average_points).toBe(8);
    expect(result?.options[0]?.points).toBe(16);
    expect(result?.options[1]?.average_points).toBe(4);
  });

  it("rejects invalid configs at create time with a question index", async () => {
    const owner = await tenant();
    const cases: unknown[][] = [
      [{ prompt: "x", kind: "scale", config: { steps: 99 } }],
      [{ prompt: "x", kind: "slider", config: { min: 10, max: 10 } }],
      [{ prompt: "x", kind: "number", config: { min: 5, max: 1 } }],
      [{ prompt: "x", kind: "allocation", config: { total: 0 } }],
      [{ prompt: "x", kind: "number", options: [{ label: "a" }, { label: "b" }] }],
    ];
    for (const questions of cases) {
      const res = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls`, {
        method: "POST",
        headers: auth(owner),
        body: JSON.stringify({ question: "bad", questions }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as ErrBody;
      expect(body.error.details?.question_index).toBe(0);
    }
  });

  it("keeps config edits structural after votes exist", async () => {
    const owner = await tenant();
    const poll = await createPoll(owner, [
      { prompt: "満足度", kind: "scale", config: { steps: 5 } },
    ]);
    const q = poll.questions[0];
    expect((await vote(poll.id, "voter-st-1", [{ question_id: q?.id, value: 3 }])).status).toBe(200);
    const res = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/${poll.id}`, {
      method: "PATCH",
      headers: auth(owner),
      body: JSON.stringify({
        question: "形式テスト",
        questions: [{ id: q?.id, prompt: "満足度", kind: "scale", config: { steps: 7 } }],
      }),
    });
    expect(res.status).toBe(409);
  });
});
