import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { applySchema } from "./fixtures";

const BASE = "https://vote.test";

beforeAll(async () => {
  await applySchema(env.DB);
});

async function tenant() {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: "複数設問" }),
  });
  expect(res.status).toBe(201);
  const data = (await res.json()) as { tenant: { id: string }; api_key: string };
  return { id: data.tenant.id, apiKey: data.api_key };
}

describe("multiple questions", () => {
  it("keeps a legacy single-question poll and accepts option_ids", async () => {
    const owner = await tenant();
    const created = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${owner.apiKey}`,
      },
      body: JSON.stringify({
        question: "好きな色は？",
        allow_multiple: false,
        options: [{ label: "赤" }, { label: "青" }],
      }),
    });
    expect(created.status).toBe(201);
    const poll = (await created.json()) as {
      poll: {
        id: string;
        options: { id: string }[];
        questions: { id: string; kind: string; options: { id: string }[] }[];
      };
    };
    expect(poll.poll.questions).toHaveLength(1);
    expect(poll.poll.questions[0]?.kind).toBe("single");
    expect(poll.poll.options).toHaveLength(2);
    await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/${poll.poll.id}/status`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${owner.apiKey}`,
      },
      body: JSON.stringify({ status: "published" }),
    });
    const vote = await SELF.fetch(`${BASE}/api/v1/polls/${poll.poll.id}/vote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        voter_token: "legacy-voter-1",
        option_ids: [poll.poll.options[0]?.id],
      }),
    });
    expect(vote.status).toBe(200);
    const results = await SELF.fetch(`${BASE}/api/v1/polls/${poll.poll.id}/results`);
    const data = (await results.json()) as {
      results: { total_voters: number; questions: { response_count: number }[] };
    };
    expect(data.results.total_voters).toBe(1);
    expect(data.results.questions[0]?.response_count).toBe(1);
  });

  it("requires every required question and aggregates each one", async () => {
    const owner = await tenant();
    const created = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${owner.apiKey}`,
      },
      body: JSON.stringify({
        question: "アンケート",
        questions: [
          {
            prompt: "色",
            kind: "single",
            required: true,
            options: [{ label: "赤" }, { label: "青" }],
          },
          {
            prompt: "時間帯",
            kind: "multiple",
            required: true,
            options: [{ label: "午前" }, { label: "午後" }],
          },
          { prompt: "感想", kind: "text", required: true },
        ],
      }),
    });
    expect(created.status).toBe(201);
    const poll = (await created.json()) as {
      poll: {
        id: string;
        questions: { id: string; kind: string; options: { id: string }[] }[];
      };
    };
    expect(poll.poll.questions).toHaveLength(3);
    const [color, time, note] = poll.poll.questions;
    await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/${poll.poll.id}/status`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${owner.apiKey}`,
      },
      body: JSON.stringify({ status: "published" }),
    });
    const partial = await SELF.fetch(`${BASE}/api/v1/polls/${poll.poll.id}/vote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        voter_token: "survey-voter-1",
        answers: [{ question_id: color?.id, option_ids: [color?.options[0]?.id] }],
      }),
    });
    expect(partial.status).toBe(400);

    const twoChoices = await SELF.fetch(`${BASE}/api/v1/polls/${poll.poll.id}/vote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        voter_token: "survey-voter-1",
        answers: [
          {
            question_id: color?.id,
            option_ids: [color?.options[0]?.id, color?.options[1]?.id],
          },
          { question_id: time?.id, option_ids: [time?.options[0]?.id] },
          { question_id: note?.id, text: "とてもよい" },
        ],
      }),
    });
    expect(twoChoices.status).toBe(400);

    const ok = await SELF.fetch(`${BASE}/api/v1/polls/${poll.poll.id}/vote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        voter_token: "survey-voter-1",
        answers: [
          { question_id: color?.id, option_ids: [color?.options[1]?.id] },
          { question_id: time?.id, option_ids: [time?.options[0]?.id, time?.options[1]?.id] },
          { question_id: note?.id, text: "とてもよい" },
        ],
      }),
    });
    expect(ok.status).toBe(200);

    const publicResults = await SELF.fetch(`${BASE}/api/v1/polls/${poll.poll.id}/results`);
    const pub = (await publicResults.json()) as {
      results: { questions: { kind: string; texts?: string[]; options: { votes: number }[] }[] };
    };
    expect(pub.results.questions[1]?.options[0]?.votes).toBe(1);
    expect(pub.results.questions[2]?.texts).toBeUndefined();
    expect(JSON.stringify(pub)).not.toContain("とてもよい");

    const exported = await SELF.fetch(
      `${BASE}/api/v1/tenants/${owner.id}/polls/${poll.poll.id}/export?format=json`,
      { headers: { authorization: `Bearer ${owner.apiKey}` } },
    );
    const exp = (await exported.json()) as {
      results: { questions: { texts?: string[] }[] };
    };
    expect(exp.results.questions[2]?.texts).toContain("とてもよい");

    const locked = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/${poll.poll.id}`, {
      method: "PATCH",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${owner.apiKey}`,
      },
      body: JSON.stringify({
        questions: [
          {
            id: color?.id,
            prompt: "色を変える",
            kind: "single",
            required: true,
            options: [
              { id: color?.options[0]?.id, label: "赤" },
              { id: color?.options[1]?.id, label: "青" },
              { label: "緑" },
            ],
          },
          {
            id: time?.id,
            prompt: "時間帯",
            kind: "multiple",
            required: true,
            options: [
              { id: time?.options[0]?.id, label: "午前" },
              { id: time?.options[1]?.id, label: "午後" },
            ],
          },
          { id: note?.id, prompt: "感想", kind: "text", required: true },
        ],
      }),
    });
    expect(locked.status).toBe(409);

    const renamed = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/${poll.poll.id}`, {
      method: "PATCH",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${owner.apiKey}`,
      },
      body: JSON.stringify({
        questions: [
          {
            id: time?.id,
            prompt: "時間帯（並び替え）",
            kind: "multiple",
            required: true,
            options: [
              { id: time?.options[1]?.id, label: "午後" },
              { id: time?.options[0]?.id, label: "午前" },
            ],
          },
          {
            id: color?.id,
            prompt: "色（文言だけ）",
            kind: "single",
            required: true,
            options: [
              { id: color?.options[0]?.id, label: "あか" },
              { id: color?.options[1]?.id, label: "あお" },
            ],
          },
          { id: note?.id, prompt: "感想", kind: "text", required: true },
        ],
      }),
    });
    expect(renamed.status).toBe(200);
    const renamedBody = (await renamed.json()) as {
      poll: { questions: { id: string; prompt: string }[] };
    };
    expect(renamedBody.poll.questions[0]?.id).toBe(time?.id);
    expect(renamedBody.poll.questions[0]?.prompt).toBe("時間帯（並び替え）");
  });
});
