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
    body: JSON.stringify({ name: "エラー位置" }),
  });
  expect(res.status).toBe(201);
  const data = (await res.json()) as { tenant: { id: string }; api_key: string };
  return { id: data.tenant.id, apiKey: data.api_key };
}

function create(owner: { id: string; apiKey: string }, payload: unknown) {
  return SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${owner.apiKey}`,
    },
    body: JSON.stringify(payload),
  });
}

function publish(owner: { id: string; apiKey: string }, pollId: string) {
  return SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/${pollId}/status`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${owner.apiKey}`,
    },
    body: JSON.stringify({ status: "published" }),
  });
}

describe("field-locatable validation errors", () => {
  it("prefixes per-question create errors and adds question_index details", async () => {
    const owner = await tenant();
    const res = await create(owner, {
      question: "アンケート",
      questions: [
        { prompt: "色", kind: "single", options: [{ label: "赤" }, { label: "青" }] },
        { prompt: "時間帯", kind: "single", options: [{ label: "午前" }, { label: "  " }] },
      ],
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrBody;
    expect(body.error.message).toMatch(/^questions\[1\]: /);
    expect(body.error.details?.question_index).toBe(1);
  });

  it("locates a broken show_if to its question", async () => {
    const owner = await tenant();
    const res = await create(owner, {
      question: "アンケート",
      questions: [
        {
          id: "11111111-1111-4111-8111-111111111111",
          prompt: "色",
          kind: "single",
          options: [
            { id: "22222222-2222-4222-8222-222222222222", label: "赤" },
            { id: "33333333-3333-4333-8333-333333333333", label: "青" },
          ],
        },
        {
          prompt: "理由",
          kind: "text",
          show_if: {
            question_id: "11111111-1111-4111-8111-111111111111",
            option_id: "99999999-9999-4999-8999-999999999999",
          },
        },
      ],
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrBody;
    expect(body.error.message).toContain("questions[1].show_if");
    expect(body.error.details?.question_index).toBe(1);
  });

  it("tags the schedule error with the closes_at field", async () => {
    const owner = await tenant();
    const res = await create(owner, {
      question: "日程",
      opens_at: "2030-05-02T10:00:00.000Z",
      closes_at: "2030-05-01T10:00:00.000Z",
      questions: [
        { prompt: "色", kind: "single", options: [{ label: "赤" }, { label: "青" }] },
      ],
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as ErrBody;
    expect(body.error.details?.field).toBe("closes_at");
  });

  it("tags vote errors with the offending question_id", async () => {
    const owner = await tenant();
    const created = await create(owner, {
      question: "アンケート",
      questions: [
        { prompt: "色", kind: "single", required: true, options: [{ label: "赤" }, { label: "青" }] },
        { prompt: "感想", kind: "text", required: true },
      ],
    });
    expect(created.status).toBe(201);
    const poll = (await created.json()) as {
      poll: { id: string; questions: { id: string; options: { id: string }[] }[] };
    };
    const [color, note] = poll.poll.questions;
    await publish(owner, poll.poll.id);

    const missing = await SELF.fetch(`${BASE}/api/v1/polls/${poll.poll.id}/vote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        voter_token: "voter-missing",
        answers: [{ question_id: color?.id, option_ids: [color?.options[0]?.id] }],
      }),
    });
    expect(missing.status).toBe(400);
    const missingBody = (await missing.json()) as ErrBody;
    expect(missingBody.error.details?.question_id).toBe(note?.id);

    const unknownOption = await SELF.fetch(`${BASE}/api/v1/polls/${poll.poll.id}/vote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        voter_token: "voter-unknown",
        answers: [
          { question_id: color?.id, option_ids: ["44444444-4444-4444-8444-444444444444"] },
          { question_id: note?.id, text: "よい" },
        ],
      }),
    });
    expect(unknownOption.status).toBe(400);
    const unknownBody = (await unknownOption.json()) as ErrBody;
    expect(unknownBody.error.details?.question_id).toBe(color?.id);
  });

  it("round-trips show_if and applies it when voting", async () => {
    const owner = await tenant();
    const q1 = "11111111-1111-4111-8111-111111111111";
    const o1 = "22222222-2222-4222-8222-222222222222";
    const o2 = "33333333-3333-4333-8333-333333333333";
    const created = await create(owner, {
      question: "分岐",
      questions: [
        {
          id: q1,
          prompt: "色",
          kind: "single",
          required: true,
          options: [
            { id: o1, label: "赤" },
            { id: o2, label: "青" },
          ],
        },
        {
          prompt: "赤の理由",
          kind: "text",
          required: true,
          show_if: { question_id: q1, option_id: o1 },
        },
      ],
    });
    expect(created.status).toBe(201);
    const poll = (await created.json()) as {
      poll: {
        id: string;
        questions: { id: string; show_if: { question_id: string; option_id: string } | null; options: { id: string }[] }[];
      };
    };
    const stored = poll.poll.questions[1];
    expect(stored?.show_if).not.toBeNull();
    // Stored ids are regenerated; the condition must point at the stored
    // first question / first option.
    expect(stored?.show_if?.question_id).toBe(poll.poll.questions[0]?.id);
    expect(stored?.show_if?.option_id).toBe(poll.poll.questions[0]?.options[0]?.id);
    await publish(owner, poll.poll.id);

    const first = poll.poll.questions[0];
    const triggerless = await SELF.fetch(`${BASE}/api/v1/polls/${poll.poll.id}/vote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        voter_token: "voter-blue",
        answers: [{ question_id: first?.id, option_ids: [first?.options[1]?.id] }],
      }),
    });
    expect(triggerless.status).toBe(200);

    const triggered = await SELF.fetch(`${BASE}/api/v1/polls/${poll.poll.id}/vote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        voter_token: "voter-red",
        answers: [{ question_id: first?.id, option_ids: [first?.options[0]?.id] }],
      }),
    });
    expect(triggered.status).toBe(400);
    const triggeredBody = (await triggered.json()) as ErrBody;
    expect(triggeredBody.error.details?.question_id).toBe(stored?.id);
  });
});
