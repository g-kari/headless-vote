import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { notifyClosingSoon } from "../src/notifications";
import { applySchema } from "./fixtures";

const BASE = "https://vote.test";
beforeAll(async () => { await applySchema(env.DB); });

async function setup(visibility: string, kind = "single", closesAt?: string) {
  const tenantResponse = await SELF.fetch(`${BASE}/api/v1/tenants`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: "Feature security regression" }),
  });
  expect(tenantResponse.status).toBe(201);
  const owner = await tenantResponse.json() as { tenant: { id: string }; api_key: string };
  const headers = { "content-type": "application/json", authorization: `Bearer ${owner.api_key}` };
  const root = `${BASE}/api/v1/tenants/${owner.tenant.id}/polls`;
  const created = await SELF.fetch(root, {
    method: "POST", headers,
    body: JSON.stringify({
      question: "Restricted results", results_visibility: visibility, closes_at: closesAt,
      questions: [{ prompt: "Choose", kind, options: [{ label: "A" }, { label: "B" }] }],
    }),
  });
  expect(created.status).toBe(201);
  const { poll } = await created.json() as {
    poll: { id: string; questions: { id: string; options: { id: string }[] }[] };
  };
  const status = await SELF.fetch(`${root}/${poll.id}/status`, {
    method: "POST", headers, body: JSON.stringify({ status: "published" }),
  });
  expect(status.status).toBe(200);
  const question = poll.questions[0]!;
  return { poll, question, headers, root };
}

function vote(pollId: string, body: unknown) {
  return SELF.fetch(`${BASE}/api/v1/polls/${pollId}/vote`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("public result authorization", () => {
  for (const visibility of ["admin_only", "after_close"]) {
    it(`does not disclose ${visibility} aggregates in vote responses`, async () => {
      const { poll, question, headers, root } = await setup(visibility);
      const submitted = await vote(poll.id, {
        voter_token: "private-result-voter", option_ids: [question.options[0]!.id],
      });
      expect(submitted.status).toBe(200);
      const data = await submitted.json() as { results: unknown; vote: unknown };
      expect(data.vote).toBeTruthy();
      expect(data.results).toBeNull();
      expect((await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/results`)).status).toBe(403);
      const admin = await SELF.fetch(`${root}/${poll.id}/results`, { headers });
      expect(admin.status).toBe(200);
      expect((await admin.json() as { results: { total_voters: number } }).results.total_voters).toBe(1);
      const closed = await SELF.fetch(`${root}/${poll.id}/status`, {
        method: "POST", headers, body: JSON.stringify({ status: "closed" }),
      });
      expect(closed.status).toBe(200);
      expect((await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/results`)).status)
        .toBe(visibility === "after_close" ? 200 : 403);
    });
  }

  it("preserves public aggregates in successful voting responses", async () => {
    const { poll, question } = await setup("public");
    const submitted = await vote(poll.id, {
      voter_token: "public-result-voter", option_ids: [question.options[0]!.id],
    });
    expect(submitted.status).toBe(200);
    expect((await submitted.json() as { results: { total_voters: number } }).results.total_voters).toBe(1);
  });
});

describe("typed answer validation", () => {
  for (const kind of ["score", "ranking"]) {
    it(`rejects the legacy choice shortcut for ${kind}`, async () => {
      const { poll, question } = await setup("public", kind);
      const optionId = question.options[0]!.id;
      const invalid = await vote(poll.id, { voter_token: "typed-voter", option_ids: [optionId] });
      expect(invalid.status).toBe(400);
      const valid = await vote(poll.id, {
        voter_token: "typed-voter",
        answers: [{ question_id: question.id, ...(kind === "score"
          ? { scores: { [optionId]: 5 } } : { option_ids: [optionId] }) }],
      });
      expect(valid.status).toBe(200);
    });
  }
});

it("claims closing notifications once across concurrent runs", async () => {
  const { poll } = await setup("public", "single", new Date(Date.now() + 3600000).toISOString());
  await Promise.all([notifyClosingSoon(env), notifyClosingSoon(env), notifyClosingSoon(env)]);
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM app_notifications WHERE poll_id = ?1 AND kind = 'closing_soon'",
  ).bind(poll.id).first<{ n: number }>();
  expect(row?.n).toBe(1);
  await notifyClosingSoon(env);
  const again = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM app_notifications WHERE poll_id = ?1 AND kind = 'closing_soon'",
  ).bind(poll.id).first<{ n: number }>();
  expect(again?.n).toBe(1);
});
