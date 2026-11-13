import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { applySchema } from "./fixtures";

const BASE = "https://vote.test";

beforeAll(async () => {
  await applySchema(env.DB);
});

interface PollJson {
  poll: {
    id: string;
    results_visibility: string;
    ip_single_vote: boolean;
    confirm_required: boolean;
    questions: {
      id: string;
      kind: string;
      show_if: { question_id: string; option_id: string } | null;
      options: { id: string; label: string }[];
    }[];
  };
}

async function tenant() {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: "機能拡張" }),
  });
  expect(res.status).toBe(201);
  const data = (await res.json()) as { tenant: { id: string }; api_key: string };
  return { id: data.tenant.id, apiKey: data.api_key };
}

async function createPoll(owner: { id: string; apiKey: string }, body: unknown) {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${owner.apiKey}` },
    body: JSON.stringify(body),
  });
  return res;
}

async function publish(owner: { id: string; apiKey: string }, pollId: string) {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/${pollId}/status`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${owner.apiKey}` },
    body: JSON.stringify({ status: "published" }),
  });
  expect(res.status).toBe(200);
}

async function vote(pollId: string, body: unknown) {
  return SELF.fetch(`${BASE}/api/v1/polls/${pollId}/vote`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("ranking and score questions", () => {
  it("aggregates ranking by Borda points and score by average", async () => {
    const owner = await tenant();
    const created = await createPoll(owner, {
      question: "順位と点数",
      questions: [
        {
          prompt: "順位付け",
          kind: "ranking",
          options: [{ label: "A" }, { label: "B" }, { label: "C" }],
        },
        {
          prompt: "点数付け",
          kind: "score",
          required: false,
          options: [{ label: "X" }, { label: "Y" }],
        },
      ],
    });
    expect(created.status).toBe(201);
    const { poll } = (await created.json()) as PollJson;
    const ranking = poll.questions[0];
    const score = poll.questions[1];
    if (!ranking || !score) throw new Error("questions missing");
    const [a, b, c] = ranking.options.map((o) => o.id);
    const [x, y] = score.options.map((o) => o.id);
    await publish(owner, poll.id);

    const v1 = await vote(poll.id, {
      voter_token: "rank-voter-1",
      answers: [
        { question_id: ranking.id, option_ids: [a, b, c] },
        { question_id: score.id, scores: { [x as string]: 5, [y as string]: 3 } },
      ],
    });
    expect(v1.status).toBe(200);
    const v2 = await vote(poll.id, {
      voter_token: "rank-voter-2",
      answers: [
        { question_id: ranking.id, option_ids: [b, a, c] },
        { question_id: score.id, scores: { [x as string]: 1 } },
      ],
    });
    expect(v2.status).toBe(200);

    const res = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/results`);
    const data = (await res.json()) as {
      results: {
        questions: {
          kind: string;
          options: { id: string; votes: number; points?: number; average_rank?: number | null; average_score?: number | null }[];
        }[];
      };
    };
    const rq = data.results.questions[0];
    const byId = new Map((rq?.options ?? []).map((o) => [o.id, o]));
    // Borda with 3 options: A gets 3+2=5, B gets 2+3=5, C gets 1+1=2.
    expect(byId.get(a as string)?.points).toBe(5);
    expect(byId.get(b as string)?.points).toBe(5);
    expect(byId.get(c as string)?.points).toBe(2);
    expect(byId.get(a as string)?.votes).toBe(1); // first-place count
    expect(byId.get(a as string)?.average_rank).toBe(1.5);
    const sq = data.results.questions[1];
    const sById = new Map((sq?.options ?? []).map((o) => [o.id, o]));
    expect(sById.get(x as string)?.average_score).toBe(3);
    expect(sById.get(x as string)?.votes).toBe(2);
    expect(sById.get(y as string)?.average_score).toBe(3);
    expect(sById.get(y as string)?.votes).toBe(1);
  });

  it("rejects out-of-range scores and unknown options", async () => {
    const owner = await tenant();
    const created = await createPoll(owner, {
      question: "点数の検証",
      questions: [
        { prompt: "点数", kind: "score", options: [{ label: "X" }, { label: "Y" }] },
      ],
    });
    const { poll } = (await created.json()) as PollJson;
    const score = poll.questions[0];
    if (!score) throw new Error("question missing");
    await publish(owner, poll.id);
    const bad = await vote(poll.id, {
      voter_token: "score-voter-1",
      answers: [{ question_id: score.id, scores: { [score.options[0]?.id as string]: 6 } }],
    });
    expect(bad.status).toBe(400);
    const bad2 = await vote(poll.id, {
      voter_token: "score-voter-1",
      answers: [{ question_id: score.id, scores: { "123e4567-e89b-12d3-a456-426614174000": 3 } }],
    });
    expect(bad2.status).toBe(400);
  });
});

describe("conditional questions (show_if)", () => {
  const QID = "11111111-1111-4111-8111-111111111111";
  const OID_YES = "22222222-2222-4222-8222-222222222222";
  const OID_NO = "33333333-3333-4333-8333-333333333333";

  async function conditionalPoll(owner: { id: string; apiKey: string }) {
    const created = await createPoll(owner, {
      question: "条件分岐",
      questions: [
        {
          id: QID,
          prompt: "続けますか",
          kind: "single",
          options: [
            { id: OID_YES, label: "はい" },
            { id: OID_NO, label: "いいえ" },
          ],
        },
        {
          prompt: "理由は",
          kind: "text",
          show_if: { question_id: QID, option_id: OID_YES },
        },
      ],
    });
    expect(created.status).toBe(201);
    const { poll } = (await created.json()) as PollJson;
    await publish(owner, poll.id);
    return poll;
  }

  it("does not require the conditional question when hidden, and stores it when shown", async () => {
    const owner = await tenant();
    const poll = await conditionalPoll(owner);
    const trigger = poll.questions[0];
    const followUp = poll.questions[1];
    if (!trigger || !followUp) throw new Error("questions missing");
    const yesOptionId = followUp.show_if?.option_id;
    expect(yesOptionId).toBeTruthy();
    const noOptionId = trigger.options.find((o) => o.id !== yesOptionId)?.id;

    // Hidden branch: the required follow-up is not enforced.
    const noVote = await vote(poll.id, {
      voter_token: "cond-voter-no",
      answers: [{ question_id: trigger.id, option_ids: [noOptionId] }],
    });
    expect(noVote.status).toBe(200);

    // Shown branch: the follow-up answer is stored.
    const yesVote = await vote(poll.id, {
      voter_token: "cond-voter-yes",
      answers: [
        { question_id: trigger.id, option_ids: [yesOptionId] },
        { question_id: followUp.id, text: "理由あり" },
      ],
    });
    expect(yesVote.status).toBe(200);
    const res = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/results`);
    const data = (await res.json()) as {
      results: { questions: { response_count: number }[] };
    };
    expect(data.results.questions[1]?.response_count).toBe(1);
  });

  it("rejects show_if pointing at a later question", async () => {
    const owner = await tenant();
    const created = await createPoll(owner, {
      question: "不正な分岐",
      questions: [
        {
          prompt: "先",
          kind: "text",
          required: false,
          show_if: { question_id: QID, option_id: OID_YES },
        },
        {
          id: QID,
          prompt: "後",
          kind: "single",
          options: [
            { id: OID_YES, label: "はい" },
            { id: OID_NO, label: "いいえ" },
          ],
        },
      ],
    });
    expect(created.status).toBe(400);
  });
});

describe("results visibility and anti-fraud options", () => {
  it("hides results until close when results_visibility is after_close", async () => {
    const owner = await tenant();
    const created = await createPoll(owner, {
      question: "非公開の結果",
      results_visibility: "after_close",
      options: [{ label: "A" }, { label: "B" }],
    });
    expect(created.status).toBe(201);
    const { poll } = (await created.json()) as PollJson;
    expect(poll.results_visibility).toBe("after_close");
    await publish(owner, poll.id);
    const hidden = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/results`);
    expect(hidden.status).toBe(403);
    await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/${poll.id}/status`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${owner.apiKey}` },
      body: JSON.stringify({ status: "closed" }),
    });
    const open = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/results`);
    expect(open.status).toBe(200);
  });

  it("requires an explicit confirmation when confirm_required is set", async () => {
    const owner = await tenant();
    const created = await createPoll(owner, {
      question: "確認つき",
      confirm_required: true,
      options: [{ label: "A" }, { label: "B" }],
    });
    const { poll } = (await created.json()) as PollJson;
    expect(poll.confirm_required).toBe(true);
    await publish(owner, poll.id);
    const firstQ = poll.questions[0];
    if (!firstQ) throw new Error("question missing");
    const noConfirm = await vote(poll.id, {
      voter_token: "confirm-voter",
      answers: [{ question_id: firstQ.id, option_ids: [firstQ.options[0]?.id] }],
    });
    expect(noConfirm.status).toBe(409);
    const confirmed = await vote(poll.id, {
      voter_token: "confirm-voter",
      confirm: true,
      answers: [{ question_id: firstQ.id, option_ids: [firstQ.options[0]?.id] }],
    });
    expect(confirmed.status).toBe(200);
  });

  it("keeps one ballot per connection when ip_single_vote is set", async () => {
    const owner = await tenant();
    const created = await createPoll(owner, {
      question: "接続元1票",
      ip_single_vote: true,
      options: [{ label: "A" }, { label: "B" }],
    });
    const { poll } = (await created.json()) as PollJson;
    expect(poll.ip_single_vote).toBe(true);
    await publish(owner, poll.id);
    const q = poll.questions[0];
    if (!q) throw new Error("question missing");
    const headers = { "content-type": "application/json", "cf-connecting-ip": "203.0.113.9" };
    const v1 = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/vote`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        voter_token: "ip-voter-one",
        answers: [{ question_id: q.id, option_ids: [q.options[0]?.id] }],
      }),
    });
    expect(v1.status).toBe(200);
    const v2 = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/vote`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        voter_token: "ip-voter-two",
        answers: [{ question_id: q.id, option_ids: [q.options[1]?.id] }],
      }),
    });
    expect(v2.status).toBe(409);
    const res = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/results`);
    const data = (await res.json()) as { results: { total_voters: number } };
    expect(data.results.total_voters).toBe(1);
    const retained = await SELF.fetch(`${BASE}/api/v1/polls/${poll.id}/ballot?voter_token=ip-voter-one`, { headers });
    const saved = (await retained.json()) as { ballot: { answers: { option_ids: string[] }[] } };
    expect(saved.ballot.answers[0]?.option_ids).toEqual([q.options[0]?.id]);
  });

  it("rejects an unknown results_visibility value", async () => {
    const owner = await tenant();
    const created = await createPoll(owner, {
      question: "不正な公開設定",
      results_visibility: "secret",
      options: [{ label: "A" }, { label: "B" }],
    });
    expect(created.status).toBe(400);
  });
});

describe("public results page", () => {
  it("serves the public results page and the hidden-until-close notice", async () => {
    const owner = await tenant();
    const created = await createPoll(owner, {
      question: "公開ページ",
      options: [{ label: "A" }, { label: "B" }],
    });
    const { poll } = (await created.json()) as PollJson;
    await publish(owner, poll.id);
    const page = await SELF.fetch(`${BASE}/polls/${poll.id}/results-page`);
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain("公開ページ");
    expect(html).toContain("自動更新");

    const created2 = await createPoll(owner, {
      question: "締切後のみ",
      results_visibility: "after_close",
      options: [{ label: "A" }, { label: "B" }],
    });
    const second = ((await created2.json()) as PollJson).poll;
    await publish(owner, second.id);
    const hiddenPage = await SELF.fetch(`${BASE}/polls/${second.id}/results-page`);
    expect(hiddenPage.status).toBe(200);
    expect(await hiddenPage.text()).toContain("結果は締切後に公開されます");
  });
});
