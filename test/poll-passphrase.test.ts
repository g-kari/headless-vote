import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { applySchema } from "./fixtures";

const BASE = "https://vote.test";
const SECRET = "himitsu-no-aikotoba";

beforeAll(async () => {
  await applySchema(env.DB);
});

interface PollBody {
  poll: { id: string; passphrase_required: boolean };
}

interface ErrBody {
  error: { code: string; message: string; details?: Record<string, unknown> };
}

async function tenant() {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: "合言葉" }),
  });
  expect(res.status).toBe(201);
  const data = (await res.json()) as { tenant: { id: string }; api_key: string };
  return { id: data.tenant.id, apiKey: data.api_key };
}

function keyAuth(apiKey: string): Record<string, string> {
  return { authorization: `Bearer ${apiKey}`, "content-type": "application/json" };
}

async function createPoll(owner: { id: string; apiKey: string }, body: unknown) {
  return SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls`, {
    method: "POST",
    headers: keyAuth(owner.apiKey),
    body: JSON.stringify(body),
  });
}

async function publish(owner: { id: string; apiKey: string }, pollId: string) {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/${pollId}/status`, {
    method: "POST",
    headers: keyAuth(owner.apiKey),
    body: JSON.stringify({ status: "published" }),
  });
  expect(res.status).toBe(200);
}

function vote(pollId: string, body: unknown) {
  return SELF.fetch(`${BASE}/api/v1/polls/${pollId}/vote`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function protectedPoll(owner: { id: string; apiKey: string }) {
  const created = await createPoll(owner, {
    question: "合言葉つき投票",
    options: [{ label: "A" }, { label: "B" }],
    passphrase: SECRET,
  });
  expect(created.status).toBe(201);
  const raw = await created.text();
  const parsed = JSON.parse(raw) as PollBody & { poll: { questions: { options: { id: string }[] }[] } };
  // The passphrase and its stored form never appear in API responses.
  expect(raw).not.toContain(SECRET);
  expect(raw).not.toContain("passphrase_hash");
  expect(parsed.poll.passphrase_required).toBe(true);
  return parsed.poll;
}

describe("poll passphrase", () => {
  it("stores only a salted hash and requires the passphrase to vote", async () => {
    const owner = await tenant();
    const poll = await protectedPoll(owner);

    const row = await env.DB.prepare("SELECT passphrase_hash FROM polls WHERE id = ?1")
      .bind(poll.id)
      .first<{ passphrase_hash: string }>();
    expect(row?.passphrase_hash).toMatch(/^v1\./);
    expect(row?.passphrase_hash).not.toContain(SECRET);

    await publish(owner, poll.id);
    const optionId = poll.questions[0]?.options[0]?.id as string;

    const missing = await vote(poll.id, { voter_token: "voter-token-1", option_ids: [optionId] });
    expect(missing.status).toBe(403);
    const missingBody = (await missing.json()) as ErrBody;
    expect(missingBody.error.code).toBe("PASSPHRASE_REQUIRED");
    expect(missingBody.error.details?.field).toBe("passphrase");

    const wrong = await vote(poll.id, {
      voter_token: "voter-token-1",
      option_ids: [optionId],
      passphrase: "wrong-pass",
    });
    expect(wrong.status).toBe(403);
    expect(((await wrong.json()) as ErrBody).error.code).toBe("PASSPHRASE_INVALID");

    const ok = await vote(poll.id, {
      voter_token: "voter-token-1",
      option_ids: [optionId],
      passphrase: SECRET,
    });
    expect(ok.status).toBe(200);
  });

  it("supports changing and clearing the passphrase via PATCH", async () => {
    const owner = await tenant();
    const poll = await protectedPoll(owner);
    await publish(owner, poll.id);
    const optionId = poll.questions[0]?.options[0]?.id as string;

    const patch = (body: unknown) =>
      SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/${poll.id}`, {
        method: "PATCH",
        headers: keyAuth(owner.apiKey),
        body: JSON.stringify(body),
      });

    const changed = await patch({ passphrase: "new-secret-2" });
    expect(changed.status).toBe(200);
    expect(((await changed.json()) as PollBody).poll.passphrase_required).toBe(true);
    const oldVote = await vote(poll.id, {
      voter_token: "voter-token-2",
      option_ids: [optionId],
      passphrase: SECRET,
    });
    expect(oldVote.status).toBe(403);
    const newVote = await vote(poll.id, {
      voter_token: "voter-token-2",
      option_ids: [optionId],
      passphrase: "new-secret-2",
    });
    expect(newVote.status).toBe(200);

    const both = await patch({ passphrase: "another-one", clear_passphrase: true });
    expect(both.status).toBe(400);

    const cleared = await patch({ clear_passphrase: true });
    expect(cleared.status).toBe(200);
    expect(((await cleared.json()) as PollBody).poll.passphrase_required).toBe(false);
    const openVote = await vote(poll.id, { voter_token: "voter-token-3", option_ids: [optionId] });
    expect(openVote.status).toBe(200);
  });

  it("rejects too-short passphrases and does not copy them on duplicate", async () => {
    const owner = await tenant();
    const short = await createPoll(owner, {
      question: "短い合言葉",
      options: [{ label: "A" }, { label: "B" }],
      passphrase: "abc",
    });
    expect(short.status).toBe(400);
    expect(((await short.json()) as ErrBody).error.details?.field).toBe("passphrase");

    const poll = await protectedPoll(owner);
    const dup = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/${poll.id}/duplicate`, {
      method: "POST",
      headers: keyAuth(owner.apiKey),
      body: JSON.stringify({}),
    });
    expect(dup.status).toBe(201);
    expect(((await dup.json()) as PollBody).poll.passphrase_required).toBe(false);
  });
});
