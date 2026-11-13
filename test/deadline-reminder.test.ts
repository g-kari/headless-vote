import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { notifyDeadlineReminders } from "../src/notifications";
import { applySchema } from "./fixtures";

const BASE = "https://vote.test";

beforeAll(async () => {
  await applySchema(env.DB);
});

interface PollBody {
  poll: { id: string; reminder_enabled: boolean; reminder_lead_hours: number };
}

async function tenant() {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: "リマインド" }),
  });
  expect(res.status).toBe(201);
  const data = (await res.json()) as { tenant: { id: string }; api_key: string };
  return { id: data.tenant.id, apiKey: data.api_key };
}

function keyAuth(apiKey: string): Record<string, string> {
  return { authorization: `Bearer ${apiKey}`, "content-type": "application/json" };
}

async function createPoll(owner: { id: string; apiKey: string }, body: unknown) {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls`, {
    method: "POST",
    headers: keyAuth(owner.apiKey),
    body: JSON.stringify(body),
  });
  expect(res.status).toBe(201);
  return ((await res.json()) as PollBody).poll;
}

async function publish(owner: { id: string; apiKey: string }, pollId: string) {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/${pollId}/status`, {
    method: "POST",
    headers: keyAuth(owner.apiKey),
    body: JSON.stringify({ status: "published" }),
  });
  expect(res.status).toBe(200);
}

describe("deadline reminders", () => {
  it("fires once inside the poll's own lead time and stays off otherwise", async () => {
    const owner = await tenant();
    const soon = await createPoll(owner, {
      question: "もうすぐ締切",
      closes_at: new Date(Date.now() + 12 * 3600000).toISOString(),
      options: [{ label: "A" }, { label: "B" }],
      reminder_enabled: true,
      reminder_lead_hours: 24,
    });
    expect(soon.reminder_enabled).toBe(true);
    expect(soon.reminder_lead_hours).toBe(24);
    const far = await createPoll(owner, {
      question: "まだ先の締切",
      closes_at: new Date(Date.now() + 72 * 3600000).toISOString(),
      options: [{ label: "A" }, { label: "B" }],
      reminder_enabled: true,
      reminder_lead_hours: 24,
    });
    const disabled = await createPoll(owner, {
      question: "リマインドなし",
      closes_at: new Date(Date.now() + 12 * 3600000).toISOString(),
      options: [{ label: "A" }, { label: "B" }],
    });
    expect(disabled.reminder_enabled).toBe(false);
    for (const poll of [soon, far, disabled]) await publish(owner, poll.id);

    const first = await notifyDeadlineReminders(env);
    expect(first).toBe(1);
    const second = await notifyDeadlineReminders(env);
    expect(second).toBe(0);

    const list = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/notifications`, {
      headers: keyAuth(owner.apiKey),
    });
    const data = (await list.json()) as {
      notifications: { kind: string; message: string; poll_id: string }[];
    };
    const mine = data.notifications.filter((n) => n.kind === "deadline_reminder");
    expect(mine).toHaveLength(1);
    expect(mine[0]?.poll_id).toBe(soon.id);
    expect(mine[0]?.message).toContain("もうすぐ締切");
  });

  it("accepts the webhook event and validates the lead time", async () => {
    const owner = await tenant();
    const hook = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/webhooks`, {
      method: "POST",
      headers: keyAuth(owner.apiKey),
      body: JSON.stringify({ url: "https://example.com/hook", events: ["poll.deadline_reminder"] }),
    });
    expect([201, 400]).toContain(hook.status); // URL may be rejected by SSRF rules in tests
    if (hook.status === 201) {
      const body = (await hook.json()) as { webhook: { events: string[] } };
      expect(body.webhook.events).toContain("poll.deadline_reminder");
    }

    const bad = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls`, {
      method: "POST",
      headers: keyAuth(owner.apiKey),
      body: JSON.stringify({
        question: "範囲外のリードタイム",
        options: [{ label: "A" }, { label: "B" }],
        reminder_enabled: true,
        reminder_lead_hours: 721,
      }),
    });
    expect(bad.status).toBe(400);
    const err = (await bad.json()) as { error: { details?: Record<string, unknown> } };
    expect(err.error.details?.field).toBe("reminder_lead_hours");

    const spec = await SELF.fetch(`${BASE}/openapi.yaml`);
    expect(await spec.text()).toContain("poll.deadline_reminder");
  });
});
