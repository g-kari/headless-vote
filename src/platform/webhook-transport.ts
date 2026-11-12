import type { Env } from "../types";
import type { WebhookTransport } from "./ports";

export const fetchWebhookTransport: WebhookTransport = {
  id: "fetch",
  async post(url, body, headers) {
    try {
      const res = await fetch(url, {
        method: "POST",
        redirect: "manual",
        signal: AbortSignal.timeout(3000),
        headers,
        body,
      });
      const status = res.status;
      await res.body?.cancel();
      return status;
    } catch {
      return 0;
    }
  },
};

export class RecordingWebhookTransport implements WebhookTransport {
  readonly id = "record";
  readonly calls: { url: string; body: string; headers: Record<string, string> }[] = [];
  status = 204;

  async post(url: string, body: string, headers: Record<string, string>): Promise<number> {
    this.calls.push({ url, body, headers });
    return this.status;
  }
}

export function createWebhookTransport(env: Env): WebhookTransport {
  const name = (env.WEBHOOK_TRANSPORT || "fetch").toLowerCase();
  if (name === "fetch") return fetchWebhookTransport;
  if (name === "record") return new RecordingWebhookTransport();
  throw new Error(`Unknown WEBHOOK_TRANSPORT "${name}"`);
}
