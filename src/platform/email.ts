import { randomId } from "../crypto";
import type { Env } from "../types";
import type { EmailMessage, EmailSender } from "./ports";

export function createOutboxEmail(env: Env): EmailSender {
  return {
    id: "outbox",
    async send(message: EmailMessage) {
      await env.DB.prepare(
        "INSERT INTO email_outbox (id, recipient, subject, body, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
      )
        .bind(randomId(), message.to, message.subject, message.text, new Date().toISOString())
        .run();
    },
  };
}

export function createHttpEmail(url: string, fetchImpl: typeof fetch = fetch): EmailSender {
  const target = assertEmailEndpoint(url);
  return {
    id: "http",
    async send(message: EmailMessage) {
      const res = await fetchImpl(target, {
        method: "POST",
        redirect: "manual",
        signal: AbortSignal.timeout(5000),
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ to: message.to, subject: message.subject, text: message.text }),
      });
      await res.body?.cancel();
      if (res.status < 200 || res.status >= 300) {
        throw new Error("Email endpoint rejected the message");
      }
    },
  };
}

export function assertEmailEndpoint(raw: string): string {
  const url = new URL(raw);
  if (url.protocol !== "https:" || url.username || url.password) {
    throw new Error("EMAIL_HTTP_URL must be https and must not include credentials");
  }
  return url.toString();
}

export const noopEmail: EmailSender = {
  id: "noop",
  async send() {
    /* The operator chose not to deliver mail. */
  },
};

export function createEmailSender(env: Env): EmailSender {
  const name = (env.EMAIL_PROVIDER || "outbox").toLowerCase();
  if (name === "noop") return noopEmail;
  if (name === "http") {
    if (!env.EMAIL_HTTP_URL) throw new Error("EMAIL_HTTP_URL is required when EMAIL_PROVIDER=http");
    return createHttpEmail(env.EMAIL_HTTP_URL);
  }
  if (name === "outbox") return createOutboxEmail(env);
  throw new Error(`Unknown EMAIL_PROVIDER "${name}"`);
}
