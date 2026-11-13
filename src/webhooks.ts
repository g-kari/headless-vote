/** Signed webhook delivery. Secrets are encrypted at rest and never logged. */

import { randomId } from "./crypto";
import { badRequest } from "./errors";
import { createWebhookTransport } from "./platform/webhook-transport";
import type { WebhookTransport } from "./platform/ports";
import { tenantQuotas } from "./quotas";
import { assertPlainText } from "./security";
import type { Env } from "./types";

export const WEBHOOK_EVENTS = ["vote.cast", "poll.published", "poll.closed", "poll.updated", "poll.closing_soon"] as const;
export type WebhookEvent = (typeof WEBHOOK_EVENTS)[number];

const encoder = new TextEncoder();

function pepper(env: Env): string {
  return env.VOTER_KEY_SECRET || env.SESSION_SECRET;
}

async function kek(secret: string): Promise<CryptoKey> {
  const raw = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(`headless-vote/webhook-kek/v1\0${secret}`),
  );
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function encryptSecret(env: Env, plain: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await kek(pepper(env));
  const cipher = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(plain)),
  );
  const packed = new Uint8Array(iv.length + cipher.length);
  packed.set(iv, 0);
  packed.set(cipher, iv.length);
  let binary = "";
  for (const b of packed) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export async function decryptSecret(env: Env, stored: string): Promise<string> {
  const padded = stored.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  const key = await kek(pepper(env));
  const clear = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: bytes.slice(0, 12) },
    key,
    bytes.slice(12),
  );
  return new TextDecoder().decode(clear);
}

export async function signWebhookBody(secret: string, body: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(body));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Public HTTPS destinations only. DNS safety also requires egress enforcement. */
export function assertWebhookUrl(raw: string): string {
  assertPlainText(raw);
  if (raw.length > 300) throw badRequest("Webhook URL is too long");
  let url: URL;
  try { url = new URL(raw); } catch { throw badRequest("Webhook URL must be https"); }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
    throw badRequest("Webhook URL must be https without credentials, a query, or a hash");
  }
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (isBlockedHost(host)) throw badRequest("Webhook URL host is not allowed");
  return url.toString();
}

function isBlockedHost(host: string): boolean {
  // URL canonicalizes IPv6, including embedded IPv4, and preserves brackets.
  if (host.startsWith("[")) {
    const words = host.slice(1, -1).split(":");
    const first = parseInt(words[0] || "0", 16);
    const second = parseInt(words[1] || "0", 16);
    // Only global unicast; exclude special-use, documentation and transition ranges.
    return first < 0x2000 || first > 0x3fff ||
      (first === 0x2001 && (second < 0x200 || second === 0xdb8)) ||
      first === 0x2002 || first === 0x3fff;
  }
  const ipv4 = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(host);
  if (ipv4) {
    const n = ipv4.slice(1).map(Number);
    const a = n[0] ?? 0, b = n[1] ?? 0, c = n[2] ?? 0;
    return n.some((x) => x > 255) || a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 168 || b === 0 || (b === 88 && c === 99))) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113);
  }
  if (!host.includes(".") || host.endsWith(".localhost") || host.endsWith(".local") ||
      host.endsWith(".internal") || host.endsWith(".home.arpa")) return true;
  return !host.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}

interface WebhookRow {
  id: string;
  tenant_id: string;
  url: string;
  secret_enc: string;
  events: string;
  created_at: string;
  disabled_at: string | null;
}

export async function createWebhook(
  env: Env,
  tenantId: string,
  urlRaw: string,
  events: WebhookEvent[],
): Promise<{ id: string; secret: string; url: string }> {
  const url = assertWebhookUrl(urlRaw);
  const unique = [...new Set(events)];
  if (unique.length === 0 || unique.some((e) => !WEBHOOK_EVENTS.includes(e))) {
    throw badRequest("Webhook events must be vote.cast, poll.published, poll.closed, poll.updated, or poll.closing_soon");
  }
  const quotas = await tenantQuotas(env, tenantId);
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  const secret = btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  const id = randomId();
  const inserted = await env.DB.prepare(
    `INSERT INTO webhooks (id, tenant_id, url, secret_enc, events, created_at)
     SELECT ?1, ?2, ?3, ?4, ?5, ?6
     WHERE (SELECT COUNT(*) FROM webhooks WHERE tenant_id = ?2 AND disabled_at IS NULL)
       < (SELECT quota_webhooks FROM tenants WHERE id = ?2)`,
  )
    .bind(id, tenantId, url, await encryptSecret(env, secret), JSON.stringify(unique), new Date().toISOString())
    .run();
  if (Number(inserted.meta.changes ?? 0) !== 1) {
    throw badRequest(`A workspace can have at most ${quotas.webhooks} webhooks`);
  }
  return { id, secret, url };
}

export async function listWebhooks(env: Env, tenantId: string) {
  const res = await env.DB.prepare(
    "SELECT id, url, events, created_at, disabled_at FROM webhooks WHERE tenant_id = ?1 ORDER BY created_at ASC",
  )
    .bind(tenantId)
    .all<{ id: string; url: string; events: string; created_at: string; disabled_at: string | null }>();
  return res.results.map((row) => ({
    id: row.id,
    url: row.url,
    events: JSON.parse(row.events) as string[],
    created_at: row.created_at,
    disabled_at: row.disabled_at,
  }));
}

export async function disableWebhook(env: Env, tenantId: string, id: string): Promise<boolean> {
  const res = await env.DB.prepare(
    "UPDATE webhooks SET disabled_at = ?1 WHERE id = ?2 AND tenant_id = ?3 AND disabled_at IS NULL",
  )
    .bind(new Date().toISOString(), id, tenantId)
    .run();
  return Number(res.meta.changes ?? 0) > 0;
}

export async function dispatchWebhooks(
  env: Env,
  tenantId: string,
  event: WebhookEvent,
  data: Record<string, unknown>,
): Promise<void> {
  const hooks = await env.DB.prepare(
    "SELECT * FROM webhooks WHERE tenant_id = ?1 AND disabled_at IS NULL",
  )
    .bind(tenantId)
    .all<WebhookRow>();
  const transport = createWebhookTransport(env);
  await Promise.all(hooks.results.map((hook) => deliver(env, hook, event, data, transport)));
}

export async function sendSignedWebhook(
  transport: WebhookTransport,
  url: string,
  secret: string,
  payload: string,
  event: string,
): Promise<number> {
  const signature = await signWebhookBody(secret, payload);
  return transport.post(assertWebhookUrl(url), payload, {
    "content-type": "application/json",
    "x-headless-vote-event": event,
    "x-headless-vote-signature": `v1=${signature}`,
  });
}

async function deliver(
  env: Env,
  hook: WebhookRow,
  event: WebhookEvent,
  data: Record<string, unknown>,
  transport: WebhookTransport,
): Promise<void> {
  let subscribed: string[] = [];
  try {
    subscribed = JSON.parse(hook.events) as string[];
  } catch {
    subscribed = [];
  }
  if (!subscribed.includes(event)) return;
  const payload = JSON.stringify({
    id: randomId(),
    type: event,
    created_at: new Date().toISOString(),
    tenant_id: hook.tenant_id,
    data,
  });
  let status = 0;
  try {
    const secret = await decryptSecret(env, hook.secret_enc);
    status = await sendSignedWebhook(transport, hook.url, secret, payload, event);
  } catch {
    status = 0;
  }
  await env.DB.prepare(
    "INSERT INTO webhook_deliveries (id, webhook_id, event, status, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
  )
    .bind(randomId(), hook.id, event, status, new Date().toISOString())
    .run();
}
