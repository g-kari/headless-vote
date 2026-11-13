/**
 * Per-workspace IP allowlist for the admin surface (admin UI + admin API).
 *
 * The configured addresses/CIDRs are a credential-adjacent secret: they are
 * stored in D1 only as AES-GCM ciphertext under a dedicated Worker secret
 * (IP_LIST_ENCRYPTION_KEY, a base64-encoded 32-byte key). Plaintext entries
 * never reach the database, logs, or the audit trail (the audit records only
 * that the restriction changed, plus the entry count).
 *
 * When IP_LIST_ENCRYPTION_KEY is not configured the feature is disabled:
 * restrictions cannot be set and any stored row is ignored. When a stored
 * row cannot be decrypted with the configured key (corruption or a wrong
 * key), enforcement fails closed for that workspace.
 */

import { base64UrlDecode, base64UrlEncode } from "./crypto";
import { badRequest } from "./errors";
import type { Env } from "./types";

const FORMAT_PREFIX = "v1.";
export const MAX_IP_ENTRIES = 50;
const MAX_ENTRY_LENGTH = 64;

/* ------------------------------------------------------------------ */
/* Encryption (AES-GCM, random IV per record)                          */
/* ------------------------------------------------------------------ */

async function loadKey(env: Env): Promise<CryptoKey | null> {
  const raw = env.IP_LIST_ENCRYPTION_KEY?.trim();
  if (!raw) return null;
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(raw.replace(/\+/g, "-").replace(/\//g, "_"));
  } catch {
    return null;
  }
  if (bytes.length !== 32) return null;
  return crypto.subtle.importKey("raw", bytes as BufferSource, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

/** True when the encryption key is configured and usable. */
export async function ipRestrictionAvailable(env: Env): Promise<boolean> {
  return (await loadKey(env)) !== null;
}

export async function encryptIpEntries(env: Env, entries: string[]): Promise<string> {
  const key = await loadKey(env);
  if (!key) throw badRequest("IP restriction is not available in this environment");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      new TextEncoder().encode(JSON.stringify(entries)),
    ),
  );
  const packed = new Uint8Array(iv.length + cipher.length);
  packed.set(iv, 0);
  packed.set(cipher, iv.length);
  return FORMAT_PREFIX + base64UrlEncode(packed);
}

export async function decryptIpEntries(env: Env, stored: string): Promise<string[]> {
  const key = await loadKey(env);
  if (!key) throw new Error("IP_LIST_ENCRYPTION_KEY is not configured");
  if (!stored.startsWith(FORMAT_PREFIX)) throw new Error("unknown ip list format");
  const bytes = base64UrlDecode(stored.slice(FORMAT_PREFIX.length));
  if (bytes.length <= 12) throw new Error("ip list record too short");
  const clear = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: bytes.slice(0, 12) as BufferSource },
    key,
    bytes.slice(12) as BufferSource,
  );
  const parsed: unknown = JSON.parse(new TextDecoder().decode(clear));
  if (!Array.isArray(parsed) || parsed.some((e) => typeof e !== "string")) {
    throw new Error("ip list payload is not a string array");
  }
  return parsed as string[];
}

/* ------------------------------------------------------------------ */
/* IP / CIDR parsing and matching (IPv4 + IPv6)                        */
/* ------------------------------------------------------------------ */

export interface ParsedIp {
  version: 4 | 6;
  bytes: Uint8Array;
}

export interface ParsedEntry extends ParsedIp {
  prefixBits: number;
}

export function parseIpv4(text: string): Uint8Array | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const part = parts[i]!;
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return null;
    const value = Number(part);
    if (value > 255) return null;
    bytes[i] = value;
  }
  return bytes;
}

export function parseIpv6(text: string): Uint8Array | null {
  let rest = text;
  let v4Tail: Uint8Array | null = null;
  if (rest.includes(".")) {
    // Embedded IPv4 tail (e.g. "::ffff:192.0.2.1"): swap it for two zero
    // groups, parse the hex form, then overwrite the last four bytes.
    const lastColon = rest.lastIndexOf(":");
    if (lastColon < 0) return null;
    v4Tail = parseIpv4(rest.slice(lastColon + 1));
    if (!v4Tail) return null;
    rest = `${rest.slice(0, lastColon + 1)}0:0`;
  }
  const halves = rest.split("::");
  if (halves.length > 2) return null;
  const parseGroups = (side: string): number[] | null => {
    if (side === "") return [];
    const groups: number[] = [];
    for (const group of side.split(":")) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
      groups.push(parseInt(group, 16));
    }
    return groups;
  };
  const head = parseGroups(halves[0]!);
  const tail = halves.length === 2 ? parseGroups(halves[1]!) : null;
  if (head === null || tail === null) return null;
  let groups: number[];
  if (tail === null) {
    groups = head;
    if (groups.length !== 8) return null;
  } else {
    const missing = 8 - (head.length + tail.length);
    if (missing < 1) return null;
    groups = [...head, ...new Array<number>(missing).fill(0), ...tail];
  }
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    bytes[i * 2] = (groups[i]! >> 8) & 0xff;
    bytes[i * 2 + 1] = groups[i]! & 0xff;
  }
  if (v4Tail) bytes.set(v4Tail, 12);
  return bytes;
}

export function parseIpAddress(text: string): ParsedIp | null {
  const trimmed = text.trim();
  if (trimmed.includes(":")) {
    const bytes = parseIpv6(trimmed);
    return bytes ? { version: 6, bytes } : null;
  }
  const bytes = parseIpv4(trimmed);
  return bytes ? { version: 4, bytes } : null;
}

/** Parse one allowlist entry: a plain IP or an IP/prefix CIDR. */
export function parseIpEntry(text: string): ParsedEntry | null {
  const trimmed = text.trim().toLowerCase();
  const slash = trimmed.indexOf("/");
  const addressPart = slash >= 0 ? trimmed.slice(0, slash) : trimmed;
  const ip = parseIpAddress(addressPart);
  if (!ip) return null;
  const maxBits = ip.version === 4 ? 32 : 128;
  if (slash < 0) return { ...ip, prefixBits: maxBits };
  const prefixPart = trimmed.slice(slash + 1);
  if (!/^(0|[1-9][0-9]{0,2})$/.test(prefixPart)) return null;
  const prefixBits = Number(prefixPart);
  if (prefixBits > maxBits) return null;
  return { ...ip, prefixBits };
}

function entryMatches(entry: ParsedEntry, ip: ParsedIp): boolean {
  if (entry.version !== ip.version) return false;
  const fullBytes = Math.floor(entry.prefixBits / 8);
  for (let i = 0; i < fullBytes; i++) {
    if (entry.bytes[i] !== ip.bytes[i]) return false;
  }
  const restBits = entry.prefixBits % 8;
  if (restBits > 0) {
    const mask = (0xff << (8 - restBits)) & 0xff;
    if ((entry.bytes[fullBytes]! & mask) !== (ip.bytes[fullBytes]! & mask)) return false;
  }
  return true;
}

/** True when `ip` is a valid address matched by at least one entry. */
export function ipMatchesEntries(ip: string, entries: string[]): boolean {
  const parsed = parseIpAddress(ip);
  if (!parsed) return false;
  for (const raw of entries) {
    const entry = parseIpEntry(raw);
    if (entry && entryMatches(entry, parsed)) return true;
  }
  return false;
}

/**
 * Validate and normalize a submitted entry list. Throws ApiError(400) with a
 * message that names the offending line numbers (never the values in logs —
 * the message is only rendered back to the submitting admin).
 */
export function validateIpEntries(rawEntries: string[]): string[] {
  const entries = rawEntries.map((e) => e.trim().toLowerCase()).filter((e) => e !== "");
  if (entries.length > MAX_IP_ENTRIES) {
    throw badRequest(`許可リストは ${MAX_IP_ENTRIES} 件までです。`);
  }
  const badLines: number[] = [];
  rawEntries.forEach((raw, index) => {
    const value = raw.trim();
    if (value === "") return;
    if (value.length > MAX_ENTRY_LENGTH || !parseIpEntry(value)) badLines.push(index + 1);
  });
  if (badLines.length > 0) {
    throw badRequest(
      `IP アドレスまたは CIDR として読み取れない行があります: ${badLines.join(", ")} 行目。`,
    );
  }
  return [...new Set(entries)];
}

/* ------------------------------------------------------------------ */
/* Storage (D1, ciphertext only)                                       */
/* ------------------------------------------------------------------ */

export type IpRestrictionState =
  | { kind: "disabled" }
  | { kind: "enabled"; entries: string[] }
  /** A stored row exists but cannot be decrypted: enforce closed. */
  | { kind: "error" };

export async function loadIpRestriction(env: Env, tenantId: string): Promise<IpRestrictionState> {
  const row = await env.DB.prepare(
    "SELECT entries_enc FROM tenant_admin_ip_rules WHERE tenant_id = ?1",
  )
    .bind(tenantId)
    .first<{ entries_enc: string }>();
  if (!row) return { kind: "disabled" };
  if (!(await loadKey(env))) return { kind: "disabled" };
  try {
    const entries = await decryptIpEntries(env, row.entries_enc);
    if (entries.length === 0) return { kind: "disabled" };
    return { kind: "enabled", entries };
  } catch {
    return { kind: "error" };
  }
}

/** Save the list. An empty list clears the restriction entirely. */
export async function saveIpRestriction(env: Env, tenantId: string, entries: string[]): Promise<void> {
  if (entries.length === 0) {
    await env.DB.prepare("DELETE FROM tenant_admin_ip_rules WHERE tenant_id = ?1")
      .bind(tenantId)
      .run();
    return;
  }
  const encrypted = await encryptIpEntries(env, entries);
  await env.DB.prepare(
    `INSERT INTO tenant_admin_ip_rules (tenant_id, entries_enc, updated_at)
     VALUES (?1, ?2, ?3)
     ON CONFLICT(tenant_id) DO UPDATE SET entries_enc = excluded.entries_enc, updated_at = excluded.updated_at`,
  )
    .bind(tenantId, encrypted, new Date().toISOString())
    .run();
}

/* ------------------------------------------------------------------ */
/* Enforcement                                                         */
/* ------------------------------------------------------------------ */

/** The trusted client IP for this request (set by the platform edge). */
export function clientIpOf(c: { req: { header: (name: string) => string | undefined } }): string {
  return (c.req.header("cf-connecting-ip") ?? "").trim();
}

/**
 * Whether an admin request from `clientIp` may reach workspace `tenantId`.
 * No restriction → allowed. Restriction on → the IP must be present and
 * match; a missing/unparseable client IP fails closed, as does an
 * undecryptable stored record.
 */
export async function isAdminIpAllowed(env: Env, tenantId: string, clientIp: string): Promise<boolean> {
  const state = await loadIpRestriction(env, tenantId);
  if (state.kind === "disabled") return true;
  if (state.kind === "error") return false;
  if (!clientIp) return false;
  return ipMatchesEntries(clientIp, state.entries);
}
