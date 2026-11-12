import { badRequest } from "./errors";
import { migrateLegacyAnonVoterKeys } from "./voter-keys";
import type { AppContext, Env, OptionRow, PollRow } from "./types";

/** Parse a JSON request body, or throw a uniform 400. */
export async function jsonBody<T extends Record<string, unknown>>(
  c: AppContext,
): Promise<T> {
  let parsed: unknown;
  try {
    parsed = await c.req.json();
  } catch {
    throw badRequest("Request body must be valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw badRequest("Request body must be a JSON object");
  }
  return parsed as T;
}

export function reqString(
  body: Record<string, unknown>,
  field: string,
  opts: { min?: number; max?: number } = {},
): string {
  const value = body[field];
  const min = opts.min ?? 1;
  const max = opts.max ?? 500;
  if (typeof value !== "string") throw badRequest(`"${field}" must be a string`);
  const trimmed = value.trim();
  if (trimmed.length < min) throw badRequest(`"${field}" is too short`);
  if (trimmed.length > max) throw badRequest(`"${field}" is too long (max ${max})`);
  return trimmed;
}

export function optString(
  body: Record<string, unknown>,
  field: string,
  opts: { max?: number } = {},
): string | null {
  const value = body[field];
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") throw badRequest(`"${field}" must be a string`);
  const max = opts.max ?? 5000;
  if (value.length > max) throw badRequest(`"${field}" is too long (max ${max})`);
  return value;
}

export function optBool(body: Record<string, unknown>, field: string): boolean {
  const value = body[field];
  if (value === undefined || value === null) return false;
  if (typeof value !== "boolean") throw badRequest(`"${field}" must be a boolean`);
  return value;
}

/** Validate an ISO-8601 datetime string; returns normalized ISO or null. */
export function optIsoDate(body: Record<string, unknown>, field: string): string | null {
  const value = body[field];
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") throw badRequest(`"${field}" must be an ISO-8601 string`);
  const time = Date.parse(value);
  if (Number.isNaN(time)) throw badRequest(`"${field}" must be an ISO-8601 datetime`);
  return new Date(time).toISOString();
}

export function nowIso(): string {
  return new Date().toISOString();
}

/* ------------------------------------------------------------------ */
/* Poll serialization + results                                        */
/* ------------------------------------------------------------------ */

export function imageUrl(origin: string, key: string | null): string | null {
  return key ? `${origin}/images/${key}` : null;
}

export function optionToJson(origin: string, row: OptionRow) {
  return {
    id: row.id,
    label: row.label,
    image_url: imageUrl(origin, row.image_key),
    position: row.position,
  };
}

export function pollToJson(origin: string, poll: PollRow, options: OptionRow[]) {
  return {
    id: poll.id,
    question: poll.question,
    description: poll.description,
    image_url: imageUrl(origin, poll.image_key),
    status: poll.status,
    allow_multiple: poll.allow_multiple === 1,
    require_login: poll.require_login === 1,
    closes_at: poll.closes_at,
    created_at: poll.created_at,
    updated_at: poll.updated_at,
    options: options.map((o) => optionToJson(origin, o)),
  };
}

export async function getPollRow(env: Env, pollId: string): Promise<PollRow | null> {
  return env.DB.prepare("SELECT * FROM polls WHERE id = ?1")
    .bind(pollId)
    .first<PollRow>();
}

export async function listOptionRows(env: Env, pollId: string): Promise<OptionRow[]> {
  const res = await env.DB.prepare(
    "SELECT * FROM options WHERE poll_id = ?1 ORDER BY position ASC, created_at ASC",
  )
    .bind(pollId)
    .all<OptionRow>();
  return res.results;
}

/** A poll rejects new votes when closed manually or past its deadline. */
export function isClosedForVoting(poll: PollRow, now = new Date()): boolean {
  if (poll.status === "closed") return true;
  if (poll.closes_at && Date.parse(poll.closes_at) <= now.getTime()) return true;
  return false;
}

export interface PollResults {
  poll_id: string;
  status: PollRow["status"];
  closes_at: string | null;
  total_voters: number;
  total_votes: number;
  options: { id: string; label: string; image_url: string | null; votes: number }[];
}

export async function computeResults(
  env: Env,
  origin: string,
  poll: PollRow,
): Promise<PollResults> {
  // Counting is by voter key, so make sure any legacy plaintext anon
  // keys have been rewritten to the HMAC form first.
  await migrateLegacyAnonVoterKeys(env, poll.id);
  const options = await listOptionRows(env, poll.id);
  const counts = await env.DB.prepare(
    "SELECT option_id, COUNT(*) AS votes FROM votes WHERE poll_id = ?1 GROUP BY option_id",
  )
    .bind(poll.id)
    .all<{ option_id: string; votes: number }>();
  const byOption = new Map(counts.results.map((r) => [r.option_id, r.votes]));
  const totals = await env.DB.prepare(
    "SELECT COUNT(DISTINCT voter_key) AS voters, COUNT(*) AS votes FROM votes WHERE poll_id = ?1",
  )
    .bind(poll.id)
    .first<{ voters: number; votes: number }>();
  return {
    poll_id: poll.id,
    status: poll.status,
    closes_at: poll.closes_at,
    total_voters: totals?.voters ?? 0,
    total_votes: totals?.votes ?? 0,
    options: options.map((o) => ({
      id: o.id,
      label: o.label,
      image_url: imageUrl(origin, o.image_key),
      votes: byOption.get(o.id) ?? 0,
    })),
  };
}
