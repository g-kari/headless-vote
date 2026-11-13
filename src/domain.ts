import { ensureVoterKeysHashed } from "./ballots";
import { ApiError, badRequest } from "./errors";
import { TEXT_KINDS, listQuestionRows, parseBallotDocument, questionConfig } from "./questions";
import { assertPlainText, readBodyLimited } from "./security";
import type { AppContext, Env, OptionRow, PollRow, QuestionConfig, QuestionRow } from "./types";

const MAX_JSON_BYTES = 64 * 1024;

/** Parse a JSON request body, or throw a uniform 400. Bodies are size-capped. */
export async function jsonBody<T extends Record<string, unknown>>(
  c: AppContext,
): Promise<T> {
  let parsed: unknown;
  try {
    const bytes = await readBodyLimited(c.req.raw, MAX_JSON_BYTES);
    if (bytes.byteLength === 0) throw badRequest("Request body must be valid JSON");
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch (err) {
    if (err instanceof ApiError) throw err;
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
  assertPlainText(trimmed);
  return trimmed;
}

export function optString(
  body: Record<string, unknown>,
  field: string,
  opts: { max?: number; newlines?: boolean } = {},
): string | null {
  const value = body[field];
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") throw badRequest(`"${field}" must be a string`);
  const max = opts.max ?? 5000;
  if (value.length > max) throw badRequest(`"${field}" is too long (max ${max})`);
  assertPlainText(value, { newlines: opts.newlines ?? false });
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

export function pollToJson(
  origin: string,
  poll: PollRow,
  options: OptionRow[],
  questions: QuestionRow[] = [],
) {
  const questionJson = questions.map((q) => ({
    id: q.id,
    prompt: q.prompt,
    description: q.description,
    image_url: imageUrl(origin, q.image_key),
    kind: q.kind,
    required: q.required === 1,
    position: q.position,
    config: q.config ? questionConfig(q) : null,
    show_if:
      q.show_if_question_id && q.show_if_option_id
        ? { question_id: q.show_if_question_id, option_id: q.show_if_option_id }
        : null,
    options: options.filter((o) => o.question_id === q.id).map((o) => optionToJson(origin, o)),
  }));
  const firstChoice = questions.find((q) => q.kind === "single" || q.kind === "multiple" || q.kind === "ranking" || q.kind === "score" || q.kind === "allocation");
  return {
    id: poll.id,
    question: poll.question,
    description: poll.description,
    image_url: imageUrl(origin, poll.image_key),
    status: poll.status,
    allow_multiple: firstChoice ? firstChoice.kind === "multiple" : poll.allow_multiple === 1,
    require_login: poll.require_login === 1,
    opens_at: poll.opens_at,
    closes_at: poll.closes_at,
    results_visibility: poll.results_visibility,
    ip_single_vote: poll.ip_single_vote === 1,
    confirm_required: poll.confirm_required === 1,
    created_at: poll.created_at,
    updated_at: poll.updated_at,
    options: questionJson.flatMap((q) => q.options),
    questions: questionJson,
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

/** True when a published poll has an open time that is still in the future. */
export function isNotYetOpen(poll: PollRow, now = new Date()): boolean {
  if (!poll.opens_at) return false;
  const time = Date.parse(poll.opens_at);
  return !Number.isNaN(time) && time > now.getTime();
}

export function assertSchedule(opensAt: string | null, closesAt: string | null): void {
  if (opensAt && closesAt && Date.parse(opensAt) >= Date.parse(closesAt)) {
    throw badRequest('"opens_at" must be earlier than "closes_at"', { field: "closes_at" });
  }
}

/** A poll rejects new votes when closed manually or past its deadline. */
export function isClosedForVoting(poll: PollRow, now = new Date()): boolean {
  if (poll.status === "closed") return true;
  if (poll.closes_at && Date.parse(poll.closes_at) <= now.getTime()) return true;
  return false;
}

/** Fail closed for unpublished polls and unknown visibility values. */
export function canViewPublicResults(poll: PollRow, now = new Date()): boolean {
  return poll.status !== "draft" && (
    poll.results_visibility === "public" ||
    (poll.results_visibility === "after_close" && isClosedForVoting(poll, now))
  );
}

export interface QuestionResult {
  id: string;
  prompt: string;
  kind: QuestionRow["kind"];
  required: boolean;
  position: number;
  response_count: number;
  config: QuestionConfig | null;
  options: {
    id: string;
    label: string;
    image_url: string | null;
    votes: number;
    points?: number;
    average_rank?: number | null;
    average_score?: number | null;
    average_points?: number | null;
  }[];
  texts?: string[];
  /** Raw numeric answers (number/slider), only with includeText. */
  values?: number[];
  /** Summary statistics for number/scale/slider questions. */
  numeric?: { count: number; average: number | null; min: number | null; max: number | null };
}

export interface PollResults {
  poll_id: string;
  status: PollRow["status"];
  opens_at: string | null;
  closes_at: string | null;
  total_voters: number;
  total_votes: number;
  options: QuestionResult["options"];
  questions: QuestionResult[];
}

export async function computeResults(
  env: Env,
  origin: string,
  poll: PollRow,
  opts: { includeText?: boolean } = {},
): Promise<PollResults> {
  await ensureVoterKeysHashed(env);
  const questions = await listQuestionRows(env, poll.id);
  const options = await listOptionRows(env, poll.id);
  const ballots = await env.DB.prepare(
    "SELECT option_ids FROM vote_ballots WHERE poll_id = ?1",
  )
    .bind(poll.id)
    .all<{ option_ids: string }>();
  const defaultQuestionId = questions[0]?.id ?? poll.id;
  const kindByQuestion = new Map(questions.map((q) => [q.id, q.kind]));
  const optionCountByQuestion = new Map<string, number>();
  for (const o of options) {
    optionCountByQuestion.set(o.question_id, (optionCountByQuestion.get(o.question_id) ?? 0) + 1);
  }
  const optionVotes = new Map<string, number>();
  const textAnswers = new Map<string, string[]>();
  const numericAnswers = new Map<string, number[]>();
  const answered = new Map<string, number>();
  const rankStats = new Map<string, { points: number; rankSum: number; count: number; first: number }>();
  const scoreStats = new Map<string, { sum: number; count: number }>();
  for (const ballot of ballots.results) {
    for (const answer of parseBallotDocument(ballot.option_ids, defaultQuestionId)) {
      answered.set(answer.question_id, (answered.get(answer.question_id) ?? 0) + 1);
      const kind = kindByQuestion.get(answer.question_id);
      if (answer.value !== null && answer.value !== undefined) {
        const list = numericAnswers.get(answer.question_id) ?? [];
        list.push(answer.value);
        numericAnswers.set(answer.question_id, list);
      }
      if (kind === "ranking") {
        const total = optionCountByQuestion.get(answer.question_id) ?? answer.option_ids.length;
        answer.option_ids.forEach((id, index) => {
          const stat = rankStats.get(id) ?? { points: 0, rankSum: 0, count: 0, first: 0 };
          stat.points += Math.max(0, total - index);
          stat.rankSum += index + 1;
          stat.count += 1;
          if (index === 0) stat.first += 1;
          rankStats.set(id, stat);
        });
      } else if (kind !== "score") {
        for (const id of answer.option_ids) optionVotes.set(id, (optionVotes.get(id) ?? 0) + 1);
      }
      if (answer.scores) {
        for (const [id, value] of Object.entries(answer.scores)) {
          const stat = scoreStats.get(id) ?? { sum: 0, count: 0 };
          stat.sum += value;
          stat.count += 1;
          scoreStats.set(id, stat);
        }
      }
      if (answer.text) {
        const list = textAnswers.get(answer.question_id) ?? [];
        list.push(answer.text);
        textAnswers.set(answer.question_id, list);
      }
    }
  }
  const round2 = (n: number) => Math.round(n * 100) / 100;
  const questionResults: QuestionResult[] = questions.map((q) => {
    const config = q.config ? questionConfig(q) : null;
    const values = numericAnswers.get(q.id) ?? [];
    let qOptions = options
      .filter((o) => o.question_id === q.id)
      .map((o) => {
        const base = {
          id: o.id,
          label: o.label,
          image_url: imageUrl(origin, o.image_key),
          votes: optionVotes.get(o.id) ?? 0,
        };
        if (q.kind === "ranking") {
          const stat = rankStats.get(o.id);
          return {
            ...base,
            votes: stat?.first ?? 0,
            points: stat?.points ?? 0,
            average_rank: stat && stat.count > 0 ? round2(stat.rankSum / stat.count) : null,
          };
        }
        if (q.kind === "score") {
          const stat = scoreStats.get(o.id);
          return {
            ...base,
            votes: stat?.count ?? 0,
            average_score: stat && stat.count > 0 ? round2(stat.sum / stat.count) : null,
          };
        }
        if (q.kind === "allocation") {
          const stat = scoreStats.get(o.id);
          return {
            ...base,
            votes: stat?.count ?? 0,
            points: stat?.sum ?? 0,
            average_points: stat && stat.count > 0 ? round2(stat.sum / stat.count) : null,
          };
        }
        return base;
      });
    if (q.kind === "scale") {
      // Steps are synthesized as options so bars and exports work uniformly.
      const steps = config?.steps ?? 5;
      qOptions = Array.from({ length: steps }, (_, i) => {
        const step = i + 1;
        return {
          id: `${q.id}:step:${step}`,
          label: String(step),
          image_url: null,
          votes: values.filter((v) => v === step).length,
        };
      });
    }
    const result: QuestionResult = {
      id: q.id,
      prompt: q.prompt,
      kind: q.kind,
      required: q.required === 1,
      position: q.position,
      response_count: answered.get(q.id) ?? 0,
      config,
      options: qOptions,
    };
    if (q.kind === "number" || q.kind === "scale" || q.kind === "slider") {
      result.numeric = values.length > 0
        ? {
            count: values.length,
            average: round2(values.reduce((a, b) => a + b, 0) / values.length),
            min: Math.min(...values),
            max: Math.max(...values),
          }
        : { count: 0, average: null, min: null, max: null };
    }
    if (opts.includeText && TEXT_KINDS.includes(q.kind)) result.texts = textAnswers.get(q.id) ?? [];
    if (opts.includeText && (q.kind === "number" || q.kind === "slider")) result.values = values;
    return result;
  });
  const flat = questionResults.flatMap((q) => q.options);
  const totalVotes = flat.reduce((sum, o) => sum + o.votes, 0);
  return {
    poll_id: poll.id,
    status: poll.status,
    opens_at: poll.opens_at,
    closes_at: poll.closes_at,
    total_voters: ballots.results.length,
    total_votes: totalVotes,
    options: flat,
    questions: questionResults,
  };
}
