import { randomId } from "./crypto";
import { ApiError, badRequest, conflict } from "./errors";
import { assertPlainText, normalizeUuid } from "./security";
import type { Env, OptionRow, QuestionConfig, QuestionKind, QuestionRow } from "./types";

export const MAX_QUESTIONS = 20;
export const MAX_OPTIONS = 50;
export const MAX_TEXT = 2000;
export const MAX_SHORT_TEXT = 200;

export const QUESTION_KINDS: readonly QuestionKind[] = [
  "single", "multiple", "text", "short_text", "ranking", "score",
  "number", "date", "scale", "slider", "allocation",
];
/** Kinds answered by picking or scoring options. */
export const OPTION_KINDS: readonly QuestionKind[] = ["single", "multiple", "ranking", "score", "allocation"];
/** Kinds answered through the free-text channel. */
export const TEXT_KINDS: readonly QuestionKind[] = ["text", "short_text", "date"];
/** Kinds answered through the single numeric value channel. */
export const VALUE_KINDS: readonly QuestionKind[] = ["number", "scale", "slider"];

/** Parse the stored config JSON of a question row. Invalid JSON reads as empty. */
export function questionConfig(row: QuestionRow): QuestionConfig {
  if (!row.config) return {};
  try {
    const parsed: unknown = JSON.parse(row.config);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return {};
    return parsed as QuestionConfig;
  } catch {
    return {};
  }
}

export interface OptionInput {
  id?: string;
  label: string;
  image_key: string | null;
}

export interface ShowIfInput {
  question_id: string;
  option_id: string;
}

export interface QuestionInput {
  id?: string;
  prompt: string;
  description: string;
  image_key: string | null;
  kind: QuestionKind;
  required: boolean;
  options: OptionInput[];
  show_if?: ShowIfInput | null;
  /** Normalized per-kind settings; null/absent when the kind needs none. */
  config?: QuestionConfig | null;
}

export interface AnswerInput {
  question_id: string;
  option_ids: string[];
  text: string | null;
  /** Per-option scores for kind = "score"/"allocation" questions (option id -> points). */
  scores: Record<string, number> | null;
  /** Single numeric answer for kind = "number"/"scale"/"slider" questions. */
  value: number | null;
}

export async function listQuestionRows(env: Env, pollId: string): Promise<QuestionRow[]> {
  const res = await env.DB.prepare(
    "SELECT * FROM questions WHERE poll_id = ?1 ORDER BY position ASC, created_at ASC",
  )
    .bind(pollId)
    .all<QuestionRow>();
  return res.results;
}

function parseOptionList(raw: unknown, field: string): OptionInput[] {
  if (!Array.isArray(raw) || raw.length < 2 || raw.length > MAX_OPTIONS) {
    throw badRequest(`"${field}" must be an array of 2 to ${MAX_OPTIONS} items`);
  }
  return raw.map((item, index) => {
    if (typeof item !== "object" || item === null) {
      throw badRequest(`${field}[${index}] must be an object`);
    }
    const o = item as Record<string, unknown>;
    const label = readString(o, "label", 200);
    const image = readOptionalString(o, "image_key", 300);
    const id = readOptionalId(o, "id");
    return { id, label, image_key: image };
  });
}

function readString(body: Record<string, unknown>, field: string, max: number): string {
  const value = body[field];
  if (typeof value !== "string") throw badRequest(`"${field}" must be a string`);
  const trimmed = value.trim();
  if (trimmed.length < 1) throw badRequest(`"${field}" is too short`);
  if (trimmed.length > max) throw badRequest(`"${field}" is too long (max ${max})`);
  assertPlainText(trimmed, { newlines: field === "description" || field === "text" });
  return trimmed;
}

function readOptionalString(
  body: Record<string, unknown>,
  field: string,
  max: number,
): string | null {
  const value = body[field];
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string") throw badRequest(`"${field}" must be a string`);
  if (value.length > max) throw badRequest(`"${field}" is too long (max ${max})`);
  assertPlainText(value);
  return value;
}

function readOptionalId(body: Record<string, unknown>, field: string): string | undefined {
  const value = body[field];
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string") throw badRequest(`"${field}" must be a string`);
  const id = normalizeUuid(value);
  if (!id) throw badRequest(`"${field}" must be an id`);
  return id;
}

/** Parse a questions array. Returns null when the field is absent. */
export function parseQuestions(body: Record<string, unknown>): QuestionInput[] | null {
  if (body["questions"] === undefined) return null;
  const raw = body["questions"];
  if (!Array.isArray(raw) || raw.length < 1 || raw.length > MAX_QUESTIONS) {
    throw badRequest(`"questions" must be an array of 1 to ${MAX_QUESTIONS} items`);
  }
  const parsed: QuestionInput[] = raw.map((item, index) => {
    try {
      return parseQuestionItem(item, index);
     } catch (err) {
      // Make every per-question failure locatable: messages that do not
      // already carry the questions[index] prefix gain it, plus details.
      if (err instanceof ApiError && err.status === 400) {
        if (!err.message.startsWith("questions[")) {
          const wrapped = badRequest(`questions[${index}]: ${err.message}`, {
            question_index: index,
            ...(err.details ?? {}),
          });
          throw wrapped;
        }
        err.details = { question_index: index, ...(err.details ?? {}) };
      }
      throw err;
    }
  });
  return finishParseQuestions(parsed);
}

function readConfigNumber(
  raw: Record<string, unknown>,
  field: string,
  opts: { integer?: boolean; min?: number; max?: number } = {},
): number | undefined {
  const value = raw[field];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw badRequest(`"config.${field}" must be a number`);
  }
  if (opts.integer && !Number.isInteger(value)) {
    throw badRequest(`"config.${field}" must be an integer`);
  }
  if (opts.min !== undefined && value < opts.min) {
    throw badRequest(`"config.${field}" must be at least ${opts.min}`);
  }
  if (opts.max !== undefined && value > opts.max) {
    throw badRequest(`"config.${field}" must be at most ${opts.max}`);
  }
  return value;
}

/** Validate and normalize the per-kind config of a question payload. */
export function parseQuestionConfig(kind: QuestionKind, raw: unknown): QuestionConfig | null {
  if (raw === undefined || raw === null) {
    if (kind === "scale") return { steps: 5 };
    if (kind === "slider") return { min: 0, max: 100, step: 1 };
    if (kind === "allocation") return { total: 100 };
    return null;
  }
  if (typeof raw !== "object" || Array.isArray(raw)) {
    throw badRequest('"config" must be an object');
  }
  const c = raw as Record<string, unknown>;
  switch (kind) {
    case "number": {
      const min = readConfigNumber(c, "min");
      const max = readConfigNumber(c, "max");
      if (min !== undefined && max !== undefined && min > max) {
        throw badRequest('"config.min" must not exceed "config.max"');
      }
      const out: QuestionConfig = {};
      if (min !== undefined) out.min = min;
      if (max !== undefined) out.max = max;
      return Object.keys(out).length > 0 ? out : null;
    }
    case "scale": {
      const steps = readConfigNumber(c, "steps", { integer: true, min: 2, max: 10 }) ?? 5;
      return { steps };
    }
    case "slider": {
      const min = readConfigNumber(c, "min") ?? 0;
      const max = readConfigNumber(c, "max") ?? 100;
      const step = readConfigNumber(c, "step") ?? 1;
      if (min >= max) throw badRequest('"config.min" must be less than "config.max"');
      if (step <= 0) throw badRequest('"config.step" must be positive');
      if (step > max - min) throw badRequest('"config.step" must not exceed the range');
      return { min, max, step };
    }
    case "allocation": {
      const total = readConfigNumber(c, "total", { integer: true, min: 1, max: 100000 }) ?? 100;
      return { total };
    }
    default:
      // Kinds without settings ignore any config payload.
      return null;
  }
}

function parseQuestionItem(item: unknown, index: number): QuestionInput {
  if (typeof item !== "object" || item === null) {
    throw badRequest(`questions[${index}] must be an object`);
  }
  const q = item as Record<string, unknown>;
  const kind = q["kind"];
  if (typeof kind !== "string" || !(QUESTION_KINDS as readonly string[]).includes(kind)) {
    throw badRequest(`questions[${index}].kind must be one of ${QUESTION_KINDS.join(", ")}`);
  }
  const typedKind = kind as QuestionKind;
  const prompt = readString(q, "prompt", 300);
  const description = typeof q["description"] === "string" ? q["description"] : "";
  if (description.length > 2000) throw badRequest('"description" is too long (max 2000)');
  if (description) assertPlainText(description, { newlines: true });
  const required = q["required"] === undefined ? true : q["required"];
  if (typeof required !== "boolean") throw badRequest(`questions[${index}].required must be a boolean`);
  const hasOptions = OPTION_KINDS.includes(typedKind);
  const options = hasOptions ? parseOptionList(q["options"], `questions[${index}].options`) : [];
  if (!hasOptions && q["options"] !== undefined && Array.isArray(q["options"]) && q["options"].length > 0) {
    throw badRequest(`questions[${index}] of kind ${typedKind} cannot have options`);
  }
  const config = parseQuestionConfig(typedKind, q["config"]);
  let showIf: ShowIfInput | null = null;
  if (q["show_if"] !== undefined && q["show_if"] !== null) {
    const raw = q["show_if"];
    if (typeof raw !== "object" || Array.isArray(raw)) {
      throw badRequest(`questions[${index}].show_if must be an object`);
    }
    const target = raw as Record<string, unknown>;
    const targetQuestion = readOptionalId(target, "question_id");
    const targetOption = readOptionalId(target, "option_id");
    if (!targetQuestion || !targetOption) {
      throw badRequest(`questions[${index}].show_if requires question_id and option_id`);
    }
    showIf = { question_id: targetQuestion, option_id: targetOption };
  }
  return {
    id: readOptionalId(q, "id"),
    prompt,
    description,
    image_key: readOptionalString(q, "image_key", 300),
    kind: typedKind,
    required,
    options,
    show_if: showIf,
    config,
  };
}

function finishParseQuestions(parsed: QuestionInput[]): QuestionInput[] {
  // Conditional display must reference an earlier single/multiple question
  // in the same payload, by the client-supplied ids of that question.
  parsed.forEach((question, index) => {
    if (!question.show_if) return;
    const targetIndex = parsed.findIndex((q) => q.id !== undefined && q.id === question.show_if?.question_id);
    if (targetIndex < 0 || targetIndex >= index) {
      throw badRequest(`questions[${index}].show_if must reference an earlier question`, { question_index: index });
    }
    const target = parsed[targetIndex];
    if (!target || (target.kind !== "single" && target.kind !== "multiple")) {
      throw badRequest(`questions[${index}].show_if target must be a single or multiple question`, { question_index: index });
    }
    if (!target.options.some((o) => o.id !== undefined && o.id === question.show_if?.option_id)) {
      throw badRequest(`questions[${index}].show_if option does not belong to the target question`, { question_index: index });
    }
  });
  return parsed;
}

export function legacyQuestion(
  prompt: string,
  allowMultiple: boolean,
  options: OptionInput[],
): QuestionInput {
  return {
    prompt,
    description: "",
    image_key: null,
    kind: allowMultiple ? "multiple" : "single",
    required: true,
    options,
    show_if: null,
    config: null,
  };
}

/** Statements run in the same batch as the guarded poll revision write. */
export function replaceQuestionStatements(
  env: Env, pollId: string, questions: QuestionInput[], revision: string,
): D1PreparedStatement[] {
  const guard = "EXISTS (SELECT 1 FROM polls WHERE id = ?1 AND revision = ?2)";
  const statements = [
    // Upgraded databases lack the fresh-schema question_id foreign key.
    env.DB.prepare(`DELETE FROM options WHERE poll_id = ?1 AND ${guard}`).bind(pollId, revision),
    env.DB.prepare(`DELETE FROM questions WHERE poll_id = ?1 AND ${guard}`).bind(pollId, revision),
  ];
  const now = new Date().toISOString();
  // Ids are regenerated on replace; client-supplied ids in show_if are
  // remapped onto the generated ids so conditions survive the rewrite.
  const questionIds = questions.map(() => randomId());
  const questionIdMap = new Map<string, string>();
  questions.forEach((q, i) => {
    if (q.id) questionIdMap.set(q.id, questionIds[i] as string);
  });
  const optionIdMap = new Map<string, string>();
  questions.forEach((q) => {
    q.options.forEach((o) => {
      if (o.id) optionIdMap.set(o.id, randomId());
    });
  });
  questions.forEach((q, position) => {
    const id = questionIds[position] as string;
    const showQ = q.show_if ? (questionIdMap.get(q.show_if.question_id) ?? null) : null;
    const showO = q.show_if ? (optionIdMap.get(q.show_if.option_id) ?? null) : null;
    statements.push(env.DB.prepare(`INSERT INTO questions
      (id, poll_id, prompt, description, image_key, kind, required, position, show_if_question_id, show_if_option_id, config, created_at)
      SELECT ?3, ?1, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?13, ?12 WHERE ${guard}`)
      .bind(pollId, revision, id, q.prompt, q.description, q.image_key, q.kind, q.required ? 1 : 0, position, showQ, showO, now, q.config ? JSON.stringify(q.config) : null));
    q.options.forEach((o, index) => {
      const optionId = o.id ? (optionIdMap.get(o.id) as string) : randomId();
      statements.push(env.DB.prepare(`INSERT INTO options
        (id, poll_id, question_id, label, image_key, position, created_at)
        SELECT ?3, ?1, ?4, ?5, ?6, ?7, ?8 WHERE ${guard}`)
        .bind(pollId, revision, optionId, id, o.label, o.image_key, index, now));
    });
  });
  return statements;
}

/** Prompt and label edits, including reorder, when option and question ids stay the same. */
export function questionTextStatements(
  env: Env,
  pollId: string,
  questions: QuestionInput[],
  existingQuestions: QuestionRow[],
  existingOptions: OptionRow[],
  revision: string,
): D1PreparedStatement[] {
  if (!sameStructure(questions, existingQuestions, existingOptions)) {
    throw conflict(
      "OPTIONS_LOCKED",
      "Questions and options cannot be added, removed, or retargeted after votes have been cast",
    );
  }
  const stmts = [];
  for (let i = 0; i < questions.length; i++) {
    const q = questions[i];
    if (!q?.id) continue;
    stmts.push(
      env.DB.prepare(
        `UPDATE questions SET prompt = ?1, description = ?2, required = ?3, position = ?4
         WHERE id = ?5 AND poll_id = ?6
         AND EXISTS (SELECT 1 FROM polls WHERE id = ?6 AND revision = ?7)`,
      ).bind(q.prompt, q.description, q.required ? 1 : 0, i, q.id, pollId, revision),
    );
    q.options.forEach((o, position) => {
      if (!o.id) return;
      stmts.push(
        env.DB.prepare(
          "UPDATE options SET label = ?1, image_key = ?2, position = ?3 WHERE id = ?4 AND question_id = ?5 AND EXISTS (SELECT 1 FROM polls WHERE id = ?6 AND revision = ?7)",
        ).bind(o.label, o.image_key, position, o.id, q.id, pollId, revision),
      );
    });
  }
  return stmts;
}

export function sameStructure(
  incoming: QuestionInput[],
  existingQuestions: QuestionRow[],
  existingOptions: OptionRow[],
): boolean {
  if (incoming.length !== existingQuestions.length) return false;
  const byId = new Map(existingQuestions.map((q) => [q.id, q]));
  const seen = new Set<string>();
  for (const q of incoming) {
    if (!q.id || seen.has(q.id)) return false;
    seen.add(q.id);
    const prev = byId.get(q.id);
    if (!prev || prev.kind !== q.kind) return false;
    // Config changes are structural: the text-only edit path never writes
    // config, so a different config must go through a full replace.
    const prevConfig = prev.config ? JSON.stringify(questionConfig(prev)) : null;
    const nextConfig = q.config ? JSON.stringify(q.config) : null;
    if (prevConfig !== nextConfig) return false;
    const prevShowQ = prev.show_if_question_id ?? null;
    const prevShowO = prev.show_if_option_id ?? null;
    if ((q.show_if?.question_id ?? null) !== prevShowQ) return false;
    if ((q.show_if?.option_id ?? null) !== prevShowO) return false;
    const prevOptions = existingOptions.filter((o) => o.question_id === q.id);
    if (!OPTION_KINDS.includes(q.kind)) {
      if (q.options.length > 0 || prevOptions.length > 0) return false;
      continue;
    }
    if (q.options.length !== prevOptions.length) return false;
    const prevIds = new Set(prevOptions.map((o) => o.id));
    const nextIds = new Set<string>();
    for (const o of q.options) {
      if (!o.id || !prevIds.has(o.id) || nextIds.has(o.id)) return false;
      nextIds.add(o.id);
    }
  }
  return seen.size === existingQuestions.length;
}

/** A question is hidden when its show_if trigger answer does not include the required option. */
function isHidden(question: QuestionRow, resolved: Map<string, AnswerInput>): boolean {
  if (!question.show_if_question_id || !question.show_if_option_id) return false;
  const trigger = resolved.get(question.show_if_question_id);
  if (!trigger) return true;
  return !trigger.option_ids.includes(question.show_if_option_id);
}

export function resolveAnswers(
  body: Record<string, unknown>,
  questions: QuestionRow[],
  options: OptionRow[],
): AnswerInput[] {
  const byQuestion = new Map<string, OptionRow[]>();
  for (const option of options) {
    const list = byQuestion.get(option.question_id) ?? [];
    list.push(option);
    byQuestion.set(option.question_id, list);
  }
  if (body["answers"] === undefined && body["option_ids"] !== undefined) {
    const choice = questions.filter((q) => q.kind === "single" || q.kind === "multiple");
    if (choice.length !== 1 || questions.length !== 1) {
      throw badRequest('"answers" is required when a poll has more than one question');
    }
    const only = choice[0];
    if (!only) throw badRequest('"answers" is required');
    return [validateChoice(only, readOptionIds(body["option_ids"]), byQuestion.get(only.id) ?? [])];
  }
  const raw = body["answers"];
  if (!Array.isArray(raw)) throw badRequest('"answers" must be an array');
  if (raw.length > MAX_QUESTIONS) throw badRequest('"answers" is too long');
  const rawByQuestion = new Map<string, Record<string, unknown>>();
  for (const item of raw) {
    if (typeof item !== "object" || item === null) throw badRequest("Each answer must be an object");
    const row = item as Record<string, unknown>;
    const questionId = readOptionalId(row, "question_id");
    if (!questionId) throw badRequest('"question_id" is required');
    if (rawByQuestion.has(questionId)) throw badRequest("Duplicate answer for a question");
    if (!questions.some((q) => q.id === questionId)) throw badRequest("Unknown question id");
    rawByQuestion.set(questionId, row);
  }
  const resolved = new Map<string, AnswerInput>();
  for (const question of questions) {
    if (isHidden(question, resolved)) continue;
    try {
    const row = rawByQuestion.get(question.id);
    if (!row) {
      if (question.required === 1) {
        throw badRequest(`Missing answer for question ${question.id}`);
      }
      continue;
    }
    const qOptions = byQuestion.get(question.id) ?? [];
    if (TEXT_KINDS.includes(question.kind)) {
      const text = row["text"];
      if (typeof text !== "string") throw badRequest('"text" must be a string');
      const trimmed = text.trim();
      if (question.kind === "short_text") {
        if (trimmed.length > MAX_SHORT_TEXT) throw badRequest(`"text" is too long (max ${MAX_SHORT_TEXT})`);
        assertPlainText(trimmed, { newlines: false });
      } else if (question.kind === "date") {
        if (!isValidDateAnswer(trimmed)) throw badRequest('"text" must be a date in YYYY-MM-DD format');
      } else {
        if (trimmed.length > MAX_TEXT) throw badRequest(`"text" is too long (max ${MAX_TEXT})`);
        assertPlainText(trimmed, { newlines: true });
      }
      if (question.required === 1 && trimmed.length < 1) throw badRequest("A required text question is empty");
      if (trimmed.length === 0) continue;
      resolved.set(question.id, { question_id: question.id, option_ids: [], text: trimmed, scores: null, value: null });
    } else if (question.kind === "score") {
      resolved.set(question.id, validateScores(question, row["scores"], qOptions));
    } else if (question.kind === "allocation") {
      resolved.set(question.id, validateAllocation(question, row["scores"], qOptions));
    } else if (VALUE_KINDS.includes(question.kind)) {
      const answer = validateValue(question, row["value"]);
      if (answer) resolved.set(question.id, answer);
    } else if (question.kind === "ranking") {
      const optionIds = readOptionIds(row["option_ids"]);
      const valid = new Set(qOptions.map((o) => o.id));
      for (const id of optionIds) {
        if (!valid.has(id)) throw badRequest("Unknown option id");
      }
      resolved.set(question.id, { question_id: question.id, option_ids: optionIds, text: null, scores: null, value: null });
    } else {
      resolved.set(question.id, validateChoice(question, readOptionIds(row["option_ids"]), qOptions));
    }
    } catch (err) {
      // Attach the offending question so clients (embed UIs, the admin
      // test tools) can place the error next to that question.
      if (err instanceof ApiError && !err.details) err.details = { question_id: question.id };
      throw err;
    }
  }
  return questions.filter((q) => resolved.has(q.id)).map((q) => resolved.get(q.id) as AnswerInput);
}

/** Strict YYYY-MM-DD calendar date check (rejects e.g. 2026-02-30). */
export function isValidDateAnswer(value: string): boolean {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!m) return false;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  if (month < 1 || month > 12 || day < 1 || day > 31) return false;
  const date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
}

function validateValue(question: QuestionRow, raw: unknown): AnswerInput | null {
  if (raw === undefined || raw === null) {
    if (question.required === 1) throw badRequest('"value" is required');
    return null;
  }
  if (typeof raw !== "number" || !Number.isFinite(raw)) {
    throw badRequest('"value" must be a number');
  }
  const config = questionConfig(question);
  if (question.kind === "scale") {
    const steps = config.steps ?? 5;
    if (!Number.isInteger(raw) || raw < 1 || raw > steps) {
      throw badRequest(`"value" must be an integer between 1 and ${steps}`);
    }
  } else if (question.kind === "slider") {
    const min = config.min ?? 0;
    const max = config.max ?? 100;
    const step = config.step ?? 1;
    if (raw < min || raw > max) {
      throw badRequest(`"value" must be between ${min} and ${max}`);
    }
    const stepsFromMin = (raw - min) / step;
    if (Math.abs(stepsFromMin - Math.round(stepsFromMin)) > 1e-9) {
      throw badRequest(`"value" must align to the step of ${step}`);
    }
  } else {
    if (config.min !== undefined && raw < config.min) {
      throw badRequest(`"value" must be at least ${config.min}`);
    }
    if (config.max !== undefined && raw > config.max) {
      throw badRequest(`"value" must be at most ${config.max}`);
    }
  }
  return { question_id: question.id, option_ids: [], text: null, scores: null, value: raw };
}

function validateScores(question: QuestionRow, raw: unknown, options: OptionRow[]): AnswerInput {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw badRequest('"scores" must be an object mapping option ids to scores');
  }
  const valid = new Set(options.map((o) => o.id));
  const scores: Record<string, number> = {};
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    const id = normalizeUuid(key);
    if (!id || !valid.has(id)) throw badRequest("Unknown option id in scores");
    if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 5) {
      throw badRequest('"scores" values must be integers between 0 and 5');
    }
    scores[id] = value;
  }
  if (Object.keys(scores).length === 0) throw badRequest('"scores" must not be empty');
  return { question_id: question.id, option_ids: [], text: null, scores, value: null };
}

function validateAllocation(question: QuestionRow, raw: unknown, options: OptionRow[]): AnswerInput {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw badRequest('"scores" must be an object mapping option ids to points');
  }
  const valid = new Set(options.map((o) => o.id));
  const scores: Record<string, number> = {};
  let sum = 0;
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    const id = normalizeUuid(key);
    if (!id || !valid.has(id)) throw badRequest("Unknown option id in scores");
    if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 100000) {
      throw badRequest('"scores" values must be integers between 0 and 100000');
    }
    scores[id] = value;
    sum += value;
  }
  const total = questionConfig(question).total ?? 100;
  if (sum !== total) {
    throw badRequest(`Allocated points must add up to ${total}`);
  }
  return { question_id: question.id, option_ids: [], text: null, scores, value: null };
}

function readOptionIds(raw: unknown): string[] {
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > MAX_OPTIONS) {
    throw badRequest('"option_ids" must be a non-empty array');
  }
  const ids: string[] = [];
  for (const id of raw) {
    if (typeof id !== "string") throw badRequest('"option_ids" must contain option id strings');
    const normalized = normalizeUuid(id);
    if (!normalized) throw badRequest('"option_ids" must contain option id strings');
    if (!ids.includes(normalized)) ids.push(normalized);
  }
  return ids;
}

function validateChoice(question: QuestionRow, optionIds: string[], options: OptionRow[]): AnswerInput {
  const valid = new Set(options.map((o) => o.id));
  for (const id of optionIds) {
    if (!valid.has(id)) throw badRequest("Unknown option id");
  }
  if (question.kind === "single" && optionIds.length !== 1) {
    throw badRequest("This question allows exactly one choice");
  }
  if (question.kind === "multiple" && optionIds.length < 1) {
    throw badRequest("Select at least one option");
  }
  return { question_id: question.id, option_ids: optionIds, text: null, scores: null, value: null };
}

export function ballotDocument(answers: AnswerInput[]): string {
  return JSON.stringify({
    v: 2,
    answers: answers.map((a) =>
      a.scores !== null
        ? { question_id: a.question_id, scores: a.scores }
        : a.value !== null
          ? { question_id: a.question_id, value: a.value }
          : a.text !== null
            ? { question_id: a.question_id, text: a.text }
            : { question_id: a.question_id, option_ids: a.option_ids },
    ),
  });
}

export function parseBallotDocument(raw: string, defaultQuestionId: string): AnswerInput[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (Array.isArray(parsed)) {
    return [{
      question_id: defaultQuestionId,
      option_ids: parsed.filter((id): id is string => typeof id === "string"),
      text: null,
      scores: null,
      value: null,
    }];
  }
  if (typeof parsed !== "object" || parsed === null || !Array.isArray((parsed as { answers?: unknown }).answers)) {
    return [];
  }
  const answers: AnswerInput[] = [];
  for (const item of (parsed as { answers: unknown[] }).answers) {
    if (typeof item !== "object" || item === null) continue;
    const row = item as Record<string, unknown>;
    if (typeof row["question_id"] !== "string") continue;
    const text = typeof row["text"] === "string" ? row["text"] : null;
    const optionIds = Array.isArray(row["option_ids"])
      ? row["option_ids"].filter((id): id is string => typeof id === "string")
      : [];
    let scores: Record<string, number> | null = null;
    const rawScores = row["scores"];
    if (typeof rawScores === "object" && rawScores !== null && !Array.isArray(rawScores)) {
      scores = {};
      for (const [key, value] of Object.entries(rawScores as Record<string, unknown>)) {
        if (typeof value === "number" && Number.isFinite(value)) scores[key] = value;
      }
      if (Object.keys(scores).length === 0) scores = null;
    }
    const value = typeof row["value"] === "number" && Number.isFinite(row["value"]) ? row["value"] : null;
    answers.push({ question_id: row["question_id"], option_ids: optionIds, text, scores, value });
  }
  return answers;
}
