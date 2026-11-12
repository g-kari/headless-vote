import { randomId } from "./crypto";
import { badRequest, conflict } from "./errors";
import { assertPlainText, normalizeUuid } from "./security";
import type { Env, OptionRow, QuestionKind, QuestionRow } from "./types";

export const MAX_QUESTIONS = 20;
export const MAX_OPTIONS = 50;
export const MAX_TEXT = 2000;

export interface OptionInput {
  id?: string;
  label: string;
  image_key: string | null;
}

export interface QuestionInput {
  id?: string;
  prompt: string;
  description: string;
  image_key: string | null;
  kind: QuestionKind;
  required: boolean;
  options: OptionInput[];
}

export interface AnswerInput {
  question_id: string;
  option_ids: string[];
  text: string | null;
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
  return raw.map((item, index) => {
    if (typeof item !== "object" || item === null) {
      throw badRequest(`questions[${index}] must be an object`);
    }
    const q = item as Record<string, unknown>;
    const kind = q["kind"];
    if (kind !== "single" && kind !== "multiple" && kind !== "text") {
      throw badRequest(`questions[${index}].kind must be single, multiple, or text`);
    }
    const prompt = readString(q, "prompt", 300);
    const description = typeof q["description"] === "string" ? q["description"] : "";
    if (description.length > 2000) throw badRequest('"description" is too long (max 2000)');
    if (description) assertPlainText(description, { newlines: true });
    const required = q["required"] === undefined ? true : q["required"];
    if (typeof required !== "boolean") throw badRequest(`questions[${index}].required must be a boolean`);
    const options = kind === "text" ? [] : parseOptionList(q["options"], `questions[${index}].options`);
    if (kind === "text" && q["options"] !== undefined && Array.isArray(q["options"]) && q["options"].length > 0) {
      throw badRequest(`questions[${index}] is free text and cannot have options`);
    }
    return {
      id: readOptionalId(q, "id"),
      prompt,
      description,
      image_key: readOptionalString(q, "image_key", 300),
      kind,
      required,
      options,
    };
  });
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
  };
}

export async function replaceQuestions(
  env: Env,
  pollId: string,
  questions: QuestionInput[],
): Promise<void> {
  const now = new Date().toISOString();
  await env.DB.prepare("DELETE FROM questions WHERE poll_id = ?1").bind(pollId).run();
  for (let i = 0; i < questions.length; i++) {
    const q = questions[i];
    if (!q) continue;
    const questionId = randomId();
    await env.DB.prepare(
      `INSERT INTO questions (id, poll_id, prompt, description, image_key, kind, required, position, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`,
    )
      .bind(
        questionId,
        pollId,
        q.prompt,
        q.description,
        q.image_key,
        q.kind,
        q.required ? 1 : 0,
        i,
        now,
      )
      .run();
    if (q.options.length > 0) {
      await env.DB.batch(
        q.options.map((o, position) =>
          env.DB.prepare(
            `INSERT INTO options (id, poll_id, question_id, label, image_key, position, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`,
          ).bind(randomId(), pollId, questionId, o.label, o.image_key, position, now),
        ),
      );
    }
  }
}

/** Prompt and label edits, including reorder, when option and question ids stay the same. */
export async function updateQuestionText(
  env: Env,
  pollId: string,
  questions: QuestionInput[],
  existingQuestions: QuestionRow[],
  existingOptions: OptionRow[],
): Promise<void> {
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
         WHERE id = ?5 AND poll_id = ?6`,
      ).bind(q.prompt, q.description, q.required ? 1 : 0, i, q.id, pollId),
    );
    q.options.forEach((o, position) => {
      if (!o.id) return;
      stmts.push(
        env.DB.prepare(
          "UPDATE options SET label = ?1, image_key = ?2, position = ?3 WHERE id = ?4 AND question_id = ?5",
        ).bind(o.label, o.image_key, position, o.id, q.id),
      );
    });
  }
  if (stmts.length > 0) await env.DB.batch(stmts);
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
    const prevOptions = existingOptions.filter((o) => o.question_id === q.id);
    if (q.kind === "text") {
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
    const choice = questions.filter((q) => q.kind !== "text");
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
  const answers: AnswerInput[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    if (typeof item !== "object" || item === null) throw badRequest("Each answer must be an object");
    const row = item as Record<string, unknown>;
    const questionId = readOptionalId(row, "question_id");
    if (!questionId) throw badRequest('"question_id" is required');
    if (seen.has(questionId)) throw badRequest("Duplicate answer for a question");
    seen.add(questionId);
    const question = questions.find((q) => q.id === questionId);
    if (!question) throw badRequest("Unknown question id");
    if (question.kind === "text") {
      const text = row["text"];
      if (typeof text !== "string") throw badRequest('"text" must be a string');
      const trimmed = text.trim();
      if (trimmed.length > MAX_TEXT) throw badRequest(`"text" is too long (max ${MAX_TEXT})`);
      assertPlainText(trimmed, { newlines: true });
      if (question.required === 1 && trimmed.length < 1) throw badRequest("A required text question is empty");
      if (trimmed.length === 0) continue;
      answers.push({ question_id: questionId, option_ids: [], text: trimmed });
    } else {
      answers.push(validateChoice(question, readOptionIds(row["option_ids"]), byQuestion.get(questionId) ?? []));
    }
  }
  for (const question of questions) {
    if (question.required === 1 && !answers.some((a) => a.question_id === question.id)) {
      throw badRequest(`Missing answer for question ${question.id}`);
    }
  }
  return answers;
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
  return { question_id: question.id, option_ids: optionIds, text: null };
}

export function ballotDocument(answers: AnswerInput[]): string {
  return JSON.stringify({
    v: 2,
    answers: answers.map((a) =>
      a.text !== null
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
    answers.push({ question_id: row["question_id"], option_ids: optionIds, text });
  }
  return answers;
}
