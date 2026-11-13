import { ApiError } from "./errors";
import {
  MAX_OPTIONS,
  MAX_QUESTIONS,
  OPTION_KINDS,
  parseQuestions,
  type QuestionInput,
} from "./questions";
import { assertPlainText } from "./security";
import type { QuestionConfig, QuestionKind } from "./types";

/**
 * CSV import for poll questions.
 *
 * Format: one row per option, with a header row. Columns (Japanese or
 * English names, any order):
 *
 *   設問文 (prompt)    — required column. Consecutive rows with the same
 *                        prompt merge into one question.
 *   形式 (kind)        — required column. A kind key (single, multiple,
 *                        text, short_text, ranking, score, number, date,
 *                        scale, slider, allocation) or its Japanese label
 *                        （単一選択、複数選択、自由記述、短いテキスト、…).
 *   必須 (required)    — 必須/任意、はい/いいえ、true/false、1/0 など。
 *                        Blank means 必須 (required).
 *   選択肢 (option)    — one option label per row. Option kinds need at
 *                        least 2 rows; other kinds leave this empty.
 *   最小値 (min) / 最大値 (max) — number and slider only.
 *   段階数 (steps)     — scale only (2-10).
 *   刻み (step)        — slider only.
 *   合計点 (total)     — allocation only.
 *
 * Within one question group, the kind / required / config cells may
 * repeat the same value but must not contradict the first row.
 * Any problem aborts the whole import: errors carry 1-based line numbers
 * (the header is line 1) and nothing is imported partially.
 */

export interface CsvImportError {
  line: number | null;
  message: string;
}

export interface CsvImportResult {
  questions: QuestionInput[] | null;
  errors: CsvImportError[];
}

/** Byte cap for one CSV payload (enforced again at the HTTP layer). */
export const CSV_IMPORT_MAX_BYTES = 256 * 1024;
/** Data-row cap; 20 questions x 50 options is the largest useful import. */
export const CSV_IMPORT_MAX_ROWS = 2000;

export const SAMPLE_QUESTIONS_CSV = [
  "設問文,形式,必須,選択肢,最小値,最大値,段階数,刻み,合計点",
  "好きな季節は？,単一選択,必須,春,,,,,",
  "好きな季節は？,単一選択,必須,夏,,,,,",
  "好きな季節は？,単一選択,必須,秋,,,,,",
  "好きな季節は？,単一選択,必須,冬,,,,,",
  "行ってみたい場所,複数選択,任意,山,,,,,",
  "行ってみたい場所,複数選択,任意,海,,,,,",
  "行ってみたい場所,複数選択,任意,街,,,,,",
  "満足度を教えてください,段階評価,必須,,,,5,,",
  "予算はいくらですか,数値入力,任意,,0,100000,,,",
  "内訳を配分してください,配点,必須,交通費,,,,,100",
  "内訳を配分してください,配点,必須,宿泊費,,,,,100",
  "内訳を配分してください,配点,必須,食費,,,,,100",
  "感想をお聞かせください,自由記述,任意,,,,,,,",
].join("\n") + "\n";

const HEADER_ALIASES: Record<string, string> = {
  "設問文": "prompt",
  prompt: "prompt",
  "形式": "kind",
  kind: "kind",
  "必須": "required",
  required: "required",
  "選択肢": "option",
  option: "option",
  "最小値": "min",
  min: "min",
  "最大値": "max",
  max: "max",
  "段階数": "steps",
  steps: "steps",
  "刻み": "step",
  step: "step",
  "合計点": "total",
  total: "total",
};

const KIND_ALIASES: Record<string, QuestionKind> = {
  single: "single",
  "単一選択": "single",
  multiple: "multiple",
  "複数選択": "multiple",
  text: "text",
  "自由記述": "text",
  "自由記述（長文）": "text",
  "長文": "text",
  short_text: "short_text",
  "短いテキスト": "short_text",
  "短文": "short_text",
  "短文テキスト": "short_text",
  ranking: "ranking",
  "順位付け": "ranking",
  score: "score",
  "点数付け": "score",
  number: "number",
  "数値入力": "number",
  "数値": "number",
  date: "date",
  "日付": "date",
  scale: "scale",
  "段階評価": "scale",
  slider: "slider",
  "スライダー": "slider",
  allocation: "allocation",
  "配点": "allocation",
};

const KIND_LABELS: Record<QuestionKind, string> = {
  single: "単一選択",
  multiple: "複数選択",
  text: "自由記述（長文）",
  short_text: "短いテキスト",
  ranking: "順位付け",
  score: "点数付け",
  number: "数値入力",
  date: "日付",
  scale: "段階評価",
  slider: "スライダー",
  allocation: "配点",
};

const REQUIRED_TRUE = new Set(["必須", "はい", "yes", "true", "1", "○", "要"]);
const REQUIRED_FALSE = new Set(["任意", "いいえ", "no", "false", "0", "×", "不要"]);

const CONFIG_COLUMNS = ["min", "max", "steps", "step", "total"] as const;
type ConfigColumn = (typeof CONFIG_COLUMNS)[number];
const CONFIG_LABELS: Record<ConfigColumn, string> = {
  min: "最小値",
  max: "最大値",
  steps: "段階数",
  step: "刻み",
  total: "合計点",
};
const KIND_CONFIG_COLUMNS: Partial<Record<QuestionKind, readonly ConfigColumn[]>> = {
  number: ["min", "max"],
  scale: ["steps"],
  slider: ["min", "max", "step"],
  allocation: ["total"],
};

/* ------------------------------------------------------------------ */
/* CSV record parser (RFC 4180 style: quotes, "" escapes, CRLF)        */
/* ------------------------------------------------------------------ */

interface CsvRecord {
  line: number;
  cells: string[];
}

function parseCsvRecords(input: string): { records: CsvRecord[]; error: CsvImportError | null } {
  const text = input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
  const records: CsvRecord[] = [];
  let cells: string[] = [];
  let field = "";
  let inQuotes = false;
  let fieldQuoted = false;
  let line = 1;
  let recordLine = 1;
  let i = 0;
  const endField = () => {
    cells.push(field);
    field = "";
    fieldQuoted = false;
  };
  const endRecord = () => {
    endField();
    records.push({ line: recordLine, cells });
    cells = [];
  };
  while (i < text.length) {
    const ch = text[i] as string;
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i++;
        continue;
      }
      if (ch === "\n") line++;
      field += ch;
      i++;
      continue;
    }
    if (ch === '"' && field === "" && !fieldQuoted) {
      inQuotes = true;
      fieldQuoted = true;
      i++;
      continue;
    }
    if (ch === ",") {
      endField();
      i++;
      continue;
    }
    if (ch === "\r" || ch === "\n") {
      endRecord();
      if (ch === "\r" && text[i + 1] === "\n") i++;
      i++;
      line++;
      recordLine = line;
      continue;
    }
    field += ch;
    i++;
  }
  if (inQuotes) {
    return {
      records,
      error: { line: recordLine, message: "引用符（\"）が閉じていません" },
    };
  }
  if (field !== "" || cells.length > 0) endRecord();
  return { records, error: null };
}

/* ------------------------------------------------------------------ */
/* Record-to-question conversion with line-numbered errors             */
/* ------------------------------------------------------------------ */

interface QuestionGroup {
  prompt: string;
  firstLine: number;
  kind: QuestionKind | null;
  required: boolean | null;
  config: Partial<Record<ConfigColumn, number>>;
  options: { label: string; line: number }[];
}

function parseRequiredCell(raw: string): boolean | null | "invalid" {
  const value = raw.trim().toLowerCase();
  if (value === "") return null;
  if (REQUIRED_TRUE.has(value)) return true;
  if (REQUIRED_FALSE.has(value)) return false;
  return "invalid";
}

function parseKindCell(raw: string): QuestionKind | null {
  const value = raw.trim().toLowerCase();
  if (value === "") return null;
  return KIND_ALIASES[value] ?? null;
}

export function parseQuestionsCsv(input: string): CsvImportResult {
  const fail = (errors: CsvImportError[]): CsvImportResult => ({ questions: null, errors });
  if (new TextEncoder().encode(input).byteLength > CSV_IMPORT_MAX_BYTES) {
    return fail([{ line: null, message: `CSV が大きすぎます（最大 ${CSV_IMPORT_MAX_BYTES / 1024} KiB）` }]);
  }
  const { records, error } = parseCsvRecords(input);
  if (error) return fail([error]);
  if (records.length === 0) {
    return fail([{ line: null, message: "CSV が空です" }]);
  }

  /* Header row: map column names to canonical fields. */
  const headerRecord = records[0] as CsvRecord;
  const headerCells = headerRecord.cells.map((cell) => cell.trim());
  // Trailing columns with an empty header are tolerated only when every
  // data cell under them is empty too (stray trailing commas).
  let columnCount = headerCells.length;
  while (columnCount > 0 && (headerCells[columnCount - 1] ?? "") === "") {
    const idx = columnCount - 1;
    const allEmpty = records.every((r) => (r.cells[idx] ?? "").trim() === "");
    if (!allEmpty) break;
    columnCount--;
  }
  const headerErrors: CsvImportError[] = [];
  const columns = new Map<string, number>();
  for (let idx = 0; idx < columnCount; idx++) {
    const name = headerCells[idx] as string;
    if (name === "") {
      headerErrors.push({ line: 1, message: `${idx + 1} 列目の列名が空です` });
      continue;
    }
    const canonical = HEADER_ALIASES[name.toLowerCase()] ?? HEADER_ALIASES[name];
    if (!canonical) {
      headerErrors.push({
        line: 1,
        message: `列「${name}」は使えません。使える列は 設問文、形式、必須、選択肢、最小値、最大値、段階数、刻み、合計点 です`,
      });
      continue;
    }
    if (columns.has(canonical)) {
      headerErrors.push({ line: 1, message: `列「${name}」が重複しています` });
      continue;
    }
    columns.set(canonical, idx);
  }
  if (!columns.has("prompt")) {
    headerErrors.push({ line: 1, message: "「設問文」の列が必要です" });
  }
  if (!columns.has("kind")) {
    headerErrors.push({ line: 1, message: "「形式」の列が必要です" });
  }
  if (headerErrors.length > 0) return fail(headerErrors);

  const cellOf = (record: CsvRecord, canonical: string): string => {
    const idx = columns.get(canonical);
    if (idx === undefined) return "";
    return record.cells[idx] ?? "";
  };

  /* Data rows: skip fully blank lines, group consecutive same prompts. */
  const dataRecords = records.slice(1).filter((r) => r.cells.some((cell) => cell.trim() !== ""));
  if (dataRecords.length === 0) {
    return fail([{ line: null, message: "設問の行がありません。ヘッダー行の下に設問の行を追加してください" }]);
  }
  if (dataRecords.length > CSV_IMPORT_MAX_ROWS) {
    return fail([{ line: null, message: `行数が上限（${CSV_IMPORT_MAX_ROWS} 行）を超えています` }]);
  }

  const errors: CsvImportError[] = [];
  const groups: QuestionGroup[] = [];
  let current: QuestionGroup | null = null;

  for (const record of dataRecords) {
    const line = record.line;
    if (record.cells.length > columnCount && record.cells.slice(columnCount).some((cell) => cell.trim() !== "")) {
      errors.push({ line, message: "列数がヘッダーと一致しません" });
    }
    const prompt = cellOf(record, "prompt").trim();
    if (prompt === "") {
      errors.push({ line, message: "設問文が入力されていません" });
      current = null;
      continue;
    }
    if (!current || current.prompt !== prompt) {
      current = {
        prompt,
        firstLine: line,
        kind: null,
        required: null,
        config: {},
        options: [],
      };
      groups.push(current);
    }
    const group = current;

    const kindCell = cellOf(record, "kind");
    if (kindCell.trim() !== "") {
      const kind = parseKindCell(kindCell);
      if (!kind) {
        errors.push({
          line,
          message: `形式「${kindCell.trim()}」は使えません。単一選択、複数選択、自由記述（長文）、短いテキスト、順位付け、点数付け、数値入力、日付、段階評価、スライダー、配点 のいずれかを指定してください`,
        });
      } else if (group.kind === null) {
        group.kind = kind;
      } else if (group.kind !== kind) {
        errors.push({ line, message: "同じ設問の行で形式が異なります" });
      }
    }

    const requiredCell = cellOf(record, "required");
    if (requiredCell.trim() !== "") {
      const required = parseRequiredCell(requiredCell);
      if (required === "invalid") {
        errors.push({
          line,
          message: `必須の指定「${requiredCell.trim()}」は使えません。必須／任意、はい／いいえ、true／false、1／0 のいずれかを指定してください`,
        });
      } else if (required !== null) {
        if (group.required === null) group.required = required;
        else if (group.required !== required) {
          errors.push({ line, message: "同じ設問の行で必須の指定が異なります" });
        }
      }
    }

    // Kind must be known before config applicability and option checks;
    // an unknown/absent kind falls back to single for error collection.
    const kind = group.kind ?? "single";
    for (const column of CONFIG_COLUMNS) {
      const raw = cellOf(record, column).trim();
      if (raw === "") continue;
      const allowed = KIND_CONFIG_COLUMNS[kind] ?? [];
      if (!allowed.includes(column)) {
        errors.push({
          line,
          message: `「${CONFIG_LABELS[column]}」は${KIND_LABELS[kind]}の設問では指定できません`,
        });
        continue;
      }
      const value = Number(raw);
      if (!Number.isFinite(value)) {
        errors.push({ line, message: `「${CONFIG_LABELS[column]}」には数値を入力してください` });
        continue;
      }
      const existing = group.config[column];
      if (existing === undefined) group.config[column] = value;
      else if (existing !== value) {
        errors.push({ line, message: `同じ設問の行で「${CONFIG_LABELS[column]}」の値が異なります` });
      }
    }

    const optionLabel = cellOf(record, "option").trim();
    if (OPTION_KINDS.includes(kind)) {
      if (optionLabel === "") {
        errors.push({ line, message: "選択肢が入力されていません" });
      } else {
        group.options.push({ label: optionLabel, line });
      }
    } else if (optionLabel !== "") {
      errors.push({
        line,
        message: `${KIND_LABELS[kind]}の設問に選択肢は指定できません`,
      });
    }
  }

  /* Per-group validation. */
  groups.forEach((group, groupIndex) => {
    if (groupIndex === MAX_QUESTIONS) {
      errors.push({ line: group.firstLine, message: `設問は最大 ${MAX_QUESTIONS} 件までです` });
    }
    if (group.kind === null) {
      errors.push({ line: group.firstLine, message: "形式が入力されていません" });
    }
    if (group.prompt.length > 300) {
      errors.push({ line: group.firstLine, message: "設問文は 300 文字までです" });
    }
    try {
      assertPlainText(group.prompt);
    } catch {
      errors.push({ line: group.firstLine, message: "設問文に使用できない文字が含まれています" });
    }
    const kind = group.kind ?? "single";
    if (OPTION_KINDS.includes(kind)) {
      if (group.options.length < 2) {
        errors.push({
          line: group.firstLine,
          message: `選択肢が ${group.options.length} 件です。選択式の設問には 2 件以上必要です`,
        });
      }
      group.options.forEach((option, optionIndex) => {
        if (optionIndex === MAX_OPTIONS) {
          errors.push({ line: option.line, message: `選択肢は最大 ${MAX_OPTIONS} 件までです` });
        }
        if (option.label.length > 200) {
          errors.push({ line: option.line, message: "選択肢の文言は 200 文字までです" });
        }
        try {
          assertPlainText(option.label);
        } catch {
          errors.push({ line: option.line, message: "選択肢の文言に使用できない文字が含まれています" });
        }
      });
    }
  });

  if (errors.length > 0) return fail(errors);
  if (groups.length > MAX_QUESTIONS) {
    return fail([{ line: null, message: `設問は最大 ${MAX_QUESTIONS} 件までです` }]);
  }

  /* Build the standard questions payload and run the shared validation
     as a final safety net (config ranges, text rules, show_if shape). */
  const payload = groups.map((group) => {
    const config: QuestionConfig = {};
    for (const column of CONFIG_COLUMNS) {
      const value = group.config[column];
      if (value !== undefined) config[column] = value;
    }
    return {
      prompt: group.prompt,
      kind: group.kind as QuestionKind,
      required: group.required ?? true,
      options: group.options.map((option) => ({ label: option.label })),
      ...(Object.keys(config).length > 0 ? { config } : {}),
    };
  });
  try {
    const questions = parseQuestions({ questions: payload });
    return { questions, errors: [] };
  } catch (err) {
    if (err instanceof ApiError) {
      return fail([{ line: null, message: err.message }]);
    }
    throw err;
  }
}
