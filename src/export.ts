import type { PollResults } from "./domain";
import type { PollRow } from "./types";

/** Spreadsheet-safe CSV cell. Quotes when needed and neutralizes formula injection. */
export function csvCell(value: string | number): string {
  let text = String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  if (/[",\n\r]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
}

export function resultsToCsv(poll: PollRow, results: PollResults): string {
  const lines = [
    ["poll_id", "survey", "question_id", "prompt", "kind", "status", "opens_at", "closes_at", "total_voters", "option_id", "label", "votes", "share", "text"].join(","),
  ];
  const questions = results.questions.length > 0
    ? results.questions
    : [{
        id: "",
        prompt: poll.question,
        kind: "single" as const,
        required: true,
        position: 0,
        response_count: results.total_voters,
        options: results.options,
        texts: [] as string[],
      }];
  for (const question of questions) {
    const denom = question.options.reduce((sum, o) => sum + o.votes, 0);
    if (question.kind === "text" || question.kind === "short_text" || question.kind === "date") {
      const texts = question.texts ?? [];
      if (texts.length === 0) lines.push(row(poll, results, question, "", "", question.response_count, 0, ""));
      for (const text of texts) lines.push(row(poll, results, question, "", "", 1, 0, text));
      continue;
    }
    if (question.kind === "number" || question.kind === "slider") {
      const values = question.values ?? [];
      if (values.length === 0) lines.push(row(poll, results, question, "", "", question.response_count, 0, ""));
      for (const value of values) lines.push(row(poll, results, question, "", "", 1, 0, String(value)));
      continue;
    }
    for (const option of question.options) {
      const share = denom > 0 ? option.votes / denom : 0;
      lines.push(row(poll, results, question, option.id, option.label, option.votes, share, ""));
    }
  }
  return `${lines.join("\n")}\n`;
}

function row(
  poll: PollRow,
  results: PollResults,
  question: { id: string; prompt: string; kind: string },
  optionId: string,
  label: string,
  votes: number,
  share: number,
  text: string,
): string {
  return [
    csvCell(poll.id),
    csvCell(poll.question),
    csvCell(question.id),
    csvCell(question.prompt),
    csvCell(question.kind),
    csvCell(poll.status),
    csvCell(poll.opens_at ?? ""),
    csvCell(poll.closes_at ?? ""),
    csvCell(results.total_voters),
    csvCell(optionId),
    csvCell(label),
    csvCell(votes),
    csvCell(share.toFixed(4)),
    csvCell(text),
  ].join(",");
}
