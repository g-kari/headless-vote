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
    ["poll_id", "question", "status", "opens_at", "closes_at", "total_voters", "total_votes", "option_id", "label", "votes", "share"].join(","),
  ];
  for (const option of results.options) {
    const share = results.total_votes > 0 ? option.votes / results.total_votes : 0;
    lines.push(
      [
        csvCell(poll.id),
        csvCell(poll.question),
        csvCell(poll.status),
        csvCell(poll.opens_at ?? ""),
        csvCell(poll.closes_at ?? ""),
        csvCell(results.total_voters),
        csvCell(results.total_votes),
        csvCell(option.id),
        csvCell(option.label),
        csvCell(option.votes),
        csvCell(share.toFixed(4)),
      ].join(","),
    );
  }
  return `${lines.join("\n")}\n`;
}
