import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

import { parseQuestionsCsv, SAMPLE_QUESTIONS_CSV } from "../src/csv-import";
import { applySchema } from "./fixtures";

const BASE = "https://vote.test";

beforeAll(async () => {
  await applySchema(env.DB);
});

const HEADER = "設問文,形式,必須,選択肢,最小値,最大値,段階数,刻み,合計点";

describe("parseQuestionsCsv", () => {
  it("parses the bundled sample into six questions", () => {
    const result = parseQuestionsCsv(SAMPLE_QUESTIONS_CSV);
    expect(result.errors).toEqual([]);
    const questions = result.questions ?? [];
    expect(questions.map((q) => q.kind)).toEqual([
      "single",
      "multiple",
      "scale",
      "number",
      "allocation",
      "text",
    ]);
    expect(questions[0]?.options.map((o) => o.label)).toEqual(["春", "夏", "秋", "冬"]);
    expect(questions[0]?.required).toBe(true);
    expect(questions[1]?.required).toBe(false);
    expect(questions[1]?.options).toHaveLength(3);
    expect(questions[2]?.config).toEqual({ steps: 5 });
    expect(questions[3]?.config).toEqual({ min: 0, max: 100000 });
    expect(questions[4]?.config).toEqual({ total: 100 });
    expect(questions[4]?.options.map((o) => o.label)).toEqual(["交通費", "宿泊費", "食費"]);
    expect(questions[5]?.options).toEqual([]);
  });

  it("accepts English headers and kind keys, in any column order", () => {
    const csv = [
      "option,kind,prompt,required",
      "はい,single,賛成ですか,yes",
      "いいえ,single,賛成ですか,yes",
      ",text,感想,no",
    ].join("\n");
    const result = parseQuestionsCsv(csv);
    expect(result.errors).toEqual([]);
    expect(result.questions).toHaveLength(2);
    expect(result.questions?.[0]?.kind).toBe("single");
    expect(result.questions?.[0]?.options.map((o) => o.label)).toEqual(["はい", "いいえ"]);
    expect(result.questions?.[1]?.required).toBe(false);
  });

  it("imports every question kind", () => {
    const csv = [
      HEADER,
      "単一,単一選択,必須,A,,,,,",
      "単一,単一選択,必須,B,,,,,",
      "複数,複数選択,必須,A,,,,,",
      "複数,複数選択,必須,B,,,,,",
      "長文,自由記述,必須,,,,,,",
      "短文,短いテキスト,任意,,,,,,",
      "順位,順位付け,必須,A,,,,,",
      "順位,順位付け,必須,B,,,,,",
      "点数,点数付け,必須,A,,,,,",
      "点数,点数付け,必須,B,,,,,",
      "数値,数値入力,必須,,1,9,,,",
      "日付,日付,必須,,,,,,",
      "段階,段階評価,必須,,,,3,,",
      "スライダー,スライダー,必須,,0,10,,2,",
      "配点,配点,必須,A,,,,,50",
      "配点,配点,必須,B,,,,,50",
    ].join("\n");
    const result = parseQuestionsCsv(csv);
    expect(result.errors).toEqual([]);
    expect(result.questions?.map((q) => q.kind)).toEqual([
      "single",
      "multiple",
      "text",
      "short_text",
      "ranking",
      "score",
      "number",
      "date",
      "scale",
      "slider",
      "allocation",
    ]);
    expect(result.questions?.[6]?.config).toEqual({ min: 1, max: 9 });
    expect(result.questions?.[8]?.config).toEqual({ steps: 3 });
    expect(result.questions?.[9]?.config).toEqual({ min: 0, max: 10, step: 2 });
    expect(result.questions?.[10]?.config).toEqual({ total: 50 });
  });

  it("rejects a header-only CSV", () => {
    const result = parseQuestionsCsv(HEADER + "\n");
    expect(result.questions).toBeNull();
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]?.message).toContain("設問の行がありません");
  });

  it("rejects an empty CSV", () => {
    const result = parseQuestionsCsv("");
    expect(result.questions).toBeNull();
    expect(result.errors[0]?.message).toContain("空");
  });

  it("reports an unknown kind with its line number", () => {
    const csv = [HEADER, "質問,三択,必須,A,,,,,"].join("\n");
    const result = parseQuestionsCsv(csv);
    expect(result.questions).toBeNull();
    expect(result.errors.some((e) => e.line === 2 && e.message.includes("三択"))).toBe(true);
  });

  it("reports a missing prompt column on line 1", () => {
    const result = parseQuestionsCsv("形式,選択肢\n単一選択,A");
    expect(result.questions).toBeNull();
    expect(result.errors.some((e) => e.line === 1 && e.message.includes("設問文"))).toBe(true);
  });

  it("reports an unknown column on line 1", () => {
    const result = parseQuestionsCsv("設問文,形式,備考\n質問,単一選択,x");
    expect(result.questions).toBeNull();
    expect(result.errors.some((e) => e.line === 1 && e.message.includes("備考"))).toBe(true);
  });

  it("handles quoted commas, escaped quotes, CRLF and a BOM", () => {
    const csv =
      "﻿" +
      [
        HEADER,
        '"好きなものは？",単一選択,必須,"りんご, ぶどう",,,,,',
        '"好きなものは？",単一選択,必須,"彼は ""はい"" と言った",,,,,',
      ].join("\r\n") +
      "\r\n";
    const result = parseQuestionsCsv(csv);
    expect(result.errors).toEqual([]);
    expect(result.questions?.[0]?.prompt).toBe("好きなものは？");
    expect(result.questions?.[0]?.options.map((o) => o.label)).toEqual([
      "りんご, ぶどう",
      '彼は "はい" と言った',
    ]);
  });

  it("reports an unterminated quote", () => {
    const result = parseQuestionsCsv(HEADER + '\n"閉じていない,単一選択,必須,A');
    expect(result.questions).toBeNull();
    expect(result.errors[0]?.line).toBe(2);
    expect(result.errors[0]?.message).toContain("引用符");
  });

  it("reports too few options at the question's first line", () => {
    const csv = [HEADER, "一つだけ,単一選択,必須,A,,,,,", "感想,自由記述,任意,,,,,,"].join("\n");
    const result = parseQuestionsCsv(csv);
    expect(result.questions).toBeNull();
    expect(result.errors.some((e) => e.line === 2 && e.message.includes("選択肢が 1 件"))).toBe(true);
  });

  it("reports an empty option cell with its line number", () => {
    const csv = [HEADER, "質問,単一選択,必須,A,,,,,", "質問,単一選択,必須,,,,,,"].join("\n");
    const result = parseQuestionsCsv(csv);
    expect(result.questions).toBeNull();
    expect(result.errors.some((e) => e.line === 3 && e.message.includes("選択肢が入力されていません"))).toBe(true);
  });

  it("reports an option on a kind that takes none", () => {
    const csv = [HEADER, "感想,自由記述,必須,余計な選択肢,,,,,"].join("\n");
    const result = parseQuestionsCsv(csv);
    expect(result.questions).toBeNull();
    expect(result.errors.some((e) => e.line === 2 && e.message.includes("選択肢は指定できません"))).toBe(true);
  });

  it("reports config on the wrong kind and non-numeric config", () => {
    const wrongKind = parseQuestionsCsv([HEADER, "質問,単一選択,必須,A,,,3,"].join("\n"));
    expect(wrongKind.questions).toBeNull();
    expect(wrongKind.errors.some((e) => e.line === 2 && e.message.includes("段階数"))).toBe(true);

    const notNumeric = parseQuestionsCsv([HEADER, "段階,段階評価,必須,,,,abc,,"].join("\n"));
    expect(notNumeric.questions).toBeNull();
    expect(notNumeric.errors.some((e) => e.line === 2 && e.message.includes("数値"))).toBe(true);
  });

  it("reports a config range error from shared validation", () => {
    const csv = [HEADER, "範囲,スライダー,必須,,50,10,,1,"].join("\n");
    const result = parseQuestionsCsv(csv);
    expect(result.questions).toBeNull();
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it("reports conflicting kind and required values inside a group", () => {
    const kindConflict = parseQuestionsCsv(
      [HEADER, "質問,単一選択,必須,A,,,,,", "質問,複数選択,必須,B,,,,,"].join("\n"),
    );
    expect(kindConflict.questions).toBeNull();
    expect(kindConflict.errors.some((e) => e.line === 3 && e.message.includes("形式が異なります"))).toBe(true);

    const requiredConflict = parseQuestionsCsv(
      [HEADER, "質問,単一選択,必須,A,,,,,", "質問,単一選択,任意,B,,,,,"].join("\n"),
    );
    expect(requiredConflict.questions).toBeNull();
    expect(requiredConflict.errors.some((e) => e.line === 3 && e.message.includes("必須の指定が異なります"))).toBe(true);
  });

  it("reports an invalid required value", () => {
    const csv = [HEADER, "質問,単一選択,たぶん,A,,,,,"].join("\n");
    const result = parseQuestionsCsv(csv);
    expect(result.questions).toBeNull();
    expect(result.errors.some((e) => e.line === 2 && e.message.includes("たぶん"))).toBe(true);
  });

  it("treats a repeated prompt after another question as a separate question", () => {
    const csv = [
      HEADER,
      "質問,単一選択,必須,A,,,,,",
      "質問,単一選択,必須,B,,,,,",
      "別の質問,自由記述,必須,,,,,,",
      "質問,単一選択,必須,A,,,,,",
      "質問,単一選択,必須,B,,,,,",
    ].join("\n");
    const result = parseQuestionsCsv(csv);
    expect(result.errors).toEqual([]);
    expect(result.questions).toHaveLength(3);
  });

  it("rejects more than 20 questions", () => {
    const rows = [HEADER];
    for (let i = 1; i <= 21; i++) rows.push(`質問${i},自由記述,必須,,,,,,`);
    const result = parseQuestionsCsv(rows.join("\n"));
    expect(result.questions).toBeNull();
    expect(result.errors.some((e) => e.message.includes("20"))).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/* API                                                                 */
/* ------------------------------------------------------------------ */

interface ErrBody {
  error: { code: string; message: string; details?: { errors?: { line: number | null; message: string }[] } };
}

async function tenant() {
  const res = await SELF.fetch(`${BASE}/api/v1/tenants`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: "CSV取り込み" }),
  });
  expect(res.status).toBe(201);
  const data = (await res.json()) as { tenant: { id: string }; api_key: string };
  return { id: data.tenant.id, apiKey: data.api_key };
}

function auth(owner: { apiKey: string }) {
  return {
    "content-type": "application/json",
    authorization: `Bearer ${owner.apiKey}`,
  };
}

describe("CSV import API", () => {
  it("parse-csv returns the questions payload (JSON body)", async () => {
    const owner = await tenant();
    const res = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/parse-csv`, {
      method: "POST",
      headers: auth(owner),
      body: JSON.stringify({ csv: SAMPLE_QUESTIONS_CSV }),
    });
    expect(res.status).toBe(200);
    const data = (await res.json()) as {
      questions: { kind: string; options: { label: string }[] }[];
    };
    expect(data.questions).toHaveLength(6);
    expect(data.questions[0]?.kind).toBe("single");
    expect(data.questions[0]?.options.map((o) => o.label)).toEqual(["春", "夏", "秋", "冬"]);
  });

  it("parse-csv accepts a raw text/csv body", async () => {
    const owner = await tenant();
    const res = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/parse-csv`, {
      method: "POST",
      headers: { "content-type": "text/csv", authorization: `Bearer ${owner.apiKey}` },
      body: SAMPLE_QUESTIONS_CSV,
    });
    expect(res.status).toBe(200);
    const data = (await res.json()) as { questions: unknown[] };
    expect(data.questions).toHaveLength(6);
  });

  it("parse-csv returns line-numbered errors and stores nothing", async () => {
    const owner = await tenant();
    const csv = [HEADER, "質問,単一選択,必須,A,,,,,", "質問,三択,必須,B,,,,,"].join("\n");
    const res = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/parse-csv`, {
      method: "POST",
      headers: auth(owner),
      body: JSON.stringify({ csv }),
    });
    expect(res.status).toBe(400);
    const data = (await res.json()) as ErrBody;
    const errors = data.error.details?.errors ?? [];
    expect(errors.some((e) => e.line === 3)).toBe(true);
  });

  it("parse-csv requires an API key", async () => {
    const owner = await tenant();
    const res = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/parse-csv`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ csv: SAMPLE_QUESTIONS_CSV }),
    });
    expect(res.status).toBe(401);
  });

  it("import-csv creates a poll that can be published and voted on", async () => {
    const owner = await tenant();
    const res = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/import-csv`, {
      method: "POST",
      headers: auth(owner),
      body: JSON.stringify({ question: "CSV で作った投票", csv: SAMPLE_QUESTIONS_CSV }),
    });
    expect(res.status).toBe(201);
    const data = (await res.json()) as {
      poll: {
        id: string;
        status: string;
        questions: { id: string; kind: string; options: { id: string; label: string }[] }[];
      };
    };
    expect(data.poll.status).toBe("draft");
    expect(data.poll.questions.map((q) => q.kind)).toEqual([
      "single",
      "multiple",
      "scale",
      "number",
      "allocation",
      "text",
    ]);

    const publish = await SELF.fetch(
      `${BASE}/api/v1/tenants/${owner.id}/polls/${data.poll.id}/status`,
      { method: "POST", headers: auth(owner), body: JSON.stringify({ status: "published" }) },
    );
    expect(publish.status).toBe(200);

    const qs = data.poll.questions;
    const answers = [
      { question_id: qs[0]?.id, option_ids: [qs[0]?.options[1]?.id] },
      { question_id: qs[1]?.id, option_ids: [qs[1]?.options[0]?.id, qs[1]?.options[2]?.id] },
      { question_id: qs[2]?.id, value: 4 },
      { question_id: qs[3]?.id, value: 5000 },
      {
        question_id: qs[4]?.id,
        scores: {
          [qs[4]?.options[0]?.id as string]: 40,
          [qs[4]?.options[1]?.id as string]: 35,
          [qs[4]?.options[2]?.id as string]: 25,
        },
      },
      { question_id: qs[5]?.id, text: "とても良かった" },
    ];
    const vote = await SELF.fetch(`${BASE}/api/v1/polls/${data.poll.id}/vote`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ voter_token: "csv-voter-1", answers }),
    });
    expect(vote.status).toBe(200);

    const results = await SELF.fetch(
      `${BASE}/api/v1/tenants/${owner.id}/polls/${data.poll.id}/results`,
      { headers: auth(owner) },
    );
    expect(results.status).toBe(200);
    const resultsData = (await results.json()) as {
      results: { total_voters: number; questions: { options: { label: string; votes: number }[] }[] };
    };
    expect(resultsData.results.total_voters).toBe(1);
    const season = resultsData.results.questions[0]?.options.find((o) => o.label === "夏");
    expect(season?.votes).toBe(1);
  });

  it("import-csv rejects a bad CSV and creates no poll", async () => {
    const owner = await tenant();
    const csv = [HEADER, "質問,三択,必須,A,,,,,"].join("\n");
    const res = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls/import-csv`, {
      method: "POST",
      headers: auth(owner),
      body: JSON.stringify({ question: "作られない投票", csv }),
    });
    expect(res.status).toBe(400);
    const data = (await res.json()) as ErrBody;
    expect((data.error.details?.errors ?? []).some((e) => e.line === 2)).toBe(true);

    const list = await SELF.fetch(`${BASE}/api/v1/tenants/${owner.id}/polls`, {
      headers: auth(owner),
    });
    const listData = (await list.json()) as { polls: unknown[] };
    expect(listData.polls).toHaveLength(0);
  });
});

/* ------------------------------------------------------------------ */
/* Editor UI                                                           */
/* ------------------------------------------------------------------ */

function getCookie(res: Response, name: string): string | null {
  for (const header of res.headers.getSetCookie()) {
    const [pair] = header.split(";");
    const eq = pair?.indexOf("=") ?? -1;
    if (eq > 0 && pair?.slice(0, eq).trim() === name) return pair.slice(eq + 1).trim();
  }
  return null;
}

function decodeFlowPayload(cookie: string): { state: string; nonce: string } {
  const payloadPart = decodeURIComponent(cookie).split(".")[0] as string;
  const padded = payloadPart.replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(atob(padded + "=".repeat((4 - (padded.length % 4)) % 4))) as {
    state: string;
    nonce: string;
  };
}

async function loginAs(sub: string, email: string): Promise<string> {
  const loginRes = await SELF.fetch(`${BASE}/admin/login`, { redirect: "manual" });
  expect(loginRes.status).toBe(302);
  const flowCookie = getCookie(loginRes, "__Host-hv_oidc_flow");
  expect(flowCookie).toBeTruthy();
  const flow = decodeFlowPayload(flowCookie as string);
  const code = `mock:${sub}:${flow.nonce}:${email}`;
  const callbackRes = await SELF.fetch(
    `${BASE}/auth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(flow.state)}`,
    { redirect: "manual", headers: { cookie: `__Host-hv_oidc_flow=${flowCookie}` } },
  );
  const session = getCookie(callbackRes, "__Host-hv_session");
  expect(session).toBeTruthy();
  return session as string;
}

describe("question editor CSV import", () => {
  it("new and edit editors ship the CSV import controls, preview and sample", async () => {
    const session = await loginAs("csv-owner", "csv@example.test");
    const cookie = `__Host-hv_session=${session}`;
    const created = await SELF.fetch(`${BASE}/admin/workspaces`, {
      method: "POST",
      headers: { cookie, origin: BASE, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ name: "CSV編集" }).toString(),
    });
    expect(created.status).toBe(200);
    const tenantId = /\/admin\/workspaces\/([0-9a-f-]{36})/.exec(await created.text())?.[1];
    expect(tenantId).toBeTruthy();

    const checkEditor = (html: string) => {
      expect(html).toContain("CSV から取り込む");
      expect(html).toContain('id="csv-file"');
      expect(html).toContain('id="csv-preview"');
      expect(html).toContain("サンプル CSV をダウンロード");
      // Parser, preview and apply logic ship with the form script.
      expect(html).toContain("parseQuestionsCsv");
      expect(html).toContain("applyCsvImport");
      expect(html).toContain("この内容を取り込む");
      expect(html).toContain("行目: ");
      // The downloadable sample is embedded in the page.
      expect(html).toContain("好きな季節は？");
      expect(html).toContain("hyo-questions-sample.csv");
      // Regression guard: the bulk-paste placeholder and split pattern
      // must reach the browser as escape sequences, not raw newlines
      // (a raw LF inside a string/regex literal kills the whole script).
      expect(html).toContain("bulkText.placeholder = '例：\\nりんご\\nみかん\\nぶどう'");
      expect(html).not.toContain("例：\nりんご");
      expect(html).toContain("split(/\\r?\\n/)");
    };

    const newPage = await SELF.fetch(`${BASE}/admin/workspaces/${tenantId}/polls/new`, {
      headers: { cookie },
    });
    expect(newPage.status).toBe(200);
    checkEditor(await newPage.text());

    // An existing poll (created via the import API) shows the same editor.
    const importRes = await SELF.fetch(`${BASE}/api/v1/tenants/${tenantId}/polls/import-csv`, {
      method: "POST",
      headers: { cookie, "content-type": "application/json", origin: BASE },
      body: JSON.stringify({ question: "編集対象", csv: SAMPLE_QUESTIONS_CSV }),
    });
    expect(importRes.status).toBe(201);
    const imported = (await importRes.json()) as { poll: { id: string } };
    const editPage = await SELF.fetch(
      `${BASE}/admin/workspaces/${tenantId}/polls/${imported.poll.id}`,
      { headers: { cookie } },
    );
    expect(editPage.status).toBe(200);
    checkEditor(await editPage.text());
  });
});
