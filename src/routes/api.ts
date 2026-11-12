import { Hono } from "hono";
import { deleteAccountData, deleteWorkspace, listMemberships } from "../account";
import { pollSubmissionSeries, workspaceSubmissionSeries } from "../analytics";
import { actorLabel, listAuditEvents, recordAudit } from "../audit";
import { bearerToken, getSessionUser, optionalVoterSub, requireAdmin } from "../auth";
import { ballotCount, upsertBallot } from "../ballots";
import { addTenantOrigin, listTenantOrigins, isAllowedTenantOrigin, removeTenantOrigin } from "../cors";
import { randomId } from "../crypto";
import { resultsToCsv } from "../export";
import {
  assertSchedule,
  computeResults,
  getPollRow,
  isClosedForVoting,
  isNotYetOpen,
  jsonBody,
  listOptionRows,
  nowIso,
  optBool,
  optIsoDate,
  optString,
  pollToJson,
  reqString,
} from "../domain";
import { ApiError, badRequest, conflict, forbidden, notFound, unauthorized } from "../errors";
import { findActiveApiKey, issueApiKey, listApiKeys, provisionTenant, publicKey, revokeApiKey, rotatePresentedKey } from "../keys";
import { addMember, listMembers, removeMember, setMemberRole } from "../members";
import { assertDailyVoteQuota, tenantQuotas } from "../quotas";
import {
  ballotDocument,
  legacyQuestion,
  listQuestionRows,
  parseQuestions,
  replaceQuestionStatements,
  resolveAnswers,
  questionTextStatements,
  type QuestionInput,
} from "../questions";
import { createObjectStore } from "../platform/objects";
import { selectAuthProvider } from "../platform";
import { assertPlainText, assertSameOriginMutation, isSafeImageKey, rateLimitByIp, readBodyLimited, sniffImage } from "../security";
import { createWebhook, disableWebhook, dispatchWebhooks, listWebhooks, WEBHOOK_EVENTS, type WebhookEvent } from "../webhooks";
import type { Env, OptionRow, PollRow, TenantRow, Variables } from "../types";

export const api = new Hono<{ Bindings: Env; Variables: Variables }>();

const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
const IMAGE_TYPES: Record<string, string> = {
  "image/png": "png",
  "image/jpeg": "jpg",
  "image/webp": "webp",
  "image/gif": "gif",
};

function originOf(c: { req: { url: string } }): string {
  return new URL(c.req.url).origin;
}

/* ------------------------------------------------------------------ */
/* Tenants                                                             */
/* ------------------------------------------------------------------ */

/** Self-serve tenant creation (SaaS onboarding). The API key is shown once. */
api.post("/tenants", async (c) => {
  await rateLimitByIp(c, "tenant-create", 80, 3600);
  const body = await jsonBody(c);
  const name = reqString(body, "name", { max: 120 });
  const { tenantId, apiKey } = await provisionTenant(c.env, name, null);
  return c.json(
    { tenant: { id: tenantId, name }, api_key: apiKey },
    201,
  );
});

/** Rotate the presented API key (old key stops working; a new write key is returned once). */
api.post("/tenants/:tenantId/rotate-key", async (c) => {
  const tenantId = c.req.param("tenantId");
  const token = bearerToken(c);
  if (!token) throw unauthorized("UNAUTHORIZED", "API key required");
  const found = await findActiveApiKey(c.env, token);
  if (!found || found.tenant.id !== tenantId) {
    throw unauthorized("INVALID_API_KEY", "API key is not valid for this tenant");
  }
  if (found.key.scope !== "write") throw forbidden("This API key is read-only");
  const apiKey = await rotatePresentedKey(c.env, tenantId, found);
  return c.json({ api_key: apiKey });
});

api.get("/tenants/:tenantId/api-keys", async (c) => {
  const tenantId = c.req.param("tenantId");
  await requireAdmin(c, tenantId, "read");
  const keys = await listApiKeys(c.env, tenantId);
  return c.json({ api_keys: keys.map(publicKey) });
});

api.post("/tenants/:tenantId/api-keys", async (c) => {
  const tenantId = c.req.param("tenantId");
  const admin = await requireAdmin(c, tenantId, "write", "owner");
  const body = await jsonBody(c);
  const name = reqString(body, "name", { max: 80 });
  const scope = body["scope"];
  if (scope !== "read" && scope !== "write") throw badRequest('"scope" must be read or write');
  const issued = await issueApiKey(c.env, tenantId, name, scope, admin);
  return c.json({ api_key: issued.apiKey, key: issued.key }, 201);
});

api.post("/tenants/:tenantId/api-keys/:keyId/revoke", async (c) => {
  const tenantId = c.req.param("tenantId");
  const admin = await requireAdmin(c, tenantId, "write", "owner");
  await revokeApiKey(c.env, tenantId, c.req.param("keyId"), admin);
  return c.json({ revoked: true });
});

/* ------------------------------------------------------------------ */
/* Admin: polls (API key or admin-UI session)                          */
/* ------------------------------------------------------------------ */

interface OptionInput {
  label: string;
  image_key: string | null;
}

function parseOptions(body: Record<string, unknown>): OptionInput[] {
  const raw = body["options"];
  if (!Array.isArray(raw) || raw.length < 2 || raw.length > 50) {
    throw badRequest('"options" must be an array of 2 to 50 items');
  }
  return raw.map((item, index) => {
    if (typeof item !== "object" || item === null) {
      throw badRequest(`options[${index}] must be an object`);
    }
    const o = item as Record<string, unknown>;
    const label = reqString(o, "label", { max: 200 });
    const imageKey = optString(o, "image_key", { max: 300 });
    return { label, image_key: imageKey };
  });
}

async function assertImageKeyBelongsToTenant(
  env: Env,
  tenantId: string,
  imageKey: string | null,
): Promise<void> {
  if (imageKey === null) return;
  if (!isSafeImageKey(imageKey, tenantId)) {
    throw badRequest("image_key does not belong to this tenant");
  }
  const obj = await createObjectStore(env).head(imageKey);
  if (!obj) throw badRequest("image_key does not reference an uploaded image");
}

async function renderPoll(c: { env: Env; req: { url: string } }, poll: PollRow) {
  const questions = await listQuestionRows(c.env, poll.id);
  const options = await listOptionRows(c.env, poll.id);
  return pollToJson(originOf(c), poll, options, questions);
}

async function questionInputsFromBody(
  c: { env: Env },
  tenantId: string,
  body: Record<string, unknown>,
  title: string,
  allowMultiple: boolean,
): Promise<QuestionInput[]> {
  const parsed = parseQuestions(body);
  const questions = parsed ?? [legacyQuestion(title, allowMultiple, parseOptions(body))];
  for (const q of questions) {
    await assertImageKeyBelongsToTenant(c.env, tenantId, q.image_key);
    for (const o of q.options) await assertImageKeyBelongsToTenant(c.env, tenantId, o.image_key);
  }
  return questions;
}

async function loadPollForAdmin(
  c: { env: Env },
  tenantId: string,
  pollId: string,
): Promise<PollRow> {
  const poll = await getPollRow(c.env, pollId);
  if (!poll || poll.tenant_id !== tenantId) throw notFound("Poll not found");
  return poll;
}

api.post("/tenants/:tenantId/polls", async (c) => {
  const tenantId = c.req.param("tenantId");
  const admin = await requireAdmin(c, tenantId);
  const body = await jsonBody(c);
  const question = reqString(body, "question", { max: 300 });
  const description = optString(body, "description", { max: 5000, newlines: true }) ?? "";
  const imageKey = optString(body, "image_key", { max: 300 });
  const allowMultiple = optBool(body, "allow_multiple");
  const requireLogin = optBool(body, "require_login");
  const opensAt = optIsoDate(body, "opens_at");
  const closesAt = optIsoDate(body, "closes_at");
  assertSchedule(opensAt, closesAt);
  const questions = await questionInputsFromBody(c, tenantId, body, question, allowMultiple);
  const firstChoice = questions.find((q) => q.kind !== "text");
  const multiple = firstChoice ? firstChoice.kind === "multiple" : allowMultiple;
  const quotas = await tenantQuotas(c.env, tenantId);
  const existingPolls = await c.env.DB.prepare(
    "SELECT COUNT(*) AS n FROM polls WHERE tenant_id = ?1",
  )
    .bind(tenantId)
    .first<{ n: number }>();
  if (Number(existingPolls?.n ?? 0) >= quotas.polls) {
    throw conflict("QUOTA_EXCEEDED", `A workspace can have at most ${quotas.polls} polls`);
  }
  await assertImageKeyBelongsToTenant(c.env, tenantId, imageKey);
  const pollId = randomId();
  const now = nowIso();
  const revision = randomId();
  const insertPoll = c.env.DB.prepare(
    `INSERT INTO polls (id, tenant_id, question, description, image_key, status, allow_multiple, require_login, opens_at, closes_at, created_at, updated_at, revision)
     SELECT ?1, ?2, ?3, ?4, ?5, 'draft', ?6, ?7, ?8, ?9, ?10, ?10, ?11
     WHERE (SELECT COUNT(*) FROM polls WHERE tenant_id = ?2) <
       (SELECT quota_polls FROM tenants WHERE id = ?2)`,
  )
    .bind(
      pollId,
      tenantId,
      question,
      description,
      imageKey,
      multiple ? 1 : 0,
      requireLogin ? 1 : 0,
      opensAt,
      closesAt,
      now,
      revision,
    );
  const [created] = await c.env.DB.batch([insertPoll, ...replaceQuestionStatements(c.env, pollId, questions, revision)]);
  if (Number(created?.meta.changes ?? 0) !== 1) throw conflict("QUOTA_EXCEEDED", "Poll quota exceeded");
  await recordAudit(c.env, {
    tenantId,
    actor: actorLabel(admin),
    action: "poll.create",
    target: pollId,
  });
  const poll = await getPollRow(c.env, pollId);
  return c.json({ poll: await renderPoll(c, poll as PollRow) }, 201);
});

api.get("/tenants/:tenantId/polls", async (c) => {
  const tenantId = c.req.param("tenantId");
  await requireAdmin(c, tenantId, "read");
  const res = await c.env.DB.prepare(
    "SELECT * FROM polls WHERE tenant_id = ?1 ORDER BY created_at DESC",
  )
    .bind(tenantId)
    .all<PollRow>();
  const polls = [];
  for (const poll of res.results) polls.push(await renderPoll(c, poll));
  return c.json({ polls });
});

api.get("/tenants/:tenantId/polls/:pollId", async (c) => {
  const tenantId = c.req.param("tenantId");
  await requireAdmin(c, tenantId, "read");
  const poll = await loadPollForAdmin(c, tenantId, c.req.param("pollId"));
  return c.json({ poll: await renderPoll(c, poll) });
});

api.patch("/tenants/:tenantId/polls/:pollId", async (c) => {
  const tenantId = c.req.param("tenantId");
  await requireAdmin(c, tenantId);
  const poll = await loadPollForAdmin(c, tenantId, c.req.param("pollId"));
  if (poll.status === "closed") {
    throw conflict("POLL_CLOSED", "A closed poll can no longer be edited");
  }
  const body = await jsonBody(c);
  const question =
    body["question"] !== undefined
      ? reqString(body, "question", { max: 300 })
      : poll.question;
  const description =
    body["description"] !== undefined
      ? (optString(body, "description", { max: 5000, newlines: true }) ?? "")
      : poll.description;
  const imageKey =
    body["image_key"] !== undefined
      ? optString(body, "image_key", { max: 300 })
      : poll.image_key;
  let allowMultiple =
    body["allow_multiple"] !== undefined
      ? optBool(body, "allow_multiple")
      : poll.allow_multiple === 1;
  const requireLogin =
    body["require_login"] !== undefined
      ? optBool(body, "require_login")
      : poll.require_login === 1;
  const opensAt =
    body["opens_at"] !== undefined ? optIsoDate(body, "opens_at") : poll.opens_at;
  const closesAt =
    body["closes_at"] !== undefined ? optIsoDate(body, "closes_at") : poll.closes_at;
  assertSchedule(opensAt, closesAt);

  await assertImageKeyBelongsToTenant(c.env, tenantId, imageKey);

  const cast = await ballotCount(c.env, poll.id);
  if (cast > 0) {
    if (allowMultiple !== (poll.allow_multiple === 1) || requireLogin !== (poll.require_login === 1)) {
      throw conflict(
        "RULES_LOCKED",
        "Voting rules cannot be changed after votes have been cast",
      );
    }
  }

  let replacement: QuestionInput[] | null = null;
  let textEdits: D1PreparedStatement[] = [];
  const newRevision = randomId();
  if (body["questions"] !== undefined || body["options"] !== undefined) {
    const existingQuestions = await listQuestionRows(c.env, poll.id);
    const existingOptions = await listOptionRows(c.env, poll.id);
    if (body["questions"] !== undefined) {
      replacement = await questionInputsFromBody(c, tenantId, body, question, allowMultiple);
    } else if (existingQuestions.length !== 1) {
      throw badRequest("Replace questions explicitly when a poll has more than one");
    } else {
      const only = existingQuestions[0];
      const legacy = legacyQuestion(question, allowMultiple, parseOptions(body));
      replacement = [{ ...legacy, id: only?.id, prompt: only?.prompt ?? legacy.prompt }];
      for (const o of replacement[0]?.options ?? []) {
        await assertImageKeyBelongsToTenant(c.env, tenantId, o.image_key);
      }
    }
    if (cast > 0) {
      if (body["questions"] === undefined) {
        throw conflict(
          "OPTIONS_LOCKED",
          "Options cannot be replaced after votes have been cast",
        );
      }
      textEdits = questionTextStatements(c.env, poll.id, replacement, existingQuestions, existingOptions, newRevision);
      replacement = null;
    }
  }

  if (replacement) {
    const first = replacement.find((q) => q.kind !== "text");
    if (first) allowMultiple = first.kind === "multiple";
  }

  // revision always changes, so a matching WHERE is a real write even when
  // the other columns stay the same. Concurrent editors lose the compare.
  const updatePoll = c.env.DB.prepare(
    `UPDATE polls SET question = ?1, description = ?2, image_key = ?3,
     allow_multiple = ?4, require_login = ?5, opens_at = ?6, closes_at = ?7, updated_at = ?8,
     revision = ?9
     WHERE id = ?10 AND revision = ?11 AND status != 'closed'
       AND (?12 = 0 OR NOT EXISTS (SELECT 1 FROM vote_ballots WHERE poll_id = ?10))`,
  ).bind(
    question,
    description,
    imageKey,
    allowMultiple ? 1 : 0,
    requireLogin ? 1 : 0,
    opensAt,
    closesAt,
    nowIso(),
    newRevision,
    poll.id,
    poll.revision,
    replacement || allowMultiple !== (poll.allow_multiple === 1) || requireLogin !== (poll.require_login === 1) ? 1 : 0,
  );

  const [updatedPoll] = await c.env.DB.batch([
    updatePoll,
    ...(replacement ? replaceQuestionStatements(c.env, poll.id, replacement, newRevision) : textEdits),
  ]);
  if (Number(updatedPoll?.meta.changes ?? 0) !== 1) {
    throw conflict("CONCURRENT_UPDATE", "The poll changed or received votes. Reload and try again.");
  }

  const updated = await getPollRow(c.env, poll.id);
  await dispatchWebhooks(c.env, tenantId, "poll.updated", { poll_id: poll.id });
  return c.json({ poll: await renderPoll(c, updated as PollRow) });
});

api.post("/tenants/:tenantId/polls/:pollId/status", async (c) => {
  const tenantId = c.req.param("tenantId");
  const admin = await requireAdmin(c, tenantId);
  const poll = await loadPollForAdmin(c, tenantId, c.req.param("pollId"));
  const body = await jsonBody(c);
  const status = body["status"];
  if (status !== "published" && status !== "closed" && status !== "draft") {
    throw badRequest('"status" must be one of draft/published/closed');
  }
  const allowed: Record<PollRow["status"], PollRow["status"][]> = {
    draft: ["published", "closed"],
    published: ["closed", "draft"],
    closed: [],
  };
  if (!allowed[poll.status].includes(status)) {
    throw conflict(
      "INVALID_STATUS_TRANSITION",
      `Cannot move a ${poll.status} poll to ${status}`,
    );
  }
  const changed = await c.env.DB.prepare("UPDATE polls SET status = ?1, updated_at = ?2, revision = ?4 WHERE id = ?3 AND status = ?5 AND revision = ?6")
    .bind(status, nowIso(), poll.id, randomId(), poll.status, poll.revision)
    .run();
  if (Number(changed.meta.changes ?? 0) !== 1) throw conflict("CONCURRENT_UPDATE", "Poll status changed. Reload and try again.");
  await recordAudit(c.env, {
    tenantId,
    actor: actorLabel(admin),
    action: "poll.status",
    target: poll.id,
    detail: `${poll.status}->${status}`,
  });
  const event = status === "published" ? "poll.published" : status === "closed" ? "poll.closed" : "poll.updated";
  await dispatchWebhooks(c.env, tenantId, event, { poll_id: poll.id, status });
  const updated = await getPollRow(c.env, poll.id);
  return c.json({ poll: await renderPoll(c, updated as PollRow) });
});

api.get("/tenants/:tenantId/polls/:pollId/results", async (c) => {
  const tenantId = c.req.param("tenantId");
  await requireAdmin(c, tenantId, "read");
  const poll = await loadPollForAdmin(c, tenantId, c.req.param("pollId"));
  return c.json({ results: await computeResults(c.env, originOf(c), poll, { includeText: true }) });
});

/* ------------------------------------------------------------------ */
/* Admin: image upload (R2)                                            */
/* ------------------------------------------------------------------ */

api.post("/tenants/:tenantId/images", async (c) => {
  const tenantId = c.req.param("tenantId");
  await requireAdmin(c, tenantId);
  await rateLimitByIp(c, `image:${tenantId}`, 30, 3600);
  const contentType = (c.req.header("content-type") ?? "").split(";")[0]?.trim().toLowerCase() ?? "";
  if (!IMAGE_TYPES[contentType]) {
    throw badRequest("Content-Type must be image/png, image/jpeg, image/webp or image/gif");
  }
  const bytes = await readBodyLimited(c.req.raw, MAX_IMAGE_BYTES);
  if (bytes.byteLength === 0) throw badRequest("Image body is empty");
  const sniffed = sniffImage(bytes, contentType);
  if (!sniffed) throw badRequest("File contents do not match the declared image type");
  const key = `t/${tenantId}/${randomId()}.${sniffed.ext}`;
  await createObjectStore(c.env).put(key, bytes, sniffed.contentType);
  const stillExists = await c.env.DB.prepare("SELECT id FROM tenants WHERE id = ?1").bind(tenantId).first();
  if (!stillExists) {
    await c.env.DB.prepare("INSERT INTO object_cleanup (tenant_id, created_at, generation) VALUES (?1, ?2, lower(hex(randomblob(16)))) ON CONFLICT(tenant_id) DO UPDATE SET generation = excluded.generation")
      .bind(tenantId, nowIso()).run();
    throw notFound("Workspace not found");
  }
  return c.json({ key, url: `${originOf(c)}/images/${key}` }, 201);
});

/* ------------------------------------------------------------------ */
/* Public voting API (headless)                                        */
/* ------------------------------------------------------------------ */

async function loadPublicPoll(env: Env, pollId: string): Promise<PollRow> {
  const poll = await getPollRow(env, pollId);
  if (!poll || poll.status === "draft") throw notFound("Poll not found");
  return poll;
}

api.get("/polls/:pollId", async (c) => {
  const poll = await loadPublicPoll(c.env, c.req.param("pollId"));
  return c.json({ poll: await renderPoll(c, poll) });
});

api.get("/polls/:pollId/results", async (c) => {
  const poll = await loadPublicPoll(c.env, c.req.param("pollId"));
  return c.json({ results: await computeResults(c.env, originOf(c), poll) });
});

api.post("/polls/:pollId/vote", async (c) => {
  await rateLimitByIp(c, "vote", 600, 60);
  const poll = await loadPublicPoll(c.env, c.req.param("pollId"));
  if (isNotYetOpen(poll)) {
    throw conflict("POLL_NOT_OPEN", "This poll is not open for voting yet");
  }
  if (isClosedForVoting(poll)) {
    throw conflict("POLL_CLOSED", "This poll is closed for voting");
  }

  // Voter identity: a verified login wins over an anonymous voter token.
  const sub = await optionalVoterSub(c);
  if (sub && !bearerToken(c)) {
    const origin = c.req.header("origin");
    const site = c.req.header("sec-fetch-site");
    if (origin) {
      if (origin === "null" || (origin !== originOf(c) && !(await isAllowedTenantOrigin(c.env, poll.tenant_id, origin)))) {
        throw forbidden("Untrusted voting origin");
      }
    } else if (site === "cross-site" || site === "same-site") {
      throw forbidden("Voting origin required");
    }
  }
  const body = await jsonBody(c);

  let voterKey: string;
  if (sub) {
    voterKey = `user:${sub}`;
  } else {
    if (poll.require_login === 1) {
      throw unauthorized(
        "LOGIN_REQUIRED",
        "This poll requires voters to log in",
      );
    }
    const voterToken = body["voter_token"];
    if (typeof voterToken !== "string") {
      throw badRequest(
        '"voter_token" (8-128 chars) is required when voting anonymously',
      );
    }
    const trimmedToken = voterToken.trim();
    if (trimmedToken.length < 8 || trimmedToken.length > 128) {
      throw badRequest(
        '"voter_token" (8-128 chars) is required when voting anonymously',
      );
    }
    assertPlainText(trimmedToken);
    voterKey = `anon:${trimmedToken}`;
  }

  await assertDailyVoteQuota(c.env, poll.tenant_id);
  const questions = await listQuestionRows(c.env, poll.id);
  const options = await listOptionRows(c.env, poll.id);
  const answers = resolveAnswers(body, questions, options);
  await upsertBallot(c.env, poll, voterKey, ballotDocument(answers), sub !== null);
  await dispatchWebhooks(c.env, poll.tenant_id, "vote.cast", {
    poll_id: poll.id,
    voter: sub ? "user" : "anonymous",
    answers: answers.map((answer) => ({
      question_id: answer.question_id,
      option_ids: answer.option_ids,
      text_length: answer.text ? answer.text.length : 0,
    })),
  });

  const results = await computeResults(c.env, originOf(c), poll);
  return c.json({
    vote: {
      poll_id: poll.id,
      option_ids: answers.flatMap((a) => a.option_ids),
      answers,
      voter: sub ? "user" : "anonymous",
    },
    results,
  });
});

/* ------------------------------------------------------------------ */
/* Images (public read through the Worker)                             */
/* ------------------------------------------------------------------ */

export async function serveImage(env: Env, key: string): Promise<Response> {
  const match =
    /^t\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.(png|jpg|webp|gif)$/.exec(
      key.toLowerCase(),
    );
  if (!match) {
    return Response.json(
      { error: { code: "NOT_FOUND", message: "Image not found" } },
      { status: 404 },
    );
  }
  const ext = match[3];
  const contentType =
    ext === "png" ? "image/png" :
    ext === "jpg" ? "image/jpeg" :
    ext === "webp" ? "image/webp" :
    ext === "gif" ? "image/gif" :
    null;
  if (!contentType || !ext) {
    return Response.json(
      { error: { code: "NOT_FOUND", message: "Image not found" } },
      { status: 404 },
    );
  }
  const tenant = await env.DB.prepare("SELECT id FROM tenants WHERE id = ?1").bind(match[1]).first();
  if (!tenant) return Response.json({ error: { code: "NOT_FOUND", message: "Image not found" } }, { status: 404 });
  const obj = await createObjectStore(env).get(key.toLowerCase());
  if (!obj) {
    return Response.json(
      { error: { code: "NOT_FOUND", message: "Image not found" } },
      { status: 404 },
    );
  }
  const headers = new Headers();
  headers.set("content-type", contentType);
  headers.set("x-content-type-options", "nosniff");
  headers.set("content-disposition", `inline; filename="image.${ext}"`);
  headers.set("cache-control", "no-store");
  headers.set("etag", obj.httpEtag);
  return new Response(obj.body, { headers });
}

api.get("/tenants/:tenantId/origins", async (c) => {
  const tenantId = c.req.param("tenantId");
  await requireAdmin(c, tenantId, "read");
  return c.json({ origins: await listTenantOrigins(c.env, tenantId) });
});

api.post("/tenants/:tenantId/origins", async (c) => {
  const tenantId = c.req.param("tenantId");
  const admin = await requireAdmin(c, tenantId, "write", "owner");
  await rateLimitByIp(c, `origins:${tenantId}`, 60, 3600);
  const body = await jsonBody(c);
  const raw = body["origin"];
  if (typeof raw !== "string") throw badRequest('"origin" must be a string');
  const saved = await addTenantOrigin(c.env, tenantId, raw);
  if (saved.created) {
    await recordAudit(c.env, {
      tenantId,
      actor: actorLabel(admin),
      action: "origin.add",
      detail: saved.origin,
    });
  }
  return c.json(saved, saved.created ? 201 : 200);
});

api.delete("/tenants/:tenantId/origins", async (c) => {
  const tenantId = c.req.param("tenantId");
  const admin = await requireAdmin(c, tenantId, "write", "owner");
  const body = await jsonBody(c);
  const raw = body["origin"];
  if (typeof raw !== "string") throw badRequest('"origin" must be a string');
  const removed = await removeTenantOrigin(c.env, tenantId, raw);
  if (!removed) throw notFound("Origin is not on the allowlist");
  await recordAudit(c.env, {
    tenantId,
    actor: actorLabel(admin),
    action: "origin.remove",
    detail: raw.slice(0, 200),
  });
  return c.json({ removed: true });
});

api.get("/tenants/:tenantId/audit", async (c) => {
  const tenantId = c.req.param("tenantId");
  await requireAdmin(c, tenantId, "read");
  return c.json({ events: await listAuditEvents(c.env, tenantId) });
});

api.get("/tenants/:tenantId/polls/:pollId/export", async (c) => {
  const tenantId = c.req.param("tenantId");
  const admin = await requireAdmin(c, tenantId, "read");
  const poll = await loadPollForAdmin(c, tenantId, c.req.param("pollId"));
  const results = await computeResults(c.env, originOf(c), poll, { includeText: true });
  const format = c.req.query("format") === "csv" ? "csv" : "json";
  await recordAudit(c.env, {
    tenantId,
    actor: actorLabel(admin),
    action: "results.export",
    target: poll.id,
    detail: format,
  });
  if (format === "csv") {
    c.header("content-type", "text/csv; charset=utf-8");
    c.header("content-disposition", 'attachment; filename="results.csv"');
    return c.body(resultsToCsv(poll, results));
  }
  c.header("content-disposition", 'attachment; filename="results.json"');
  return c.json({ poll: await renderPoll(c, poll), results });
});

api.get("/tenants/:tenantId/export", async (c) => {
  const tenantId = c.req.param("tenantId");
  const admin = await requireAdmin(c, tenantId, "read");
  const tenant = await c.env.DB.prepare("SELECT id, name, created_at FROM tenants WHERE id = ?1")
    .bind(tenantId)
    .first<{ id: string; name: string; created_at: string }>();
  if (!tenant) throw notFound("Workspace not found");
  const polls = await c.env.DB.prepare("SELECT * FROM polls WHERE tenant_id = ?1")
    .bind(tenantId)
    .all<PollRow>();
  const exported = [];
  for (const poll of polls.results) {
    const options = await listOptionRows(c.env, poll.id);
    exported.push({
      poll: await renderPoll(c, poll),
      results: await computeResults(c.env, originOf(c), poll, { includeText: true }),
    });
  }
  await recordAudit(c.env, {
    tenantId,
    actor: actorLabel(admin),
    action: "tenant.export",
  });
  c.header("content-disposition", 'attachment; filename="workspace.json"');
  return c.json({
    tenant,
    polls: exported,
    origins: await listTenantOrigins(c.env, tenantId),
    api_keys: (await listApiKeys(c.env, tenantId)).map(publicKey),
    audit: await listAuditEvents(c.env, tenantId, 200),
  });
});

api.get("/tenants/:tenantId/quotas", async (c) => {
  const tenantId = c.req.param("tenantId");
  await requireAdmin(c, tenantId, "read");
  const quotas = await tenantQuotas(c.env, tenantId);
  const polls = await c.env.DB.prepare("SELECT COUNT(*) AS n FROM polls WHERE tenant_id = ?1")
    .bind(tenantId)
    .first<{ n: number }>();
  const keys = await c.env.DB.prepare(
    "SELECT COUNT(*) AS n FROM api_keys WHERE tenant_id = ?1 AND revoked_at IS NULL",
  )
    .bind(tenantId)
    .first<{ n: number }>();
  const hooks = await c.env.DB.prepare(
    "SELECT COUNT(*) AS n FROM webhooks WHERE tenant_id = ?1 AND disabled_at IS NULL",
  )
    .bind(tenantId)
    .first<{ n: number }>();
  return c.json({
    plan: quotas.plan,
    limits: {
      polls: quotas.polls,
      api_keys: quotas.keys,
      webhooks: quotas.webhooks,
      votes_per_day: quotas.votesPerDay,
    },
    used: {
      polls: Number(polls?.n ?? 0),
      api_keys: Number(keys?.n ?? 0),
      webhooks: Number(hooks?.n ?? 0),
    },
  });
});

api.get("/tenants/:tenantId/analytics", async (c) => {
  const tenantId = c.req.param("tenantId");
  await requireAdmin(c, tenantId, "read");
  return c.json({
    days: await workspaceSubmissionSeries(c.env, tenantId),
    note: "Counts are submission events, not unique people.",
  });
});

api.get("/tenants/:tenantId/polls/:pollId/analytics", async (c) => {
  const tenantId = c.req.param("tenantId");
  await requireAdmin(c, tenantId, "read");
  const poll = await loadPollForAdmin(c, tenantId, c.req.param("pollId"));
  return c.json({
    poll_id: poll.id,
    days: await pollSubmissionSeries(c.env, poll.id),
    note: "Counts are submission events, not unique people.",
  });
});

api.get("/tenants/:tenantId/members", async (c) => {
  const tenantId = c.req.param("tenantId");
  await requireAdmin(c, tenantId, "read");
  return c.json({ members: await listMembers(c.env, tenantId) });
});

api.post("/tenants/:tenantId/members", async (c) => {
  const tenantId = c.req.param("tenantId");
  const admin = await requireAdmin(c, tenantId, "write", "owner");
  const body = await jsonBody(c);
  const sub = body["user_sub"];
  if (typeof sub !== "string") throw badRequest('"user_sub" must be a string');
  const member = await addMember(c.env, tenantId, sub, body["role"] ?? "member", admin);
  return c.json({ member }, 201);
});

api.patch("/tenants/:tenantId/members", async (c) => {
  const tenantId = c.req.param("tenantId");
  const admin = await requireAdmin(c, tenantId, "write", "owner");
  const body = await jsonBody(c);
  const sub = body["user_sub"];
  if (typeof sub !== "string") throw badRequest('"user_sub" must be a string');
  await setMemberRole(c.env, tenantId, sub, body["role"], admin);
  return c.json({ updated: true });
});

api.delete("/tenants/:tenantId/members", async (c) => {
  const tenantId = c.req.param("tenantId");
  const admin = await requireAdmin(c, tenantId, "write", "owner");
  const body = await jsonBody(c);
  const sub = body["user_sub"];
  if (typeof sub !== "string") throw badRequest('"user_sub" must be a string');
  await removeMember(c.env, tenantId, sub, admin);
  return c.json({ removed: true });
});

api.get("/tenants/:tenantId/webhooks", async (c) => {
  const tenantId = c.req.param("tenantId");
  await requireAdmin(c, tenantId, "read");
  return c.json({ webhooks: await listWebhooks(c.env, tenantId) });
});

api.post("/tenants/:tenantId/webhooks", async (c) => {
  const tenantId = c.req.param("tenantId");
  const admin = await requireAdmin(c, tenantId, "write", "owner");
  const body = await jsonBody(c);
  const url = body["url"];
  if (typeof url !== "string") throw badRequest('"url" must be a string');
  const rawEvents = body["events"];
  const events = Array.isArray(rawEvents) && rawEvents.length > 0
    ? rawEvents.filter((event): event is WebhookEvent => typeof event === "string" && (WEBHOOK_EVENTS as readonly string[]).includes(event))
    : [...WEBHOOK_EVENTS];
  const created = await createWebhook(c.env, tenantId, url, events);
  await recordAudit(c.env, {
    tenantId,
    actor: actorLabel(admin),
    action: "webhook.create",
    target: created.id,
    detail: created.url.slice(0, 200),
  });
  return c.json({ webhook: { id: created.id, url: created.url, events }, secret: created.secret }, 201);
});

api.post("/tenants/:tenantId/webhooks/:webhookId/disable", async (c) => {
  const tenantId = c.req.param("tenantId");
  const admin = await requireAdmin(c, tenantId, "write", "owner");
  const ok = await disableWebhook(c.env, tenantId, c.req.param("webhookId"));
  if (!ok) throw notFound("Webhook not found");
  await recordAudit(c.env, {
    tenantId,
    actor: actorLabel(admin),
    action: "webhook.disable",
    target: c.req.param("webhookId"),
  });
  return c.json({ disabled: true });
});

api.get("/me", async (c) => {
  const user = await getSessionUser(c);
  if (!user) throw unauthorized("UNAUTHORIZED", "Sign in required");
  return c.json({
    profile: { sub: user.sub, email: user.email, name: user.name },
    auth: "oidc",
    password: null,
    note: selectAuthProvider(c.env.AUTH_PROVIDER).capabilities.localPasswords
      ? "This deployment stores passwords. Email confirmation and password reset use the configured email adapter."
      : "Sign-in is delegated to the configured identity provider. This app stores no password.",
    workspaces: await listMemberships(c.env, user.sub),
  });
});

api.get("/me/export", async (c) => {
  const user = await getSessionUser(c);
  if (!user) throw unauthorized("UNAUTHORIZED", "Sign in required");
  c.header("content-disposition", 'attachment; filename="account.json"');
  c.header("cache-control", "private, no-store");
  return c.json({
    profile: { sub: user.sub, email: user.email, name: user.name },
    workspaces: await listMemberships(c.env, user.sub),
    note: "Secrets, voter tokens, and free-text answers are omitted.",
  });
});

api.delete("/me", async (c) => {
  assertSameOriginMutation(c);
  const user = await getSessionUser(c);
  if (!user) throw unauthorized("UNAUTHORIZED", "Sign in required");
  const body = await jsonBody(c);
  if (body["confirm"] !== "delete my data") {
    throw badRequest('Send {"confirm":"delete my data"} to delete this app\'s copy of your data');
  }
  const result = await deleteAccountData(c.env, user.sub);
  return c.json({ deleted: true, ...result, idp_account: "unchanged" });
});

api.delete("/tenants/:tenantId", async (c) => {
  const tenantId = c.req.param("tenantId");
  const admin = await requireAdmin(c, tenantId, "write", "owner");
  const body = await jsonBody(c);
  const confirm = body["confirm_name"];
  if (typeof confirm !== "string") throw badRequest('"confirm_name" must match the workspace name');
  const tenant = await c.env.DB.prepare("SELECT name FROM tenants WHERE id = ?1")
    .bind(tenantId)
    .first<{ name: string }>();
  if (!tenant) throw notFound("Workspace not found");
  if (confirm !== tenant.name) throw badRequest('"confirm_name" must match the workspace name');
  await recordAudit(c.env, {
    tenantId,
    actor: actorLabel(admin),
    action: "tenant.delete",
    detail: tenant.name.slice(0, 80),
  });
  await deleteWorkspace(c.env, tenantId);
  return c.json({ deleted: true });
});

export { ApiError };
export type { OptionRow, TenantRow };
