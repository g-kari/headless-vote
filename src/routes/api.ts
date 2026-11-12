import { Hono } from "hono";
import { findTenantByApiKey, optionalVoterSub, requireAdmin } from "../auth";
import { randomId, randomToken, sha256Hex } from "../crypto";
import {
  computeResults,
  getPollRow,
  isClosedForVoting,
  jsonBody,
  listOptionRows,
  nowIso,
  optBool,
  optIsoDate,
  optString,
  pollToJson,
  reqString,
} from "../domain";
import { ApiError, badRequest, conflict, notFound, payloadTooLarge, unauthorized } from "../errors";
import { sniffImageExt } from "../image-format";
import { putImageWithQuota } from "../image-quota";
import { readBodyLimited } from "../body-limit";
import { clientIp, enforceRateLimit, HOUR, LIMITS } from "../rate-limit";
import {
  anonVoterKey,
  migrateLegacyAnonVoterKeys,
  userVoterKey,
} from "../voter-keys";
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
  // Unauthenticated endpoint: bound tenant minting per source IP, and
  // with a global daily ceiling so distributed sources stay bounded.
  await enforceRateLimit(
    c.env,
    "tenant-create",
    clientIp(c),
    LIMITS.tenantCreatePerIpPerHour,
    HOUR,
  );
  await enforceRateLimit(
    c.env,
    "tenant-create-global",
    "all",
    LIMITS.tenantCreateGlobalPerDay,
    24 * HOUR,
  );
  const body = await jsonBody(c);
  const name = reqString(body, "name", { max: 120 });
  const tenantId = randomId();
  const apiKey = randomToken("hvk");
  const apiKeyHash = await sha256Hex(apiKey);
  await c.env.DB.prepare(
    "INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
  )
    .bind(tenantId, name, apiKeyHash, nowIso())
    .run();
  return c.json(
    { tenant: { id: tenantId, name }, api_key: apiKey },
    201,
  );
});

/** Rotate the tenant API key (authenticated with the current key). */
api.post("/tenants/:tenantId/rotate-key", async (c) => {
  const tenantId = c.req.param("tenantId");
  const token = c.req.header("authorization")?.replace(/^Bearer\s+/i, "").trim();
  if (!token) throw unauthorized("UNAUTHORIZED", "API key required");
  const tenant = await findTenantByApiKey(c.env, token);
  if (!tenant || tenant.id !== tenantId) {
    throw unauthorized("INVALID_API_KEY", "API key is not valid for this tenant");
  }
  await enforceRateLimit(
    c.env,
    "rotate-key",
    tenantId,
    LIMITS.rotateKeyPerTenantPerHour,
    HOUR,
  );
  const apiKey = randomToken("hvk");
  const rotated = await c.env.DB.prepare("UPDATE tenants SET api_key_hash = ?1 WHERE id = ?2 AND api_key_hash = ?3")
    .bind(await sha256Hex(apiKey), tenantId, tenant.api_key_hash)
    .run();
  if (rotated.meta.changes !== 1) throw conflict("KEY_CHANGED", "API key changed. Authenticate again.");
  return c.json({ api_key: apiKey });
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
  if (!imageKey.startsWith(`t/${tenantId}/`)) {
    throw badRequest("image_key does not belong to this tenant");
  }
  const obj = await env.IMAGES.head(imageKey);
  if (!obj) throw badRequest("image_key does not reference an uploaded image");
}

async function insertOptions(
  env: Env,
  pollId: string,
  options: OptionInput[],
): Promise<void> {
  const now = nowIso();
  const stmts = options.map((o, i) =>
    env.DB.prepare(
      "INSERT INTO options (id, poll_id, label, image_key, position, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    ).bind(randomId(), pollId, o.label, o.image_key, i, now),
  );
  await env.DB.batch(stmts);
}

/** The CHECK constraint aborts the whole batch, including preceding ballot deletes.
 * Guard rows never survive a successful transaction; failed batches roll back.
 */
export async function guardedPollBatch(
  env: Env,
  predicate: string,
  values: (string | number | null)[],
  statements: D1PreparedStatement[],
): Promise<void> {
  const id = randomId();
  try {
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO poll_mutation_guards (id, valid)
        VALUES (?1, CASE WHEN ${predicate} THEN 1 ELSE 0 END)`).bind(id, ...values),
      ...statements,
      env.DB.prepare("DELETE FROM poll_mutation_guards WHERE id = ?1").bind(id),
    ]);
  } catch (error) {
    // Do not mask storage failures as a policy conflict.
    if (String(error).includes("poll_mutation_allowed")) {
      throw conflict("POLL_CHANGED", "Poll changed or voting is no longer allowed. Reload and retry.");
    }
    throw error;
  }
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
  await requireAdmin(c, tenantId);
  const body = await jsonBody(c);
  const question = reqString(body, "question", { max: 300 });
  const description = optString(body, "description", { max: 5000 }) ?? "";
  const imageKey = optString(body, "image_key", { max: 300 });
  const allowMultiple = optBool(body, "allow_multiple");
  const requireLogin = optBool(body, "require_login");
  const closesAt = optIsoDate(body, "closes_at");
  const options = parseOptions(body);
  await assertImageKeyBelongsToTenant(c.env, tenantId, imageKey);
  for (const o of options) {
    await assertImageKeyBelongsToTenant(c.env, tenantId, o.image_key);
  }
  const pollId = randomId();
  const now = nowIso();
  await c.env.DB.prepare(
    `INSERT INTO polls (id, tenant_id, question, description, image_key, status, allow_multiple, require_login, closes_at, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5, 'draft', ?6, ?7, ?8, ?9, ?9)`,
  )
    .bind(
      pollId,
      tenantId,
      question,
      description,
      imageKey,
      allowMultiple ? 1 : 0,
      requireLogin ? 1 : 0,
      closesAt,
      now,
    )
    .run();
  await insertOptions(c.env, pollId, options);
  const poll = await getPollRow(c.env, pollId);
  const opts = await listOptionRows(c.env, pollId);
  return c.json({ poll: pollToJson(originOf(c), poll as PollRow, opts) }, 201);
});

api.get("/tenants/:tenantId/polls", async (c) => {
  const tenantId = c.req.param("tenantId");
  await requireAdmin(c, tenantId);
  const res = await c.env.DB.prepare(
    "SELECT * FROM polls WHERE tenant_id = ?1 ORDER BY created_at DESC",
  )
    .bind(tenantId)
    .all<PollRow>();
  const polls = [];
  for (const poll of res.results) {
    const opts = await listOptionRows(c.env, poll.id);
    polls.push(pollToJson(originOf(c), poll, opts));
  }
  return c.json({ polls });
});

api.get("/tenants/:tenantId/polls/:pollId", async (c) => {
  const tenantId = c.req.param("tenantId");
  await requireAdmin(c, tenantId);
  const poll = await loadPollForAdmin(c, tenantId, c.req.param("pollId"));
  const opts = await listOptionRows(c.env, poll.id);
  return c.json({ poll: pollToJson(originOf(c), poll, opts) });
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
      ? (optString(body, "description", { max: 5000 }) ?? "")
      : poll.description;
  const imageKey =
    body["image_key"] !== undefined
      ? optString(body, "image_key", { max: 300 })
      : poll.image_key;
  const allowMultiple =
    body["allow_multiple"] !== undefined
      ? optBool(body, "allow_multiple")
      : poll.allow_multiple === 1;
  const requireLogin =
    body["require_login"] !== undefined
      ? optBool(body, "require_login")
      : poll.require_login === 1;
  const closesAt =
    body["closes_at"] !== undefined ? optIsoDate(body, "closes_at") : poll.closes_at;

  await assertImageKeyBelongsToTenant(c.env, tenantId, imageKey);

  let replacementOptions: OptionInput[] | null = null;
  if (body["options"] !== undefined) {
    replacementOptions = parseOptions(body);
    for (const o of replacementOptions) {
      await assertImageKeyBelongsToTenant(c.env, tenantId, o.image_key);
    }
    // Options can only be replaced while nobody has voted yet.
    const voted = await c.env.DB.prepare(
      "SELECT COUNT(*) AS n FROM votes WHERE poll_id = ?1",
    )
      .bind(poll.id)
      .first<{ n: number }>();
    if ((voted?.n ?? 0) > 0) {
      throw conflict(
        "OPTIONS_LOCKED",
        "Options cannot be replaced after votes have been cast",
      );
    }
  }

  const mutations = [c.env.DB.prepare(
    `UPDATE polls SET question = ?1, description = ?2, image_key = ?3,
     allow_multiple = ?4, require_login = ?5, closes_at = ?6, updated_at = ?7, revision = revision + 1
     WHERE id = ?8`,
  )
    .bind(
      question,
      description,
      imageKey,
      allowMultiple ? 1 : 0,
      requireLogin ? 1 : 0,
      closesAt,
      nowIso(),
      poll.id,
    )
    ];

  if (replacementOptions) {
    mutations.push(c.env.DB.prepare("DELETE FROM options WHERE poll_id = ?1").bind(poll.id));
    const now = nowIso();
    mutations.push(...replacementOptions.map((o, i) => c.env.DB.prepare(
      "INSERT INTO options (id, poll_id, label, image_key, position, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    ).bind(randomId(), poll.id, o.label, o.image_key, i, now)));

  }

  await guardedPollBatch(c.env,
    `EXISTS (SELECT 1 FROM polls WHERE id = ?2 AND revision = ?3 AND status != 'closed')
     AND (?4 = 0 OR NOT EXISTS (SELECT 1 FROM votes WHERE poll_id = ?2))`,
    [poll.id, poll.revision, replacementOptions ? 1 : 0], mutations);

  const updated = await getPollRow(c.env, poll.id);
  const opts = await listOptionRows(c.env, poll.id);
  return c.json({ poll: pollToJson(originOf(c), updated as PollRow, opts) });
});

api.post("/tenants/:tenantId/polls/:pollId/status", async (c) => {
  const tenantId = c.req.param("tenantId");
  await requireAdmin(c, tenantId);
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
  await guardedPollBatch(c.env,
    "EXISTS (SELECT 1 FROM polls WHERE id = ?2 AND revision = ?3 AND status = ?4)",
    [poll.id, poll.revision, poll.status], [
      c.env.DB.prepare("UPDATE polls SET status = ?1, updated_at = ?2, revision = revision + 1 WHERE id = ?3")
        .bind(status, nowIso(), poll.id),
    ]);
  const updated = await getPollRow(c.env, poll.id);
  const opts = await listOptionRows(c.env, poll.id);
  return c.json({ poll: pollToJson(originOf(c), updated as PollRow, opts) });
});

api.get("/tenants/:tenantId/polls/:pollId/results", async (c) => {
  const tenantId = c.req.param("tenantId");
  await requireAdmin(c, tenantId);
  const poll = await loadPollForAdmin(c, tenantId, c.req.param("pollId"));
  return c.json({ results: await computeResults(c.env, originOf(c), poll) });
});

/* ------------------------------------------------------------------ */
/* Admin: image upload (R2)                                            */
/* ------------------------------------------------------------------ */

api.post("/tenants/:tenantId/images", async (c) => {
  const tenantId = c.req.param("tenantId");
  await requireAdmin(c, tenantId);
  await enforceRateLimit(
    c.env,
    "image-upload",
    tenantId,
    LIMITS.imageUploadPerTenantPerHour,
    HOUR,
  );
  const contentType = (c.req.header("content-type") ?? "").split(";")[0]?.trim() ?? "";
  const declaredExt = IMAGE_TYPES[contentType];
  if (!declaredExt) {
    throw badRequest("Content-Type must be image/png, image/jpeg, image/webp or image/gif");
  }
  const data = await readBodyLimited(c.req.raw, MAX_IMAGE_BYTES);
  if (data.byteLength === 0) throw badRequest("Image body is empty");
  if (data.byteLength > MAX_IMAGE_BYTES) {
    throw payloadTooLarge("Image must be at most 5 MiB");
  }
  // The declared type is not trusted: the magic bytes must match it.
  const sniffedExt = sniffImageExt(data);
  if (sniffedExt === null || sniffedExt !== declaredExt) {
    throw badRequest("Image contents do not match the declared image type");
  }
  const key = `t/${tenantId}/${randomId()}.${declaredExt}`;
  await putImageWithQuota(c.env, tenantId, key, data, contentType);
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
  const opts = await listOptionRows(c.env, poll.id);
  return c.json({ poll: pollToJson(originOf(c), poll, opts) });
});

api.get("/polls/:pollId/results", async (c) => {
  const poll = await loadPublicPoll(c.env, c.req.param("pollId"));
  return c.json({ results: await computeResults(c.env, originOf(c), poll) });
});

api.post("/polls/:pollId/vote", async (c) => {
  const poll = await loadPublicPoll(c.env, c.req.param("pollId"));
  await enforceRateLimit(
    c.env,
    "vote",
    `${poll.id}:${clientIp(c)}`,
    LIMITS.votePerPollIpPerHour,
    HOUR,
  );
  if (isClosedForVoting(poll)) {
    throw conflict("POLL_CLOSED", "This poll is closed for voting");
  }
  await migrateLegacyAnonVoterKeys(c.env, poll.id);

  // Voter identity: logged-in (0g0-id sub) wins over anonymous voter token.
  const sub = await optionalVoterSub(c);
  const body = await jsonBody(c);

  // A voter_token, when present and valid, identifies the anonymous
  // ballot this voter cast before logging in.
  const rawToken = body["voter_token"];
  const presentedToken =
    typeof rawToken === "string" &&
    rawToken.trim().length >= 8 &&
    rawToken.trim().length <= 128
      ? rawToken.trim()
      : null;

  let voterKey: string;
  let claimedAnonKey: string | null = null;
  if (sub) {
    voterKey = userVoterKey(sub);
    if (presentedToken !== null) {
      claimedAnonKey = await anonVoterKey(c.env.SESSION_SECRET, presentedToken);
    }
  } else {
    if (poll.require_login === 1) {
      throw unauthorized(
        "LOGIN_REQUIRED",
        "This poll requires voters to log in with 0g0-id",
      );
    }
    if (presentedToken === null) {
      throw badRequest(
        '"voter_token" (8-128 chars) is required when voting anonymously',
      );
    }
    voterKey = await anonVoterKey(c.env.SESSION_SECRET, presentedToken);
  }

  const rawOptionIds = body["option_ids"];
  if (!Array.isArray(rawOptionIds) || rawOptionIds.length === 0) {
    throw badRequest('"option_ids" must be a non-empty array');
  }
  const optionIds = [...new Set(rawOptionIds)];
  if (optionIds.some((id) => typeof id !== "string")) {
    throw badRequest('"option_ids" must contain option id strings');
  }
  if (poll.allow_multiple !== 1 && optionIds.length !== 1) {
    throw badRequest("This poll allows exactly one choice");
  }
  const options = await listOptionRows(c.env, poll.id);
  const validIds = new Set(options.map((o) => o.id));
  for (const id of optionIds as string[]) {
    if (!validIds.has(id)) throw badRequest(`Unknown option id: ${id}`);
  }

  // One person, one vote: replace any previous selections atomically.
  // When a logged-in vote also presents the voter's anonymous token,
  // the anonymous ballot is folded into the login identity in the same
  // batch, so the person is not counted twice on this poll.
  const now = nowIso();
  const stmts = [
    c.env.DB.prepare("DELETE FROM votes WHERE poll_id = ?1 AND voter_key = ?2").bind(
      poll.id,
      voterKey,
    ),
    ...(claimedAnonKey && claimedAnonKey !== voterKey
      ? [
          c.env.DB.prepare(
            "DELETE FROM votes WHERE poll_id = ?1 AND voter_key = ?2",
          ).bind(poll.id, claimedAnonKey),
        ]
      : []),
    ...(optionIds as string[]).map((optionId) =>
      c.env.DB.prepare(
        `INSERT INTO votes (id, poll_id, option_id, voter_key, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5)`,
      ).bind(randomId(), poll.id, optionId, voterKey, now),
    ),
  ];
  await guardedPollBatch(c.env,
    `EXISTS (SELECT 1 FROM polls WHERE id = ?2 AND status = 'published'
       AND (closes_at IS NULL OR julianday(closes_at) > julianday('now'))
       AND (require_login = 0 OR ?3 = 1)
       AND (allow_multiple = 1 OR ?4 = 1))
     AND (SELECT COUNT(*) FROM options WHERE poll_id = ?2
       AND id IN (SELECT value FROM json_each(?5))) = ?4`,
    [poll.id, sub ? 1 : 0, optionIds.length, JSON.stringify(optionIds)], stmts);

  const results = await computeResults(c.env, originOf(c), poll);
  return c.json({
    vote: { poll_id: poll.id, option_ids: optionIds, voter: sub ? "user" : "anonymous" },
    results,
  });
});

/* ------------------------------------------------------------------ */
/* Images (public read through the Worker)                             */
/* ------------------------------------------------------------------ */

export async function serveImage(
  env: Env,
  key: string,
): Promise<Response> {
  if (!/^t\/[0-9a-f-]{36}\/[0-9a-f-]{36}\.(png|jpg|webp|gif)$/.test(key)) {
    throw notFound("Image not found");
  }
  const obj = await env.IMAGES.get(key);
  if (!obj) throw notFound("Image not found");
  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  // The served type follows the key's whitelisted extension, never
  // stored metadata, and nosniff is set explicitly by the Worker.
  const ext = key.slice(key.lastIndexOf(".") + 1);
  const servedType: Record<string, string> = {
    png: "image/png",
    jpg: "image/jpeg",
    webp: "image/webp",
    gif: "image/gif",
  };
  headers.set("content-type", servedType[ext] ?? "application/octet-stream");
  headers.set("x-content-type-options", "nosniff");
  headers.set("etag", obj.httpEtag);
  headers.set("cache-control", "public, max-age=86400, immutable");
  return new Response(obj.body, { headers });
}

export { ApiError };
export type { OptionRow, TenantRow };
