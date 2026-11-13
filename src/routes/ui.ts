import { Hono, type Context } from "hono";
import { deleteAccountData, deleteWorkspace, listMemberships } from "../account";
import { subjectForAccount } from "../accounts";
import { selectAuthProvider } from "../platform";
import { pollSubmissionSeries, workspaceSubmissionSeries } from "../analytics";
import { bumpSessionEpoch, clearSessionCookie, getSessionUser, isTenantMember, listTenantsForUser, memberRole } from "../auth";
import {
  addTenantOrigin,
  listTenantOrigins,
  removeTenantOrigin,
} from "../cors";
import { actorLabel, listAuditEvents, recordAudit } from "../audit";
import {
  clientIpOf,
  ipMatchesEntries,
  ipRestrictionAvailable,
  isAdminIpAllowed,
  loadIpRestriction,
  saveIpRestriction,
  validateIpEntries,
} from "../ip-restriction";
import { listQuestionRows, questionConfig } from "../questions";
import { computeResults, getPollRow, isClosedForVoting, listOptionRows, type PollResults } from "../domain";
import { issueApiKey, limitKeyRotation, listApiKeys, provisionTenant, revokeApiKey } from "../keys";
import { addMember, cancelInvite, inviteMemberByEmail, listInvites, listMembers, removeMember, setMemberRole } from "../members";
import { tenantQuotas } from "../quotas";
import { createWebhook, disableWebhook, listWebhooks } from "../webhooks";
import { ApiError } from "../errors";
import {
  assertSameOriginMutation,
  normalizeUuid,
  rateLimitByIp,
  readUrlEncodedForm,
} from "../security";
import { escapeHtml, layout, safeJsonForScript, scriptTag } from "../views";
import type { Env, PollRow, SessionUser, Variables } from "../types";

export const ui = new Hono<{ Bindings: Env; Variables: Variables }>();

function originOf(c: { req: { url: string } }): string {
  return new URL(c.req.url).origin;
}

function routeTenant(c: { req: { param: (name: string) => string } }): string | null {
  return normalizeUuid(c.req.param("tenantId"));
}

async function requireMember(
  c: { env: Env; req: { url: string } },
  tenantId: string,
): Promise<SessionUser | null> {
  const id = normalizeUuid(tenantId);
  if (!id) return null;
  const user = await getSessionUser(c as never);
  if (!user) return null;
  if (!(await isTenantMember(c.env, id, user.accountId))) return null;
  return user;
}

async function requireOwnerUser(
  c: Context<{ Bindings: Env; Variables: Variables }>,
  tenantId: string,
): Promise<SessionUser | Response> {
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  const role = await memberRole(c.env, tenantId, user.accountId);
  if (role !== "owner") {
    return c.html(layout({
      title: "権限がありません",
      userEmail: user.email ?? user.name ?? user.accountId,
      body: `<h1>権限がありません</h1><p>メンバーの管理、API キー、Webhook、許可オリジン、ワークスペースの削除はオーナーだけが実行できます。</p>`,
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }), 403);
  }
  return user;
}

/**
 * Per-workspace admin IP allowlist for the admin UI. Only workspace-scoped
 * pages are guarded, and only once the visitor is known to be a member of
 * that workspace (signed-out visitors and non-members keep the usual
 * redirect behaviour). The login flow itself (/admin/login, /auth/*) is
 * deliberately outside the restriction: it is account-scoped, happens
 * before a workspace is chosen, and guarding it could lock an owner out of
 * every workspace at once. The guard still applies to every workspace page
 * and action after login.
 */
async function adminIpUiGuard(
  c: Context<{ Bindings: Env; Variables: Variables }>,
  next: () => Promise<void>,
): Promise<Response | void> {
  const tenantId = normalizeUuid(c.req.param("tenantId") ?? "");
  if (tenantId) {
    const user = await getSessionUser(c);
    if (user && (await isTenantMember(c.env, tenantId, user.accountId))) {
      const clientIp = clientIpOf(c);
      if (!(await isAdminIpAllowed(c.env, tenantId, clientIp))) {
        return c.html(
          layout({
            title: "IP 制限によりアクセスできません",
            userEmail: user.email ?? user.name ?? user.accountId,
            body: `<h1>このワークスペースは IP 制限が有効です</h1>
              <p class="lead">現在のアクセス元 IP（<code>${escapeHtml(clientIp || "不明")}</code>）は、このワークスペースの管理画面の許可リストに含まれていません。</p>
              <p class="muted">許可されたネットワークからアクセスし直してください。許可リストの変更は、許可済み IP からオーナーが設定画面で行えます。</p>
              <div class="actions"><a class="btn" href="/admin">ワークスペース一覧へ</a></div>`,
            origin: originOf(c),
            nonce: c.get("cspNonce") ?? "",
          }),
          403,
        );
      }
    }
  }
  await next();
}
ui.use("/admin/workspaces/:tenantId", adminIpUiGuard);
ui.use("/admin/workspaces/:tenantId/*", adminIpUiGuard);

/* ------------------------------------------------------------------ */
/* Landing + workspace list                                            */
/* ------------------------------------------------------------------ */

ui.get("/", async (c) => {
  const user = await getSessionUser(c);
  const body = `
    <h1>Hyo 投票管理</h1>
    <p class="lead">投票の作成・公開・集計を行うサービスです。管理画面と API の両方から、同じ投票を操作できます。</p>
    <div class="actions">
      <a class="btn primary" href="/admin">管理画面を開く</a>
      <a class="btn" href="/docs">API 仕様書</a>
      <a class="btn" href="/api/v1/health">API の状態を見る</a>
    </div>
    <h2>処理の流れ</h2>
    <div class="flow" role="img" aria-label="投票を作成し、公開し、投票を受け付け、集計結果を表示する流れ">
      <span class="node">1. 投票を作成</span><span class="arrow" aria-hidden="true">→</span>
      <span class="node">2. 公開</span><span class="arrow" aria-hidden="true">→</span>
      <span class="node">3. 投票を受け付け</span><span class="arrow" aria-hidden="true">→</span>
      <span class="node">4. 集計結果を表示</span>
    </div>
    <h2>仕様</h2>
    <dl class="spec">
      <dt>投票の設定</dt><dd>1つの投票に設問を最大20件まで追加できます。形式は単一選択・複数選択・自由記述・短いテキスト・順位付け・点数付け・数値入力・日付・段階評価・スライダー・配点。設問と選択肢に画像を添付できます。</dd>
      <dt>投票ごとに選べる項目</dt><dd>ログイン必須か任意か、公開日時と締切日時。</dd>
      <dt>投票の数え方</dt><dd>1人1票。締切前なら投票の変更ができます。ログインした人はアカウント単位、匿名の人は投票者トークン単位で数えます。</dd>
      <dt>匿名投票の限界</dt><dd>トークンを変えた同一人物は別人として数えられます。厳密に1人1票が必要な投票では「ログイン必須」を選んでください。</dd>
      <dt>集計結果</dt><dd>管理画面のグラフと API（GET /api/v1/polls/:id/results）で取得できます。CSV / JSON への書き出しにも対応します。</dd>
    </dl>`;
  return c.html(
    layout({
      title: "投票 SaaS",
      userEmail: user?.email ?? user?.name ?? user?.accountId ?? null,
      body,
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }),
  );
});

ui.get("/admin", async (c) => {
  const user = await getSessionUser(c);
  if (!user) {
    const body = `
      <h1>管理画面</h1>
      <p class="lead">管理画面のログインは ${escapeHtml(selectAuthProvider(c.env.AUTH_PROVIDER).label(c.env))} を使います。ログインすると、自分のワークスペース（投票の運用単位）を作成し、設問・選択肢・画像の設定や結果の確認ができます。</p>
      <div class="actions"><a class="btn primary" href="/admin/login">${escapeHtml(selectAuthProvider(c.env.AUTH_PROVIDER).label(c.env))} でログイン</a></div>
      <h2>API キーで使う場合</h2>
      <p class="muted">画面を使わない運用では、テナント作成時に発行される API キーで管理 API を呼び出せます。API キーの発行は <code>POST /api/v1/tenants</code> から行えます（README 参照）。</p>`;
    return c.html(layout({ title: "管理画面", userEmail: null, body, origin: originOf(c), nonce: c.get("cspNonce") ?? "" }));
  }

  const tenants = await listTenantsForUser(c.env, user.accountId);
  const rows = tenants
    .map(
      (t) => `<li>
        <span class="grow"><strong>${escapeHtml(t.name)}</strong><br>
        <span class="muted small">ワークスペース ID: <code>${escapeHtml(t.id)}</code></span></span>
        <a class="btn small primary" href="/admin/workspaces/${t.id}">開く</a>
      </li>`,
    )
    .join("");
  const body = `
    <h1>ワークスペース</h1>
    <p class="lead">ワークスペースごとに投票と API キーが分かれます。ほかのワークスペースのデータは見えません。</p>
    ${rows ? `<ul class="rows">${rows}</ul>` : '<p class="muted">まだワークスペースがありません。下のフォームから作成してください。</p>'}
    <h2>新しいワークスペース</h2>
      <form method="post" action="/admin/workspaces">
        <label for="ws-name">ワークスペース名</label>
        <input id="ws-name" type="text" name="name" required maxlength="120" placeholder="例: イベント投票">
        <div class="actions"><button class="btn primary" type="submit">作成する</button></div>
      </form>`;
  return c.html(
    layout({
      title: "ワークスペース",
      userEmail: user.email ?? user.name ?? user.accountId,
      body,
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }),
  );
});

ui.post("/admin/workspaces", async (c) => {
  const user = await getSessionUser(c);
  if (!user) return c.redirect("/admin/login", 302);
  assertSameOriginMutation(c);
  await rateLimitByIp(c, "tenant-create", 80, 3600);
  const form = await readUrlEncodedForm(c);
  const name = String(form.get("name") ?? "").trim();
  if (!name || name.length > 120) {
    return c.html(
      layout({
        title: "エラー",
        userEmail: user.email ?? user.name ?? user.accountId,
        body: `<h1>名前を確認してください</h1><p class="muted">ワークスペース名は1〜120文字で入力してください。</p><p><a href="/admin">戻る</a></p>`,
        origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
      }),
      400,
    );
  }
  const { tenantId, apiKey } = await provisionTenant(c.env, name, user.accountId);
  const body = `
    <h1>ワークスペースを作成しました</h1>
    <section class="section">
      <p><strong>${escapeHtml(name)}</strong></p>
      <div class="notice"><strong>API キーはこの画面でだけ表示されます。</strong>
      管理 API の認証に使うので、控えて安全な場所に保管してください。</div>
      <p><code style="font-size:1.05rem">${escapeHtml(apiKey)}</code></p>
      <div class="actions"><a class="btn primary" href="/admin/workspaces/${tenantId}">ワークスペースを開く</a></div>
    </section>`;
  return c.html(
    layout({
      title: "ワークスペースを作成しました",
      userEmail: user.email ?? user.name ?? user.accountId,
      body,
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }),
  );
});

/* ------------------------------------------------------------------ */
/* Workspace dashboard                                                 */
/* ------------------------------------------------------------------ */

function statusBadge(status: PollRow["status"]): string {
  const label = status === "draft" ? "下書き" : status === "published" ? "公開中" : "締切済み";
  return `<span class="badge ${status}">${label}</span>`;
}

ui.post("/admin/workspaces/:tenantId/notifications/:notificationId/read", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  assertSameOriginMutation(c);
  await c.env.DB.prepare(
    "UPDATE app_notifications SET read_at = ?1 WHERE id = ?2 AND tenant_id = ?3 AND read_at IS NULL",
  )
    .bind(new Date().toISOString(), c.req.param("notificationId"), tenantId)
    .run();
  return c.redirect(`/admin/workspaces/${tenantId}`, 302);
});

ui.get("/admin/workspaces/:tenantId", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  const tenant = await c.env.DB.prepare("SELECT * FROM tenants WHERE id = ?1")
    .bind(tenantId)
    .first<{ id: string; name: string }>();
  if (!tenant) return c.redirect("/admin", 302);
  const polls = await c.env.DB.prepare(
    "SELECT * FROM polls WHERE tenant_id = ?1 ORDER BY created_at DESC",
  )
    .bind(tenantId)
    .all<PollRow>();
  const role = await memberRole(c.env, tenantId, user.accountId);
  const notifications = await c.env.DB.prepare(
    "SELECT id, message, created_at, read_at FROM app_notifications WHERE tenant_id = ?1 ORDER BY read_at IS NOT NULL, created_at DESC LIMIT 10",
  )
    .bind(tenantId)
    .all<{ id: string; message: string; created_at: string; read_at: string | null }>();
  const notificationItems = notifications.results
    .map(
      (n) => `<li>${n.read_at ? "" : '<span class="badge published">未読</span> '}${escapeHtml(n.message)} <span class="muted small">${escapeHtml(n.created_at)}</span>
        ${n.read_at ? "" : `<form method="post" action="/admin/workspaces/${escapeHtml(tenantId)}/notifications/${escapeHtml(n.id)}/read" style="display:inline"><button class="btn small" type="submit">既読にする</button></form>`}
      </li>`,
    )
    .join("");
  const quotas = await tenantQuotas(c.env, tenantId);
  const keys = await listApiKeys(c.env, tenantId);
  const keyItems = keys
    .map(
      (key) => `<li>${escapeHtml(key.name)} <code>${escapeHtml(key.key_prefix)}…</code> ${key.scope === "write" ? "読み書き" : "読み取り"} ${key.revoked_at ? '<span class="badge closed">失効</span>' : role === "owner" ? `<form method="post" action="/admin/workspaces/${escapeHtml(tenantId)}/api-keys/revoke" style="display:inline"><input type="hidden" name="key_id" value="${escapeHtml(key.id)}"><button class="btn small danger" type="submit">失効</button></form>` : ""}</li>`,
    )
    .join("");
  const rows = polls.results
    .map(
      (p) => `<tr>
        <td data-label="設問"><a href="/admin/workspaces/${tenantId}/polls/${p.id}">${escapeHtml(p.question)}</a><br>
        <span class="muted small">${escapeHtml(p.id)}</span></td>
        <td data-label="状態">${statusBadge(p.status)}</td>
        <td data-label="設定" class="small">${p.require_login === 1 ? "ログイン必須" : "誰でも投票可"}<br>${p.allow_multiple === 1 ? "複数選択可" : "単一選択"}</td>
        <td data-label="締切" class="small">${p.closes_at ? escapeHtml(p.closes_at) : "締切なし"}</td>
        <td><a class="btn small" href="/admin/workspaces/${tenantId}/polls/${p.id}/results">結果</a>
        <a class="btn small" href="/admin/workspaces/${tenantId}/polls/${p.id}/analytics">推移</a></td>
      </tr>`,
    )
    .join("");
  const body = `
    <p class="muted small"><a href="/admin">ワークスペース一覧</a></p>
    <h1>${escapeHtml(tenant.name)}</h1>
    <p class="muted">投票 ${polls.results.length} / ${quotas.polls} 件（公開中 ${polls.results.filter((p) => p.status === "published").length}）／ 記録された票 ${Number((await c.env.DB.prepare("SELECT COUNT(*) AS n FROM vote_ballots WHERE poll_id IN (SELECT id FROM polls WHERE tenant_id = ?1)").bind(tenantId).first<{ n: number }>())?.n ?? 0)} 件。プラン ${escapeHtml(quotas.plan)}。1 日の送信上限は ${quotas.votesPerDay} 件です。</p>
    <div class="actions">
      <a class="btn primary" href="/admin/workspaces/${escapeHtml(tenantId)}/polls/new">新しい投票を作る</a>
      <a class="btn" href="/admin/workspaces/${escapeHtml(tenantId)}/analytics">投票の推移</a>
      <a class="btn" href="/admin/workspaces/${escapeHtml(tenantId)}/settings">設定</a>
      <a class="btn" href="/admin/workspaces/${escapeHtml(tenantId)}/audit">操作履歴</a>
    </div>
    ${notificationItems ? `<h2>通知</h2>
    <section class="section">
      <ul>${notificationItems}</ul>
    </section>` : ""}
    <h2>投票一覧</h2>
    <section class="section">
      ${rows ? `<div class="table-wrapper" tabindex="0" role="region" aria-label="投票一覧"><table><thead><tr><th scope="col">設問</th><th scope="col">状態</th><th scope="col">設定</th><th scope="col">締切</th><th scope="col"><span class="muted">操作</span></th></tr></thead><tbody>${rows}</tbody></table></div>` : '<p class="muted">まだ投票がありません。</p>'}
    </section>
    <h2>API キー</h2>
    <section class="section">
      <p class="muted">管理 API のキーは SHA-256 で保存し、作成時に一度だけ表示します。<code>read</code> は参照と書き出し、<code>write</code> は作成・更新・失効もできます。</p>
      ${keyItems ? `<ul>${keyItems}</ul>` : ""}
      ${role === "owner" ? `<form method="post" action="/admin/workspaces/${escapeHtml(tenantId)}/api-keys" aria-labelledby="key-heading">
        <h3 id="key-heading">新しいキー</h3>
        <label for="key-name">名前</label>
        <input id="key-name" name="name" type="text" required maxlength="80" autocomplete="off">
        <label for="key-scope">権限</label>
        <select id="key-scope" name="scope">
          <option value="read">読み取り</option>
          <option value="write" selected>読み書き</option>
        </select>
        <div class="actions"><button class="btn" type="submit">発行する</button></div>
      </form>
      <p class="muted">下の再発行は、いま有効なキーをすべて失効させて書き込みキーを 1 つ作ります。</p>
      <button class="btn danger" type="button" id="open-rotate">API キーを再発行する</button>
      <dialog id="rotate-dialog" aria-labelledby="rotate-dialog-title">
        <h2 id="rotate-dialog-title">API キーを再発行しますか？</h2>
        <p>再発行すると、古いキーは使えなくなります。新しいキーは発行直後に一度だけ表示されます。</p>
        <form method="post" action="/admin/workspaces/${escapeHtml(tenantId)}/rotate-key">
          <div class="dialog-actions">
            <button class="btn" type="button" id="close-rotate" autofocus>やめる</button>
            <button class="btn danger" type="submit">再発行する</button>
          </div>
        </form>
      </dialog>` : `<p class="muted">キーの発行と失効はオーナーだけが実行できます。</p>`}
      ${role === "owner" ? scriptTag(c.get("cspNonce") ?? "", `
        const openRotate = document.getElementById("open-rotate");
        const rotateDialog = document.getElementById("rotate-dialog");
        const closeRotate = document.getElementById("close-rotate");
        if (openRotate instanceof HTMLButtonElement && rotateDialog instanceof HTMLDialogElement) {
          openRotate.addEventListener("click", () => { rotateDialog.showModal(); });
        }
        if (closeRotate instanceof HTMLButtonElement && rotateDialog instanceof HTMLDialogElement) {
          closeRotate.addEventListener("click", () => { rotateDialog.close(); });
        }
      `) : ""}
    </section>`;
  return c.html(
    layout({
      title: tenant.name,
      userEmail: user.email ?? user.name ?? user.accountId,
      body,
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }),
  );
});

ui.post("/admin/workspaces/:tenantId/rotate-key", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const user = await requireOwnerUser(c, tenantId);
  if (user instanceof Response) return user;
  assertSameOriginMutation(c);
  await readUrlEncodedForm(c);
  const actor = { kind: "session" as const, tenantId, accountId: user.accountId, role: "owner" as const };
  await limitKeyRotation(c.env, tenantId);
  const existing = await listApiKeys(c.env, tenantId);
  for (const key of existing) {
    if (!key.revoked_at) await revokeApiKey(c.env, tenantId, key.id, actor);
  }
  const issued = await issueApiKey(c.env, tenantId, "再発行", "write", actor);
  const apiKey = issued.apiKey;
  const body = `
    <h1>API キーを再発行しました</h1>
    <section class="section">
      <div class="notice"><strong>新しい API キーはこの画面でだけ表示されます。</strong> 控えて安全な場所に保管してください。古いキーはもう使えません。</div>
      <p><code style="font-size:1.05rem">${escapeHtml(apiKey)}</code></p>
      <div class="actions"><a class="btn primary" href="/admin/workspaces/${tenantId}">ワークスペースに戻る</a></div>
    </section>`;
  return c.html(
    layout({
      title: "API キーを再発行しました",
      userEmail: user.email ?? user.name ?? user.accountId,
      body,
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }),
  );
});

ui.post("/admin/workspaces/:tenantId/api-keys", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const user = await requireOwnerUser(c, tenantId);
  if (user instanceof Response) return user;
  assertSameOriginMutation(c);
  const form = await readUrlEncodedForm(c);
  const name = String(form.get("name") ?? "").trim();
  const scope = form.get("scope") === "read" ? "read" : "write";
  try {
    const issued = await issueApiKey(c.env, tenantId, name, scope, {
      kind: "session",
      tenantId,
      accountId: user.accountId,
      role: "owner",
    });
    const body = `
      <h1>API キーを発行しました</h1>
      <section class="section">
        <div class="notice"><strong>このキーは今だけ表示されます。</strong> ${escapeHtml(issued.key.prefix)}… / ${issued.key.scope}</div>
        <p><code style="font-size:1.05rem">${escapeHtml(issued.apiKey)}</code></p>
        <div class="actions"><a class="btn primary" href="/admin/workspaces/${escapeHtml(tenantId)}">ワークスペースに戻る</a></div>
      </section>`;
    return c.html(layout({
      title: "API キーを発行しました",
      userEmail: user.email ?? user.name ?? user.accountId,
      body,
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }));
  } catch (err) {
    if (!(err instanceof ApiError)) throw err;
    return c.html(layout({
      title: "エラー",
      userEmail: user.email ?? user.name ?? user.accountId,
      body: `<h1>キーを発行できません</h1><p class="muted">${escapeHtml(err.message)}</p><p><a href="/admin/workspaces/${escapeHtml(tenantId)}">戻る</a></p>`,
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }), 400);
  }
});

ui.post("/admin/workspaces/:tenantId/api-keys/revoke", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const user = await requireOwnerUser(c, tenantId);
  if (user instanceof Response) return user;
  assertSameOriginMutation(c);
  const form = await readUrlEncodedForm(c);
  const keyId = String(form.get("key_id") ?? "");
  if (!normalizeUuid(keyId)) return c.redirect(`/admin/workspaces/${tenantId}`, 302);
  await revokeApiKey(c.env, tenantId, keyId, { kind: "session", tenantId, accountId: user.accountId, role: "owner" });
  return c.redirect(`/admin/workspaces/${tenantId}`, 303);
});

/* ------------------------------------------------------------------ */
/* Embed origin settings (per workspace)                               */
/* ------------------------------------------------------------------ */

function seriesTable(days: { date: string; count: number }[]): string {
  const max = Math.max(1, ...days.map((day) => day.count));
  const rows = days
    .map((day) => {
      const width = Math.round((day.count / max) * 100);
      return `<div class="bar-row"><span>${escapeHtml(day.date)}</span><div class="bar-track" role="img" aria-label="${day.count} 件"><div class="bar-fill" style="width:${width}%"></div></div><strong>${day.count}</strong></div>`;
    })
    .join("");
  return `<div role="region" aria-label="日次の送信件数">${rows}</div>`;
}

function settingsBody(
  tenantId: string,
  workspaceName: string,
  origins: string[],
  error: string | null,
  owner: boolean,
  extras: { quotas: string; members: string; webhooks: string; branding: string; ipRestriction: string },
): string {
  const tid = escapeHtml(tenantId);
  const items = origins
    .map(
      (origin) => `<li>
        <code>${escapeHtml(origin)}</code>
        ${owner ? `<form method="post" action="/admin/workspaces/${tid}/origins/remove" style="display:inline">
          <input type="hidden" name="origin" value="${escapeHtml(origin)}">
          <button class="btn small" type="submit">削除</button>
        </form>` : ""}
      </li>`,
    )
    .join("");
  return `
    <p class="muted small"><a href="/admin/workspaces/${tid}">ワークスペースに戻る</a></p>
    <h1>ワークスペース設定</h1>
    ${extras.quotas}
    ${extras.members}
    ${extras.webhooks}
    ${extras.branding}
    ${extras.ipRestriction}
    <p class="lead">${escapeHtml(workspaceName)} の投票を、別のサイトのブラウザから呼ぶときに許可するオリジンです。
    この管理画面と同じオリジンから使う場合は追加不要です。ワイルドカードやパスは使えません。</p>
    ${error ? `<div class="notice bad" role="alert">${escapeHtml(error)}</div>` : ""}
    <h2>許可しているオリジン</h2>
    <section class="section">
      ${items ? `<ul>${items}</ul>` : `<p class="muted">まだ許可しているオリジンはありません。この状態では、別サイトのブラウザから公開 API の応答を読めません。</p>`}
    </section>
    ${owner ? `<h2 id="origin-heading">許可するオリジンを追加</h2>
    <section class="section">
      <form method="post" action="/admin/workspaces/${tid}/origins" aria-labelledby="origin-heading">
        <label for="origin">オリジン <span class="hint">例: https://www.example.com 。https のみ（localhost は http も可）。</span></label>
        <input id="origin" name="origin" type="url" required maxlength="200" placeholder="https://www.example.com" spellcheck="false" autocapitalize="none" autocomplete="off" inputmode="url">
        <div class="actions"><button class="btn primary" type="submit">追加する</button></div>
      </form>
    </section>` : `<p class="muted">許可オリジンの変更はオーナーだけが実行できます。</p>`}
    <h2>ワークスペースの書き出しと削除</h2>
    <section class="section">
      <p class="muted">書き出しには設問、集計、許可オリジン、キーのメタデータ、操作履歴が含まれます。投票者トークンやキーの秘密は含みません。</p>
      <p><a class="btn" href="/api/v1/tenants/${tid}/export">JSON で書き出す</a></p>
      ${owner ? `<form method="post" action="/admin/workspaces/${tid}/delete" aria-labelledby="delete-heading">
        <h3 id="delete-heading">削除</h3>
        <label for="confirm-name">確認のためワークスペース名を入力</label>
        <input id="confirm-name" name="confirm_name" type="text" required maxlength="120" autocomplete="off">
        <div class="actions"><button class="btn danger" type="submit">ワークスペースを削除する</button></div>
      </form>` : `<p class="muted">ワークスペースの削除はオーナーだけが実行できます。</p>`}
    </section>`;
}

async function ipRestrictionSection(
  env: Env,
  tenantId: string,
  owner: boolean,
  currentIp: string,
  opts: { warnEntries?: string | null; error?: string | null; entriesText?: string } = {},
): Promise<string> {
  const tid = escapeHtml(tenantId);
  const available = await ipRestrictionAvailable(env);
  const state = await loadIpRestriction(env, tenantId);
  const entries = state.kind === "enabled" ? state.entries : [];
  const shownEntries = opts.entriesText ?? entries.join("\n");
  const statusLine = state.kind === "error"
    ? `<div class="notice bad" role="alert">保存されている制限データを復号できませんでした。安全のため、このワークスペースへの管理アクセスは現在すべて拒否されています。</div>`
    : state.kind === "enabled"
      ? `<p>状態: <strong>有効</strong>（${entries.length} 件の許可エントリ）。許可リストに含まれない IP からは、このワークスペースの管理画面と管理 API を開けません。投票の公開ページと投票 API には影響しません。</p>`
      : `<p>状態: <strong>無効</strong>。現在はすべての IP から管理アクセスできます。</p>`;
  if (!available) {
    return `<h2>管理画面の IP 制限</h2><section class="section">
      ${statusLine}
      <p class="muted">このデプロイでは暗号鍵（IP_LIST_ENCRYPTION_KEY）が未設定のため、IP 制限の設定は利用できません。許可リストは暗号化して保存する設計で、鍵がない環境では機能自体を無効にしています。</p>
    </section>`;
  }
  if (!owner) {
    return `<h2>管理画面の IP 制限</h2><section class="section">
      ${statusLine}
      <p class="muted">IP 制限の変更はオーナーだけが実行できます。許可リストの内容はオーナーにだけ表示されます。</p>
    </section>`;
  }
  const warn = opts.warnEntries != null
    ? `<div class="notice bad" role="alert">
        <p><strong>警告: 現在のアクセス元 IP（<code>${escapeHtml(currentIp || "不明")}</code>）は、新しい許可リストに含まれていません。</strong></p>
        <p>このまま保存すると、この接続からは管理画面と管理 API を開けなくなります。許可リストに現在の IP を追加するか、下の確認にチェックして保存してください。</p>
      </div>
      <form method="post" action="/admin/workspaces/${tid}/ip-restriction">
        <input type="hidden" name="entries" value="${escapeHtml(opts.warnEntries)}">
        <label class="check"><input type="checkbox" name="confirm_lockout" value="1" required> 現在の IP が含まれていないことを理解し、このまま保存します</label>
        <div class="actions"><button class="btn danger" type="submit">警告を理解して保存する</button></div>
      </form>`
    : "";
  return `<h2>管理画面の IP 制限</h2><section class="section">
    ${statusLine}
    ${opts.error ? `<div class="notice bad" role="alert">${escapeHtml(opts.error)}</div>` : ""}
    <p class="muted">許可する IP アドレスまたは CIDR を 1 行に 1 件ずつ書きます（IPv4 / IPv6 対応、最大 50 件）。空にして保存すると制限を解除します。リストは暗号化して保存され、平文では残りません。ログイン画面そのものには適用されません（ログイン後、各ワークスペースの画面と API で判定します）。</p>
    <p>現在のアクセス元 IP: <code>${escapeHtml(currentIp || "不明")}</code></p>
    <form method="post" action="/admin/workspaces/${tid}/ip-restriction">
      <label for="ip-entries">許可する IP / CIDR <span class="hint">例: 192.0.2.10 や 198.51.100.0/24、2001:db8::/32。保存時に現在の IP が含まれていない場合は確認を求めます。</span></label>
      <textarea id="ip-entries" name="entries" rows="6" spellcheck="false" autocapitalize="none" autocomplete="off" placeholder="192.0.2.10&#10;198.51.100.0/24">${escapeHtml(shownEntries)}</textarea>
      <div class="actions"><button class="btn primary" type="submit">IP 制限を保存する</button></div>
    </form>
    ${warn}
  </section>`;
}

async function settingsExtras(
  env: Env,
  tenantId: string,
  owner: boolean,
  nonce = "",
  ipOpts: { currentIp?: string; warnEntries?: string | null; error?: string | null; entriesText?: string } = {},
) {
  const quotas = await tenantQuotas(env, tenantId);
  const members = await listMembers(env, tenantId);
  const invites = await listInvites(env, tenantId);
  const hooks = await listWebhooks(env, tenantId);
  const tid = escapeHtml(tenantId);
  const memberItems = members
    .map((member) => {
      const label = member.name || member.email
        ? `${escapeHtml(member.name ?? "")}${member.name && member.email ? " " : ""}${member.email ? `&lt;${escapeHtml(member.email)}&gt;` : ""} <code>${escapeHtml(member.account_id)}</code>`
        : `<code>${escapeHtml(member.account_id)}</code>`;
      return `<li>${label} ${member.role === "owner" ? "オーナー" : "メンバー"}
      ${owner ? `<form method="post" action="/admin/workspaces/${tid}/members/role" style="display:inline">
        <input type="hidden" name="account_id" value="${escapeHtml(member.account_id)}">
        <input type="hidden" name="role" value="${member.role === "owner" ? "member" : "owner"}">
        <button class="btn small" type="submit">${member.role === "owner" ? "メンバーにする" : "オーナーにする"}</button>
      </form>
      <form method="post" action="/admin/workspaces/${tid}/members/remove" style="display:inline">
        <input type="hidden" name="account_id" value="${escapeHtml(member.account_id)}">
        <button class="btn small danger" type="submit">外す</button>
      </form>` : ""}
    </li>`;
    })
    .join("");
  const inviteItems = invites
    .map((invite) => `<li>${escapeHtml(invite.email)} ${invite.role === "owner" ? "オーナー" : "メンバー"}（招待中・初回ログインで参加）
      ${owner ? `<form method="post" action="/admin/workspaces/${tid}/members/invite-remove" style="display:inline">
        <input type="hidden" name="email" value="${escapeHtml(invite.email)}">
        <button class="btn small danger" type="submit">招待を取り消す</button>
      </form>` : ""}
    </li>`)
    .join("");
  const hookItems = hooks
    .map((hook) => `<li><code>${escapeHtml(hook.url)}</code> ${hook.events.map((event) => escapeHtml(event)).join(", ")} ${hook.disabled_at ? '<span class="badge closed">停止</span>' : owner ? `<form method="post" action="/admin/workspaces/${tid}/webhooks/disable" style="display:inline"><input type="hidden" name="webhook_id" value="${escapeHtml(hook.id)}"><button class="btn small" type="submit">停止</button></form>` : ""}</li>`)
    .join("");
  const brand = await env.DB.prepare(
    "SELECT brand_color, brand_logo_key FROM tenants WHERE id = ?1",
  )
    .bind(tenantId)
    .first<{ brand_color: string | null; brand_logo_key: string | null }>();
  const brandingScript = scriptTag(
    nonce,
    `
const TID = ${JSON.stringify(tenantId)};
document.getElementById('branding-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const status = document.getElementById('branding-status');
  status.textContent = '保存しています';
  try {
    let logoKey = document.getElementById('brand-logo-key').value || null;
    const file = document.getElementById('brand-logo-file').files[0];
    if (file) {
      const res = await fetch('/api/v1/tenants/' + TID + '/images', {
        method: 'POST',
        headers: { 'content-type': file.type },
        body: file,
        credentials: 'same-origin',
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error((data.error && data.error.message) || 'ロゴのアップロードに失敗しました');
      logoKey = data.key;
    }
    if (document.getElementById('brand-logo-clear').checked) logoKey = null;
    const colorValue = document.getElementById('brand-color').value;
    const body = {
      brand_color: document.getElementById('brand-color-clear').checked ? null : colorValue,
      brand_logo_key: logoKey,
    };
    const res = await fetch('/api/v1/tenants/' + TID + '/branding', {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      credentials: 'same-origin',
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error((data.error && data.error.message) || '保存に失敗しました');
    status.textContent = '保存しました';
  } catch (e) {
    status.textContent = e.message || String(e);
  }
});
`,
  );
  return {
    ipRestriction: await ipRestrictionSection(env, tenantId, owner, ipOpts.currentIp ?? "", ipOpts),
    branding: `<h2>ブランド設定</h2><section class="section">
      <p class="muted">公開結果ページと共有用画像に使う、ワークスペースのアクセント色とロゴです。</p>
      ${
        owner
          ? `<form id="branding-form">
        <label for="brand-color">アクセント色</label>
        <input id="brand-color" type="color" value="${escapeHtml(brand?.brand_color ?? "#1e4fd8")}">
        <label class="check"><input id="brand-color-clear" type="checkbox"> 色を未設定に戻す</label>
        <label for="brand-logo-file">ロゴ画像 <span class="hint">PNG / JPEG / WebP / GIF、5 MiB まで。選ばなければ現在のロゴを維持します。</span></label>
        ${brand?.brand_logo_key ? `<p><img src="/images/${escapeHtml(brand.brand_logo_key)}" alt="現在のロゴ" style="max-height:64px"></p>` : ""}
        <input id="brand-logo-file" type="file" accept="image/png,image/jpeg,image/webp,image/gif">
        <input type="hidden" id="brand-logo-key" value="${escapeHtml(brand?.brand_logo_key ?? "")}">
        <label class="check"><input id="brand-logo-clear" type="checkbox"> ロゴを外す</label>
        <div class="actions"><button class="btn" type="submit">ブランド設定を保存</button></div>
        <p class="muted small" id="branding-status" role="status"></p>
      </form>
      ${brandingScript}`
          : `<p class="muted">ブランド設定の変更はオーナーだけが実行できます。</p>`
      }
    </section>`,
    quotas: `<h2>利用上限</h2><section class="section"><p>プラン <strong>${escapeHtml(quotas.plan)}</strong>。投票 ${quotas.polls} 件、有効な API キー ${quotas.keys} 個、Webhook ${quotas.webhooks} 件、1 日の投票送信 ${quotas.votesPerDay} 件まで。上限はワークスペースに保存され、自分では引き上げられません。</p></section>`,
    members: `<h2>メンバー</h2><section class="section">${memberItems ? `<ul>${memberItems}</ul>` : `<p class="muted">メンバーはいません。</p>`}
      ${inviteItems ? `<h3>招待中</h3><ul>${inviteItems}</ul>` : ""}
      ${owner ? `<form method="post" action="/admin/workspaces/${tid}/members" aria-labelledby="member-heading">
        <h3 id="member-heading">アカウント ID またはメールアドレスで追加</h3>
        <label for="member-identifier">アカウント ID / メールアドレス</label>
        <input id="member-identifier" name="identifier" type="text" required maxlength="256" autocomplete="off" spellcheck="false">
        <p class="muted small">アカウント ID は、追加したい人のアカウント画面に表示される Hyo 内部の ID です。メールアドレスで追加すると、そのアドレスのアカウントが既にあれば即時に参加し、まだ無ければ招待として保留され、相手の初回ログイン時に参加します。招待メールはこのアプリから送りません。</p>
        <label for="member-role">役割</label>
        <select id="member-role" name="role"><option value="member" selected>メンバー</option><option value="owner">オーナー</option></select>
        <div class="actions"><button class="btn" type="submit">追加する</button></div>
      </form>` : `<p class="muted">メンバーの追加はオーナーだけが実行できます。招待メールはこのアプリから送りません。</p>`}
    </section>`,
    webhooks: `<h2>Webhook</h2><section class="section">
      <p class="muted">投票の送信、公開、締切、更新を HTTPS の URL に送ります。署名は <code>X-Headless-Vote-Signature: v1=</code> と HMAC-SHA256 です。秘密は作成時に一度だけ表示し、保存時は暗号化します。投票者トークンや自由記述の本文は送りません。</p>
      ${hookItems ? `<ul>${hookItems}</ul>` : `<p class="muted">Webhook はありません。</p>`}
      ${owner ? `<form method="post" action="/admin/workspaces/${tid}/webhooks">
        <label for="hook-url">URL</label>
        <input id="hook-url" name="url" type="url" required maxlength="300" placeholder="https://example.com/hooks/vote" spellcheck="false" autocomplete="off">
        <div class="actions"><button class="btn" type="submit">追加する</button></div>
      </form>` : ""}
    </section>`,
  };
}

ui.get("/admin/workspaces/:tenantId/settings", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  const tenant = await c.env.DB.prepare("SELECT name FROM tenants WHERE id = ?1")
    .bind(tenantId)
    .first<{ name: string }>();
  if (!tenant) return c.redirect("/admin", 302);
  const origins = await listTenantOrigins(c.env, tenantId);
  const owner = (await memberRole(c.env, tenantId, user.accountId)) === "owner";
  return c.html(
    layout({
      title: "設定",
      userEmail: user.email ?? user.name ?? user.accountId,
      body: settingsBody(tenantId, tenant.name, origins, null, owner, await settingsExtras(c.env, tenantId, owner, c.get("cspNonce") ?? "", { currentIp: clientIpOf(c) })),
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }),
  );
});

ui.post("/admin/workspaces/:tenantId/origins", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const user = await requireOwnerUser(c, tenantId);
  if (user instanceof Response) return user;
  assertSameOriginMutation(c);
  const form = await readUrlEncodedForm(c);
  try {
    await addTenantOrigin(c.env, tenantId, String(form.get("origin") ?? ""));
  } catch (err) {
    if (err instanceof ApiError) {
      const tenant = await c.env.DB.prepare("SELECT name FROM tenants WHERE id = ?1")
        .bind(tenantId)
        .first<{ name: string }>();
      const origins = await listTenantOrigins(c.env, tenantId);
      return c.html(
        layout({
          title: "設定",
          userEmail: user.email ?? user.name ?? user.accountId,
          body: settingsBody(tenantId, tenant?.name ?? "", origins, err.message, true, await settingsExtras(c.env, tenantId, true, c.get("cspNonce") ?? "", { currentIp: clientIpOf(c) })),
          origin: originOf(c),
          nonce: c.get("cspNonce") ?? "",
        }),
        400,
      );
    }
    throw err;
  }
  return c.redirect(`/admin/workspaces/${tenantId}/settings`, 303);
});

ui.post("/admin/workspaces/:tenantId/origins/remove", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const user = await requireOwnerUser(c, tenantId);
  if (user instanceof Response) return user;
  assertSameOriginMutation(c);
  const form = await readUrlEncodedForm(c);
  await removeTenantOrigin(c.env, tenantId, String(form.get("origin") ?? ""));
  return c.redirect(`/admin/workspaces/${tenantId}/settings`, 303);
});

ui.post("/admin/workspaces/:tenantId/ip-restriction", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const user = await requireOwnerUser(c, tenantId);
  if (user instanceof Response) return user;
  assertSameOriginMutation(c);
  const form = await readUrlEncodedForm(c);
  const entriesText = String(form.get("entries") ?? "");
  const currentIp = clientIpOf(c);
  const renderSettings = async (
    ipOpts: { error?: string | null; warnEntries?: string | null },
    status: 400,
  ) => {
    const tenant = await c.env.DB.prepare("SELECT name FROM tenants WHERE id = ?1")
      .bind(tenantId)
      .first<{ name: string }>();
    const origins = await listTenantOrigins(c.env, tenantId);
    return c.html(
      layout({
        title: "設定",
        userEmail: user.email ?? user.name ?? user.accountId,
        body: settingsBody(
          tenantId,
          tenant?.name ?? "",
          origins,
          null,
          true,
          await settingsExtras(c.env, tenantId, true, c.get("cspNonce") ?? "", {
            currentIp,
            entriesText,
            ...ipOpts,
          }),
        ),
        origin: originOf(c),
        nonce: c.get("cspNonce") ?? "",
      }),
      status,
    );
  };
  if (!(await ipRestrictionAvailable(c.env))) {
    return renderSettings(
      { error: "この環境では暗号鍵が未設定のため、IP 制限を利用できません。" },
      400,
    );
  }
  let entries: string[];
  try {
    entries = validateIpEntries(entriesText.split(/\r?\n/));
  } catch (err) {
    if (err instanceof ApiError) return renderSettings({ error: err.message }, 400);
    throw err;
  }
  const confirmed = String(form.get("confirm_lockout") ?? "") === "1";
  if (
    entries.length > 0 &&
    !confirmed &&
    !(currentIp && ipMatchesEntries(currentIp, entries))
  ) {
    // Lockout guard: the submitter's own IP is not on the new list. Do not
    // save yet; re-render with a strong warning and an explicit confirm.
    return renderSettings({ warnEntries: entries.join("\n") }, 400);
  }
  await saveIpRestriction(c.env, tenantId, entries);
  await recordAudit(c.env, {
    tenantId,
    actor: actorLabel({ kind: "session", tenantId, accountId: user.accountId, role: "owner" }),
    action: "admin_ip_restriction.update",
    detail: entries.length > 0 ? `entries=${entries.length}` : "restriction cleared",
  });
  return c.redirect(`/admin/workspaces/${tenantId}/settings`, 303);
});

ui.post("/admin/workspaces/:tenantId/delete", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const user = await requireOwnerUser(c, tenantId);
  if (user instanceof Response) return user;
  assertSameOriginMutation(c);
  const form = await readUrlEncodedForm(c);
  const tenant = await c.env.DB.prepare("SELECT name FROM tenants WHERE id = ?1")
    .bind(tenantId)
    .first<{ name: string }>();
  if (!tenant || String(form.get("confirm_name") ?? "") !== tenant.name) {
    const origins = await listTenantOrigins(c.env, tenantId);
    return c.html(layout({
      title: "設定",
      userEmail: user.email ?? user.name ?? user.accountId,
      body: settingsBody(tenantId, tenant?.name ?? "", origins, "ワークスペース名が一致しません。", true, await settingsExtras(c.env, tenantId, true, c.get("cspNonce") ?? "", { currentIp: clientIpOf(c) })),
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }), 400);
  }
  await deleteWorkspace(c.env, tenantId);
  return c.redirect("/admin", 303);
});

ui.get("/admin/workspaces/:tenantId/audit", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  const events = await listAuditEvents(c.env, tenantId);
  const rows = events
    .map(
      (event) => `<tr>
        <td data-label="日時">${escapeHtml(event.created_at)}</td>
        <td data-label="操作">${escapeHtml(event.action)}</td>
        <td data-label="実行者">${escapeHtml(event.actor)}</td>
        <td data-label="対象">${escapeHtml(event.target ?? "")}</td>
        <td data-label="内容">${escapeHtml(event.detail)}</td>
      </tr>`,
    )
    .join("");
  const body = `
    <p class="muted small"><a href="/admin/workspaces/${escapeHtml(tenantId)}">ワークスペースに戻る</a></p>
    <h1>操作履歴</h1>
    <section class="section">
      ${rows ? `<div class="table-wrapper" tabindex="0" role="region" aria-label="操作履歴"><table><thead><tr><th scope="col">日時</th><th scope="col">操作</th><th scope="col">実行者</th><th scope="col">対象</th><th scope="col">内容</th></tr></thead><tbody>${rows}</tbody></table></div>` : '<p class="muted">まだ記録がありません。</p>'}
    </section>`;
  return c.html(layout({
    title: "操作履歴",
    userEmail: user.email ?? user.name ?? user.accountId,
    body,
    origin: originOf(c),
    nonce: c.get("cspNonce") ?? "",
  }));
});

ui.get("/admin/workspaces/:tenantId/analytics", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  const days = await workspaceSubmissionSeries(c.env, tenantId);
  const body = `
    <p class="muted small"><a href="/admin/workspaces/${escapeHtml(tenantId)}">ワークスペースに戻る</a></p>
    <h1>投票の推移</h1>
    <p class="lead">直近 14 日の送信件数です。同じ人が投票をやり直すと、別の送信として数えます。人数ではありません。</p>
    <section class="section">${seriesTable(days)}</section>`;
  return c.html(layout({
    title: "投票の推移",
    userEmail: user.email ?? user.name ?? user.accountId,
    body,
    origin: originOf(c),
    nonce: c.get("cspNonce") ?? "",
  }));
});

ui.get("/admin/workspaces/:tenantId/polls/:pollId/analytics", async (c) => {
  const tenantId = routeTenant(c);
  const pollId = normalizeUuid(c.req.param("pollId"));
  if (!tenantId || !pollId) return c.redirect("/admin", 302);
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  const poll = await getPollRow(c.env, pollId);
  if (!poll || poll.tenant_id !== tenantId) return c.redirect(`/admin/workspaces/${tenantId}`, 302);
  const days = await pollSubmissionSeries(c.env, poll.id);
  const body = `
    <p class="muted small"><a href="/admin/workspaces/${escapeHtml(tenantId)}/polls/${escapeHtml(poll.id)}/results">結果に戻る</a></p>
    <h1>${escapeHtml(poll.question)}</h1>
    <p class="lead">直近 14 日の送信件数です。人数ではなく、投票が保存された回数です。</p>
    <section class="section">${seriesTable(days)}</section>`;
  return c.html(layout({
    title: "投票の推移",
    userEmail: user.email ?? user.name ?? user.accountId,
    body,
    origin: originOf(c),
    nonce: c.get("cspNonce") ?? "",
  }));
});

ui.post("/admin/workspaces/:tenantId/members", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const user = await requireOwnerUser(c, tenantId);
  if (user instanceof Response) return user;
  assertSameOriginMutation(c);
  const form = await readUrlEncodedForm(c);
  try {
    const identifier = String(form.get("identifier") ?? "").trim();
    const role = form.get("role") === "owner" ? "owner" : "member";
    const actor = {
      kind: "session" as const,
      tenantId,
      accountId: user.accountId,
      role: "owner" as const,
    };
    if (identifier.includes("@")) {
      await inviteMemberByEmail(c.env, tenantId, identifier, role, actor);
    } else {
      await addMember(c.env, tenantId, identifier, role, actor);
    }
  } catch (err) {
    if (!(err instanceof ApiError)) throw err;
    return c.html(layout({
      title: "設定",
      userEmail: user.email ?? user.name ?? user.accountId,
      body: `<h1>メンバーを追加できません</h1><p>${escapeHtml(err.message)}</p><p><a href="/admin/workspaces/${escapeHtml(tenantId)}/settings">戻る</a></p>`,
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }), 400);
  }
  return c.redirect(`/admin/workspaces/${tenantId}/settings`, 303);
});

ui.post("/admin/workspaces/:tenantId/members/invite-remove", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const user = await requireOwnerUser(c, tenantId);
  if (user instanceof Response) return user;
  assertSameOriginMutation(c);
  const form = await readUrlEncodedForm(c);
  try {
    await cancelInvite(c.env, tenantId, String(form.get("email") ?? ""), {
      kind: "session", tenantId, accountId: user.accountId, role: "owner",
    });
  } catch (err) {
    if (!(err instanceof ApiError)) throw err;
    return c.html(layout({
      title: "設定",
      userEmail: user.email ?? user.name ?? user.accountId,
      body: `<h1>招待を取り消せません</h1><p>${escapeHtml(err.message)}</p><p><a href="/admin/workspaces/${escapeHtml(tenantId)}/settings">戻る</a></p>`,
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }), 400);
  }
  return c.redirect(`/admin/workspaces/${tenantId}/settings`, 303);
});

ui.post("/admin/workspaces/:tenantId/members/role", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const user = await requireOwnerUser(c, tenantId);
  if (user instanceof Response) return user;
  assertSameOriginMutation(c);
  const form = await readUrlEncodedForm(c);
  try {
    await setMemberRole(c.env, tenantId, String(form.get("account_id") ?? ""), form.get("role"), {
      kind: "session", tenantId, accountId: user.accountId, role: "owner",
    });
  } catch (err) {
    if (!(err instanceof ApiError)) throw err;
    return c.html(layout({
      title: "設定",
      userEmail: user.email ?? user.name ?? user.accountId,
      body: `<h1>役割を変更できません</h1><p>${escapeHtml(err.message)}</p><p><a href="/admin/workspaces/${escapeHtml(tenantId)}/settings">戻る</a></p>`,
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }), 400);
  }
  return c.redirect(`/admin/workspaces/${tenantId}/settings`, 303);
});

ui.post("/admin/workspaces/:tenantId/members/remove", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const user = await requireOwnerUser(c, tenantId);
  if (user instanceof Response) return user;
  assertSameOriginMutation(c);
  const form = await readUrlEncodedForm(c);
  try {
    await removeMember(c.env, tenantId, String(form.get("account_id") ?? ""), {
      kind: "session", tenantId, accountId: user.accountId, role: "owner",
    });
  } catch (err) {
    if (!(err instanceof ApiError)) throw err;
    return c.html(layout({
      title: "設定",
      userEmail: user.email ?? user.name ?? user.accountId,
      body: `<h1>メンバーを外せません</h1><p>${escapeHtml(err.message)}</p><p><a href="/admin/workspaces/${escapeHtml(tenantId)}/settings">戻る</a></p>`,
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }), 400);
  }
  return c.redirect(`/admin/workspaces/${tenantId}/settings`, 303);
});

ui.post("/admin/workspaces/:tenantId/webhooks", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const user = await requireOwnerUser(c, tenantId);
  if (user instanceof Response) return user;
  assertSameOriginMutation(c);
  const form = await readUrlEncodedForm(c);
  try {
    const created = await createWebhook(c.env, tenantId, String(form.get("url") ?? ""), [
      "vote.cast", "poll.published", "poll.closed", "poll.updated",
    ]);
    const body = `
      <h1>Webhook を追加しました</h1>
      <section class="section">
        <div class="notice"><strong>署名の秘密はこの画面でだけ表示されます。</strong> <code>X-Headless-Vote-Signature</code> の HMAC 鍵です。</div>
        <p><code>${escapeHtml(created.secret)}</code></p>
        <p class="muted">${escapeHtml(created.url)}</p>
        <div class="actions"><a class="btn primary" href="/admin/workspaces/${escapeHtml(tenantId)}/settings">設定に戻る</a></div>
      </section>`;
    return c.html(layout({
      title: "Webhook を追加しました",
      userEmail: user.email ?? user.name ?? user.accountId,
      body,
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }));
  } catch (err) {
    if (!(err instanceof ApiError)) throw err;
    return c.html(layout({
      title: "設定",
      userEmail: user.email ?? user.name ?? user.accountId,
      body: `<h1>Webhook を追加できません</h1><p>${escapeHtml(err.message)}</p><p><a href="/admin/workspaces/${escapeHtml(tenantId)}/settings">戻る</a></p>`,
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }), 400);
  }
});

ui.post("/admin/workspaces/:tenantId/webhooks/disable", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const user = await requireOwnerUser(c, tenantId);
  if (user instanceof Response) return user;
  assertSameOriginMutation(c);
  const form = await readUrlEncodedForm(c);
  const id = String(form.get("webhook_id") ?? "");
  if (normalizeUuid(id)) await disableWebhook(c.env, tenantId, id);
  return c.redirect(`/admin/workspaces/${tenantId}/settings`, 303);
});

ui.get("/admin/account", async (c) => {
  const user = await getSessionUser(c);
  if (!user) return c.redirect("/admin", 302);
  const memberships = await listMemberships(c.env, user.accountId);
  const rows = memberships
    .map((m) => `<tr><td>${escapeHtml(m.name)}</td><td>${m.role === "owner" ? "オーナー" : "メンバー"}</td><td>${escapeHtml(m.plan)}</td></tr>`)
    .join("");
  const body = `
    <h1>アカウント</h1>
    <section class="section">
      <h2>プロフィール</h2>
      <p>名前: ${escapeHtml(user.name ?? "未設定")}</p>
      <p>メール: ${escapeHtml(user.email ?? "未設定")}</p>
      <p>アカウント ID: <code>${escapeHtml(user.accountId)}</code></p>
      <p class="muted small">Hyo 内部のアカウント ID です。ワークスペースへ招待してもらうときに使います。ログイン先の認証プロバイダの識別子は Hyo の画面や API には表示しません。</p>
      <p class="muted">${selectAuthProvider(c.env.AUTH_PROVIDER).capabilities.localPasswords
        ? "このデプロイはメールとパスワードを保存します。確認と再設定のリンクは、設定したメール送信アダプタから届きます。"
        : `${escapeHtml(selectAuthProvider(c.env.AUTH_PROVIDER).label(c.env))} でログインしています。このアプリはパスワードを保存しないため、メール確認とパスワード再設定は認証プロバイダ側の機能です。`}</p>
    </section>
    <h2>参加しているワークスペース</h2>
    <section class="section">
      ${rows ? `<div class="table-wrapper" tabindex="0" role="region" aria-label="ワークスペース"><table><thead><tr><th scope="col">名前</th><th scope="col">役割</th><th scope="col">プラン</th></tr></thead><tbody>${rows}</tbody></table></div>` : `<p class="muted">まだ参加していません。</p>`}
      <p><a class="btn" href="/api/v1/me/export">自分のデータを JSON で書き出す</a></p>
    </section>
    <h2>セッション</h2>
    <section class="section">
      <p class="muted">ログイン中のすべてのブラウザ・端末で、このアカウントのセッションを無効化します。実行すると自分もログアウトします。</p>
      <form method="post" action="/admin/account/revoke-sessions">
        <div class="actions"><button class="btn danger" type="submit">すべてのセッションを無効化</button></div>
      </form>
    </section>
    <h2>このアプリ上のデータを削除</h2>
    <section class="section">
      <p class="muted">あなたが唯一のオーナーであるワークスペースは削除されます。他にオーナーがいるワークスペースでは、あなたの参加だけが外れます。外部の認証プロバイダのアカウント自体は削除されません。ローカル認証の場合は、このアプリのパスワードも削除されます。</p>
      <form method="post" action="/admin/account/delete">
        <label for="confirm-delete">確認のため <code>delete my data</code> と入力</label>
        <input id="confirm-delete" name="confirm" type="text" required maxlength="40" autocomplete="off">
        <div class="actions"><button class="btn danger" type="submit">データを削除する</button></div>
      </form>
    </section>`;
  return c.html(layout({
    title: "アカウント",
    userEmail: user.email ?? user.name ?? user.accountId,
    body,
    origin: originOf(c),
    nonce: c.get("cspNonce") ?? "",
  }));
});

ui.post("/admin/account/revoke-sessions", async (c) => {
  const user = await getSessionUser(c);
  if (!user) return c.redirect("/admin", 302);
  assertSameOriginMutation(c);
  if (user.authProvider === "local") {
    // Local accounts version their sessions on the user row instead.
    const subject = await subjectForAccount(c.env, user.accountId);
    const localId = subject?.startsWith("local:") ? subject.slice("local:".length) : null;
    if (localId) {
      await c.env.DB.prepare(
        "UPDATE local_users SET session_version = session_version + 1 WHERE id = ?1",
      )
        .bind(localId)
        .run();
    }
  } else {
    await bumpSessionEpoch(c.env, user.accountId);
  }
  c.header("Set-Cookie", clearSessionCookie(c.req.url));
  return c.redirect("/admin", 303);
});

ui.post("/admin/account/delete", async (c) => {
  const user = await getSessionUser(c);
  if (!user) return c.redirect("/admin", 302);
  assertSameOriginMutation(c);
  const form = await readUrlEncodedForm(c);
  if (String(form.get("confirm") ?? "") !== "delete my data") {
    return c.html(layout({
      title: "アカウント",
      userEmail: user.email ?? user.name ?? user.accountId,
      body: `<h1>削除できません</h1><p>確認の文字列が一致しません。</p><p><a href="/admin/account">戻る</a></p>`,
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }), 400);
  }
  await deleteAccountData(c.env, user.accountId);
  return c.redirect("/", 303);
});

/* ------------------------------------------------------------------ */
/* Poll form (new / edit)                                              */
/* ------------------------------------------------------------------ */

function pollFormScript(tenantId: string, pollId: string | null, nonce: string): string {
  const code = `
(() => {
const TENANT = ${safeJsonForScript(tenantId)};
const POLL_ID = ${safeJsonForScript(pollId)};
const questionsEl = document.getElementById('questions');
const errorEl = document.getElementById('form-error');
const OPTION_KINDS = ['single', 'multiple', 'ranking', 'score', 'allocation'];
const KIND_HINTS = {
  single: '投票者は選択肢から1つだけ選びます。',
  multiple: '投票者は選択肢を複数選べます。',
  text: '投票者が自由に文章を入力します（長文・改行可）。選択肢は不要です。',
  short_text: '投票者が短い文章を1行で入力します（200文字まで）。選択肢は不要です。',
  ranking: '投票者は選択肢を並べ替えて順位を付けます。選択肢が順位付けの対象になります。',
  score: '投票者は選択肢ごとに0〜5点で評価します。選択肢が評価の対象になります。',
  number: '投票者が数値を入力します。最小値・最大値で範囲を絞れます。選択肢は不要です。',
  date: '投票者が日付（YYYY-MM-DD）を入力します。選択肢は不要です。',
  scale: '投票者が段階（既定は5段階）から1つ選びます。選択肢は不要です。',
  slider: '投票者がスライダーで範囲内の数値を選びます。選択肢は不要です。',
  allocation: '投票者が合計点を各選択肢へ割り振ります。選択肢が配点の対象になります。',
};
const KIND_OPTIONS = [
  ['single', '単一選択'], ['multiple', '複数選択'], ['text', '自由記述（長文）'],
  ['short_text', '短いテキスト（1行）'], ['ranking', '順位付け'], ['score', '点数付け（0〜5）'],
  ['number', '数値入力'], ['date', '日付'], ['scale', '段階評価'], ['slider', 'スライダー'],
  ['allocation', '配点（合計を割り振る）'],
];

/* ---- inline field errors -------------------------------------------- */
let errorSeq = 0;
function showFieldError(field, message) {
  clearFieldError(field);
  const div = document.createElement('div');
  div.className = 'field-error';
  div.id = 'fe-' + (++errorSeq);
  div.textContent = message;
  field.setAttribute('aria-invalid', 'true');
  field.setAttribute('aria-describedby', div.id);
  field.after(div);
  field._hvError = div;
  return div;
}
function showBoxError(box, message) {
  clearFieldError(box);
  const div = document.createElement('div');
  div.className = 'field-error';
  div.textContent = message;
  box.classList.add('has-error');
  box.after(div);
  box._hvError = div;
  return div;
}
function clearFieldError(el) {
  if (!el) return;
  if (el._hvError) { el._hvError.remove(); el._hvError = null; }
  el.classList.remove('has-error');
  if (el.getAttribute && el.getAttribute('aria-invalid')) {
    el.removeAttribute('aria-invalid');
    el.removeAttribute('aria-describedby');
  }
}
function clearAllErrors() {
  errorEl.style.display = 'none';
  errorEl.textContent = '';
  for (const el of document.querySelectorAll('#poll-form [aria-invalid="true"], #poll-form .has-error')) {
    clearFieldError(el);
  }
  // Error nodes whose anchor lost its marker are removed as well.
  for (const div of document.querySelectorAll('#poll-form .field-error')) div.remove();
}

function addOptionRow(list, label, imageKey, optionId) {
  const row = document.createElement('div');
  row.className = 'option-row';
  const input = document.createElement('input');
  input.type = 'text';
  input.className = 'opt-label';
  input.maxLength = 200;
  input.placeholder = '選択肢の文言';
  input.value = label || '';
  row.append(input);
  if (imageKey) {
    const img = document.createElement('img');
    img.className = 'opt-preview';
    img.alt = '';
    img.src = '/images/' + imageKey;
    row.append(img);
  }
  const fileLabel = document.createElement('label');
  fileLabel.className = 'btn small';
  fileLabel.style.margin = '0';
  fileLabel.append(document.createTextNode('画像'));
  const file = document.createElement('input');
  file.type = 'file';
  file.className = 'opt-file';
  file.accept = 'image/png,image/jpeg,image/webp,image/gif';
  file.hidden = true;
  fileLabel.append(file);
  const key = document.createElement('input');
  key.type = 'hidden';
  key.className = 'opt-key';
  key.value = imageKey || '';
  const idInput = document.createElement('input');
  idInput.type = 'hidden';
  idInput.className = 'opt-id';
  idInput.value = optionId || crypto.randomUUID();
  const remove = document.createElement('button');
  remove.type = 'button';
  remove.className = 'btn small danger opt-remove';
  remove.textContent = '削除';
  remove.addEventListener('click', () => { row.remove(); refreshShowIf(); });
  row.append(fileLabel, key, idInput, remove);
  list.append(row);
}

function refreshShowIf() {
  const cards = [...questionsEl.querySelectorAll('.question-card')];
  cards.forEach((card, idx) => {
    const qSel = card.querySelector('.q-showif-q');
    const oSel = card.querySelector('.q-showif-o');
    if (!qSel || !oSel) return;
    const optWrap = card.querySelector('.q-showif-opt');
    const noneHint = card.querySelector('.q-showif-none');
    const prevQ = qSel.value || card.dataset.sq || '';
    const prevO = oSel.value || card.dataset.so || '';
    qSel.replaceChildren();
    const none = document.createElement('option');
    none.value = '';
    none.textContent = '条件なし（常に表示）';
    qSel.append(none);
    for (let i = 0; i < idx; i++) {
      const other = cards[i];
      const k = other.querySelector('.q-kind').value;
      if (k !== 'single' && k !== 'multiple') continue;
      const opt = document.createElement('option');
      opt.value = other.querySelector('.q-id').value;
      opt.textContent = '設問' + (i + 1) + '「' + (other.querySelector('.q-prompt').value.trim() || '無題') + '」の回答が次のとき';
      qSel.append(opt);
    }
    const eligible = qSel.options.length > 1;
    qSel.value = [...qSel.options].some((o) => o.value === prevQ) ? prevQ : '';
    // No earlier single/multiple question: explain instead of showing
    // dead controls. No target chosen yet: keep the option select hidden
    // rather than rendering an empty box.
    qSel.hidden = !eligible;
    if (noneHint) noneHint.hidden = eligible;
    const hasTarget = eligible && !!qSel.value;
    if (optWrap) optWrap.hidden = !hasTarget;
    oSel.replaceChildren();
    const target = hasTarget ? cards.find((cd) => cd.querySelector('.q-id').value === qSel.value) : null;
    if (target) {
      for (const row of target.querySelectorAll('.option-row')) {
        const opt = document.createElement('option');
        opt.value = row.querySelector('.opt-id').value;
        opt.textContent = row.querySelector('.opt-label').value.trim() || '選択肢';
        oSel.append(opt);
      }
      oSel.value = [...oSel.options].some((o) => o.value === prevO) ? prevO : (oSel.options[0] ? oSel.options[0].value : '');
    }
    oSel.disabled = !target;
  });
}
questionsEl.addEventListener('input', () => refreshShowIf());

function addQuestionCard(data) {
  const card = document.createElement('section');
  card.className = 'card question-card';
  const prompt = document.createElement('input');
  prompt.type = 'text';
  prompt.className = 'q-prompt';
  prompt.maxLength = 300;
  prompt.required = true;
  prompt.placeholder = '設問文';
  prompt.value = (data && data.prompt) || '';
  const kind = document.createElement('select');
  kind.className = 'q-kind';
  for (const [value, label] of KIND_OPTIONS) {
    const opt = document.createElement('option');
    opt.value = value;
    opt.textContent = label;
    if (data && data.kind === value) opt.selected = true;
    kind.append(opt);
  }
  const kindHint = document.createElement('p');
  kindHint.className = 'q-kind-hint muted small';
  const configWrap = document.createElement('div');
  configWrap.className = 'q-config';
  const cfgFields = {};
  for (const [key, label] of [['min', '最小値'], ['max', '最大値'], ['steps', '段階数'], ['step', '刻み'], ['total', '合計点']]) {
    const wrap = document.createElement('label');
    wrap.className = 'cfg-field';
    const input = document.createElement('input');
    input.type = 'number';
    input.className = 'cfg-' + key;
    wrap.append(document.createTextNode(label + ' '), input);
    configWrap.append(wrap);
    cfgFields[key] = { wrap, input };
  }
  if (data && data.config) {
    for (const key of Object.keys(cfgFields)) {
      if (data.config[key] !== undefined && data.config[key] !== null) cfgFields[key].input.value = data.config[key];
    }
  }
  const requiredLabel = document.createElement('label');
  requiredLabel.className = 'check';
  const required = document.createElement('input');
  required.type = 'checkbox';
  required.className = 'q-required';
  required.checked = !data || data.required !== false;
  requiredLabel.append(required, document.createTextNode('必須'));
  const qid = document.createElement('input');
  qid.type = 'hidden';
  qid.className = 'q-id';
  qid.value = (data && data.id) || crypto.randomUUID();
  const showIfWrap = document.createElement('div');
  showIfWrap.className = 'q-showif';
  const showIfLabel = document.createElement('span');
  showIfLabel.className = 'hint';
  showIfLabel.textContent = '表示条件: ';
  const showQ = document.createElement('select');
  showQ.className = 'q-showif-q';
  const showNone = document.createElement('span');
  showNone.className = 'q-showif-none muted small';
  showNone.textContent = '前の単一選択・複数選択の設問があると、その回答を表示条件にできます。';
  const showOptWrap = document.createElement('span');
  showOptWrap.className = 'q-showif-opt';
  const showO = document.createElement('select');
  showO.className = 'q-showif-o';
  showOptWrap.append(document.createTextNode(' のときだけ表示 '), showO);
  showQ.addEventListener('change', refreshShowIf);
  if (data && data.show_if) {
    card.dataset.sq = data.show_if.question_id;
    card.dataset.so = data.show_if.option_id;
  }
  showIfWrap.append(showIfLabel, showQ, showNone, showOptWrap);
  const options = document.createElement('div');
  options.className = 'q-options';
  const addOpt = document.createElement('button');
  addOpt.type = 'button';
  addOpt.className = 'btn small';
  addOpt.textContent = '選択肢を追加';
  addOpt.addEventListener('click', () => { addOptionRow(options, '', null, ''); refreshShowIf(); });
  /* Bulk paste: newline-separated labels, added to or replacing the rows.
     Blank lines are ignored; the 50-option server limit is enforced here. */
  const bulk = document.createElement('div');
  bulk.className = 'q-bulk';
  const bulkLabel = document.createElement('label');
  bulkLabel.className = 'small';
  bulkLabel.textContent = '選択肢をまとめて入力（1行に1つ）';
  const bulkText = document.createElement('textarea');
  bulkText.className = 'q-bulk-text';
  bulkText.rows = 4;
  bulkText.placeholder = '例：\nりんご\nみかん\nぶどう';
  bulkLabel.append(bulkText);
  const bulkActions = document.createElement('div');
  bulkActions.className = 'actions';
  const bulkAdd = document.createElement('button');
  bulkAdd.type = 'button';
  bulkAdd.className = 'btn small';
  bulkAdd.textContent = '貼り付けから追加';
  const bulkReplace = document.createElement('button');
  bulkReplace.type = 'button';
  bulkReplace.className = 'btn small';
  bulkReplace.textContent = '貼り付けで置き換え';
  function applyBulk(replace) {
    clearFieldError(bulkText);
    const lines = bulkText.value.split(/\r?\n/).map((s) => s.trim()).filter((s) => s.length > 0);
    if (lines.length === 0) {
      showFieldError(bulkText, '選択肢が入力されていません。1行に1つ入力してください。');
      bulkText.focus();
      return;
    }
    const rows = [...options.querySelectorAll('.option-row')];
    if (replace) {
      for (const row of rows) row.remove();
    } else {
      // Drop untouched empty rows first so pasted labels do not sit
      // behind blanks that would fail validation at save time.
      for (const row of rows) {
        const label = row.querySelector('.opt-label').value.trim();
        const key = row.querySelector('.opt-key').value;
        if (!label && !key) row.remove();
      }
    }
    const room = 50 - options.querySelectorAll('.option-row').length;
    if (room <= 0) {
      showFieldError(bulkText, '選択肢は最大50件までです。');
      return;
    }
    const take = lines.slice(0, room);
    for (const line of take) addOptionRow(options, line.slice(0, 200), null, '');
    bulkText.value = '';
    if (lines.length > take.length) {
      showFieldError(bulkText, '選択肢は最大50件までのため、' + (lines.length - take.length) + '件は追加できませんでした。');
    }
    refreshShowIf();
  }
  bulkAdd.addEventListener('click', () => applyBulk(false));
  bulkReplace.addEventListener('click', () => applyBulk(true));
  bulkActions.append(bulkAdd, bulkReplace);
  bulk.append(bulkLabel, bulkActions);
  const CONFIG_FIELDS = {
    number: ['min', 'max'],
    scale: ['steps'],
    slider: ['min', 'max', 'step'],
    allocation: ['total'],
  };
  const syncKind = () => {
    const noOptions = !OPTION_KINDS.includes(kind.value);
    options.hidden = noOptions;
    addOpt.hidden = noOptions;
    bulk.hidden = noOptions;
    kindHint.textContent = KIND_HINTS[kind.value] || '';
    const fields = CONFIG_FIELDS[kind.value] || [];
    configWrap.hidden = fields.length === 0;
    for (const key of Object.keys(cfgFields)) cfgFields[key].wrap.hidden = !fields.includes(key);
  };
  kind.addEventListener('change', () => { syncKind(); refreshShowIf(); });
  const up = document.createElement('button');
  up.type = 'button';
  up.className = 'btn small';
  up.textContent = '上へ';
  up.addEventListener('click', () => { if (card.previousElementSibling) questionsEl.insertBefore(card, card.previousElementSibling); refreshShowIf(); });
  const down = document.createElement('button');
  down.type = 'button';
  down.className = 'btn small';
  down.textContent = '下へ';
  down.addEventListener('click', () => { if (card.nextElementSibling) questionsEl.insertBefore(card.nextElementSibling, card); refreshShowIf(); });
  const del = document.createElement('button');
  del.type = 'button';
  del.className = 'btn small danger';
  del.textContent = '設問を削除';
  del.addEventListener('click', () => { card.remove(); refreshShowIf(); });
  const actions = document.createElement('div');
  actions.className = 'actions';
  actions.append(up, down, del);
  card.append(prompt, kind, kindHint, configWrap, requiredLabel, qid, showIfWrap, options, addOpt, bulk, actions);
  questionsEl.append(card);
  const seedOptions = (data && data.options) || [];
  if (seedOptions.length === 0 && (!data || OPTION_KINDS.includes(data.kind))) {
    addOptionRow(options, '', null, '');
    addOptionRow(options, '', null, '');
  }
  for (const o of seedOptions) addOptionRow(options, o.label, o.image_key, o.id);
  syncKind();
  refreshShowIf();
}
document.getElementById('add-question').addEventListener('click', () => addQuestionCard(null));

async function uploadImage(file) {
  const res = await fetch('/api/v1/tenants/' + TENANT + '/images', {
    method: 'POST',
    headers: { 'content-type': file.type },
    body: file,
    credentials: 'same-origin',
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((data.error && data.error.message) || '画像のアップロードに失敗しました');
  return data.key;
}

async function uploadFrom(row, fileInputSelector, keySelector) {
  const input = row.querySelector(fileInputSelector);
  if (input && input.files && input.files[0]) {
    const key = await uploadImage(input.files[0]);
    row.querySelector(keySelector).value = key;
  }
}

/* Validate the whole form, placing a message next to each problem field.
 * Returns the question payload when valid, or null after showing errors. */
function validateForm() {
  clearAllErrors();
  const problems = [];
  const titleEl = document.getElementById('question');
  if (!titleEl.value.trim()) problems.push([titleEl, '設問文を入力してください']);
  const opensEl = document.getElementById('opens-at');
  const closesEl = document.getElementById('closes-at');
  if (opensEl.value && closesEl.value && new Date(opensEl.value) >= new Date(closesEl.value)) {
    problems.push([closesEl, '締切日時は開始日時より後にしてください']);
  }
  const passphraseEl = document.getElementById('passphrase');
  const passphraseValue = passphraseEl ? passphraseEl.value : '';
  const clearPassphraseEl = document.getElementById('clear-passphrase');
  if (passphraseValue && passphraseValue.trim().length < 4) {
    problems.push([passphraseEl, '合言葉は4〜128文字にしてください']);
  }
  if (passphraseValue && clearPassphraseEl && clearPassphraseEl.checked) {
    problems.push([passphraseEl, '合言葉の解除と新しい合言葉の入力は同時にはできません']);
  }
  const questionCards = [...questionsEl.querySelectorAll('.question-card')];
  if (questionCards.length < 1) problems.push([questionsEl, '設問は1つ以上必要です']);
  if (questionCards.length > 20) problems.push([questionsEl, '設問は20個までです']);
  const questions = [];
  questionCards.forEach((card, cardIndex) => {
    const kind = card.querySelector('.q-kind').value;
    const promptEl = card.querySelector('.q-prompt');
    const prompt = promptEl.value.trim();
    if (!prompt) problems.push([promptEl, '設問文を入力してください']);
    const options = [];
    if (OPTION_KINDS.includes(kind)) {
      const optionsEl = card.querySelector('.q-options');
      const rows = [...card.querySelectorAll('.option-row')];
      if (rows.length < 2) problems.push([optionsEl, '選択式の設問には選択肢が2つ以上必要です']);
      for (const row of rows) {
        const labelEl = row.querySelector('.opt-label');
        const label = labelEl.value.trim();
        if (!label) problems.push([labelEl, '選択肢の文言を入力してください']);
        options.push({
          id: row.querySelector('.opt-id').value || undefined,
          label,
          image_key: row.querySelector('.opt-key').value || null,
          _row: row,
        });
      }
    }
    const cfgNum = (key) => {
      const el = card.querySelector('.cfg-' + key);
      const v = el.value.trim();
      return { el, value: v === '' ? null : Number(v) };
    };
    let config = null;
    if (kind === 'number') {
      const mn = cfgNum('min');
      const mx = cfgNum('max');
      for (const f of [mn, mx]) if (f.value !== null && !Number.isFinite(f.value)) problems.push([f.el, '数値を入力してください']);
      if (mn.value !== null && mx.value !== null && mn.value > mx.value) problems.push([mx.el, '最大値は最小値以上にしてください']);
      config = {};
      if (mn.value !== null) config.min = mn.value;
      if (mx.value !== null) config.max = mx.value;
      if (Object.keys(config).length === 0) config = null;
    } else if (kind === 'scale') {
      const st = cfgNum('steps');
      const steps = st.value === null ? 5 : st.value;
      if (!Number.isInteger(steps) || steps < 2 || steps > 10) problems.push([st.el, '段階数は2〜10の整数にしてください']);
      config = { steps };
    } else if (kind === 'slider') {
      const mn = cfgNum('min');
      const mx = cfgNum('max');
      const st = cfgNum('step');
      const min = mn.value === null ? 0 : mn.value;
      const max = mx.value === null ? 100 : mx.value;
      const step = st.value === null ? 1 : st.value;
      if (min >= max) problems.push([mx.el, '最大値は最小値より大きくしてください']);
      if (!(step > 0)) problems.push([st.el, '刻みは0より大きくしてください']);
      config = { min, max, step };
    } else if (kind === 'allocation') {
      const tt = cfgNum('total');
      const total = tt.value === null ? 100 : tt.value;
      if (!Number.isInteger(total) || total < 1) problems.push([tt.el, '合計点は1以上の整数にしてください']);
      config = { total };
    }
    const showQ = card.querySelector('.q-showif-q').value;
    const showO = card.querySelector('.q-showif-o').value;
    if (showQ && !showO) {
      problems.push([card.querySelector('.q-showif'), '表示条件の選択肢を選んでください']);
    }
    questions.push({
      id: card.querySelector('.q-id').value || undefined,
      prompt,
      kind,
      required: card.querySelector('.q-required').checked,
      options,
      config,
      show_if: showQ ? { question_id: showQ, option_id: showO } : null,
      _card: card,
      _index: cardIndex,
    });
  });
  if (problems.length > 0) {
    for (const [field, message] of problems) {
      if (field.classList && (field.classList.contains('q-options') || field.classList.contains('q-showif') || field === questionsEl)) {
        showBoxError(field, message);
      } else {
        showFieldError(field, message);
      }
    }
    errorEl.textContent = '入力内容に ' + problems.length + ' 件の問題があります。各欄の表示を確認してください。';
    errorEl.style.display = 'block';
    const firstAnchor = problems[0][0];
    firstAnchor.scrollIntoView({ block: 'center', behavior: 'smooth' });
    const focusTarget = firstAnchor.querySelector && firstAnchor.querySelector('input, select, textarea')
      ? firstAnchor.querySelector('input, select, textarea') : firstAnchor;
    if (focusTarget && focusTarget.focus) setTimeout(() => focusTarget.focus({ preventScroll: true }), 250);
    return null;
  }
  return questions;
}

/* Map an API validation message onto the field it belongs to. */
function showServerError(message, details) {
  if ((details && details.field === 'passphrase') || (message || '').includes('passphrase')) {
    const passEl = document.getElementById('passphrase');
    if (passEl) {
      showFieldError(passEl, '合言葉を確認してください（4〜128文字）。');
      passEl.scrollIntoView({ block: 'center', behavior: 'smooth' });
      return;
    }
  }
  const cards = [...questionsEl.querySelectorAll('.question-card')];
  let idx = -1;
  const m = /questions\[(\d+)\]/.exec(message || '');
  if (m) idx = Number(m[1]);
  if (details && typeof details.question_index === 'number') idx = details.question_index;
  if ((message || '').includes('"opens_at" must be earlier') || (details && details.field === 'closes_at')) {
    showFieldError(document.getElementById('closes-at'), '締切日時は開始日時より後にしてください');
    document.getElementById('closes-at').scrollIntoView({ block: 'center', behavior: 'smooth' });
    return;
  }
  if (idx >= 0 && cards[idx]) {
    const card = cards[idx];
    let anchor;
    if ((message || '').includes('show_if')) {
      anchor = showBoxError(card.querySelector('.q-showif'), '表示条件を確認してください。対象は前の単一・複数選択の設問と、その選択肢です。');
    } else if ((message || '').includes('config')) {
      anchor = showBoxError(card.querySelector('.q-config'), '形式の設定（範囲・段階数・合計点など）を確認してください。');
    } else if ((message || '').includes('option')) {
      anchor = showBoxError(card.querySelector('.q-options'), '選択肢を確認してください。2〜50個、各200文字までです。');
    } else {
      anchor = showFieldError(card.querySelector('.q-prompt'), 'この設問の内容を確認してください。');
    }
    card.scrollIntoView({ block: 'center', behavior: 'smooth' });
    errorEl.textContent = '設問 ' + (idx + 1) + ' に問題があります: ' + message;
    errorEl.style.display = 'block';
    return;
  }
  errorEl.textContent = message || '保存に失敗しました';
  errorEl.style.display = 'block';
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

async function submitPoll(ev) {
  ev.preventDefault();
  const questions = validateForm();
  if (!questions) return;
  try {
    await uploadFrom(document.getElementById('poll-image-row'), '#poll-image-file', '#poll-image-key');
    for (const q of questions) {
      for (const o of q.options) {
        if (o._row) await uploadFrom(o._row, '.opt-file', '.opt-key');
        o.image_key = o._row ? (o._row.querySelector('.opt-key').value || null) : o.image_key;
        delete o._row;
      }
      delete q._card;
      delete q._index;
    }
    const payload = {
      question: document.getElementById('question').value.trim(),
      description: document.getElementById('description').value,
      image_key: document.getElementById('poll-image-key').value || null,
      require_login: document.getElementById('require-login').checked,
      results_visibility: document.getElementById('results-visibility').value,
      ip_single_vote: document.getElementById('ip-single-vote').checked,
      confirm_required: document.getElementById('confirm-required').checked,
      opens_at: document.getElementById('opens-at').value ? new Date(document.getElementById('opens-at').value).toISOString() : null,
      closes_at: document.getElementById('closes-at').value ? new Date(document.getElementById('closes-at').value).toISOString() : null,
      questions,
    };
    const passphraseValue = document.getElementById('passphrase').value;
    if (passphraseValue) payload.passphrase = passphraseValue;
    const clearPassphraseEl = document.getElementById('clear-passphrase');
    if (clearPassphraseEl && clearPassphraseEl.checked) payload.clear_passphrase = true;
    const url = POLL_ID
      ? '/api/v1/tenants/' + TENANT + '/polls/' + POLL_ID
      : '/api/v1/tenants/' + TENANT + '/polls';
    const res = await fetch(url, {
      method: POLL_ID ? 'PATCH' : 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
      credentials: 'same-origin',
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      showServerError((data.error && data.error.message) || '保存に失敗しました', data.error && data.error.details);
      return;
    }
    location.href = '/admin/workspaces/' + TENANT + '/polls/' + data.poll.id;
  } catch (e) {
    errorEl.textContent = e.message || String(e);
    errorEl.style.display = 'block';
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
}
document.getElementById('poll-form').addEventListener('submit', submitPoll);
// Clear a field's error as soon as the user starts fixing it.
document.getElementById('poll-form').addEventListener('input', (ev) => {
  const t = ev.target;
  clearFieldError(t);
  const box = t.closest && (t.closest('.q-options') || t.closest('.q-showif'));
  if (box) clearFieldError(box);
});
const seedEl = document.getElementById('poll-seed');
let pending = [];
try { pending = JSON.parse(seedEl && seedEl.textContent ? seedEl.textContent : '[]'); } catch (e) { pending = []; }
if (!Array.isArray(pending) || pending.length === 0) addQuestionCard(null);
else for (const q of pending) addQuestionCard(q);
for (const id of ['opens-at', 'closes-at']) {
  const el = document.getElementById(id);
  if (el && el.value) {
    const d = new Date(el.value + 'Z');
    if (!isNaN(d.getTime())) {
      const pad = (n) => String(n).padStart(2, '0');
      el.value = d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes());
    }
  }
}
})();
`;
  return scriptTag(nonce, code);
}

function pollFormBody(opts: {
  tenantId: string;
  poll: PollRow | null;
  questions: {
    id: string;
    prompt: string;
    kind: string;
    required: boolean;
    show_if: { question_id: string; option_id: string } | null;
    options: { id: string; label: string; image_key: string | null }[];
  }[];
  nonce: string;
}): string {
  const p = opts.poll;
  const closesLocal = p?.closes_at ? escapeHtml(p.closes_at.slice(0, 16)) : "";
  const seed = safeJsonForScript(opts.questions);
  return `
    <p class="muted small"><a href="/admin/workspaces/${opts.tenantId}">ワークスペースに戻る</a></p>
    <h1>${p ? "投票を編集" : "新しい投票を作る"}</h1>
    <div class="error" id="form-error" role="alert"></div>
    <section class="section">
    <form id="poll-form">
      <label for="question">設問文</label>
      <input id="question" type="text" required maxlength="300" value="${p ? escapeHtml(p.question) : ""}" placeholder="例: 次のイベントの日程はどれがいいですか？">
      <label for="description">説明 <span class="hint">任意。投票する人への補足を書けます。</span></label>
      <textarea id="description" maxlength="5000">${p ? escapeHtml(p.description) : ""}</textarea>
      <div id="poll-image-row">
        <label for="poll-image-file">設問の画像 <span class="hint">任意。PNG / JPEG / WebP / GIF、5 MiB まで。</span></label>
        ${p?.image_key ? `<p><img src="/images/${escapeHtml(p.image_key)}" alt="設問の画像" style="max-width:240px;border:1px solid var(--border)"></p>` : ""}
        <input id="poll-image-file" type="file" accept="image/png,image/jpeg,image/webp,image/gif">
        <input type="hidden" id="poll-image-key" value="${escapeHtml(p?.image_key ?? "")}">
      </div>
      <label for="opens-at">開始日時 <span class="hint">任意。空欄なら公開後すぐに投票できます。</span></label>
      <input id="opens-at" type="datetime-local" value="${p?.opens_at ? escapeHtml(p.opens_at.slice(0, 16)) : ""}">
      <label for="closes-at">締切日時 <span class="hint">任意。空欄なら手動で締め切るまで投票できます。</span></label>
      <input id="closes-at" type="datetime-local" value="${closesLocal}">
      <div class="check">
        <input id="require-login" type="checkbox" ${p?.require_login === 1 ? "checked" : ""}>
        <label for="require-login" style="margin:0"><span>ログイン必須にする</span>
        <small>オンにするとログインした人だけが投票できます。オフ（既定）なら誰でも投票できます。</small></label>
      </div>
      <label for="results-visibility">結果の公開範囲</label>
      <select id="results-visibility">
        <option value="public" ${!p || p.results_visibility === "public" ? "selected" : ""}>いつでも公開</option>
        <option value="after_close" ${p?.results_visibility === "after_close" ? "selected" : ""}>締切後に公開</option>
        <option value="admin_only" ${p?.results_visibility === "admin_only" ? "selected" : ""}>公開しない（管理者のみ）</option>
      </select>
      <div class="check">
        <input id="ip-single-vote" type="checkbox" ${p?.ip_single_vote === 1 ? "checked" : ""}>
        <label for="ip-single-vote" style="margin:0"><span>同じ接続元からは1票だけにする</span>
        <small>オンにすると、匿名票はブラウザではなく接続元（IP）で1票に制限されます。同じネットワークの別人はまとめられる点に注意してください。</small></label>
      </div>
      <div class="check">
        <input id="confirm-required" type="checkbox" ${p?.confirm_required === 1 ? "checked" : ""}>
        <label for="confirm-required" style="margin:0"><span>投票前に確認ステップを必須にする</span>
        <small>オンにすると、API は confirm: true が付いた投票だけを受け付けます。誤送信やボットの単純な連投を抑えるための確認です。</small></label>
      </div>
      <label for="passphrase">合言葉 <span class="hint">${p?.passphrase_hash ? "設定済みです。入力すると新しい合言葉に置き換わります。空欄のままなら変更しません。" : "任意。設定すると、投票時に合言葉の入力が必要になります。合言葉はハッシュ化して保存され、画面には表示されません。"}</span></label>
      <input id="passphrase" type="password" autocomplete="new-password" maxlength="128" placeholder="4〜128文字">
      ${p?.passphrase_hash ? `<div class="check">
        <input id="clear-passphrase" type="checkbox">
        <label for="clear-passphrase" style="margin:0"><span>合言葉を解除する</span>
        <small>チェックすると、この投票は合言葉なしで投票できるようになります。</small></label>
      </div>` : ""}
      <h2>設問</h2>
      <p class="muted small">形式は単一選択、複数選択、自由記述（長文／短いテキスト）、順位付け、点数付け、数値入力、日付、段階評価、スライダー、配点です。単一・複数選択の回答を条件に、後ろの設問を表示する分岐も付けられます。並び順は上から下です。最大 20 問。</p>
      <div id="questions"></div>
      <div class="actions"><button type="button" class="btn" id="add-question">設問を追加</button></div>
      <div class="actions"><button class="btn primary" type="submit">${p ? "変更を保存" : "下書きとして作成"}</button></div>
    </form>
    </section>
    <script type="application/json" id="poll-seed">${seed}</script>
    ${pollFormScript(opts.tenantId, p?.id ?? null, opts.nonce)}`;
}

ui.get("/admin/workspaces/:tenantId/polls/new", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  return c.html(
    layout({
      title: "新しい投票を作る",
      userEmail: user.email ?? user.name ?? user.accountId,
      body: pollFormBody({ tenantId, poll: null, questions: [], nonce: c.get("cspNonce") ?? "" }),
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }),
  );
});

ui.get("/admin/workspaces/:tenantId/polls/:pollId", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const pollId = normalizeUuid(c.req.param("pollId"));
  if (!pollId) return c.redirect(`/admin/workspaces/${tenantId}`, 302);
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  const poll = await getPollRow(c.env, pollId);
  if (!poll || poll.tenant_id !== tenantId) return c.redirect(`/admin/workspaces/${tenantId}`, 302);
  const options = await listOptionRows(c.env, pollId);
  const questionRows = await listQuestionRows(c.env, pollId);
  const questionSeed = questionRows.map((q) => ({
    id: q.id,
    prompt: q.prompt,
    kind: q.kind,
    config: q.config ? questionConfig(q) : null,
    required: q.required === 1,
    show_if:
      q.show_if_question_id && q.show_if_option_id
        ? { question_id: q.show_if_question_id, option_id: q.show_if_option_id }
        : null,
    options: options.filter((o) => o.question_id === q.id).map((o) => ({
      id: o.id,
      label: o.label,
      image_key: o.image_key,
    })),
  }));
  const origin = originOf(c);
  const nonce = c.get("cspNonce") ?? "";
  const stepDefs = [
    { key: "draft", label: "下書き" },
    { key: "published", label: "公開中" },
    { key: "closed", label: "締切" },
  ] as const;
  const stepOrder = { draft: 0, published: 1, closed: 2 } as const;
  const currentStep = stepOrder[poll.status];
  const stepsHtml = stepDefs
    .map((s, i) => {
      const cls = i < currentStep ? "step done" : i === currentStep ? "step current" : "step";
      const dot = i === currentStep && poll.status === "published" ? '<span class="dot" aria-hidden="true"></span>' : "";
      return `<span class="${cls}">${dot}${s.label}</span>`;
    })
    .join('<span class="arrow" aria-hidden="true">→</span>');
  const statusActions =
    poll.status === "draft"
      ? `<button class="btn primary" type="button" data-ask-status="published">公開する</button>`
      : poll.status === "published"
        ? `<button class="btn danger" type="button" data-ask-status="closed">締め切る</button>`
        : `<span class="muted">締切済みのため、状態は変更できません。</span>`;
  const body = `
    <p class="muted small"><a href="/admin/workspaces/${tenantId}">ワークスペースに戻る</a></p>
    <div class="poll-head">
      <div style="flex:1;min-width:260px">
        <h1 style="margin-top:0">${escapeHtml(poll.question)}</h1>
        <p>${statusBadge(poll.status)} <span class="muted small">投票 ID: <code>${poll.id}</code></span></p>
        <div class="steps" role="img" aria-label="状態の流れ: 下書き、公開中、締切。現在は${poll.status === "draft" ? "下書き" : poll.status === "published" ? "公開中" : "締切"}です">${stepsHtml}</div>
        <div class="actions">${statusActions}
          <a class="btn" href="/admin/workspaces/${tenantId}/polls/${poll.id}/results">結果を見る</a>
        </div>
      </div>
      ${poll.image_key ? `<img src="/images/${escapeHtml(poll.image_key)}" alt="設問の画像">` : ""}
    </div>
    <h2>公開 API</h2>
    <section class="section">
      <p class="small">投票の取得: <code>GET ${escapeHtml(origin)}/api/v1/polls/${escapeHtml(poll.id)}</code><br>
      投票の実行: <code>POST ${escapeHtml(origin)}/api/v1/polls/${escapeHtml(poll.id)}/vote</code><br>
      結果の取得: <code>GET ${escapeHtml(origin)}/api/v1/polls/${escapeHtml(poll.id)}/results</code><br>
      自分の票の確認: <code>GET ${escapeHtml(origin)}/api/v1/polls/${escapeHtml(poll.id)}/ballot?voter_token=...</code></p>
    </section>
    ${poll.status === "draft" ? "" : `<h2>共有</h2>
    <section class="section">
      <p class="small">結果ページ: <a href="/polls/${escapeHtml(poll.id)}/results-page">${escapeHtml(origin)}/polls/${escapeHtml(poll.id)}/results-page</a></p>
      <div class="poll-head">
        <img src="/api/v1/polls/${escapeHtml(poll.id)}/qr.svg" alt="結果ページへの QR コード" width="180" height="180">
        <div>
          <p class="muted small">QR コードは結果ページへのリンクです。共有用画像はワークスペースのブランド色で生成されます。</p>
          <p><a class="btn" href="/api/v1/polls/${escapeHtml(poll.id)}/og.svg">共有用画像（SVG）を開く</a></p>
        </div>
      </div>
    </section>`}
    <section class="section">
      <p class="small">埋め込みや API の使い方は <a href="/docs">API 仕様書</a> にまとまっています。</p>
      ${poll.status === "draft" ? "" : `<h3>埋め込み用スニペット</h3>
      <p class="muted small">別サイトから呼ぶときは、そのオリジンを設定画面の許可リストに追加してください。開始前は POLL_NOT_OPEN、締切後は POLL_CLOSED が返ります。</p>
      <div class="copyable">
        <span class="copy">
          <button type="button" class="btn small copy-button" command="--copy" commandfor="embed-snippet">スニペットをコピー</button>
          <span class="tip" role="status"></span>
        </span>
        <pre id="embed-snippet" tabindex="0">${escapeHtml(`const pollId = "${poll.id}";
const base = "${origin}";
const poll = await fetch(base + "/api/v1/polls/" + pollId).then((r) => r.json());
const answers = poll.poll.questions.map((q) => {
  if (q.kind === "text" || q.kind === "short_text" || q.kind === "date") return { question_id: q.id, text: "" };
  if (q.kind === "score" || q.kind === "allocation") return { question_id: q.id, scores: Object.fromEntries(q.options.map((o) => [o.id, 0])) };
  if (q.kind === "number" || q.kind === "scale" || q.kind === "slider") return { question_id: q.id, value: 0 };
  return { question_id: q.id, option_ids: [q.options[0].id] };
});
await fetch(base + "/api/v1/polls/" + pollId + "/vote", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    voter_token: "stable-id-for-this-voter",
    ...(poll.poll.confirm_required ? { confirm: true } : {}),
    ...(poll.poll.passphrase_required ? { passphrase: "設定した合言葉" } : {}),
    answers,
  }),
});`)}</pre>
      </div>
      ${scriptTag(nonce, `
        (() => {
        function copyText(button, target) {
          const text = target && target.innerText ? target.innerText.trim() : "";
          if (!text) return;
          const tip = button.nextElementSibling;
          const finish = (ok) => {
            button.removeAttribute("data-copied");
            button.removeAttribute("data-failed");
            button.setAttribute(ok ? "data-copied" : "data-failed", "");
            if (tip) tip.textContent = ok ? "コピーしました" : "コピーできませんでした";
          };
          const write = navigator.clipboard && navigator.clipboard.writeText
            ? navigator.clipboard.writeText(text)
            : Promise.reject();
          write.then(() => finish(true)).catch(() => finish(false));
        }
        if ("CommandEvent" in window) {
          document.addEventListener("command", (event) => {
            if (event.command === "--copy") copyText(event.source, event.target);
          }, true);
        } else {
          document.addEventListener("click", (event) => {
            const button = event.target.closest && event.target.closest('button[command="--copy"]');
            if (!button) return;
            const target = document.getElementById(button.getAttribute("commandfor"));
            if (target) copyText(button, target);
          });
        }
        })();
      `)}`}
    </section>
    <div id="flash" class="notice bad" role="alert" hidden></div>
    <dialog id="status-dialog" aria-labelledby="status-dialog-title">
      <h2 id="status-dialog-title">状態を変更しますか？</h2>
      <p id="status-dialog-text" class="muted"></p>
      <div class="dialog-actions">
        <button class="btn" type="button" id="status-cancel" autofocus>やめる</button>
        <button class="btn primary" type="button" id="status-confirm">変更する</button>
      </div>
    </dialog>
    ${scriptTag(nonce, `
      (() => {
      const TENANT = ${safeJsonForScript(tenantId)};
      const POLL = ${safeJsonForScript(poll.id)};
      let pendingStatus = null;
      for (const button of document.querySelectorAll("[data-ask-status]")) {
        button.addEventListener("click", () => {
          pendingStatus = button.getAttribute("data-ask-status");
          const text = document.getElementById("status-dialog-text");
          const title = document.getElementById("status-dialog-title");
          text.textContent = pendingStatus === "published"
            ? "この投票を公開します。公開後は API から投票できるようになります。"
            : "この投票を締め切ります。締切後は投票できなくなります。";
          title.textContent = (pendingStatus === "published" ? "公開" : "締め切る") + "しますか？";
          document.getElementById("status-dialog").showModal();
        });
      }
      document.getElementById("status-cancel").addEventListener("click", () => {
        document.getElementById("status-dialog").close();
      });
      document.getElementById("status-confirm").addEventListener("click", async () => {
        document.getElementById("status-dialog").close();
        const res = await fetch("/api/v1/tenants/" + TENANT + "/polls/" + POLL + "/status", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ status: pendingStatus }),
          credentials: "same-origin",
        });
        if (res.ok) { location.reload(); return; }
        const d = await res.json().catch(() => ({}));
        const flash = document.getElementById("flash");
        flash.textContent = (d.error && d.error.message) || "状態の変更に失敗しました";
        flash.hidden = false;
      });
      })();
    `)}
    ${poll.status !== "closed" ? pollFormBody({ tenantId, poll, questions: questionSeed, nonce }) : `<h2>内容</h2><section class="section">${questionSeed.map((q) => `<h3>${escapeHtml(q.prompt)}</h3><p class="muted small">${questionKindLabel(q.kind)}</p><ul>${q.options.map((o) => `<li>${escapeHtml(o.label)}</li>`).join("")}</ul>`).join("")}</section>`}`;
  return c.html(
    layout({
      title: poll.question,
      userEmail: user.email ?? user.name ?? user.accountId,
      body,
      origin,
      nonce: c.get("cspNonce") ?? "",
    }),
  );
});

/* ------------------------------------------------------------------ */
/* Results page                                                        */
/* ------------------------------------------------------------------ */

const SEGMENT_COLORS = ["#1e4fd8", "#e07b00", "#0c6b34", "#b91c1c", "#6d28d9", "#0e7490"];

function questionKindLabel(kind: string): string {
  switch (kind) {
    case "text": return "自由記述";
    case "short_text": return "短いテキスト";
    case "multiple": return "複数選択";
    case "ranking": return "順位付け";
    case "score": return "点数付け";
    case "number": return "数値入力";
    case "date": return "日付";
    case "scale": return "段階評価";
    case "slider": return "スライダー";
    case "allocation": return "配点";
    default: return "単一選択";
  }
}

function resultsSections(results: PollResults, poll: PollRow): string {
  const colorOf = (i: number) => SEGMENT_COLORS[i % SEGMENT_COLORS.length] as string;
  const kindLabel = questionKindLabel;
  return (results.questions.length > 0 ? results.questions : [{
    id: poll.id,
    prompt: poll.question,
    kind: "single" as const,
    required: true,
    position: 0,
    response_count: results.total_voters,
    config: null,
    options: results.options,
    texts: [] as string[],
  }]).map((q) => {
    const denom = q.options.reduce((sum, o) => sum + o.votes, 0);
    const totalPoints = q.options.reduce((sum, o) => sum + (o.points ?? 0), 0);
    const maxVotes = Math.max(1, ...q.options.map((o) => o.votes));
    const maxPoints = Math.max(1, ...q.options.map((o) => o.points ?? 0));
    const bars = q.options.map((o, i) => {
      if (q.kind === "ranking") {
        const pct = totalPoints > 0 ? Math.round(((o.points ?? 0) / totalPoints) * 1000) / 10 : 0;
        const width = Math.round(((o.points ?? 0) / maxPoints) * 1000) / 10;
        return `<div class="bar-row" data-qid="${escapeHtml(q.id)}" data-oid="${escapeHtml(o.id)}">
        <div>${escapeHtml(o.label)}</div>
        <div class="bar-track" role="img" aria-label="${escapeHtml(o.label)}: ${o.points ?? 0}ポイント (${pct}%)"><div class="bar-fill" style="width:${width}%;--d:${(i * 0.08).toFixed(2)}s"></div></div>
        <div><strong data-points>${o.points ?? 0}</strong> ポイント <span class="muted">(1位 <span data-first>${o.votes}</span> 回 ／ 平均 <span data-avg>${o.average_rank ?? "-"}</span> 位)</span></div>
      </div>`;
      }
      if (q.kind === "score") {
        const avg = o.average_score ?? 0;
        const width = Math.round((avg / 5) * 1000) / 10;
        return `<div class="bar-row" data-qid="${escapeHtml(q.id)}" data-oid="${escapeHtml(o.id)}">
        <div>${escapeHtml(o.label)}</div>
        <div class="bar-track" role="img" aria-label="${escapeHtml(o.label)}: 平均 ${o.average_score ?? "-"} 点（5点満点）"><div class="bar-fill" style="width:${width}%;--d:${(i * 0.08).toFixed(2)}s"></div></div>
        <div><strong data-avg>${o.average_score ?? "-"}</strong> / 5 <span class="muted">(<span data-evals>${o.votes}</span> 件の評価)</span></div>
      </div>`;
      }
      if (q.kind === "allocation") {
        const totalAlloc = q.config?.total ?? 100;
        const avgP = o.average_points ?? 0;
        const width = Math.round((avgP / totalAlloc) * 1000) / 10;
        return `<div class="bar-row" data-qid="${escapeHtml(q.id)}" data-oid="${escapeHtml(o.id)}">
        <div>${escapeHtml(o.label)}</div>
        <div class="bar-track" role="img" aria-label="${escapeHtml(o.label)}: 平均 ${o.average_points ?? "-"} 点（合計 ${totalAlloc} 点の配点）"><div class="bar-fill" style="width:${width}%;--d:${(i * 0.08).toFixed(2)}s"></div></div>
        <div>平均 <strong data-avgpoints>${o.average_points ?? "-"}</strong> 点 <span class="muted">(合計 <span data-points>${o.points ?? 0}</span> 点 ／ <span data-evals>${o.votes}</span> 件)</span></div>
      </div>`;
      }
      const pct = denom > 0 ? Math.round((o.votes / denom) * 1000) / 10 : 0;
      const width = Math.round((o.votes / maxVotes) * 1000) / 10;
      return `<div class="bar-row" data-qid="${escapeHtml(q.id)}" data-oid="${escapeHtml(o.id)}">
        <div>${escapeHtml(o.label)}</div>
        <div class="bar-track" role="img" aria-label="${escapeHtml(o.label)}: ${o.votes}票 (${pct}%)"><div class="bar-fill" style="width:${width}%;--d:${(i * 0.08).toFixed(2)}s"></div></div>
        <div><strong data-votes>${o.votes}</strong> 票 <span class="muted">(<span data-pct>${pct}</span>%)</span></div>
      </div>`;
    }).join("");
    const stackSegments = q.options.map((o, i) => {
      const pct = denom > 0 ? (o.votes / denom) * 100 : 0;
      return `<div class="stack-seg" data-oid="${escapeHtml(o.id)}" style="width:${pct}%;background:${colorOf(i)};--d:${(i * 0.08).toFixed(2)}s"></div>`;
    }).join("");
    const legend = q.options.map((o, i) => `<span><span class="sw" style="background:${colorOf(i)}"></span>${escapeHtml(o.label)}</span>`).join("");
    const texts = (q.texts ?? []).map((t) => `<li>${escapeHtml(t)}</li>`).join("");
    const isTextKind = q.kind === "text" || q.kind === "short_text" || q.kind === "date";
    const isValueKind = q.kind === "number" || q.kind === "slider";
    const numericBlock = q.numeric
      ? `<p class="small">平均 <strong data-num-avg="${escapeHtml(q.id)}">${q.numeric.average ?? "-"}</strong> ／ 最小 <span data-num-min="${escapeHtml(q.id)}">${q.numeric.min ?? "-"}</span> ／ 最大 <span data-num-max="${escapeHtml(q.id)}">${q.numeric.max ?? "-"}</span></p>`
      : "";
    return `<h2>${escapeHtml(q.prompt)}</h2>
      <p class="muted small">${kindLabel(q.kind)} ／ 回答 <span data-resp="${escapeHtml(q.id)}">${q.response_count}</span></p>
      ${isTextKind ? `<ul>${texts || '<li class="muted">まだ回答がありません。</li>'}</ul>` : isValueKind ? numericBlock : `${bars}${q.kind === "scale" ? numericBlock : ""}${denom > 0 && q.kind !== "allocation" ? `<div class="stack" data-stack="${escapeHtml(q.id)}" role="img" aria-label="得票割合の積み上げグラフ">${stackSegments}</div><div class="legend">${legend}</div>` : ""}`}`;
  }).join("");
}



ui.get("/docs", async (c) => {
  const nonce = c.get("cspNonce") ?? "";
  // Standalone page (not the shared layout): Redoc needs the full viewport
  // width. The spec lives in public/openapi.yaml and the Redoc bundle is
  // vendored at public/redoc.standalone.js; /docs gets a dedicated CSP
  // variant in security.ts for Redoc's runtime styles and markdown.
  const body = `<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>API 仕様書 | Hyo</title>
<meta name="description" content="Hyo の API 仕様書（OpenAPI / Redoc）">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="icon" href="/favicon-32x32.png" type="image/png" sizes="32x32">
<link rel="icon" href="/favicon-16x16.png" type="image/png" sizes="16x16">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<style nonce="${escapeHtml(nonce)}">
  body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",sans-serif}
  .docs-bar{display:flex;align-items:center;gap:1rem;padding:.6rem 1rem;border-bottom:2px solid #111;background:#fff}
  .docs-bar .brand{font-weight:800;font-size:1.15rem;color:#111;text-decoration:none}
  .docs-bar .brand span{color:#1e4fd8}
  .docs-bar nav{margin-left:auto;display:flex;gap:.5rem}
  .docs-bar nav a{color:#1e4fd8;text-decoration:none;font-weight:600;border:1.5px solid #1e4fd8;padding:.3rem .8rem}
  .docs-bar nav a:hover{background:#1e4fd8;color:#fff}
</style>
</head>
<body>
<header class="docs-bar">
  <a class="brand" href="/">Hyo <span>API 仕様書</span></a>
  <nav>
    <a href="/openapi.yaml">OpenAPI (YAML)</a>
    <a href="/admin">管理画面</a>
  </nav>
</header>
<div id="redoc"></div>
<script nonce="${escapeHtml(nonce)}" src="/redoc.standalone.js"></script>
<script nonce="${escapeHtml(nonce)}">
  Redoc.init("/openapi.yaml", {
    hideHostname: false,
    expandResponses: "200,201",
    pathInMiddlePanel: true,
    menuToggle: true,
    theme: {
      colors: { primary: { main: "#1e4fd8" } },
      typography: {
        fontFamily: "system-ui, -apple-system, 'Segoe UI', sans-serif",
        headings: { fontFamily: "inherit" },
      },
      sidebar: { backgroundColor: "#f6f7f9", textColor: "#1a1d21" },
      rightPanel: { backgroundColor: "#23272e" },
    },
  }, document.getElementById("redoc"));
</script>
</body>
</html>`;
  return c.html(body);
});

ui.get("/polls/:pollId/results-page", async (c) => {
  const pollId = normalizeUuid(c.req.param("pollId"));
  const nonce = c.get("cspNonce") ?? "";
  const origin = originOf(c);
  if (!pollId) return c.text("Not found", 404);
  const poll = await getPollRow(c.env, pollId);
  if (!poll || poll.status === "draft") {
    return c.html(
      layout({
        title: "結果が見つかりません",
        userEmail: "",
        body: "<h1>結果が見つかりません</h1><p class=\"muted\">投票が存在しないか、まだ下書きです。</p>",
        origin,
        nonce,
      }),
      404,
    );
  }
  if (poll.results_visibility === "admin_only") {
    return c.html(
      layout({
        title: "結果は非公開です",
        userEmail: "",
        body: "<h1>結果は非公開です</h1><p class=\"muted\">この投票の結果は管理者だけが確認できます。</p>",
        origin,
        nonce,
      }),
      403,
    );
  }
  if (poll.results_visibility === "after_close" && !isClosedForVoting(poll)) {
    return c.html(
      layout({
        title: `結果: ${poll.question}`,
        userEmail: "",
        body: `
    <h1>${escapeHtml(poll.question)}</h1>
    <p class="muted">結果は締切後に公開されます${poll.closes_at ? `（締切: ${escapeHtml(poll.closes_at)}）` : ""}。</p>
    <div class="flow" role="img" aria-label="投票を受け付け中、締切後に結果を公開する流れ">
      <span class="node">1. 投票を受け付け中</span><span class="arrow" aria-hidden="true">→</span>
      <span class="node">2. 締切</span><span class="arrow" aria-hidden="true">→</span>
      <span class="node">3. 結果を公開</span>
    </div>`,
        origin,
        nonce,
      }),
    );
  }
  const results = await computeResults(c.env, origin, poll);
  const sections = resultsSections(results, poll);
  const brand = await c.env.DB.prepare(
    "SELECT brand_color, brand_logo_key FROM tenants WHERE id = ?1",
  )
    .bind(poll.tenant_id)
    .first<{ brand_color: string | null; brand_logo_key: string | null }>();
  const refreshScript = scriptTag(
    nonce,
    `
(() => {
  const POLL_ID = ${JSON.stringify(pollId)};
  let seen = ${results.total_voters} + ":" + ${results.total_votes};
  let reloaded = false;
  try { reloaded = sessionStorage.getItem("hv-reloaded-" + POLL_ID) === "1"; } catch (e) { reloaded = true; }
  const round1 = (n) => Math.round(n * 10) / 10;
  const esc = (s) => CSS.escape(s);
  function reloadOnce() {
    if (reloaded) return;
    try { sessionStorage.setItem("hv-reloaded-" + POLL_ID, "1"); } catch (e) { /* ignore */ }
    location.reload();
  }
  function applyResults(r) {
    const totalsEl = document.getElementById("total-voters");
    if (totalsEl) totalsEl.textContent = String(r.total_voters);
    const votesEl = document.getElementById("total-votes");
    if (votesEl) votesEl.textContent = String(r.total_votes);
    const questions = r.questions.length > 0 ? r.questions : [{
      id: r.poll_id, kind: "single", response_count: r.total_voters, options: r.options,
    }];
    for (const q of questions) {
      const resp = document.querySelector('[data-resp="' + esc(q.id) + '"]');
      if (resp) resp.textContent = String(q.response_count);
      const denom = q.options.reduce((sum, o) => sum + o.votes, 0);
      const totalPoints = q.options.reduce((sum, o) => sum + (o.points || 0), 0);
      const maxVotes = Math.max(1, ...q.options.map((o) => o.votes));
      const maxPoints = Math.max(1, ...q.options.map((o) => o.points || 0));
      const stack = document.querySelector('[data-stack="' + esc(q.id) + '"]');
      if (q.numeric) {
        const setNum = (attr, v) => { const el = document.querySelector('[' + attr + '="' + esc(q.id) + '"]'); if (el) el.textContent = v != null ? String(v) : "-"; };
        setNum("data-num-avg", q.numeric.average);
        setNum("data-num-min", q.numeric.min);
        setNum("data-num-max", q.numeric.max);
      }
      if (!["text", "short_text", "date", "number", "slider", "allocation"].includes(q.kind)) {
        if ((denom > 0) !== !!stack) return false;
        if (stack) {
          for (const o of q.options) {
            const seg = stack.querySelector('[data-oid="' + esc(o.id) + '"]');
            if (!seg) return false;
            seg.style.width = (denom > 0 ? (o.votes / denom) * 100 : 0) + "%";
          }
        }
      }
      for (const o of q.options) {
        const row = document.querySelector('.bar-row[data-qid="' + esc(q.id) + '"][data-oid="' + esc(o.id) + '"]');
        if (!row) return false;
        const fill = row.querySelector(".bar-fill");
        const track = row.querySelector(".bar-track");
        const label = row.children[0].textContent;
        const set = (sel, value) => { const el = row.querySelector(sel); if (el) el.textContent = String(value); };
        if (q.kind === "ranking") {
          const pts = o.points || 0;
          fill.style.width = round1((pts / maxPoints) * 100) + "%";
          const pct = totalPoints > 0 ? round1((pts / totalPoints) * 100) : 0;
          set("[data-points]", pts);
          set("[data-first]", o.votes);
          set("[data-avg]", o.average_rank != null ? o.average_rank : "-");
          track.setAttribute("aria-label", label + ": " + pts + "ポイント (" + pct + "%)");
        } else if (q.kind === "score") {
          const avg = o.average_score != null ? o.average_score : 0;
          fill.style.width = round1((avg / 5) * 100) + "%";
          set("[data-avg]", o.average_score != null ? o.average_score : "-");
          set("[data-evals]", o.votes);
          track.setAttribute("aria-label", label + ": 平均 " + (o.average_score != null ? o.average_score : "-") + " 点（5点満点）");
        } else if (q.kind === "allocation") {
          const totalAlloc = (q.config && q.config.total) || 100;
          const avgP = o.average_points != null ? o.average_points : 0;
          fill.style.width = round1((avgP / totalAlloc) * 100) + "%";
          set("[data-avgpoints]", o.average_points != null ? o.average_points : "-");
          set("[data-points]", o.points || 0);
          set("[data-evals]", o.votes);
          track.setAttribute("aria-label", label + ": 平均 " + (o.average_points != null ? o.average_points : "-") + " 点（合計 " + totalAlloc + " 点の配点）");
        } else {
          fill.style.width = round1((o.votes / maxVotes) * 100) + "%";
          const pct = denom > 0 ? round1((o.votes / denom) * 100) : 0;
          set("[data-votes]", o.votes);
          set("[data-pct]", pct);
          track.setAttribute("aria-label", label + ": " + o.votes + "票 (" + pct + "%)");
        }
      }
    }
    return true;
  }
  setInterval(async () => {
    try {
      const res = await fetch("/api/v1/polls/" + POLL_ID + "/results", { headers: { accept: "application/json" } });
      if (!res.ok) return;
      const data = await res.json();
      const stamp = data.results.total_voters + ":" + data.results.total_votes;
      if (stamp === seen) return;
      if (applyResults(data.results)) {
        seen = stamp;
      } else {
        reloadOnce();
      }
    } catch (e) { /* keep the current view */ }
  }, 10000);
})();
`,
  );
  const printScript = scriptTag(
    nonce,
    `document.getElementById("print-results")?.addEventListener("click", () => window.print());`,
  );
  const body = `
    ${brand?.brand_logo_key ? `<p><img src="/images/${escapeHtml(brand.brand_logo_key)}" alt="ワークスペースのロゴ" style="max-height:64px"></p>` : ""}
    <h1>${escapeHtml(poll.question)}</h1>
    <p class="muted small">投票者数 <span id="total-voters">${results.total_voters}</span> 人 ／ 総票数 <span id="total-votes">${results.total_votes}</span> 票${poll.closes_at ? ` ／ 締切 ${escapeHtml(poll.closes_at)}` : ""} ／ 10秒ごとに自動更新</p>
    <div class="actions no-print"><button class="btn" type="button" id="print-results">印刷／PDFに保存</button></div>
    <section class="section">
      ${sections || '<p class="muted">設問がありません。</p>'}
    </section>
    ${refreshScript}${printScript}`;
  return c.html(
    layout({
      title: `結果: ${poll.question}`,
      userEmail: "",
      body,
      origin,
      nonce,
      brandColor: brand?.brand_color ?? null,
    }),
  );
});

ui.get("/admin/workspaces/:tenantId/polls/:pollId/results", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const pollId = normalizeUuid(c.req.param("pollId"));
  if (!pollId) return c.redirect(`/admin/workspaces/${tenantId}`, 302);
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  const poll = await getPollRow(c.env, pollId);
  if (!poll || poll.tenant_id !== tenantId) return c.redirect(`/admin/workspaces/${tenantId}`, 302);
  const results = await computeResults(c.env, originOf(c), poll, { includeText: true });
  const sections = resultsSections(results, poll);
  const body = `
    <p class="muted small no-print"><a href="/admin/workspaces/${tenantId}/polls/${pollId}">投票に戻る</a></p>
    <h1>結果</h1>
    <div class="actions no-print">
      <button class="btn" type="button" id="print-results">印刷／PDFに保存</button>
      <a class="btn" href="/api/v1/tenants/${escapeHtml(tenantId)}/polls/${escapeHtml(pollId)}/export?format=csv">CSV で書き出す</a>
      <a class="btn" href="/api/v1/tenants/${escapeHtml(tenantId)}/polls/${escapeHtml(pollId)}/export?format=json">JSON で書き出す</a>
    </div>
    <section class="section">
      <div class="poll-head">
        <div style="flex:1;min-width:260px">
          <strong>${escapeHtml(poll.question)}</strong>
          <p class="muted small">${statusBadge(poll.status)} ／ 投票者数 ${results.total_voters} 人 ／ 総票数 ${results.total_votes} 票${poll.closes_at ? ` ／ 締切 ${escapeHtml(poll.closes_at)}` : ""}</p>
        </div>
        ${poll.image_key ? `<img src="/images/${escapeHtml(poll.image_key)}" alt="設問の画像">` : ""}
      </div>
      ${sections || '<p class="muted">設問がありません。</p>'}
      <p class="muted small">割合は、その設問の選択票に対する割合です。複数選択では合計が100%を超えることがあります。自由記述は管理画面と書き出しにだけ全文が出ます。</p>
    </section>
    ${scriptTag(c.get("cspNonce") ?? "", `document.getElementById("print-results")?.addEventListener("click", () => window.print());`)}`;
  return c.html(
    layout({
      title: `結果: ${poll.question}`,
      userEmail: user.email ?? user.name ?? user.accountId,
      body,
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }),
  );
});
