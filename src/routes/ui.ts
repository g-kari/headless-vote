import { Hono, type Context } from "hono";
import { deleteAccountData, deleteWorkspace, listMemberships } from "../account";
import { selectAuthProvider } from "../platform";
import { pollSubmissionSeries, workspaceSubmissionSeries } from "../analytics";
import { bumpSessionEpoch, clearSessionCookie, getSessionUser, isTenantMember, listTenantsForUser, memberRole } from "../auth";
import {
  addTenantOrigin,
  listTenantOrigins,
  removeTenantOrigin,
} from "../cors";
import { listAuditEvents } from "../audit";
import { listQuestionRows } from "../questions";
import { computeResults, getPollRow, isClosedForVoting, listOptionRows, type PollResults } from "../domain";
import { issueApiKey, limitKeyRotation, listApiKeys, provisionTenant, revokeApiKey } from "../keys";
import { addMember, listMembers, removeMember, setMemberRole } from "../members";
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
  if (!(await isTenantMember(c.env, id, user.sub))) return null;
  return user;
}

async function requireOwnerUser(
  c: Context<{ Bindings: Env; Variables: Variables }>,
  tenantId: string,
): Promise<SessionUser | Response> {
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  const role = await memberRole(c.env, tenantId, user.sub);
  if (role !== "owner") {
    return c.html(layout({
      title: "権限がありません",
      userEmail: user.email ?? user.sub,
      body: `<h1>権限がありません</h1><p>メンバーの管理、API キー、Webhook、許可オリジン、ワークスペースの削除はオーナーだけが実行できます。</p>`,
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }), 403);
  }
  return user;
}

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
      <dt>投票の設定</dt><dd>1つの投票に設問を最大20件まで追加できます。形式は単一選択・複数選択・自由記述。設問と選択肢に画像を添付できます。</dd>
      <dt>投票ごとに選べる項目</dt><dd>ログイン必須か任意か、公開日時と締切日時。</dd>
      <dt>投票の数え方</dt><dd>1人1票。締切前なら投票の変更ができます。ログインした人はアカウント単位、匿名の人は投票者トークン単位で数えます。</dd>
      <dt>匿名投票の限界</dt><dd>トークンを変えた同一人物は別人として数えられます。厳密に1人1票が必要な投票では「ログイン必須」を選んでください。</dd>
      <dt>集計結果</dt><dd>管理画面のグラフと API（GET /api/v1/polls/:id/results）で取得できます。CSV / JSON への書き出しにも対応します。</dd>
    </dl>`;
  return c.html(
    layout({
      title: "投票 SaaS",
      userEmail: user?.email ?? user?.sub ?? null,
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

  const tenants = await listTenantsForUser(c.env, user.sub);
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
      userEmail: user.email ?? user.sub,
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
        userEmail: user.email ?? user.sub,
        body: `<h1>名前を確認してください</h1><p class="muted">ワークスペース名は1〜120文字で入力してください。</p><p><a href="/admin">戻る</a></p>`,
        origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
      }),
      400,
    );
  }
  const { tenantId, apiKey } = await provisionTenant(c.env, name, user.sub);
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
      userEmail: user.email ?? user.sub,
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
  const role = await memberRole(c.env, tenantId, user.sub);
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
      userEmail: user.email ?? user.sub,
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
  const actor = { kind: "session" as const, tenantId, sub: user.sub, role: "owner" as const };
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
      userEmail: user.email ?? user.sub,
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
      sub: user.sub,
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
      userEmail: user.email ?? user.sub,
      body,
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }));
  } catch (err) {
    if (!(err instanceof ApiError)) throw err;
    return c.html(layout({
      title: "エラー",
      userEmail: user.email ?? user.sub,
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
  await revokeApiKey(c.env, tenantId, keyId, { kind: "session", tenantId, sub: user.sub, role: "owner" });
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
  extras: { quotas: string; members: string; webhooks: string; branding: string },
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

async function settingsExtras(env: Env, tenantId: string, owner: boolean, nonce = "") {
  const quotas = await tenantQuotas(env, tenantId);
  const members = await listMembers(env, tenantId);
  const hooks = await listWebhooks(env, tenantId);
  const tid = escapeHtml(tenantId);
  const memberItems = members
    .map((member) => `<li><code>${escapeHtml(member.user_sub)}</code> ${member.role === "owner" ? "オーナー" : "メンバー"}
      ${owner ? `<form method="post" action="/admin/workspaces/${tid}/members/role" style="display:inline">
        <input type="hidden" name="user_sub" value="${escapeHtml(member.user_sub)}">
        <input type="hidden" name="role" value="${member.role === "owner" ? "member" : "owner"}">
        <button class="btn small" type="submit">${member.role === "owner" ? "メンバーにする" : "オーナーにする"}</button>
      </form>
      <form method="post" action="/admin/workspaces/${tid}/members/remove" style="display:inline">
        <input type="hidden" name="user_sub" value="${escapeHtml(member.user_sub)}">
        <button class="btn small danger" type="submit">外す</button>
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
      ${owner ? `<form method="post" action="/admin/workspaces/${tid}/members" aria-labelledby="member-heading">
        <h3 id="member-heading">利用者 ID（sub）で追加</h3>
        <label for="member-sub">sub</label>
        <input id="member-sub" name="user_sub" type="text" required maxlength="256" autocomplete="off" spellcheck="false">
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
  const owner = (await memberRole(c.env, tenantId, user.sub)) === "owner";
  return c.html(
    layout({
      title: "設定",
      userEmail: user.email ?? user.sub,
      body: settingsBody(tenantId, tenant.name, origins, null, owner, await settingsExtras(c.env, tenantId, owner, c.get("cspNonce") ?? "")),
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
          userEmail: user.email ?? user.sub,
          body: settingsBody(tenantId, tenant?.name ?? "", origins, err.message, true, await settingsExtras(c.env, tenantId, true, c.get("cspNonce") ?? "")),
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
      userEmail: user.email ?? user.sub,
      body: settingsBody(tenantId, tenant?.name ?? "", origins, "ワークスペース名が一致しません。", true, await settingsExtras(c.env, tenantId, true, c.get("cspNonce") ?? "")),
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
    userEmail: user.email ?? user.sub,
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
    userEmail: user.email ?? user.sub,
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
    userEmail: user.email ?? user.sub,
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
    await addMember(c.env, tenantId, String(form.get("user_sub") ?? ""), form.get("role") === "owner" ? "owner" : "member", {
      kind: "session",
      tenantId,
      sub: user.sub,
      role: "owner",
    });
  } catch (err) {
    if (!(err instanceof ApiError)) throw err;
    return c.html(layout({
      title: "設定",
      userEmail: user.email ?? user.sub,
      body: `<h1>メンバーを追加できません</h1><p>${escapeHtml(err.message)}</p><p><a href="/admin/workspaces/${escapeHtml(tenantId)}/settings">戻る</a></p>`,
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
    await setMemberRole(c.env, tenantId, String(form.get("user_sub") ?? ""), form.get("role"), {
      kind: "session", tenantId, sub: user.sub, role: "owner",
    });
  } catch (err) {
    if (!(err instanceof ApiError)) throw err;
    return c.html(layout({
      title: "設定",
      userEmail: user.email ?? user.sub,
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
    await removeMember(c.env, tenantId, String(form.get("user_sub") ?? ""), {
      kind: "session", tenantId, sub: user.sub, role: "owner",
    });
  } catch (err) {
    if (!(err instanceof ApiError)) throw err;
    return c.html(layout({
      title: "設定",
      userEmail: user.email ?? user.sub,
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
      userEmail: user.email ?? user.sub,
      body,
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }));
  } catch (err) {
    if (!(err instanceof ApiError)) throw err;
    return c.html(layout({
      title: "設定",
      userEmail: user.email ?? user.sub,
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
  const memberships = await listMemberships(c.env, user.sub);
  const rows = memberships
    .map((m) => `<tr><td>${escapeHtml(m.name)}</td><td>${m.role === "owner" ? "オーナー" : "メンバー"}</td><td>${escapeHtml(m.plan)}</td></tr>`)
    .join("");
  const body = `
    <h1>アカウント</h1>
    <section class="section">
      <h2>プロフィール</h2>
      <p>名前: ${escapeHtml(user.name ?? "未設定")}</p>
      <p>メール: ${escapeHtml(user.email ?? "未設定")}</p>
      <p>sub: <code>${escapeHtml(user.sub)}</code></p>
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
    userEmail: user.email ?? user.sub,
    body,
    origin: originOf(c),
    nonce: c.get("cspNonce") ?? "",
  }));
});

ui.post("/admin/account/revoke-sessions", async (c) => {
  const user = await getSessionUser(c);
  if (!user) return c.redirect("/admin", 302);
  assertSameOriginMutation(c);
  if (user.sub.startsWith("local:")) {
    // Local accounts version their sessions on the user row instead.
    await c.env.DB.prepare(
      "UPDATE local_users SET session_version = session_version + 1 WHERE id = ?1",
    )
      .bind(user.sub.slice("local:".length))
      .run();
  } else {
    await bumpSessionEpoch(c.env, user.sub);
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
      userEmail: user.email ?? user.sub,
      body: `<h1>削除できません</h1><p>確認の文字列が一致しません。</p><p><a href="/admin/account">戻る</a></p>`,
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }), 400);
  }
  await deleteAccountData(c.env, user.sub);
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
    qSel.value = [...qSel.options].some((o) => o.value === prevQ) ? prevQ : '';
    oSel.replaceChildren();
    const target = cards.find((cd) => cd.querySelector('.q-id').value === qSel.value);
    if (target) {
      for (const row of target.querySelectorAll('.option-row')) {
        const opt = document.createElement('option');
        opt.value = row.querySelector('.opt-id').value;
        opt.textContent = row.querySelector('.opt-label').value.trim() || '選択肢';
        oSel.append(opt);
      }
      oSel.value = [...oSel.options].some((o) => o.value === prevO) ? prevO : (oSel.options[0] ? oSel.options[0].value : '');
    }
    oSel.disabled = !qSel.value;
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
  for (const [value, label] of [['single', '単一選択'], ['multiple', '複数選択'], ['text', '自由記述'], ['ranking', '順位付け'], ['score', '点数付け（0〜5）']]) {
    const opt = document.createElement('option');
    opt.value = value;
    opt.textContent = label;
    if (data && data.kind === value) opt.selected = true;
    kind.append(opt);
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
  const showO = document.createElement('select');
  showO.className = 'q-showif-o';
  showQ.addEventListener('change', refreshShowIf);
  if (data && data.show_if) {
    card.dataset.sq = data.show_if.question_id;
    card.dataset.so = data.show_if.option_id;
  }
  showIfWrap.append(showIfLabel, showQ, document.createTextNode(' のときだけ表示 '), showO);
  const options = document.createElement('div');
  options.className = 'q-options';
  const addOpt = document.createElement('button');
  addOpt.type = 'button';
  addOpt.className = 'btn small';
  addOpt.textContent = '選択肢を追加';
  addOpt.addEventListener('click', () => { addOptionRow(options, '', null, ''); refreshShowIf(); });
  const syncKind = () => { options.hidden = kind.value === 'text'; addOpt.hidden = kind.value === 'text'; };
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
  card.append(prompt, kind, requiredLabel, qid, showIfWrap, options, addOpt, actions);
  questionsEl.append(card);
  refreshShowIf();
  const seedOptions = (data && data.options) || [];
  if (seedOptions.length === 0 && (!data || data.kind !== 'text')) {
    addOptionRow(options, '', null, '');
    addOptionRow(options, '', null, '');
  }
  for (const o of seedOptions) addOptionRow(options, o.label, o.image_key, o.id);
  syncKind();
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

async function submitPoll(ev) {
  ev.preventDefault();
  errorEl.style.display = 'none';
  try {
    await uploadFrom(document.getElementById('poll-image-row'), '#poll-image-file', '#poll-image-key');
    const questions = [];
    for (const card of questionsEl.querySelectorAll('.question-card')) {
      const kind = card.querySelector('.q-kind').value;
      const prompt = card.querySelector('.q-prompt').value.trim();
      if (!prompt) throw new Error('設問文が空です');
      const options = [];
      if (kind !== 'text') {
        for (const row of card.querySelectorAll('.option-row')) {
          await uploadFrom(row, '.opt-file', '.opt-key');
          const label = row.querySelector('.opt-label').value.trim();
          if (!label) throw new Error('選択肢の文言が空です');
          const imageKey = row.querySelector('.opt-key').value || null;
          const id = row.querySelector('.opt-id').value || undefined;
          options.push({ id, label, image_key: imageKey });
        }
        if (options.length < 2) throw new Error('選択式の設問には選択肢が2つ以上必要です');
      }
      const id = card.querySelector('.q-id').value || undefined;
      const showQ = card.querySelector('.q-showif-q').value;
      const showO = card.querySelector('.q-showif-o').value;
      if (showQ && !showO) throw new Error('表示条件の選択肢が未選択です');
      questions.push({
        id,
        prompt,
        kind,
        required: card.querySelector('.q-required').checked,
        options,
        show_if: showQ ? { question_id: showQ, option_id: showO } : null,
      });
    }
    if (questions.length < 1) throw new Error('設問は1つ以上必要です');
    if (questions.length > 20) throw new Error('設問は20個までです');
    const closesRaw = document.getElementById('closes-at').value;
    const opensRaw = document.getElementById('opens-at').value;
    const payload = {
      question: document.getElementById('question').value.trim(),
      description: document.getElementById('description').value,
      image_key: document.getElementById('poll-image-key').value || null,
      require_login: document.getElementById('require-login').checked,
      results_visibility: document.getElementById('results-visibility').value,
      ip_single_vote: document.getElementById('ip-single-vote').checked,
      confirm_required: document.getElementById('confirm-required').checked,
      opens_at: opensRaw ? new Date(opensRaw).toISOString() : null,
      closes_at: closesRaw ? new Date(closesRaw).toISOString() : null,
      questions,
    };
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
    if (!res.ok) throw new Error((data.error && data.error.message) || '保存に失敗しました');
    location.href = '/admin/workspaces/' + TENANT + '/polls/' + data.poll.id;
  } catch (e) {
    errorEl.textContent = e.message || String(e);
    errorEl.style.display = 'block';
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
}
document.getElementById('poll-form').addEventListener('submit', submitPoll);
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
      <h2>設問</h2>
      <p class="muted small">形式は単一選択、複数選択、自由記述、順位付け、点数付けです。単一・複数選択の回答を条件に、後ろの設問を表示する分岐も付けられます。並び順は上から下です。最大 20 問。</p>
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
      userEmail: user.email ?? user.sub,
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
  if (q.kind === "text") return { question_id: q.id, text: "" };
  if (q.kind === "score") return { question_id: q.id, scores: Object.fromEntries(q.options.map((o) => [o.id, 0])) };
  return { question_id: q.id, option_ids: [q.options[0].id] };
});
await fetch(base + "/api/v1/polls/" + pollId + "/vote", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    voter_token: "stable-id-for-this-voter",
    ...(poll.poll.confirm_required ? { confirm: true } : {}),
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
    ${poll.status !== "closed" ? pollFormBody({ tenantId, poll, questions: questionSeed, nonce }) : `<h2>内容</h2><section class="section">${questionSeed.map((q) => `<h3>${escapeHtml(q.prompt)}</h3><p class="muted small">${q.kind === "text" ? "自由記述" : q.kind === "multiple" ? "複数選択" : q.kind === "ranking" ? "順位付け" : q.kind === "score" ? "点数付け" : "単一選択"}</p><ul>${q.options.map((o) => `<li>${escapeHtml(o.label)}</li>`).join("")}</ul>`).join("")}</section>`}`;
  return c.html(
    layout({
      title: poll.question,
      userEmail: user.email ?? user.sub,
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

function resultsSections(results: PollResults, poll: PollRow): string {
  const colorOf = (i: number) => SEGMENT_COLORS[i % SEGMENT_COLORS.length] as string;
  const kindLabel = (kind: string) =>
    kind === "text"
      ? "自由記述"
      : kind === "multiple"
        ? "複数選択"
        : kind === "ranking"
          ? "順位付け"
          : kind === "score"
            ? "点数付け"
            : "単一選択";
  return (results.questions.length > 0 ? results.questions : [{
    id: poll.id,
    prompt: poll.question,
    kind: "single" as const,
    required: true,
    position: 0,
    response_count: results.total_voters,
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
    return `<h2>${escapeHtml(q.prompt)}</h2>
      <p class="muted small">${q.kind === "text" ? "自由記述" : q.kind === "multiple" ? "複数選択" : q.kind === "ranking" ? "順位付け" : q.kind === "score" ? "点数付け" : "単一選択"} ／ 回答 <span data-resp="${escapeHtml(q.id)}">${q.response_count}</span></p>
      ${q.kind === "text" ? `<ul>${texts || '<li class="muted">まだ回答がありません。</li>'}</ul>` : `${bars}${denom > 0 ? `<div class="stack" data-stack="${escapeHtml(q.id)}" role="img" aria-label="得票割合の積み上げグラフ">${stackSegments}</div><div class="legend">${legend}</div>` : ""}`}`;
  }).join("");
}



ui.get("/docs", async (c) => {
  const origin = originOf(c);
  const nonce = c.get("cspNonce") ?? "";
  const user = await getSessionUser(c);
  const body = `
    <h1>API 仕様書</h1>
    <p class="lead">Hyo の公開 API と管理 API の使い方です。ベース URL は <code>${escapeHtml(origin)}</code>、形式は JSON です。</p>
    <h2>認証</h2>
    <section class="section">
      <p>管理 API は次のどちらかで認証します。</p>
      <ul>
        <li>API キー: <code>Authorization: Bearer hv_...</code>。キーはワークスペース作成時に発行され、<code>read</code>（参照・書き出し）と <code>write</code>（作成・更新・失効）の 2 つの権限があります。キーの追加発行・失効・ローテーションは管理 API と設定画面から行えます。</li>
        <li>管理画面のログインセッション（Cookie）。画面と同じ操作を fetch で呼べます。</li>
      </ul>
      <p>公開 API（投票の取得・投票・結果・自分の票・QR・共有画像）は認証不要です。投票にログインが必須の投票では、投票だけログインセッションが必要です。</p>
    </section>
    <h2>公開 API</h2>
    <section class="section">
      <ul>
        <li><code>GET /api/v1/polls/:pollId</code> — 投票と設問（形式・表示条件を含む）を取得</li>
        <li><code>POST /api/v1/polls/:pollId/vote</code> — 投票する（下の形式）</li>
        <li><code>GET /api/v1/polls/:pollId/results</code> — 設問ごとの集計。公開範囲が「締切後」や「非公開」の投票では 403</li>
        <li><code>GET /api/v1/polls/:pollId/ballot?voter_token=...</code> — 自分の票の控えと変更可否</li>
        <li><code>GET /api/v1/polls/:pollId/qr.svg</code> — 結果ページへの QR コード（SVG）</li>
        <li><code>GET /api/v1/polls/:pollId/og.svg</code> — 共有用画像（SVG、ブランド色を反映）</li>
        <li><code>GET /polls/:pollId/results-page</code> — 人間向けの結果ページ（10 秒ごとに自動更新）</li>
      </ul>
      <h3>投票のリクエスト</h3>
      <pre>${escapeHtml(`POST /api/v1/polls/<pollId>/vote
{
  "voter_token": "stable-id-for-this-voter",
  "answers": [
    { "question_id": "<id>", "option_ids": ["<option id>"] },
    { "question_id": "<id>", "text": "自由記述の回答" },
    { "question_id": "<id>", "scores": { "<option id>": 5 } }
  ]
}`)}</pre>
      <p class="muted small">voter_token は投票者を識別する安定した文字列（8〜128 文字）で、同じトークンの再投票は前の票を上書きします。設問の形式は single（1 つだけ）、multiple（複数可）、text（自由記述）、ranking（option_ids の並びが順位）、score（選択肢ごとに 0〜5 点）です。表示条件（show_if）が付いた設問は、条件を満たさない回答では送らなくて構いません。確認ステップ必須の投票では <code>confirm: true</code> が必要です。</p>
    </section>
    <h2>管理 API</h2>
    <section class="section">
      <ul>
        <li><code>POST /api/v1/tenants</code> — ワークスペース作成（API キーを返す）</li>
        <li><code>POST /api/v1/tenants/:id/polls</code> — 投票作成（questions 配列で複数設問、最大 20 問）</li>
        <li><code>PATCH /api/v1/tenants/:id/polls/:pollId</code> — 投票の編集</li>
        <li><code>POST /api/v1/tenants/:id/polls/:pollId/status</code> — 公開・締切（published / closed）</li>
        <li><code>POST /api/v1/tenants/:id/polls/:pollId/duplicate</code> — 投票の複製（下書きとして）</li>
        <li><code>GET /api/v1/tenants/:id/polls/:pollId/results</code> — 管理用の集計</li>
        <li><code>GET /api/v1/tenants/:id/polls/:pollId/export?format=csv|json</code> — 書き出し</li>
        <li><code>GET /api/v1/tenants/:id/polls/:pollId/analytics</code> — 日別の投票推移</li>
        <li><code>POST /api/v1/tenants/:id/templates</code> / <code>GET /api/v1/tenants/:id/templates</code> / <code>POST /api/v1/tenants/:id/templates/:templateId/polls</code> / <code>DELETE /api/v1/tenants/:id/templates/:templateId</code> — テンプレート</li>
        <li><code>GET /api/v1/tenants/:id/api-keys</code>、<code>POST</code>、<code>POST /api/v1/tenants/:id/api-keys/:keyId/revoke</code>、<code>POST /api/v1/tenants/:id/rotate-key</code> — キー管理</li>
        <li><code>PATCH /api/v1/tenants/:id/branding</code> — ブランド色とロゴ（オーナー）</li>
        <li><code>GET /api/v1/tenants/:id/notifications</code>、<code>POST /api/v1/tenants/:id/notifications/:notificationId/read</code> — 通知</li>
        <li><code>GET /api/v1/tenants/:id/audit</code> — 操作履歴</li>
        <li><code>GET /api/v1/tenants/:id/export</code> — ワークスペースの書き出し</li>
      </ul>
      <h3>サンプル（JavaScript）</h3>
      <pre>${escapeHtml(`const base = "${origin}";
const key = "hv_..."; // write キー
const created = await fetch(base + "/api/v1/tenants/<tenantId>/polls", {
  method: "POST",
  headers: { "content-type": "application/json", authorization: "Bearer " + key },
  body: JSON.stringify({
    question: "好きな季節は？",
    questions: [
      { prompt: "季節", kind: "single", options: [{ label: "春" }, { label: "夏" }, { label: "秋" }, { label: "冬" }] },
      { prompt: "理由", kind: "text", required: false },
    ],
  }),
}).then((r) => r.json());`)}</pre>
    </section>
    <h2>Webhook</h2>
    <section class="section">
      <p>イベントは <code>vote.cast</code>、<code>poll.published</code>、<code>poll.closed</code>、<code>poll.updated</code>、<code>poll.closing_soon</code>（締切 48 時間以内に 1 回）です。本文は JSON（<code>id</code>、<code>type</code>、<code>created_at</code>、<code>tenant_id</code>、<code>data</code>）で、ヘッダー <code>X-Headless-Vote-Event</code> と署名 <code>X-Headless-Vote-Signature: v1=&lt;hex&gt;</code>（本文全体の HMAC-SHA256）が付きます。検証サンプル:</p>
      <pre>${escapeHtml(`import { createHmac, timingSafeEqual } from "node:crypto";

function verify(secret, rawBody, signatureHeader) {
  const expected = "v1=" + createHmac("sha256", secret)
    .update(rawBody)
    .digest("hex");
  const a = Buffer.from(expected);
  const b = Buffer.from(signatureHeader);
  return a.length === b.length && timingSafeEqual(a, b);
}`)}</pre>
      <p class="muted small">配送結果（HTTP ステータス）はサーバ側に記録されます。本文の <code>id</code> がイベントごとの一意な ID なので、受け側での重複判定に使えます。URL は公開前に検証され、プライベートアドレス宛ては送られません。</p>
    </section>
    <h2>埋め込みと CORS</h2>
    <section class="section">
      <p>別サイトのブラウザから公開 API を読む場合は、そのオリジンをワークスペース設定の許可リストに追加してください。各投票の管理画面に、設問形式に応じた埋め込み用スニペットを用意しています。</p>
    </section>
    <h2>主なエラーコード</h2>
    <section class="section">
      <ul>
        <li><code>POLL_NOT_OPEN</code>（409）— 開始日時より前</li>
        <li><code>POLL_CLOSED</code>（409）— 締切済み</li>
        <li><code>CONFIRM_REQUIRED</code>（409）— 確認ステップ必須の投票で confirm が無い</li>
        <li><code>LOGIN_REQUIRED</code>（401）— ログイン必須の投票</li>
        <li><code>OPTIONS_LOCKED</code>（409）— 投票が入った後の設問・選択肢の構造変更</li>
        <li><code>QUOTA_EXCEEDED</code>（409）— 件数や 1 日の上限</li>
        <li><code>RATE_LIMITED</code>（429）— 短時間の大量リクエスト</li>
      </ul>
    </section>`;
  return c.html(
    layout({
      title: "API 仕様書",
      userEmail: user?.email ?? user?.sub ?? null,
      body,
      origin,
      nonce,
    }),
  );
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
      if (q.kind !== "text") {
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
  const body = `
    ${brand?.brand_logo_key ? `<p><img src="/images/${escapeHtml(brand.brand_logo_key)}" alt="ワークスペースのロゴ" style="max-height:64px"></p>` : ""}
    <h1>${escapeHtml(poll.question)}</h1>
    <p class="muted small">投票者数 <span id="total-voters">${results.total_voters}</span> 人 ／ 総票数 <span id="total-votes">${results.total_votes}</span> 票${poll.closes_at ? ` ／ 締切 ${escapeHtml(poll.closes_at)}` : ""} ／ 10秒ごとに自動更新</p>
    <section class="section">
      ${sections || '<p class="muted">設問がありません。</p>'}
    </section>
    ${refreshScript}`;
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
    <p class="muted small"><a href="/admin/workspaces/${tenantId}/polls/${pollId}">投票に戻る</a></p>
    <h1>結果</h1>
    <div class="actions">
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
    </section>`;
  return c.html(
    layout({
      title: `結果: ${poll.question}`,
      userEmail: user.email ?? user.sub,
      body,
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }),
  );
});
