import { Hono } from "hono";
import { getSessionUser, isTenantMember, listTenantsForUser } from "../auth";
import {
  addTenantOrigin,
  listTenantOrigins,
  removeTenantOrigin,
} from "../cors";
import { listAuditEvents } from "../audit";
import { computeResults, getPollRow, listOptionRows } from "../domain";
import { issueApiKey, listApiKeys, provisionTenant, revokeApiKey } from "../keys";
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

/* ------------------------------------------------------------------ */
/* Landing + workspace list                                            */
/* ------------------------------------------------------------------ */

ui.get("/", async (c) => {
  const user = await getSessionUser(c);
  const body = `
    <h1>投票を、API でも画面でも。</h1>
    <p class="lead">headless-vote は、投票の作成・実施・集計を行える SaaS です。
    画面を持たないシステムからは API で、人はこの管理画面から、同じ投票を運用できます。</p>
    <div class="actions">
      <a class="btn primary" href="/admin">管理画面を開く</a>
      <a class="btn" href="/api/v1/health">API の状態を見る</a>
    </div>
    <h2>できること</h2>
    <div class="grid">
      <section class="card"><strong>設問と選択肢の設定</strong>
        <p class="muted">設問文・説明・選択肢に加えて、画像も添付できます。締切日時、複数選択の可否、ログイン必須かどうかも投票ごとに選べます。</p></section>
      <section class="card"><strong>1人1票</strong>
        <p class="muted">ログインした人はアカウントに、未ログインの人は投票者トークンに紐付けて数えます。締切前なら投票のやり直しもできます。</p></section>
      <section class="card"><strong>結果の見える化</strong>
        <p class="muted">集計結果は管理画面で棒グラフとして確認でき、API からも取得できます。</p></section>
    </div>`;
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
      <p class="lead">管理画面のログインは 0g0-id を使います。ログインすると、自分のワークスペース（投票の運用単位）を作成し、設問・選択肢・画像の設定や結果の確認ができます。</p>
      <div class="actions"><a class="btn primary" href="/admin/login">0g0-id でログイン</a></div>
      <h2>API キーで使う場合</h2>
      <p class="muted">画面を使わない運用では、テナント作成時に発行される API キーで管理 API を呼び出せます。API キーの発行は <code>POST /api/v1/tenants</code> から行えます（README 参照）。</p>`;
    return c.html(layout({ title: "管理画面", userEmail: null, body, origin: originOf(c), nonce: c.get("cspNonce") ?? "" }));
  }

  const tenants = await listTenantsForUser(c.env, user.sub);
  const cards = tenants
    .map(
      (t) => `<section class="card">
        <strong>${escapeHtml(t.name)}</strong>
        <p class="muted small">ワークスペース ID: <code>${escapeHtml(t.id)}</code></p>
        <div class="actions"><a class="btn small primary" href="/admin/workspaces/${t.id}">開く</a></div>
      </section>`,
    )
    .join("");
  const body = `
    <h1>ワークスペース</h1>
    <p class="lead">ワークスペースごとに投票と API キーが分かれます。ほかのワークスペースのデータは見えません。</p>
    <div class="grid">${cards || '<section class="card"><p class="muted">まだワークスペースがありません。下のフォームから作成してください。</p></section>'}</div>
    <h2>新しいワークスペース</h2>
    <section class="card">
      <form method="post" action="/admin/workspaces">
        <label for="ws-name">ワークスペース名</label>
        <input id="ws-name" type="text" name="name" required maxlength="120" placeholder="例: イベント投票">
        <div class="actions"><button class="btn primary" type="submit">作成する</button></div>
      </form>
    </section>`;
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
    <section class="card">
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
  const keys = await listApiKeys(c.env, tenantId);
  const keyItems = keys
    .map(
      (key) => `<li>${escapeHtml(key.name)} <code>${escapeHtml(key.key_prefix)}…</code> ${key.scope === "write" ? "読み書き" : "読み取り"} ${key.revoked_at ? '<span class="badge closed">失効</span>' : `<form method="post" action="/admin/workspaces/${escapeHtml(tenantId)}/api-keys/revoke" style="display:inline"><input type="hidden" name="key_id" value="${escapeHtml(key.id)}"><button class="btn small danger" type="submit">失効</button></form>`}</li>`,
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
        <td><a class="btn small" href="/admin/workspaces/${tenantId}/polls/${p.id}/results">結果</a></td>
      </tr>`,
    )
    .join("");
  const body = `
    <p class="muted small"><a href="/admin">ワークスペース一覧</a></p>
    <h1>${escapeHtml(tenant.name)}</h1>
    <p class="muted">投票 ${polls.results.length} 件（公開中 ${polls.results.filter((p) => p.status === "published").length}）／ 記録された票 ${Number((await c.env.DB.prepare("SELECT COUNT(*) AS n FROM vote_ballots WHERE poll_id IN (SELECT id FROM polls WHERE tenant_id = ?1)").bind(tenantId).first<{ n: number }>())?.n ?? 0)} 件。1 ワークスペースあたり投票は 100 件、有効な API キーは 10 個までです。</p>
    <div class="actions">
      <a class="btn primary" href="/admin/workspaces/${escapeHtml(tenantId)}/polls/new">新しい投票を作る</a>
      <a class="btn" href="/admin/workspaces/${escapeHtml(tenantId)}/settings">埋め込み設定</a>
      <a class="btn" href="/admin/workspaces/${escapeHtml(tenantId)}/audit">操作履歴</a>
    </div>
    <h2>投票一覧</h2>
    <section class="card">
      ${rows ? `<div class="table-wrapper" tabindex="0" role="region" aria-label="投票一覧"><table><thead><tr><th scope="col">設問</th><th scope="col">状態</th><th scope="col">設定</th><th scope="col">締切</th><th scope="col"><span class="muted">操作</span></th></tr></thead><tbody>${rows}</tbody></table></div>` : '<p class="muted">まだ投票がありません。</p>'}
    </section>
    <h2>API キー</h2>
    <section class="card">
      <p class="muted">管理 API のキーは SHA-256 で保存し、作成時に一度だけ表示します。<code>read</code> は参照と書き出し、<code>write</code> は作成・更新・失効もできます。</p>
      ${keyItems ? `<ul>${keyItems}</ul>` : ""}
      <form method="post" action="/admin/workspaces/${escapeHtml(tenantId)}/api-keys" aria-labelledby="key-heading">
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
      </dialog>
      ${scriptTag(c.get("cspNonce") ?? "", `
        document.getElementById("open-rotate").addEventListener("click", () => {
          document.getElementById("rotate-dialog").showModal();
        });
        document.getElementById("close-rotate").addEventListener("click", () => {
          document.getElementById("rotate-dialog").close();
        });
      `)}
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
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  assertSameOriginMutation(c);
  await readUrlEncodedForm(c);
  const actor = { kind: "session" as const, tenantId, sub: user.sub };
  const existing = await listApiKeys(c.env, tenantId);
  for (const key of existing) {
    if (!key.revoked_at) await revokeApiKey(c.env, tenantId, key.id, actor);
  }
  const issued = await issueApiKey(c.env, tenantId, "再発行", "write", actor);
  const apiKey = issued.apiKey;
  const body = `
    <h1>API キーを再発行しました</h1>
    <section class="card">
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
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  assertSameOriginMutation(c);
  const form = await readUrlEncodedForm(c);
  const name = String(form.get("name") ?? "").trim();
  const scope = form.get("scope") === "read" ? "read" : "write";
  try {
    const issued = await issueApiKey(c.env, tenantId, name, scope, {
      kind: "session",
      tenantId,
      sub: user.sub,
    });
    const body = `
      <h1>API キーを発行しました</h1>
      <section class="card">
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
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  assertSameOriginMutation(c);
  const form = await readUrlEncodedForm(c);
  const keyId = String(form.get("key_id") ?? "");
  if (!normalizeUuid(keyId)) return c.redirect(`/admin/workspaces/${tenantId}`, 302);
  await revokeApiKey(c.env, tenantId, keyId, { kind: "session", tenantId, sub: user.sub });
  return c.redirect(`/admin/workspaces/${tenantId}`, 303);
});

/* ------------------------------------------------------------------ */
/* Embed origin settings (per workspace)                               */
/* ------------------------------------------------------------------ */

function settingsBody(
  tenantId: string,
  workspaceName: string,
  origins: string[],
  error: string | null,
): string {
  const tid = escapeHtml(tenantId);
  const items = origins
    .map(
      (origin) => `<li>
        <code>${escapeHtml(origin)}</code>
        <form method="post" action="/admin/workspaces/${tid}/origins/remove" style="display:inline">
          <input type="hidden" name="origin" value="${escapeHtml(origin)}">
          <button class="btn small" type="submit">削除</button>
        </form>
      </li>`,
    )
    .join("");
  return `
    <p class="muted small"><a href="/admin/workspaces/${tid}">ワークスペースに戻る</a></p>
    <h1>埋め込み設定</h1>
    <p class="lead">${escapeHtml(workspaceName)} の投票を、別のサイトのブラウザから呼ぶときに許可するオリジンです。
    <code>https://vote.0g0.xyz</code> と同じサイトから使う場合は追加不要です。ワイルドカードやパスは使えません。</p>
    ${error ? `<div class="notice bad" role="alert">${escapeHtml(error)}</div>` : ""}
    <h2>許可しているオリジン</h2>
    <section class="card">
      ${items ? `<ul>${items}</ul>` : `<p class="muted">まだ許可しているオリジンはありません。この状態では、別サイトのブラウザから公開 API の応答を読めません。</p>`}
    </section>
    <h2 id="origin-heading">許可するオリジンを追加</h2>
    <section class="card">
      <form method="post" action="/admin/workspaces/${tid}/origins" aria-labelledby="origin-heading">
        <label for="origin">オリジン <span class="hint">例: https://www.example.com 。https のみ（localhost は http も可）。</span></label>
        <input id="origin" name="origin" type="url" required maxlength="200" placeholder="https://www.example.com" spellcheck="false" autocapitalize="none" autocomplete="off" inputmode="url">
        <div class="actions"><button class="btn primary" type="submit">追加する</button></div>
      </form>
    </section>
    <h2>ワークスペースの書き出しと削除</h2>
    <section class="card">
      <p class="muted">書き出しには設問、集計、許可オリジン、キーのメタデータ、操作履歴が含まれます。投票者トークンやキーの秘密は含みません。</p>
      <p><a class="btn" href="/api/v1/tenants/${tid}/export">JSON で書き出す</a></p>
      <form method="post" action="/admin/workspaces/${tid}/delete" aria-labelledby="delete-heading">
        <h3 id="delete-heading">削除</h3>
        <label for="confirm-name">確認のためワークスペース名を入力</label>
        <input id="confirm-name" name="confirm_name" type="text" required maxlength="120" autocomplete="off">
        <div class="actions"><button class="btn danger" type="submit">ワークスペースを削除する</button></div>
      </form>
    </section>`;
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
  return c.html(
    layout({
      title: "埋め込み設定",
      userEmail: user.email ?? user.sub,
      body: settingsBody(tenantId, tenant.name, origins, null),
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }),
  );
});

ui.post("/admin/workspaces/:tenantId/origins", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
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
          title: "埋め込み設定",
          userEmail: user.email ?? user.sub,
          body: settingsBody(tenantId, tenant?.name ?? "", origins, err.message),
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
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  assertSameOriginMutation(c);
  const form = await readUrlEncodedForm(c);
  await removeTenantOrigin(c.env, tenantId, String(form.get("origin") ?? ""));
  return c.redirect(`/admin/workspaces/${tenantId}/settings`, 303);
});

ui.post("/admin/workspaces/:tenantId/delete", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  assertSameOriginMutation(c);
  const form = await readUrlEncodedForm(c);
  const tenant = await c.env.DB.prepare("SELECT name FROM tenants WHERE id = ?1")
    .bind(tenantId)
    .first<{ name: string }>();
  if (!tenant || String(form.get("confirm_name") ?? "") !== tenant.name) {
    const origins = await listTenantOrigins(c.env, tenantId);
    return c.html(layout({
      title: "埋め込み設定",
      userEmail: user.email ?? user.sub,
      body: settingsBody(tenantId, tenant?.name ?? "", origins, "ワークスペース名が一致しません。"),
      origin: originOf(c),
      nonce: c.get("cspNonce") ?? "",
    }), 400);
  }
  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM audit_events WHERE tenant_id = ?1").bind(tenantId),
    c.env.DB.prepare("DELETE FROM tenants WHERE id = ?1").bind(tenantId),
  ]);
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
    <section class="card">
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

/* ------------------------------------------------------------------ */
/* Poll form (new / edit)                                              */
/* ------------------------------------------------------------------ */

function pollFormScript(tenantId: string, pollId: string | null, nonce: string): string {
  const code = `
const TENANT = ${safeJsonForScript(tenantId)};
const POLL_ID = ${safeJsonForScript(pollId)};
const optionsEl = document.getElementById('options');
const errorEl = document.getElementById('form-error');

function addOptionRow(label, imageKey) {
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
  const remove = document.createElement('button');
  remove.type = 'button';
  remove.className = 'btn small danger opt-remove';
  remove.textContent = '削除';
  remove.addEventListener('click', () => row.remove());
  row.append(fileLabel, key, remove);
  optionsEl.append(row);
}
document.getElementById('add-option').addEventListener('click', () => addOptionRow('', null));

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
    const options = [];
    for (const row of optionsEl.querySelectorAll('.option-row')) {
      await uploadFrom(row, '.opt-file', '.opt-key');
      const label = row.querySelector('.opt-label').value.trim();
      if (!label) throw new Error('選択肢の文言が空です');
      const key = row.querySelector('.opt-key').value || null;
      options.push({ label, image_key: key });
    }
    if (options.length < 2) throw new Error('選択肢は2つ以上必要です');
    const closesRaw = document.getElementById('closes-at').value;
    const opensRaw = document.getElementById('opens-at').value;
    const payload = {
      question: document.getElementById('question').value.trim(),
      description: document.getElementById('description').value,
      image_key: document.getElementById('poll-image-key').value || null,
      allow_multiple: document.getElementById('allow-multiple').checked,
      require_login: document.getElementById('require-login').checked,
      opens_at: opensRaw ? new Date(opensRaw).toISOString() : null,
      closes_at: closesRaw ? new Date(closesRaw).toISOString() : null,
      options,
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
if (!Array.isArray(pending)) pending = [];
for (const o of pending) addOptionRow(o.label, o.image_key);
if (pending.length === 0) { addOptionRow('', null); addOptionRow('', null); }
`;
  return scriptTag(nonce, code);
}

function pollFormBody(opts: {
  tenantId: string;
  poll: PollRow | null;
  options: { label: string; image_key: string | null }[];
  nonce: string;
}): string {
  const p = opts.poll;
  const closesLocal = p?.closes_at ? escapeHtml(p.closes_at.slice(0, 16)) : "";
  const seed = safeJsonForScript(
    opts.options.map((o) => ({ label: o.label, image_key: o.image_key })),
  );
  return `
    <p class="muted small"><a href="/admin/workspaces/${opts.tenantId}">ワークスペースに戻る</a></p>
    <h1>${p ? "投票を編集" : "新しい投票を作る"}</h1>
    <div class="error" id="form-error" role="alert"></div>
    <section class="card">
    <form id="poll-form">
      <label for="question">設問文</label>
      <input id="question" type="text" required maxlength="300" value="${p ? escapeHtml(p.question) : ""}" placeholder="例: 次のイベントの日程はどれがいいですか？">
      <label for="description">説明 <span class="hint">任意。投票する人への補足を書けます。</span></label>
      <textarea id="description" maxlength="5000">${p ? escapeHtml(p.description) : ""}</textarea>
      <div id="poll-image-row">
        <label for="poll-image-file">設問の画像 <span class="hint">任意。PNG / JPEG / WebP / GIF、5 MiB まで。</span></label>
        ${p?.image_key ? `<p><img src="/images/${escapeHtml(p.image_key)}" alt="設問の画像" style="max-width:240px;border-radius:10px;border:1px solid var(--border)"></p>` : ""}
        <input id="poll-image-file" type="file" accept="image/png,image/jpeg,image/webp,image/gif">
        <input type="hidden" id="poll-image-key" value="${escapeHtml(p?.image_key ?? "")}">
      </div>
      <label for="opens-at">開始日時 <span class="hint">任意。空欄なら公開後すぐに投票できます。</span></label>
      <input id="opens-at" type="datetime-local" value="${p?.opens_at ? escapeHtml(p.opens_at.slice(0, 16)) : ""}">
      <label for="closes-at">締切日時 <span class="hint">任意。空欄なら手動で締め切るまで投票できます。</span></label>
      <input id="closes-at" type="datetime-local" value="${closesLocal}">
      <div class="check">
        <input id="allow-multiple" type="checkbox" ${p?.allow_multiple === 1 ? "checked" : ""}>
        <label for="allow-multiple" style="margin:0"><span>複数選択を許可する</span>
        <small>オフの場合は1つだけ選ぶ投票になります。</small></label>
      </div>
      <div class="check">
        <input id="require-login" type="checkbox" ${p?.require_login === 1 ? "checked" : ""}>
        <label for="require-login" style="margin:0"><span>ログイン必須にする</span>
        <small>オンにすると 0g0-id でログインした人だけが投票できます。オフ（既定）なら誰でも投票できます。</small></label>
      </div>
      <h2>選択肢</h2>
      <div id="options"></div>
      <div class="actions"><button type="button" class="btn" id="add-option">選択肢を追加</button></div>
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
      body: pollFormBody({ tenantId, poll: null, options: [], nonce: c.get("cspNonce") ?? "" }),
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
  const origin = originOf(c);
  const nonce = c.get("cspNonce") ?? "";
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
        <div class="actions">${statusActions}
          <a class="btn" href="/admin/workspaces/${tenantId}/polls/${poll.id}/results">結果を見る</a>
        </div>
      </div>
      ${poll.image_key ? `<img src="/images/${escapeHtml(poll.image_key)}" alt="設問の画像">` : ""}
    </div>
    <h2>公開 API</h2>
    <section class="card">
      <p class="small">投票の取得: <code>GET ${escapeHtml(origin)}/api/v1/polls/${escapeHtml(poll.id)}</code><br>
      投票の実行: <code>POST ${escapeHtml(origin)}/api/v1/polls/${escapeHtml(poll.id)}/vote</code><br>
      結果の取得: <code>GET ${escapeHtml(origin)}/api/v1/polls/${escapeHtml(poll.id)}/results</code></p>
      ${poll.status === "draft" ? "" : `<h3>埋め込み用スニペット</h3>
      <p class="muted small">別サイトから呼ぶときは、そのオリジンを埋め込み設定に追加してください。開始前は POLL_NOT_OPEN、締切後は POLL_CLOSED が返ります。</p>
      <div class="copyable">
        <span class="copy">
          <button type="button" class="btn small copy-button" command="--copy" commandfor="embed-snippet">スニペットをコピー</button>
          <span class="tip" role="status"></span>
        </span>
        <pre id="embed-snippet" tabindex="0">${escapeHtml(`const pollId = "${poll.id}";
const base = "${origin}";
const poll = await fetch(base + "/api/v1/polls/" + pollId).then((r) => r.json());
await fetch(base + "/api/v1/polls/" + pollId + "/vote", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ voter_token: "stable-id-for-this-voter", option_ids: [poll.poll.options[0].id] }),
});`)}</pre>
      </div>
      ${scriptTag(nonce, `
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
    `)}
    ${poll.status !== "closed" ? pollFormBody({ tenantId, poll, options, nonce }) : `<h2>内容</h2><section class="card"><p>${escapeHtml(poll.description || "")}</p><ul>${options.map((o) => `<li>${escapeHtml(o.label)}</li>`).join("")}</ul></section>`}`;
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

ui.get("/admin/workspaces/:tenantId/polls/:pollId/results", async (c) => {
  const tenantId = routeTenant(c);
  if (!tenantId) return c.redirect("/admin", 302);
  const pollId = normalizeUuid(c.req.param("pollId"));
  if (!pollId) return c.redirect(`/admin/workspaces/${tenantId}`, 302);
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  const poll = await getPollRow(c.env, pollId);
  if (!poll || poll.tenant_id !== tenantId) return c.redirect(`/admin/workspaces/${tenantId}`, 302);
  const results = await computeResults(c.env, originOf(c), poll);
  const maxVotes = Math.max(1, ...results.options.map((o) => o.votes));
  const bars = results.options
    .map((o) => {
      const pct = results.total_votes > 0 ? Math.round((o.votes / results.total_votes) * 1000) / 10 : 0;
      const width = Math.round((o.votes / maxVotes) * 1000) / 10;
      return `<div class="bar-row">
        <div>${o.image_url ? `<img src="${escapeHtml(o.image_url)}" alt="" style="width:34px;height:34px;object-fit:cover;border-radius:7px;vertical-align:middle;margin-right:.4rem">` : ""}${escapeHtml(o.label)}</div>
        <div class="bar-track" role="img" aria-label="${escapeHtml(o.label)}: ${o.votes}票 (${pct}%)"><div class="bar-fill" style="width:${width}%"></div></div>
        <div><strong>${o.votes}</strong> 票 <span class="muted">(${pct}%)</span></div>
      </div>`;
    })
    .join("");
  const body = `
    <p class="muted small"><a href="/admin/workspaces/${tenantId}/polls/${pollId}">投票に戻る</a></p>
    <h1>結果</h1>
    <div class="actions">
      <a class="btn" href="/api/v1/tenants/${escapeHtml(tenantId)}/polls/${escapeHtml(pollId)}/export?format=csv">CSV で書き出す</a>
      <a class="btn" href="/api/v1/tenants/${escapeHtml(tenantId)}/polls/${escapeHtml(pollId)}/export?format=json">JSON で書き出す</a>
    </div>
    <section class="card">
      <div class="poll-head">
        <div style="flex:1;min-width:260px">
          <strong>${escapeHtml(poll.question)}</strong>
          <p class="muted small">${statusBadge(poll.status)} ／ 投票者数 ${results.total_voters} 人 ／ 総票数 ${results.total_votes} 票${poll.closes_at ? ` ／ 締切 ${escapeHtml(poll.closes_at)}` : ""}</p>
        </div>
        ${poll.image_key ? `<img src="/images/${escapeHtml(poll.image_key)}" alt="設問の画像">` : ""}
      </div>
      ${bars || '<p class="muted">選択肢がありません。</p>'}
      <p class="muted small">割合は総票数に対する各選択肢の票数の割合です。複数選択の投票では、合計が100%を超えることがあります。</p>
      <h2>集計表</h2>
      <div class="table-wrapper" tabindex="0" role="region" aria-label="集計表">
        <table><thead><tr><th scope="col">選択肢</th><th scope="col">票数</th><th scope="col">割合</th></tr></thead>
        <tbody>${results.options.map((o) => { const pct = results.total_votes > 0 ? Math.round((o.votes / results.total_votes) * 1000) / 10 : 0; return `<tr><td data-label="選択肢">${escapeHtml(o.label)}</td><td data-label="票数">${o.votes}</td><td data-label="割合">${pct}%</td></tr>`; }).join("")}</tbody></table>
      </div>
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
