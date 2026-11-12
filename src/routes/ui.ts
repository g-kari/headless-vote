import { Hono } from "hono";
import {
  clearSessionCookie,
  csrfTokenForSession,
  getSessionUser,
  isTenantMember,
  listTenantsForUser,
  revokeAllSessions,
  verifyCsrfToken,
} from "../auth";
import { randomId, randomToken, sha256Hex } from "../crypto";
import { computeResults, getPollRow, listOptionRows, nowIso } from "../domain";
import { enforceRateLimit, HOUR, LIMITS } from "../rate-limit";
import { escapeHtml, jsonForScript, layout } from "../views";
import type { AppContext, Env, PollRow, SessionUser, Variables } from "../types";

export const ui = new Hono<{ Bindings: Env; Variables: Variables }>();

function originOf(c: { req: { url: string } }): string {
  return new URL(c.req.url).origin;
}

/** Render the shared layout with this session's CSRF token wired in. */
async function page(
  c: AppContext,
  opts: { title: string; userEmail?: string | null; body: string; origin: string },
): Promise<string> {
  const csrfToken = await csrfTokenForSession(c);
  return layout(Object.assign({}, opts, { csrfToken }));
}

/** 403 page for a failed CSRF check on a UI form POST. */
async function csrfFailure(c: AppContext, user: SessionUser) {
  return c.html(
    await page(c, {
      title: "エラー",
      userEmail: user.email ?? user.sub,
      body: `<h1>リクエストを確認できませんでした</h1><p class="muted">セキュリティ確認（CSRF トークン）に失敗しました。画面を開き直してから、もう一度お試しください。</p><p><a href="/admin">管理画面に戻る</a></p>`,
      origin: originOf(c),
    }),
    403,
  );
}

async function formCsrfOk(c: AppContext, form: FormData): Promise<boolean> {
  return verifyCsrfToken(c, String(form.get("csrf_token") ?? "") || null);
}

async function requireMember(
  c: { env: Env; req: { url: string } },
  tenantId: string,
): Promise<SessionUser | null> {
  const user = await getSessionUser(c as never);
  if (!user) return null;
  if (!(await isTenantMember(c.env, tenantId, user.sub))) return null;
  return user;
}

/* ------------------------------------------------------------------ */
/* Landing + workspace list                                            */
/* ------------------------------------------------------------------ */

ui.get("/", async (c) => {
  const user = await getSessionUser(c);
  const body = `
    <h1>headless-vote 投票管理</h1>
    <p class="lead">投票の作成・公開・集計を行うサービスです。管理画面と API の両方から、同じ投票を操作できます。</p>
    <div class="actions">
      <a class="btn primary" href="/admin">管理画面を開く</a>
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
      <dt>投票の設定</dt><dd>設問文・説明・選択肢（2〜50件）。選択肢と設問に画像を添付できます。</dd>
      <dt>投票ごとに選べる項目</dt><dd>ログイン必須か任意か、複数選択の可否、締切日時。</dd>
      <dt>投票の数え方</dt><dd>1人1票。締切前なら投票の変更ができます。ログインした人はアカウント単位、匿名の人は投票者トークン単位で数えます。</dd>
      <dt>匿名投票の限界</dt><dd>トークンを変えた同一人物は別人として数えられます。厳密に1人1票が必要な投票では「ログイン必須」を選んでください。</dd>
      <dt>集計結果</dt><dd>管理画面のグラフと API（GET /api/v1/polls/:id/results）で取得できます。</dd>
    </dl>`;
  return c.html(
    await page(c, {
      title: "投票 SaaS",
      userEmail: user?.email ?? user?.sub ?? null,
      body,
      origin: originOf(c),
    }),
  );
});

ui.get("/admin", async (c) => {
  const user = await getSessionUser(c);
  if (!user) {
    const body = `
      <h1>管理画面</h1>
      <p class="lead">ログインは 0g0-id を使います。ログイン後、ワークスペース（投票の運用単位）を作成し、投票の設定と結果の確認ができます。</p>
      <div class="actions"><a class="btn primary" href="/admin/login">0g0-id でログイン</a></div>
      <h2>API キーで使う場合</h2>
      <p class="muted">画面を使わない運用では、テナント作成時に発行される API キーで管理 API を呼び出せます。API キーは <code>POST /api/v1/tenants</code> で発行します（README 参照）。</p>`;
    return c.html(await page(c, { title: "管理画面", userEmail: null, body, origin: originOf(c) }));
  }

  const tenants = await listTenantsForUser(c.env, user.sub);
  const csrf = await csrfTokenForSession(c);
  const csrfField = csrf
    ? `<input type="hidden" name="csrf_token" value="${escapeHtml(csrf)}">`
    : "";
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
      ${csrfField}
      <label for="ws-name">ワークスペース名</label>
      <input id="ws-name" type="text" name="name" required maxlength="120" placeholder="例: イベント投票">
      <div class="actions"><button class="btn primary" type="submit">作成する</button></div>
    </form>
    <h2>セッション</h2>
    <p class="muted">ログイン中のセッションはサーバ側で管理されています。端末をなくした場合などは、すべてのセッションを無効化できます（この端末からもログアウトします）。</p>
    <form method="post" action="/admin/sessions/revoke-all">
      ${csrfField}
      <div class="actions"><button class="btn danger" type="submit">すべてのセッションを無効化する</button></div>
    </form>`;
  return c.html(
    await page(c, {
      title: "ワークスペース",
      userEmail: user.email ?? user.sub,
      body,
      origin: originOf(c),
    }),
  );
});

ui.post("/admin/workspaces", async (c) => {
  const user = await getSessionUser(c);
  if (!user) return c.redirect("/admin/login", 302);
  await enforceRateLimit(
    c.env,
    "workspace-create",
    user.sub,
    LIMITS.workspaceCreatePerUserPerHour,
    HOUR,
  );
  const form = await c.req.formData();
  if (!(await formCsrfOk(c, form))) return csrfFailure(c, user);
  const name = String(form.get("name") ?? "").trim();
  if (!name || name.length > 120) {
    return c.html(
      await page(c, {
        title: "エラー",
        userEmail: user.email ?? user.sub,
        body: `<h1>名前を確認してください</h1><p class="muted">ワークスペース名は1〜120文字で入力してください。</p><p><a href="/admin">戻る</a></p>`,
        origin: originOf(c),
      }),
      400,
    );
  }
  const tenantId = randomId();
  const apiKey = randomToken("hvk");
  const now = nowIso();
  await c.env.DB.batch([
    c.env.DB.prepare(
      "INSERT INTO tenants (id, name, api_key_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
    ).bind(tenantId, name, await sha256Hex(apiKey), now),
    c.env.DB.prepare(
      "INSERT INTO tenant_members (tenant_id, user_sub, role, created_at) VALUES (?1, ?2, 'owner', ?3)",
    ).bind(tenantId, user.sub, now),
  ]);
  const body = `
    <h1>ワークスペースを作成しました</h1>
    <p><strong>${escapeHtml(name)}</strong></p>
    <div class="notice"><strong>API キーはこの画面でだけ表示されます。</strong>
    管理 API の認証に使うので、控えて安全な場所に保管してください。</div>
    <p><code style="font-size:1.05rem">${escapeHtml(apiKey)}</code></p>
    <div class="actions"><a class="btn primary" href="/admin/workspaces/${tenantId}">ワークスペースを開く</a></div>`;
  return c.html(
    await page(c, {
      title: "ワークスペースを作成しました",
      userEmail: user.email ?? user.sub,
      body,
      origin: originOf(c),
    }),
  );
});

/** Revoke every session of the signed-in user (all devices). */
ui.post("/admin/sessions/revoke-all", async (c) => {
  const user = await getSessionUser(c);
  if (!user) return c.redirect("/admin/login", 302);
  const form = await c.req.formData();
  if (!(await formCsrfOk(c, form))) return csrfFailure(c, user);
  await revokeAllSessions(c.env, user.sub);
  c.header("Set-Cookie", clearSessionCookie());
  return c.redirect("/admin", 302);
});

/* ------------------------------------------------------------------ */
/* Workspace dashboard                                                 */
/* ------------------------------------------------------------------ */

function statusBadge(status: PollRow["status"]): string {
  const label = status === "draft" ? "下書き" : status === "published" ? "公開中" : "締切済み";
  return `<span class="badge ${status}">${label}</span>`;
}

ui.get("/admin/workspaces/:tenantId", async (c) => {
  const tenantId = c.req.param("tenantId");
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  const tenant = await c.env.DB.prepare("SELECT * FROM tenants WHERE id = ?1")
    .bind(tenantId)
    .first<{ id: string; name: string }>();
  if (!tenant) return c.redirect("/admin", 302);
  const csrf = await csrfTokenForSession(c);
  const csrfField = csrf
    ? `<input type="hidden" name="csrf_token" value="${escapeHtml(csrf)}">`
    : "";
  const polls = await c.env.DB.prepare(
    "SELECT * FROM polls WHERE tenant_id = ?1 ORDER BY created_at DESC",
  )
    .bind(tenantId)
    .all<PollRow>();
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
  const counts = {
    total: polls.results.length,
    published: polls.results.filter((p) => p.status === "published").length,
    draft: polls.results.filter((p) => p.status === "draft").length,
    closed: polls.results.filter((p) => p.status === "closed").length,
  };
  const body = `
    <p class="muted small"><a href="/admin">ワークスペース一覧</a></p>
    <h1>${escapeHtml(tenant.name)}</h1>
    <div class="stats" role="img" aria-label="投票の件数: 合計 ${counts.total} 件、公開中 ${counts.published} 件、下書き ${counts.draft} 件、締切済み ${counts.closed} 件">
      <div class="stat"><span class="num">${counts.total}</span><span class="lbl">投票の合計</span></div>
      <div class="stat"><span class="num">${counts.published}</span><span class="lbl">公開中</span></div>
      <div class="stat"><span class="num">${counts.draft}</span><span class="lbl">下書き</span></div>
      <div class="stat"><span class="num">${counts.closed}</span><span class="lbl">締切済み</span></div>
    </div>
    <div class="actions"><a class="btn primary" href="/admin/workspaces/${tenantId}/polls/new">新しい投票を作る</a></div>
    <h2>投票一覧</h2>
    ${rows ? `<div class="table-wrapper" tabindex="0" role="region" aria-label="投票一覧"><table><thead><tr><th scope="col">設問</th><th scope="col">状態</th><th scope="col">設定</th><th scope="col">締切</th><th scope="col"><span class="muted">操作</span></th></tr></thead><tbody>${rows}</tbody></table></div>` : '<p class="muted">まだ投票がありません。</p>'}
    <h2>API キー</h2>
    <p class="muted">管理 API（<code>/api/v1/tenants/${tenantId}/…</code>）の認証には、このワークスペースの API キーを使います。キーを再発行すると、古いキーは使えなくなります。</p>
    <button class="btn danger" type="button" onclick="document.getElementById('rotate-dialog').showModal()">API キーを再発行する</button>
    <dialog id="rotate-dialog" closedby="any" aria-labelledby="rotate-dialog-title">
      <h2 id="rotate-dialog-title">API キーを再発行しますか？</h2>
      <p>再発行すると、古いキーは使えなくなります。新しいキーは発行直後に一度だけ表示されます。</p>
      <form method="post" action="/admin/workspaces/${tenantId}/rotate-key">
        ${csrfField}
        <div class="dialog-actions">
          <button class="btn" type="button" autofocus onclick="this.closest('dialog').close()">やめる</button>
          <button class="btn danger" type="submit">再発行する</button>
        </div>
      </form>
    </dialog>`;
  return c.html(
    await page(c, {
      title: tenant.name,
      userEmail: user.email ?? user.sub,
      body,
      origin: originOf(c),
    }),
  );
});

ui.post("/admin/workspaces/:tenantId/rotate-key", async (c) => {
  const tenantId = c.req.param("tenantId");
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  await enforceRateLimit(
    c.env,
    "rotate-key",
    tenantId,
    LIMITS.rotateKeyPerTenantPerHour,
    HOUR,
  );
  let form: FormData;
  try {
    form = await c.req.formData();
  } catch {
    return csrfFailure(c, user);
  }
  if (!(await formCsrfOk(c, form))) return csrfFailure(c, user);
  const apiKey = randomToken("hvk");
  await c.env.DB.prepare("UPDATE tenants SET api_key_hash = ?1 WHERE id = ?2")
    .bind(await sha256Hex(apiKey), tenantId)
    .run();
  const body = `
    <h1>API キーを再発行しました</h1>
    <div class="notice"><strong>新しい API キーはこの画面でだけ表示されます。</strong> 控えて安全な場所に保管してください。古いキーはもう使えません。</div>
    <p><code style="font-size:1.05rem">${escapeHtml(apiKey)}</code></p>
    <div class="actions"><a class="btn primary" href="/admin/workspaces/${tenantId}">ワークスペースに戻る</a></div>`;
  return c.html(
    await page(c, {
      title: "API キーを再発行しました",
      userEmail: user.email ?? user.sub,
      body,
      origin: originOf(c),
    }),
  );
});

/* ------------------------------------------------------------------ */
/* Poll form (new / edit)                                              */
/* ------------------------------------------------------------------ */

function pollFormScript(
  tenantId: string,
  pollId: string | null,
  csrfToken: string | null,
): string {
  const isEdit = pollId !== null;
  return `
<script>
const TENANT = ${jsonForScript(tenantId)};
const POLL_ID = ${jsonForScript(pollId)};
const CSRF_TOKEN = ${jsonForScript(csrfToken)};
const optionsEl = document.getElementById('options');
const errorEl = document.getElementById('form-error');

function addOptionRow(label, imageKey) {
  const row = document.createElement('div');
  row.className = 'option-row';
  row.innerHTML =
    '<input type="text" class="opt-label" maxlength="200" placeholder="選択肢の文言" value="">' +
    (imageKey ? '<img class="opt-preview" alt="">' : '') +
    '<label class="btn small" style="margin:0">画像<input type="file" class="opt-file" accept="image/png,image/jpeg,image/webp,image/gif" hidden></label>' +
    '<input type="hidden" class="opt-key">' +
    '<button type="button" class="btn small danger opt-remove">削除</button>';
  row.querySelector('.opt-label').value = label || '';
  row.querySelector('.opt-label').addEventListener('input', (ev) => ev.target.removeAttribute('aria-invalid'));
  row.querySelector('.opt-key').value = imageKey || '';
  const img = row.querySelector('.opt-preview');
  if (img && imageKey) img.src = '/images/' + imageKey;
  row.querySelector('.opt-remove').addEventListener('click', () => row.remove());
  optionsEl.appendChild(row);
}
document.getElementById('add-option').addEventListener('click', () => addOptionRow('', null));

async function uploadImage(file) {
  const res = await fetch('/api/v1/tenants/' + TENANT + '/images', {
    method: 'POST',
    headers: { 'content-type': file.type, 'x-csrf-token': CSRF_TOKEN },
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
      const labelInput = row.querySelector('.opt-label');
      const label = labelInput.value.trim();
      if (!label) {
        labelInput.setAttribute('aria-invalid', 'true');
        labelInput.focus();
        throw new Error('選択肢の文言が空です');
      }
      const key = row.querySelector('.opt-key').value || null;
      options.push({ label, image_key: key });
    }
    if (options.length < 2) throw new Error('選択肢は2つ以上必要です');
    const closesRaw = document.getElementById('closes-at').value;
    const payload = {
      question: document.getElementById('question').value.trim(),
      description: document.getElementById('description').value,
      image_key: document.getElementById('poll-image-key').value || null,
      allow_multiple: document.getElementById('allow-multiple').checked,
      require_login: document.getElementById('require-login').checked,
      closes_at: closesRaw ? new Date(closesRaw).toISOString() : null,
      options,
    };
    const url = POLL_ID
      ? '/api/v1/tenants/' + TENANT + '/polls/' + POLL_ID
      : '/api/v1/tenants/' + TENANT + '/polls';
    const res = await fetch(url, {
      method: POLL_ID ? 'PATCH' : 'POST',
      headers: { 'content-type': 'application/json', 'x-csrf-token': CSRF_TOKEN },
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
</script>`;
}

function pollFormBody(opts: {
  tenantId: string;
  poll: PollRow | null;
  options: { label: string; image_key: string | null }[];
  csrfToken: string | null;
}): string {
  const p = opts.poll;
  const closesLocal = p?.closes_at ? p.closes_at.slice(0, 16) : "";
  // Option data travels as a JSON data block (never executed as code)
  // with script-breaking characters escaped by jsonForScript.
  const optionsData = `<script type="application/json" id="pending-options">${jsonForScript(opts.options)}</script>`;
  return `
    <p class="muted small"><a href="/admin/workspaces/${opts.tenantId}">ワークスペースに戻る</a></p>
    <h1>${p ? "投票を編集" : "新しい投票を作る"}</h1>
    <div class="error" id="form-error" role="alert"></div>
    <form id="poll-form">
      <label for="question">設問文</label>
      <input id="question" type="text" required maxlength="300" value="${p ? escapeHtml(p.question) : ""}" placeholder="例: 次のイベントの日程はどれがいいですか？">
      <label for="description">説明 <span class="hint">任意。投票する人への補足を書けます。</span></label>
      <textarea id="description" maxlength="5000">${p ? escapeHtml(p.description) : ""}</textarea>
      <div id="poll-image-row">
        <label for="poll-image-file">設問の画像 <span class="hint">任意。PNG / JPEG / WebP / GIF、5 MiB まで。</span></label>
        ${p?.image_key ? `<p><img src="/images/${escapeHtml(p.image_key)}" alt="設問の画像" style="max-width:240px;border-radius:10px;border:1px solid var(--border)"></p>` : ""}
        <input id="poll-image-file" type="file" accept="image/png,image/jpeg,image/webp,image/gif">
        <input type="hidden" id="poll-image-key" value="${p?.image_key ?? ""}">
      </div>
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
    ${optionsData}
    ${pollFormScript(opts.tenantId, p?.id ?? null, opts.csrfToken)}
    <script>
      const initialOptions = JSON.parse(document.getElementById('pending-options').textContent);
      for (const o of initialOptions) addOptionRow(o.label, o.image_key);
      if (initialOptions.length === 0) { addOptionRow('', null); addOptionRow('', null); }
    </script>`;
}

ui.get("/admin/workspaces/:tenantId/polls/new", async (c) => {
  const tenantId = c.req.param("tenantId");
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  const csrfToken = await csrfTokenForSession(c);
  return c.html(
    await page(c, {
      title: "新しい投票を作る",
      userEmail: user.email ?? user.sub,
      body: pollFormBody({ tenantId, poll: null, options: [], csrfToken }),
      origin: originOf(c),
    }),
  );
});

ui.get("/admin/workspaces/:tenantId/polls/:pollId", async (c) => {
  const tenantId = c.req.param("tenantId");
  const pollId = c.req.param("pollId");
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  const poll = await getPollRow(c.env, pollId);
  if (!poll || poll.tenant_id !== tenantId) return c.redirect(`/admin/workspaces/${tenantId}`, 302);
  const options = await listOptionRows(c.env, pollId);
  const csrfToken = await csrfTokenForSession(c);
  const origin = originOf(c);
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
      ? `<button class="btn primary" type="button" onclick="askStatus('published','公開する')">公開する</button>`
      : poll.status === "published"
        ? `<button class="btn danger" type="button" onclick="askStatus('closed','締め切る')">締め切る</button>`
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
    <p class="small">投票の取得: <code>GET ${origin}/api/v1/polls/${poll.id}</code><br>
    投票の実行: <code>POST ${origin}/api/v1/polls/${poll.id}/vote</code><br>
    結果の取得: <code>GET ${origin}/api/v1/polls/${poll.id}/results</code></p>
    <div id="flash" class="notice bad" role="alert" hidden></div>
    <dialog id="status-dialog" closedby="any" aria-labelledby="status-dialog-title">
      <h2 id="status-dialog-title">状態を変更しますか？</h2>
      <p id="status-dialog-text" class="muted"></p>
      <div class="dialog-actions">
        <button class="btn" type="button" autofocus onclick="document.getElementById('status-dialog').close()">やめる</button>
        <button class="btn primary" type="button" onclick="doStatus()">変更する</button>
      </div>
    </dialog>
    <script>
      const STATUS_URL = ${jsonForScript(`/api/v1/tenants/${tenantId}/polls/${poll.id}/status`)};
      const STATUS_CSRF = ${jsonForScript(csrfToken)};
      let pendingStatus = null;
      function askStatus(status, label) {
        pendingStatus = status;
        document.getElementById('status-dialog-text').textContent =
          status === 'published' ? 'この投票を公開します。公開後は API から投票できるようになります。' : 'この投票を締め切ります。締切後は投票できなくなります。';
        document.getElementById('status-dialog-title').textContent = label + 'しますか？';
        document.getElementById('status-dialog').showModal();
      }
      async function doStatus() {
        document.getElementById('status-dialog').close();
        const res = await fetch(STATUS_URL, {
          method: 'POST', headers: { 'content-type': 'application/json', 'x-csrf-token': STATUS_CSRF },
          body: JSON.stringify({ status: pendingStatus }), credentials: 'same-origin',
        });
        if (res.ok) { location.reload(); return; }
        const d = await res.json().catch(() => ({}));
        const flash = document.getElementById('flash');
        flash.textContent = (d.error && d.error.message) || '状態の変更に失敗しました';
        flash.hidden = false;
      }
    </script>
    ${poll.status !== "closed" ? pollFormBody({ tenantId, poll, options, csrfToken }) : `<h2>内容</h2><p>${escapeHtml(poll.description || "")}</p><ul>${options.map((o) => `<li>${escapeHtml(o.label)}</li>`).join("")}</ul>`}`;
  return c.html(
    await page(c, {
      title: poll.question,
      userEmail: user.email ?? user.sub,
      body,
      origin,
    }),
  );
});

/* ------------------------------------------------------------------ */
/* Results page                                                        */
/* ------------------------------------------------------------------ */

ui.get("/admin/workspaces/:tenantId/polls/:pollId/results", async (c) => {
  const tenantId = c.req.param("tenantId");
  const pollId = c.req.param("pollId");
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  const poll = await getPollRow(c.env, pollId);
  if (!poll || poll.tenant_id !== tenantId) return c.redirect(`/admin/workspaces/${tenantId}`, 302);
  const results = await computeResults(c.env, originOf(c), poll);
  const maxVotes = Math.max(1, ...results.options.map((o) => o.votes));
  // Saturated categorical palette for the stacked share bar (no pastels).
  const SEGMENT_COLORS = ["#1e4fd8", "#e07b00", "#0c6b34", "#b91c1c", "#6d28d9", "#0e7490"];
  const colorOf = (i: number) => SEGMENT_COLORS[i % SEGMENT_COLORS.length] as string;
  const bars = results.options
    .map((o, i) => {
      const pct = results.total_votes > 0 ? Math.round((o.votes / results.total_votes) * 1000) / 10 : 0;
      const width = Math.round((o.votes / maxVotes) * 1000) / 10;
      return `<div class="bar-row">
        <div>${o.image_url ? `<img src="${escapeHtml(o.image_url)}" alt="" style="width:34px;height:34px;object-fit:cover;vertical-align:middle;margin-right:.4rem">` : ""}${escapeHtml(o.label)}</div>
        <div class="bar-track" role="img" aria-label="${escapeHtml(o.label)}: ${o.votes}票 (${pct}%)"><div class="bar-fill" style="width:${width}%;--d:${(i * 0.08).toFixed(2)}s"></div></div>
        <div><strong>${o.votes}</strong> 票 <span class="muted">(${pct}%)</span></div>
      </div>`;
    })
    .join("");
  const stackSegments = results.options
    .map((o, i) => {
      const pct = results.total_votes > 0 ? (o.votes / results.total_votes) * 100 : 0;
      return `<div class="stack-seg" style="width:${pct}%;background:${colorOf(i)};--d:${(i * 0.08).toFixed(2)}s"></div>`;
    })
    .join("");
  const legend = results.options
    .map((o, i) => `<span><span class="sw" style="background:${colorOf(i)}"></span>${escapeHtml(o.label)}</span>`)
    .join("");
  const body = `
    <p class="muted small"><a href="/admin/workspaces/${tenantId}/polls/${pollId}">投票に戻る</a></p>
    <h1>結果</h1>
    <div class="poll-head">
      <div style="flex:1;min-width:260px">
        <strong>${escapeHtml(poll.question)}</strong>
        <p class="muted small">${statusBadge(poll.status)} ／ 投票者数 ${results.total_voters} 人 ／ 総票数 ${results.total_votes} 票${poll.closes_at ? ` ／ 締切 ${escapeHtml(poll.closes_at)}` : ""}</p>
      </div>
      ${poll.image_key ? `<img src="/images/${escapeHtml(poll.image_key)}" alt="設問の画像">` : ""}
    </div>
    <h2>得票割合</h2>
    ${results.total_votes > 0 ? `<div class="stack" role="img" aria-label="得票割合の内訳">${stackSegments}</div><div class="legend">${legend}</div>` : '<p class="muted">まだ票が入っていません。</p>'}
    <h2>選択肢ごとの票数</h2>
    ${bars || '<p class="muted">選択肢がありません。</p>'}
    <p class="muted small">割合は総票数に対する各選択肢の票数の割合です。複数選択の投票では、合計が100%を超えることがあります。</p>
    <h2>集計表</h2>
    <div class="table-wrapper" tabindex="0" role="region" aria-label="集計表">
      <table><thead><tr><th scope="col">選択肢</th><th scope="col">票数</th><th scope="col">割合</th></tr></thead>
      <tbody>${results.options.map((o) => { const pct = results.total_votes > 0 ? Math.round((o.votes / results.total_votes) * 1000) / 10 : 0; return `<tr><td data-label="選択肢">${escapeHtml(o.label)}</td><td data-label="票数">${o.votes}</td><td data-label="割合">${pct}%</td></tr>`; }).join("")}</tbody></table>
    </div>`;
  return c.html(
    await page(c, {
      title: `結果: ${poll.question}`,
      userEmail: user.email ?? user.sub,
      body,
      origin: originOf(c),
    }),
  );
});
