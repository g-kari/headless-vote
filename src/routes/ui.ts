import { Hono } from "hono";
import { getSessionUser, isTenantMember, listTenantsForUser } from "../auth";
import { randomId, randomToken, sha256Hex } from "../crypto";
import { computeResults, getPollRow, listOptionRows, nowIso } from "../domain";
import { escapeHtml, layout } from "../views";
import type { Env, PollRow, SessionUser, Variables } from "../types";

export const ui = new Hono<{ Bindings: Env; Variables: Variables }>();

function originOf(c: { req: { url: string } }): string {
  return new URL(c.req.url).origin;
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
    return c.html(layout({ title: "管理画面", userEmail: null, body, origin: originOf(c) }));
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
    }),
  );
});

ui.post("/admin/workspaces", async (c) => {
  const user = await getSessionUser(c);
  if (!user) return c.redirect("/admin/login", 302);
  const form = await c.req.formData();
  const name = String(form.get("name") ?? "").trim();
  if (!name || name.length > 120) {
    return c.html(
      layout({
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
  const tenantId = c.req.param("tenantId");
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
    <div class="actions"><a class="btn primary" href="/admin/workspaces/${tenantId}/polls/new">新しい投票を作る</a></div>
    <h2>投票一覧</h2>
    <section class="card">
      ${rows ? `<div class="table-wrapper" tabindex="0" role="region" aria-label="投票一覧"><table><thead><tr><th scope="col">設問</th><th scope="col">状態</th><th scope="col">設定</th><th scope="col">締切</th><th scope="col"><span class="muted">操作</span></th></tr></thead><tbody>${rows}</tbody></table></div>` : '<p class="muted">まだ投票がありません。</p>'}
    </section>
    <h2>API キー</h2>
    <section class="card">
      <p class="muted">管理 API（<code>/api/v1/tenants/${tenantId}/…</code>）の認証には、このワークスペースの API キーを使います。キーを再発行すると、古いキーは使えなくなります。</p>
      <button class="btn danger" type="button" onclick="document.getElementById('rotate-dialog').showModal()">API キーを再発行する</button>
      <dialog id="rotate-dialog" aria-labelledby="rotate-dialog-title">
        <h2 id="rotate-dialog-title">API キーを再発行しますか？</h2>
        <p>再発行すると、古いキーは使えなくなります。新しいキーは発行直後に一度だけ表示されます。</p>
        <form method="post" action="/admin/workspaces/${tenantId}/rotate-key">
          <div class="dialog-actions">
            <button class="btn" type="button" autofocus onclick="this.closest('dialog').close()">やめる</button>
            <button class="btn danger" type="submit">再発行する</button>
          </div>
        </form>
      </dialog>
    </section>`;
  return c.html(
    layout({
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
  const apiKey = randomToken("hvk");
  await c.env.DB.prepare("UPDATE tenants SET api_key_hash = ?1 WHERE id = ?2")
    .bind(await sha256Hex(apiKey), tenantId)
    .run();
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
    }),
  );
});

/* ------------------------------------------------------------------ */
/* Poll form (new / edit)                                              */
/* ------------------------------------------------------------------ */

function pollFormScript(tenantId: string, pollId: string | null): string {
  const isEdit = pollId !== null;
  return `
<script>
const TENANT = ${JSON.stringify(tenantId)};
const POLL_ID = ${JSON.stringify(pollId)};
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
</script>`;
}

function pollFormBody(opts: {
  tenantId: string;
  poll: PollRow | null;
  options: { label: string; image_key: string | null }[];
}): string {
  const p = opts.poll;
  const closesLocal = p?.closes_at ? p.closes_at.slice(0, 16) : "";
  const optionRows = opts.options
    .map(
      (o) => `
    <script>window.__pendingOptions = window.__pendingOptions || []; window.__pendingOptions.push(${JSON.stringify(o)});</script>`,
    )
    .join("");
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
    </section>
    ${optionRows}
    ${pollFormScript(opts.tenantId, p?.id ?? null)}
    <script>
      for (const o of (window.__pendingOptions || [])) addOptionRow(o.label, o.image_key);
      if (!window.__pendingOptions || window.__pendingOptions.length === 0) { addOptionRow('', null); addOptionRow('', null); }
    </script>`;
}

ui.get("/admin/workspaces/:tenantId/polls/new", async (c) => {
  const tenantId = c.req.param("tenantId");
  const user = await requireMember(c, tenantId);
  if (!user) return c.redirect("/admin", 302);
  return c.html(
    layout({
      title: "新しい投票を作る",
      userEmail: user.email ?? user.sub,
      body: pollFormBody({ tenantId, poll: null, options: [] }),
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
  const origin = originOf(c);
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
        <div class="actions">${statusActions}
          <a class="btn" href="/admin/workspaces/${tenantId}/polls/${poll.id}/results">結果を見る</a>
        </div>
      </div>
      ${poll.image_key ? `<img src="/images/${escapeHtml(poll.image_key)}" alt="設問の画像">` : ""}
    </div>
    <h2>公開 API</h2>
    <section class="card">
      <p class="small">投票の取得: <code>GET ${origin}/api/v1/polls/${poll.id}</code><br>
      投票の実行: <code>POST ${origin}/api/v1/polls/${poll.id}/vote</code><br>
      結果の取得: <code>GET ${origin}/api/v1/polls/${poll.id}/results</code></p>
    </section>
    <div id="flash" class="notice bad" role="alert" hidden></div>
    <dialog id="status-dialog" aria-labelledby="status-dialog-title">
      <h2 id="status-dialog-title">状態を変更しますか？</h2>
      <p id="status-dialog-text" class="muted"></p>
      <div class="dialog-actions">
        <button class="btn" type="button" autofocus onclick="document.getElementById('status-dialog').close()">やめる</button>
        <button class="btn primary" type="button" onclick="doStatus()">変更する</button>
      </div>
    </dialog>
    <script>
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
        const res = await fetch('/api/v1/tenants/${tenantId}/polls/${poll.id}/status', {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ status: pendingStatus }), credentials: 'same-origin',
        });
        if (res.ok) { location.reload(); return; }
        const d = await res.json().catch(() => ({}));
        const flash = document.getElementById('flash');
        flash.textContent = (d.error && d.error.message) || '状態の変更に失敗しました';
        flash.hidden = false;
      }
    </script>
    ${poll.status !== "closed" ? pollFormBody({ tenantId, poll, options }) : `<h2>内容</h2><section class="card"><p>${escapeHtml(poll.description || "")}</p><ul>${options.map((o) => `<li>${escapeHtml(o.label)}</li>`).join("")}</ul></section>`}`;
  return c.html(
    layout({
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
    }),
  );
});
