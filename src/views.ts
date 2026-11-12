/** Shared HTML shell + styles for the admin UI (server-rendered, no build step). */

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** JSON for embedding inside a <script> element. Escapes HTML-significant characters. */
export function safeJsonForScript(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

export function scriptTag(nonce: string, code: string): string {
  return `<script nonce="${escapeHtml(nonce)}">${code}</script>`;
}

export const LOGO_SVG = `<svg width="30" height="30" viewBox="0 0 64 64" role="img" aria-label="headless-vote logo"><rect width="64" height="64" rx="14" fill="#5b5bd6"/><path d="M19.2 30.1 L27.8 39.4 L45.4 20.2" fill="none" stroke="#ffffff" stroke-width="6.7" stroke-linecap="round" stroke-linejoin="round"/><rect x="17.9" y="44.8" width="28.2" height="4.8" rx="2.4" fill="#ffffff" opacity="0.92"/></svg>`;

const CSS = `
/* Color tokens follow the OS scheme via light-dark() (modern-web-guidance: dark-mode). */
:root{
  --bg:light-dark(#f6f7fb,#10121c); --surface:light-dark(#ffffff,#181b29); --surface-2:light-dark(#eef0f7,#1f2333);
  --text:light-dark(#16182b,#eceef6); --muted:light-dark(#5b6070,#a2a8bd);
  --border:light-dark(#dde1ec,#2a2f45); --accent:light-dark(#5b5bd6,#8f8ff2); --accent-strong:light-dark(#4646b8,#a5a5f5);
  --accent-soft:light-dark(#ececfb,#262647);
  --ok:light-dark(#12805c,#3ecf9a); --warn:light-dark(#b25e09,#f0a24a); --danger:light-dark(#c62f3b,#ff7a85);
  --closed-bg:light-dark(#f6e3e4,#3a2329);
  --radius:14px;
  --shadow:0 1px 2px rgba(16,18,43,.05),0 8px 24px -12px rgba(16,18,43,.18);
  color-scheme:light dark;
  accent-color:#5b5bd6;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Hiragino Kaku Gothic ProN","Noto Sans JP",sans-serif;
  background:var(--bg);color:var(--text);line-height:1.65;font-size:16px}
a{color:var(--accent-strong)}
a:focus-visible,button:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
header.site{position:sticky;top:0;z-index:10;background:color-mix(in srgb,var(--surface) 88%,transparent);
  backdrop-filter:blur(10px);border-bottom:1px solid var(--border)}
header.site .bar{max-width:1080px;margin:0 auto;padding:.65rem 1rem;display:flex;align-items:center;gap:.75rem}
.brand{display:flex;align-items:center;gap:.55rem;font-weight:700;font-size:1.1rem;color:var(--text);text-decoration:none}
.brand svg{color:var(--accent)}
header.site .spacer{flex:1}
header.site .user{color:var(--muted);font-size:.9rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:40vw}
main{max-width:1080px;margin:0 auto;padding:1.25rem 1rem 3rem}
h1{font-size:1.55rem;line-height:1.3;margin:.4rem 0 1rem}
h2{font-size:1.15rem;margin:1.6rem 0 .7rem}
p.lead{color:var(--muted);max-width:65ch}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:1.1rem 1.15rem;box-shadow:var(--shadow)}
.grid{display:grid;gap:1rem;grid-template-columns:repeat(auto-fill,minmax(290px,1fr))}
.btn{display:inline-flex;align-items:center;gap:.45rem;border:1px solid var(--border);background:var(--surface);
  color:var(--text);border-radius:10px;padding:.55rem 1rem;font-size:.95rem;font-weight:600;cursor:pointer;text-decoration:none}
.btn:hover{border-color:var(--accent)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.primary:hover{background:var(--accent-strong)}
.btn.danger{color:var(--danger)}
.btn.small{padding:.35rem .7rem;font-size:.88rem}
.badge{display:inline-block;padding:.1rem .55rem;border-radius:999px;font-size:.8rem;font-weight:700;background:var(--surface-2);color:var(--muted)}
.badge.published{background:var(--accent-soft);color:var(--accent-strong)}
.badge.closed{background:var(--closed-bg);color:var(--danger)}
label{display:block;font-weight:600;margin:.85rem 0 .3rem}
label .hint{display:block;font-weight:400;color:var(--muted);font-size:.87rem}
input[type=text],input[type=datetime-local],textarea,select{width:100%;padding:.6rem .7rem;border:1px solid var(--border);
  border-radius:10px;background:var(--surface);color:var(--text);font:inherit}
textarea{min-height:5.5rem;resize:vertical}
.check{display:flex;gap:.55rem;align-items:flex-start;margin-top:.8rem}
.check input{width:1.15rem;height:1.15rem;margin-top:.3rem;accent-color:var(--accent)}
.check span{font-weight:600}
.check small{display:block;color:var(--muted);font-weight:400}
.option-row{display:flex;gap:.6rem;align-items:center;margin-top:.55rem}
.option-row input[type=text]{flex:1}
.option-row img{width:44px;height:44px;object-fit:cover;border-radius:8px;border:1px solid var(--border)}
.poll-head{display:flex;gap:1rem;align-items:flex-start;flex-wrap:wrap}
.poll-head img{width:84px;height:84px;object-fit:cover;border-radius:12px;border:1px solid var(--border)}
.muted{color:var(--muted)}
.small{font-size:.9rem}
code{background:var(--surface-2);padding:.1rem .4rem;border-radius:6px;font-size:.88em;word-break:break-all}
pre{background:var(--surface-2);padding:.8rem;border-radius:10px;overflow:auto}
.bar-row{display:grid;grid-template-columns:minmax(90px,1fr) 3fr auto;gap:.8rem;align-items:center;margin:.55rem 0}
.bar-track{background:var(--surface-2);border-radius:999px;height:22px;overflow:hidden}
.bar-fill{background:linear-gradient(90deg,var(--accent),var(--accent-strong));height:100%;border-radius:999px;min-width:2px}
.notice{border:1px solid var(--warn);background:color-mix(in srgb,var(--warn) 10%,var(--surface));
  padding:.8rem 1rem;border-radius:10px;margin:1rem 0}
.error{border:1px solid var(--danger);color:var(--danger);padding:.8rem 1rem;border-radius:10px;margin:1rem 0;display:none}
.actions{display:flex;gap:.6rem;flex-wrap:wrap;margin-top:1rem}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:.55rem .5rem;border-bottom:1px solid var(--border);vertical-align:top}
/* Native modal dialogs (modern-web-guidance: dialog). */
dialog{border:1px solid var(--border);border-radius:var(--radius);background:var(--surface);color:var(--text);
  padding:1.25rem;max-width:min(26rem,calc(100vw - 2rem));box-shadow:var(--shadow)}
dialog:modal{overscroll-behavior:contain}
dialog::backdrop{background:rgba(0,0,0,.45);overflow:hidden;overscroll-behavior:contain}
dialog h2{margin-top:0;font-size:1.1rem}
.dialog-actions{display:flex;gap:.5rem;justify-content:flex-end;margin-top:1rem}
/* Action results announced via a live region (accessible-error-announcement). */
.notice.ok{border-color:var(--ok);background:color-mix(in srgb,var(--ok) 10%,var(--surface))}
.notice.bad{border-color:var(--danger);background:color-mix(in srgb,var(--danger) 8%,var(--surface))}
/* Fields turn red only after interaction (:user-invalid). */
input:user-invalid,textarea:user-invalid,select:user-invalid{border-color:var(--danger)}
.field-error{color:var(--danger);font-size:.87rem;margin:.3rem 0 0}
/* Responsive table: scrollable region + sticky header + stacked cards (responsive-table). */
.table-wrapper{overflow:auto;max-inline-size:100%;container-type:inline-size}
.table-wrapper thead th{position:sticky;top:0;background:var(--surface);z-index:1}
@container (max-width:34rem){
  .table-wrapper thead{display:none}
  .table-wrapper table,.table-wrapper tbody,.table-wrapper tr,.table-wrapper td{display:block}
  .table-wrapper tr{padding:.45rem 0;border-bottom:1px solid var(--border)}
  .table-wrapper td{border:0;padding:.12rem .5rem}
  .table-wrapper td::before{content:attr(data-label);display:block;font-size:.75rem;color:var(--muted)}
}
@media (max-width:640px){ .bar-row{grid-template-columns:1fr;gap:.2rem} header.site .user{display:none} }
`;

export function layout(opts: {
  title: string;
  userEmail?: string | null;
  body: string;
  origin: string;
  nonce: string;
}): string {
  const userArea = opts.userEmail
    ? `<span class="user">${escapeHtml(opts.userEmail)}</span>
       <form method="post" action="/admin/logout" style="margin:0"><button class="btn small" type="submit">ログアウト</button></form>`
    : `<a class="btn small primary" href="/admin/login">0g0-id でログイン</a>`;
  return `<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>${escapeHtml(opts.title)} | headless-vote</title>
<meta name="description" content="headless-vote — Headless 投票 SaaS。API と管理画面で投票を作成・運用できます。">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="icon" href="/favicon-32x32.png" type="image/png" sizes="32x32">
<link rel="icon" href="/favicon-16x16.png" type="image/png" sizes="16x16">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<meta property="og:title" content="headless-vote">
<meta property="og:description" content="Headless 投票 SaaS。API と管理画面で投票を作成・運用できます。">
<meta property="og:type" content="website">
<meta property="og:url" content="${escapeHtml(opts.origin)}/">
<meta property="og:image" content="${escapeHtml(opts.origin)}/ogp.png">
<meta name="twitter:card" content="summary_large_image">
<style nonce="${escapeHtml(opts.nonce)}">${CSS}</style>
</head>
<body>
<header class="site"><div class="bar">
  <a class="brand" href="/admin">${LOGO_SVG}<span>headless-vote</span></a>
  <span class="spacer"></span>
  ${userArea}
</div></header>
<main>
${opts.body}
</main>
</body>
</html>`;
}
