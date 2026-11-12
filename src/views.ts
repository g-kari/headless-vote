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

/*
 * Design system (carried over from the PR #4 revision):
 * - No card layouts and no pastel tints: flat sections separated by
 *   rules, neutral grays, and one saturated accent color.
 * - Structure and results are shown as diagrams (flow steps, bars,
 *   stacked share bar) rather than prose blocks.
 * - Motion: cross-document view transitions, entrance animation and
 *   animated bars, all only under prefers-reduced-motion: no-preference.
 */
export function scriptTag(nonce: string, code: string): string {
  return `<script nonce="${escapeHtml(nonce)}">${code}</script>`;
}

export const LOGO_SVG = `<svg width="30" height="30" viewBox="0 0 64 64" role="img" aria-label="headless-vote logo"><rect width="64" height="64" rx="14" fill="#1e4fd8"/><path d="M19.2 30.1 L27.8 39.4 L45.4 20.2" fill="none" stroke="#ffffff" stroke-width="6.7" stroke-linecap="round" stroke-linejoin="round"/><rect x="17.9" y="44.8" width="28.2" height="4.8" rx="2.4" fill="#ffffff" opacity="0.92"/></svg>`;

const CSS = `
:root{
  --bg:light-dark(#ffffff,#0c1015); --surface-2:light-dark(#eceff3,#1a212b);
  --text:light-dark(#12161c,#eef2f7); --muted:light-dark(#454f5c,#a7b2c0);
  --border:light-dark(#77808e,#5b6a7d); --accent:light-dark(#1e4fd8,#5b8cff);
  --accent-strong:light-dark(#173ea8,#8fb0ff); --on-accent:light-dark(#ffffff,#0a1120);
  --ok:light-dark(#0c6b34,#3ecf8a); --warn:light-dark(#8a5a00,#f0a24a); --danger:light-dark(#b91c1c,#ff7a85);
  color-scheme:light dark;
  accent-color:var(--accent);
  scrollbar-color:var(--border) var(--bg);
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Hiragino Kaku Gothic ProN","Noto Sans JP",sans-serif;
  background:var(--bg);color:var(--text);line-height:1.65;font-size:100%}
a{color:var(--accent-strong)}
a:focus-visible,button:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.skip{position:absolute;left:.5rem;top:-4rem;z-index:30;background:var(--text);color:var(--bg);
  padding:.5rem .9rem;font-weight:700;transition:top .15s ease}
.skip:focus{top:.5rem;color:var(--bg)}
header.site{position:sticky;top:0;z-index:10;background:var(--bg);border-bottom:2px solid var(--text)}
header.site .bar{max-width:1080px;margin:0 auto;padding:.6rem 1rem;display:flex;align-items:center;gap:.75rem}
.brand{display:flex;align-items:center;gap:.55rem;font-weight:700;font-size:1.1rem;color:var(--text);text-decoration:none}
header.site .spacer{flex:1}
header.site .user{color:var(--muted);font-size:.9rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:40vw}
main{max-width:1080px;margin:0 auto;padding:1.25rem 1rem 3rem}
h1{font-size:1.55rem;line-height:1.35;margin:.4rem 0 1rem}
h2{font-size:1.12rem;margin:2rem 0 .8rem;padding-bottom:.35rem;border-bottom:2px solid var(--text)}
p.lead{color:var(--muted);max-width:65ch}
.section{border-top:1px solid var(--border);padding-top:1rem;margin-top:1rem}
.btn{display:inline-flex;align-items:center;gap:.45rem;border:2px solid var(--text);background:var(--bg);
  color:var(--text);padding:.5rem 1rem;font-size:.95rem;font-weight:700;cursor:pointer;text-decoration:none;
  transition:background-color .15s ease,color .15s ease,border-color .15s ease,transform .15s ease}
.btn:hover{border-color:var(--accent);color:var(--accent-strong)}
.btn:active{transform:translateY(1px)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}
.btn.primary:hover{background:var(--accent-strong);border-color:var(--accent-strong);color:var(--on-accent)}
.btn.danger{color:var(--danger);border-color:var(--danger)}
.btn.danger:hover{background:var(--danger);color:#fff}
.btn.small{padding:.3rem .7rem;font-size:.88rem}
.badge{display:inline-block;padding:.12rem .6rem;font-size:.8rem;font-weight:700;background:var(--muted);color:var(--bg)}
.badge.published{background:var(--accent);color:var(--on-accent)}
.badge.closed{background:var(--danger);color:#fff}
label{display:block;font-weight:600;margin:.85rem 0 .3rem}
label .hint{display:block;font-weight:400;color:var(--muted);font-size:.87rem}
input[type=text],input[type=datetime-local],textarea,select{width:100%;padding:.6rem .7rem;border:1.5px solid var(--border);
  background:var(--bg);color:var(--text);font:inherit}
input[aria-invalid="true"]{border-color:var(--danger);outline:2px solid var(--danger);outline-offset:1px}
textarea{min-height:5.5rem;resize:vertical}
.check{display:flex;gap:.55rem;align-items:flex-start;margin-top:.8rem}
.check input{width:1.15rem;height:1.15rem;margin-top:.3rem;accent-color:var(--accent)}
.check span{font-weight:600}
.check small{display:block;color:var(--muted);font-weight:400}
.option-row{display:flex;gap:.6rem;align-items:center;margin-top:.55rem}
.option-row input[type=text]{flex:1}
.option-row img{width:44px;height:44px;object-fit:cover;border:1px solid var(--border)}
.poll-head{display:flex;gap:1rem;align-items:flex-start;flex-wrap:wrap}
.poll-head img{width:84px;height:84px;object-fit:cover;border:1px solid var(--border)}
.muted{color:var(--muted)}
.small{font-size:.9rem}
code{background:var(--surface-2);padding:.1rem .4rem;font-size:.88em;word-break:break-all}
pre{background:var(--surface-2);padding:.8rem;overflow:auto}
.notice{border:2px solid var(--warn);border-left-width:10px;padding:.8rem 1rem;margin:1rem 0}
.notice.ok{border-color:var(--ok)}
.notice.bad{border-color:var(--danger)}
.error{border:2px solid var(--danger);border-left-width:10px;color:var(--danger);padding:.8rem 1rem;margin:1rem 0;display:none}
.actions{display:flex;gap:.6rem;flex-wrap:wrap;margin-top:1rem}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:.55rem .5rem;border-bottom:1px solid var(--border);vertical-align:top}
/* Flat row list (workspace picker etc.): no card boxes. */
.rows{list-style:none;margin:0;padding:0}
.rows li{display:flex;align-items:center;gap:1rem;flex-wrap:wrap;padding:.8rem 0;border-bottom:1px solid var(--border)}
.rows li:first-child{border-top:1px solid var(--border)}
.rows .grow{flex:1;min-width:220px}
/* Data figures strip. */
.stats{display:flex;flex-wrap:wrap;border:2px solid var(--text)}
.stat{flex:1;min-width:120px;padding:.6rem .9rem;border-left:1px solid var(--border)}
.stat:first-child{border-left:0}
.stat .num{display:block;font-size:1.6rem;font-weight:800;line-height:1.2}
.stat .lbl{font-size:.85rem;color:var(--muted)}
/* Flow / status diagrams. */
.flow{display:flex;align-items:stretch;gap:.5rem;flex-wrap:wrap;margin:.6rem 0}
.flow .node{border:2px solid var(--text);padding:.55rem .8rem;font-weight:700;display:flex;align-items:center}
.flow .arrow{align-self:center;font-weight:800;color:var(--muted)}
.steps{display:flex;align-items:center;gap:.45rem;flex-wrap:wrap;margin:.4rem 0 .2rem}
.step{border:2px solid var(--border);color:var(--muted);padding:.25rem .7rem;font-weight:700;font-size:.9rem}
.step.done{background:var(--text);border-color:var(--text);color:var(--bg)}
.step.current{border-color:var(--accent);color:var(--accent-strong)}
.step .dot{display:inline-block;width:.55rem;height:.55rem;border-radius:50%;background:var(--accent);margin-right:.4rem;vertical-align:baseline}
.steps .arrow{color:var(--muted);font-weight:800}
dl.spec{display:grid;grid-template-columns:minmax(120px,220px) 1fr;gap:.35rem 1.2rem;margin:.4rem 0}
dl.spec dt{font-weight:700}
dl.spec dd{margin:0;color:var(--muted)}
/* Result charts. */
.bar-row{display:grid;grid-template-columns:minmax(90px,1fr) 3fr auto;gap:.8rem;align-items:center;margin:.55rem 0}
.bar-track{background:var(--surface-2);height:22px}
.bar-fill{background:var(--accent);height:100%;min-width:2px;transform-origin:left center}
.stack{display:flex;height:28px;border:2px solid var(--text);overflow:hidden;margin:.6rem 0 .3rem}
.stack-seg{height:100%;transform-origin:left center}
.legend{display:flex;flex-wrap:wrap;gap:.4rem 1.1rem;font-size:.88rem;color:var(--muted)}
.legend .sw{display:inline-block;width:.8rem;height:.8rem;margin-right:.35rem;vertical-align:-.05rem}
/* Native modal dialogs (modern-web-guidance: dialog). */
dialog{border:2px solid var(--text);background:var(--bg);color:var(--text);
  padding:1.25rem;max-width:min(26rem,calc(100vw - 2rem))}
dialog:modal{overscroll-behavior:contain}
dialog::backdrop{background:rgba(0,0,0,.55);overflow:hidden;overscroll-behavior:contain}
dialog h2{margin-top:0;font-size:1.1rem;border-bottom:0}
.dialog-actions{display:flex;gap:.5rem;justify-content:flex-end;margin-top:1rem}
/* Fields turn red only after interaction (:user-invalid). */
input:user-invalid,textarea:user-invalid,select:user-invalid{border-color:var(--danger)}
/* Responsive table: scrollable region + sticky header + stacked rows. */
.table-wrapper{overflow:auto;max-inline-size:100%;container-type:inline-size}
.table-wrapper thead th{position:sticky;top:0;background:var(--bg);z-index:1}
@container (max-width:34rem){
  .table-wrapper thead{display:none}
  .table-wrapper table,.table-wrapper tbody,.table-wrapper tr,.table-wrapper td{display:block}
  .table-wrapper tr{padding:.45rem 0;border-bottom:1px solid var(--border)}
  .table-wrapper td{border:0;padding:.12rem .5rem}
  .table-wrapper td::before{content:attr(data-label);display:block;font-size:.75rem;color:var(--muted)}
}
@media (max-width:640px){
  .bar-row{grid-template-columns:1fr;gap:.2rem}
  header.site .user{display:none}
  dl.spec{grid-template-columns:1fr}
  .flow .node{flex:1;justify-content:center;text-align:center}
}
/* Forced colors: keep chart shapes and state badges legible. */
@media (forced-colors: active){
  .bar-fill,.stack-seg{background:Highlight}
  .badge,.step{border:1px solid ButtonText}
}
/* Motion (only when the user has not asked for reduced motion). */
@media (prefers-reduced-motion: no-preference){
  @view-transition{ navigation:auto }
  main{animation:page-in .3s ease-out}
  .bar-fill,.stack-seg{animation:grow-x .7s ease-out both;animation-delay:var(--d,0s)}
  dialog[open]{animation:dialog-in .18s ease-out}
  dialog[open]::backdrop{animation:fade-in .18s ease-out}
  .step.current .dot{animation:pulse 1.6s ease-in-out infinite}
}
@keyframes page-in{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
@keyframes grow-x{from{transform:scaleX(0)}to{transform:scaleX(1)}}
@keyframes dialog-in{from{opacity:0;transform:translateY(8px) scale(.98)}to{opacity:1;transform:none}}
@keyframes fade-in{from{opacity:0}to{opacity:1}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}

/* Embed snippet + form helpers (flat, no cards). */
.copyable{border:1px solid var(--border);padding:.8rem;margin:.6rem 0}
.copyable pre{margin:.5rem 0 0;overflow-x:auto;font-size:.85rem;line-height:1.5}
.copy{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap}
.tip{color:var(--muted);font-size:.85rem}
.field-error{color:var(--danger);font-size:.88rem;font-weight:600}
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
       <a class="btn small" href="/admin/account">アカウント</a>
       <form method="post" action="/admin/logout" style="margin:0"><button class="btn small" type="submit">ログアウト</button></form>`
    : `<a class="btn small primary" href="/admin/login">ログイン</a>`;
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
<a class="skip" href="#main">本文へ移動</a>
<header class="site"><div class="bar">
  <a class="brand" href="/admin">${LOGO_SVG}<span>headless-vote</span></a>
  <span class="spacer"></span>
  ${userArea}
</div></header>
<main id="main">
${opts.body}
</main>
</body>
</html>`;
}
