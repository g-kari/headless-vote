# headless-vote

Headless な投票 SaaS です。
投票の作成と管理はブラウザの管理画面で行います。
投票の取得・実行・結果は JSON の API で提供します。
複数の利用者（テナント）が、それぞれ自分の投票を運用できます。

![ロゴ](public/logo.svg)

## 構成

![構成図](docs/architecture.svg)

- Cloudflare Workers（Hono / TypeScript）
- D1（テナント・投票・票のデータ）
- R2（設問・選択肢の画像）
- 管理画面のログインは 0g0-id（OIDC、認可コード + PKCE）
- 本番ドメインは https://vote.0g0.xyz

## 概念

### テナント（ワークスペース）

利用者ごとの作業単位です。テナント同士のデータは混ざりません。
テナントを作ると管理用 API キーが 1 回だけ表示されます。
API キーは SHA-256 ハッシュで保存します。平文は保存しません。

管理操作の認証は 2 通りです。

- 管理画面: 0g0-id でログインし、セッション Cookie で認証します。
  ログインしたユーザー（sub）がメンバーであるテナントだけを操作できます。
- 管理 API: `Authorization: Bearer <API キー>` で認証します。

### 投票者

投票はログインしてもしなくてもできます。

- ログイン時: 0g0-id の ID トークン（`Authorization: Bearer <ID トークン>`）を送ります。
  1 人 1 票の判定はユーザー（sub）単位です。
- 未ログイン時: 投票者トークン（任意の不透明な文字列）を送ります。
  判定はトークン単位です。

再投票すると上書きされます。締切後は投票できません。
投票ごとに「ログイン必須」か「誰でも投票可」かを選べます。既定は「誰でも投票可」です。

注意: 0g0-id の sub はクライアントごとに変わります（pairwise）。
このアプリの ID トークンで投票した票は、このアプリの sub に紐付きます。

## API 仕様

ベース URL は `/api/v1` です。
エラーはすべて同じ形で返します。

```json
{ "error": { "code": "POLL_CLOSED", "message": "This poll is closed for voting." } }
```

主なエラーコード: `BAD_REQUEST`（400）、`UNAUTHORIZED`（401）、`RATE_LIMITED`（429）、
`LOGIN_REQUIRED`（401、ログイン必須の投票に未ログインで投票）、
`INVALID_TOKEN`（401）、`FORBIDDEN`（403）、`NOT_FOUND`（404）、
`POLL_CLOSED`（409）、`OPTIONS_LOCKED`（409、投票が入った投票の選択肢は変更不可）、
`RULES_LOCKED`（409、投票後はログイン必須・複数選択を変更不可）、
`CONCURRENT_UPDATE`（409）、`PAYLOAD_TOO_LARGE`（413）。

### テナント管理（要 API キー、作成のみ認証不要）

| メソッド | パス | 内容 |
|---|---|---|
| POST | `/tenants` | テナント作成。API キーを返す（1 回だけ） |
| POST | `/tenants/:tenantId/rotate-key` | API キーの再発行 |

### 投票の管理（要 API キー、または管理画面のセッション）

| メソッド | パス | 内容 |
|---|---|---|
| POST | `/tenants/:tenantId/polls` | 投票を作成（下書き） |
| GET | `/tenants/:tenantId/polls` | 一覧 |
| GET | `/tenants/:tenantId/polls/:pollId` | 1 件取得 |
| PATCH | `/tenants/:tenantId/polls/:pollId` | 編集（締切済みは不可） |
| POST | `/tenants/:tenantId/polls/:pollId/status` | 状態変更（`published` / `closed` / `draft`） |
| GET | `/tenants/:tenantId/polls/:pollId/results` | 結果 |
| POST | `/tenants/:tenantId/images` | 画像アップロード（R2）。本文に画像バイナリ、対応形式は PNG / JPEG / WebP / GIF、5 MiB まで。中身が宣言した形式と一致すること |
| GET | `/tenants/:tenantId/origins` | ブラウザ埋め込みを許可するオリジン一覧 |
| POST | `/tenants/:tenantId/origins` | オリジンを追加。`{ "origin": "https://www.example.com" }` |
| DELETE | `/tenants/:tenantId/origins` | オリジンを削除。`{ "origin": "https://www.example.com" }` |

投票の作成リクエスト例:

```json
{
  "question": "イベントアンケート",
  "description": "すべて答えてください",
  "require_login": false,
  "opens_at": "2026-12-01T00:00:00.000Z",
  "closes_at": "2026-12-31T15:00:00.000Z",
  "questions": [
    {
      "prompt": "好きな季節は？",
      "kind": "single",
      "required": true,
      "options": [{ "label": "春" }, { "label": "夏" }]
    },
    {
      "prompt": "当てはまるものをすべて",
      "kind": "multiple",
      "required": true,
      "options": [{ "label": "午前" }, { "label": "午後" }]
    },
    { "prompt": "ひとこと", "kind": "text", "required": false }
  ]
}
```

`questions` を省略した場合は、従来どおり `question` と `options` と `allow_multiple` から設問が 1 つ作られます。設問は 1〜20 個です。選択式は選択肢 2〜50 個、自由記述は 2000 文字までです。票が入ったあとは設問の追加・削除・種類変更・選択肢の増減はできません（文言と並びの更新はできます）。

### 公開 API（投票者向け）

| メソッド | パス | 内容 |
|---|---|---|
| GET | `/polls/:pollId` | 投票の取得（下書きは 404） |
| GET | `/polls/:pollId/results` | 結果の取得 |
| POST | `/polls/:pollId/vote` | 投票の実行 |

投票リクエスト例（未ログイン）:

```json
{
  "voter_token": "any-opaque-string-1234",
  "answers": [
    { "question_id": "<questionId>", "option_ids": ["<optionId>"] },
    { "question_id": "<textQuestionId>", "text": "よかったです" }
  ]
}
```

設問が 1 つだけの投票は、従来の `{ "option_ids": ["<optionId>"] }` も受け付けます。必須の設問はすべてこの 1 回の送信に含めます。ログイン時は `voter_token` の代わりに `Authorization: Bearer <ID トークン>` を付けます。

集計は設問ごとです。自由記述の本文は、管理 API・管理画面・書き出しにだけ含まれ、公開の結果 API では件数だけです。

画像は `GET /images/t/<tenantId>/<file>` で配信します。
投票の JSON では `image_url` として絶対 URL が返ります。

### ブラウザからの埋め込み（CORS）

公開 API（投票の取得・投票・結果）と画像を、別サイトのブラウザから読むには、そのサイトのオリジンをワークスペースの許可リストに入れます。リストはワークスペースごとで、管理画面の「埋め込み設定」（`/admin/workspaces/<tenantId>/settings`）から追加・削除します。API キーでも同じ操作ができます。

- 例: `https://www.example.com`
- `https://vote.0g0.xyz` 自身からの利用は同一オリジンなので、リストへの追加は不要です
- `https` のみ。例外は `http://localhost`、`http://127.0.0.1`、`http://[::1]`（ポート付き可）
- パス、クエリ、ユーザー情報、ワイルドカード（`*`）は拒否します。保存時に `https://Example.COM:443/` のような入力は `https://example.com` に正規化します
- 1 ワークスペースあたり 20 件まで
- リクエストの `Origin` が保存した値と完全一致するときだけ `Access-Control-Allow-Origin` を返します。`*` は使いません。`Vary: Origin` を付けます
- 一致しない、または `Origin` が無い場合は CORS ヘッダーを付けません（サーバーからの呼び出しはそのまま動きます）
- 管理 API と管理画面は、許可オリジンからでもクロスオリジンでは開きません

未ログインの投票は、呼び出し側が渡す `voter_token` ごとに 1 票です。トークンは呼び出し側が安定して発行する前提で、データベースには HMAC だけを保存します。人と 1 対 1 にしたい投票は「ログイン必須」にしてください。

## ワークスペースの運用機能

- **API キー**: ワークスペースごとに複数持てます。権限は `read`（参照と書き出し）か `write`（作成・更新・失効も可）。平文は発行時に一度だけ返り、保存するのは SHA-256 と先頭のプレフィックスです。`POST /api/v1/tenants/:id/api-keys`、失効は `POST .../api-keys/:keyId/revoke`。従来の `POST .../rotate-key` は、そのリクエストのキーを失効して書き込みキーを 1 つ発行します。有効なキーは 10 個までです。
- **複数設問**: 1 つの投票に単一選択・複数選択・自由記述を混在できます。投票は全設問を 1 回で送ります。
- **開始日時**: `opens_at` を付けると、その時刻より前の投票は `POLL_NOT_OPEN`（409）です。`closes_at` より前である必要があります。
- **結果の書き出し**: `GET /api/v1/tenants/:id/polls/:pollId/export?format=csv` または `format=json`。集計だけで、投票者トークンは含みません。CSV はスプレッドシートの式として解釈されないようセルを中和します。
- **ワークスペースの書き出しと削除**: `GET /api/v1/tenants/:id/export`。削除は `DELETE /api/v1/tenants/:id` に `{ "confirm_name": "ワークスペース名" }`。管理画面の埋め込み設定からも行えます。
- **操作履歴**: `GET /api/v1/tenants/:id/audit` と管理画面の「操作履歴」。キーの秘密は記録しません。
- **埋め込みスニペット**: 公開中の投票の管理画面に、取得と投票の例を出します。
- **上限**: 投票は 1 ワークスペース 100 件まで（`QUOTA_EXCEEDED`）。課金プランごとの上限はまだありません。

## 管理画面

- `/admin` から 0g0-id でログインします。ログアウトは POST のみです（`/admin/logout` を開いただけではセッションは消えません）。
- ワークスペースの作成、投票の作成・編集・公開・締切ができます。
- 設問と選択肢に画像を付けられます（R2 にアップロード）。
- 結果はバーと集計表で確認できます。

### 0g0-id のクライアント登録

認可コードフロー（PKCE S256、パブリッククライアント）を使います。
クライアントは DCR（RFC 7591）で登録できます。

```bash
node scripts/register-oidc-client.mjs
# 既定のリダイレクト URI: https://vote.0g0.xyz/auth/callback
```

表示された `client_id` を `wrangler.toml` の `OIDC_CLIENT_ID` に設定して再デプロイします。
ローカル開発では `REDIRECT_URI=http://localhost:8787/auth/callback` を付けて登録します。

必要な設定:

- 変数: `OIDC_ISSUER`（既定 `https://id.0g0.xyz`）、`OIDC_CLIENT_ID`、`OIDC_SCOPES`（既定 `openid profile email`）、`APP_ORIGIN`（本番は `https://vote.0g0.xyz`。管理ログインをこのオリジンに限定します）
- シークレット: `SESSION_SECRET`（セッション Cookie の署名用。`wrangler secret put SESSION_SECRET`）。任意で `VOTER_KEY_SECRET`（投票者識別子の HMAC。未設定時は `SESSION_SECRET` を使います。セッション秘密だけをローテーションしたいときに分けてください）

## ローカル開発

```bash
npm install --legacy-peer-deps
npm run db:migrate:local
npm run dev          # http://localhost:8787
npm test             # vitest（Workers ランタイム + モック IdP）
npm run typecheck    # tsc（アプリ + テスト）
```

テストは IdP をモックします。実ログインは不要です。

## デプロイ

### 手動デプロイ

```bash
npx wrangler d1 create headless-vote          # 出力された database_id を wrangler.toml に記入
npx wrangler r2 bucket create headless-vote-images
npx wrangler secret put SESSION_SECRET
npx wrangler d1 migrations apply headless-vote --remote
node scripts/register-oidc-client.mjs          # client_id を wrangler.toml に記入
npx wrangler deploy                            # vote.0g0.xyz のカスタムドメインが付きます。workers.dev のホスト名は出しません
```

### GitHub 連携の自動デプロイ（Workers Builds）

main へ push すると自動でデプロイされる構成にできます。
Cloudflare ダッシュボードで 1 回だけ設定します。

1. Workers & Pages → `headless-vote` → Settings → Builds
2. Git リポジトリ `g-kari/headless-vote` を接続し、本番ブランチを `main` にする
3. ビルドコマンド: `npm ci --legacy-peer-deps`
4. デプロイコマンド: `npx wrangler d1 migrations apply headless-vote --remote && npx wrangler deploy`

デプロイコマンドにマイグレーション適用を含めるので、push のたびに D1 へ自動で当たります。

## 依存関係の更新

Renovate と Dependabot を併用します。担当を分けているので競合しません。

- Renovate（`renovate.json`）: 主担当。通常の npm / GitHub Actions 更新を扱い、CI が通れば自動マージします（major は手動確認）。
- Dependabot（`.github/dependabot.yml`）: セキュリティ更新の担当。通常更新は Renovate に任せます。Dependabot の PR は `.github/workflows/dependabot-automerge.yml` が自動マージを有効化し、CI 成功後に取り込みます。

main ブランチは CI（`check`）の成功を必須にしているため、自動マージは CI が通ったものだけが進みます。

## 開発メモ

- 管理画面のデザインは `.claude/skills/modern-web-guidance` のガイダンスに沿っています。
  要点: ダークモードは `light-dark()` と `color-scheme`、確認はネイティブ `<dialog>`、
  表はキーボードでスクロールできるラッパーと sticky ヘッダー（狭い画面ではカード化）、
  エラーはライブリージョンで通知、入力エラー表示は `:user-invalid` で操作後にだけ出します。
- 構成図（`docs/architecture.svg`）と結果表示（バー + 集計表）は、
  `.claude/skills/visual-explainer` の考え方（図に動詞ラベル、数値には図と表の両方）に沿っています。
- ブランド画像は `public/` にあります。`favicon.svg` が正で、PNG / ICO / apple-touch-icon / OGP は同じ図形から生成しました。
