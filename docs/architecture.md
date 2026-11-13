# Architecture

English summary: Hyo keeps polls, ballots, and authorization in the core. Authentication, email, object storage, the rate-limit counter, webhook delivery, and analytics time series sit behind small interfaces in `src/platform`. `createPlatform` reads configuration and returns the adapters for this process. Swapping a provider does not change how a vote is stored.

投票のルール（設問、票、権限、上限）はコアにあります。ホストに依存する処理は `src/platform` のインターフェースの後ろにあります。`createPlatform` が設定を読んで、そのプロセスで使うアダプタを返します。

```
HTTP (Hono)
  routes/api.ts    polls, votes, keys, exports
  routes/ui.ts     admin screens
  routes/auth.ts   login, selected by AUTH_PROVIDER
        |
        v
  domain, questions, ballots, quotas, members
        |
        v
  Platform
    AuthProvider       oidc | local
    EmailSender        outbox | http | noop
    ObjectStore        r2 | memory
    RateLimitStore     d1 | memory
    WebhookTransport   fetch
    AnalyticsStore     d1 | memory
        |
        v
  D1 (SQL for the product data) and the selected adapter's own store
```

D1 に置いてある投票データそのものは、アダプタを替えても同じテーブルです。レート制限のカウンタ、分析イベント、画像、メール、OIDC のトークン検証だけがアダプタ経由です。SQL を別のデータベースに移すときは、`Env.DB` を同じ `prepare` / `bind` / `batch` の形で実装したバインディングに差し替えます。クエリはコアに残してあるので、ドライバを替える人はその形を守ります。

セッション Cookie の署名は `SESSION_SECRET` です。これはアダプタではなく、どのログイン方法でも共通のホスト秘密です。
