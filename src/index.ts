import { Hono } from "hono";
import { drainObjectCleanup } from "./object-cleanup";
import { notifyClosingSoon } from "./notifications";
import { allowsCrossSiteEmbed, applyPublicCors, isPublicEmbedPath } from "./cors";
import { ApiError } from "./errors";
import { serveImage } from "./routes/api";
import { authRoutes } from "./routes/auth";
import { ui } from "./routes/ui";
import { api } from "./routes/api";
import {
  applySecurityHeaders,
  ASSET_PATHS,
  newCspNonce,
  shouldBlockCrossSite,
} from "./security";
import type { Env, Variables } from "./types";

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

app.use("*", async (c, next) => {
  c.set("cspNonce", newCspNonce());
  const path = new URL(c.req.url).pathname;
  if (
    shouldBlockCrossSite(c.req.raw, (pathname, method) => {
      if (ASSET_PATHS.has(pathname) && (method === "GET" || method === "HEAD")) return true;
      return allowsCrossSiteEmbed(pathname, method);
    })
  ) {
    applySecurityHeaders(c, { html: false });
    return c.json({ error: { code: "FORBIDDEN", message: "Cross-site request blocked" } }, 403);
  }
  if (c.req.method === "OPTIONS" && isPublicEmbedPath(path)) {
    await applyPublicCors(c);
    applySecurityHeaders(c, { html: false });
    return c.body(null, 204);
  }
  await next();
  await applyPublicCors(c);
  applySecurityHeaders(c);
});

app.get("/api/v1/health", (c) => c.json({ ok: true, service: "headless-vote" }));

// Brand assets live in public/ and are served by the platform's asset
// router in production. This fallback covers runtimes that dispatch every
// request to the Worker first (e.g. the test pool).
app.use(async (c, next) => {
  if (c.req.method === "GET" && ASSET_PATHS.has(new URL(c.req.url).pathname) && c.env.ASSETS) {
    return c.env.ASSETS.fetch(c.req.raw);
  }
  return next();
});

app.route("/api/v1", api);
app.route("/", authRoutes);
app.route("/", ui);

app.get("/images/t/:tenantId/:file", async (c) => {
  const key = `t/${c.req.param("tenantId")}/${c.req.param("file")}`;
  return serveImage(c.env, key);
});

app.onError(async (err, c) => {
  await applyPublicCors(c);
  if (err instanceof ApiError) {
    if (err.retryAfter !== undefined) {
      c.header("Retry-After", String(err.retryAfter));
    }
    applySecurityHeaders(c, { html: false });
    return c.json(
      {
        error: {
          code: err.code,
          message: err.message,
          ...(err.details ? { details: err.details } : {}),
        },
      },
      err.status as 400,
    );
  }
  console.error("unhandled error", err instanceof Error ? err.message : "unknown");
  const wantsHtml = (c.req.header("accept") ?? "").includes("text/html") &&
    !c.req.path.startsWith("/api/");
  if (wantsHtml) {
    applySecurityHeaders(c, { html: true });
    return c.html(
      "<!doctype html><meta charset=utf-8><title>Error</title><p>Something went wrong. Please try again.</p>",
      500,
    );
  }
  applySecurityHeaders(c, { html: false });
  return c.json(
    { error: { code: "INTERNAL", message: "Internal server error" } },
    500,
  );
});

app.notFound((c) => {
  applySecurityHeaders(c, { html: !c.req.path.startsWith("/api/") });
  if (c.req.path.startsWith("/api/")) {
    return c.json({ error: { code: "NOT_FOUND", message: "Not found" } }, 404);
  }
  return c.html("<!doctype html><meta charset=utf-8><title>404</title><p>Not found.</p>", 404);
});

export default {
  fetch: app.fetch,
  async scheduled(_event: ScheduledEvent, env: Env): Promise<void> {
    await drainObjectCleanup(env);
    await notifyClosingSoon(env);
  },
};
