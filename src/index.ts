import { Hono } from "hono";
import { ApiError } from "./errors";
import { api, serveImage } from "./routes/api";
import { authRoutes } from "./routes/auth";
import { ui } from "./routes/ui";
import type { Env, Variables } from "./types";

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

app.get("/api/v1/health", (c) => c.json({ ok: true, service: "headless-vote" }));

// Brand assets live in public/ and are served by the platform's asset
// router in production. This fallback covers runtimes that dispatch every
// request to the Worker first (e.g. the test pool).
const ASSET_PATHS = new Set([
  "/favicon.svg",
  "/favicon-16x16.png",
  "/favicon-32x32.png",
  "/favicon.ico",
  "/apple-touch-icon.png",
  "/logo.svg",
  "/ogp.png",
]);
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

app.onError((err, c) => {
  if (err instanceof ApiError) {
    return c.json(
      { error: { code: err.code, message: err.message } },
      err.status as 400,
    );
  }
  console.error("unhandled error", err);
  const wantsHtml = (c.req.header("accept") ?? "").includes("text/html") &&
    !c.req.path.startsWith("/api/");
  if (wantsHtml) {
    return c.html(
      "<!doctype html><meta charset=utf-8><title>Error</title><p>Something went wrong. Please try again.</p>",
      500,
    );
  }
  return c.json(
    { error: { code: "INTERNAL", message: "Internal server error" } },
    500,
  );
});

app.notFound((c) => {
  if (c.req.path.startsWith("/api/")) {
    return c.json({ error: { code: "NOT_FOUND", message: "Not found" } }, 404);
  }
  return c.html("<!doctype html><meta charset=utf-8><title>404</title><p>Not found.</p>", 404);
});

export default app;
