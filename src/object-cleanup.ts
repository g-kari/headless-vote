import { createObjectStore } from "./platform/objects";
import type { Env } from "./types";

/** Durable, bounded cleanup. Retry from the prefix start, even after failure. */
export async function drainObjectCleanup(env: Env, maxPages = 20): Promise<void> {
  const rows = await env.DB.prepare(
    "SELECT tenant_id, generation FROM object_cleanup ORDER BY created_at ASC LIMIT ?1",
  ).bind(maxPages).all<{ tenant_id: string; generation: string }>();
  const store = createObjectStore(env);
  let pages = 0;
  for (const row of rows.results) {
    // Never delete a live workspace, even if an invalid/stale job is present.
    const live = await env.DB.prepare("SELECT 1 AS ok FROM tenants WHERE id = ?1")
      .bind(row.tenant_id).first();
    if (live) continue;
    try {
      while (pages++ < maxPages) {
        // Starting at the beginning avoids skipping keys if a prior invocation
        // removed the page or a parallel cleanup ran. Keys are never reused.
        const next = await store.deletePrefix(`t/${row.tenant_id}/`);
        if (next === null) {
          await env.DB.batch([
            env.DB.prepare(`DELETE FROM object_cleanup WHERE tenant_id = ?1 AND generation = ?2
              AND NOT EXISTS (SELECT 1 FROM image_upload_intents WHERE tenant_id = ?1)`)
              .bind(row.tenant_id, row.generation),
            // An in-flight/uncertain put may create an object after this empty
            // sweep. Retain its job and rotate it so other tenants get a turn.
            env.DB.prepare("UPDATE object_cleanup SET created_at = ?3 WHERE tenant_id = ?1 AND generation = ?2")
              .bind(row.tenant_id, row.generation, new Date().toISOString()),
          ]);
          break;
        }
      }
    } catch {
      // Keep the durable job for a later schedule. Public reads already fail
      // closed because the workspace was removed in the same transaction.
    }
    if (pages >= maxPages) return;
  }
}
