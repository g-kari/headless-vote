import { nowIso } from "./domain";
import { randomId } from "./crypto";
import { ApiError, notFound } from "./errors";
import { createObjectStore } from "./platform/objects";
import type { Env } from "./types";

export const MAX_IMAGES_PER_TENANT = 500;
export const MAX_IMAGE_BYTES_PER_TENANT = 500 * 1024 * 1024;

interface ImageUsage {
  image_count: number;
  total_bytes: number;
}

/** Seed legacy usage once. Concurrent scans must use the winning DB row. */
export async function getImageUsage(env: Env, tenantId: string): Promise<ImageUsage> {
  const read = () => env.DB.prepare(
    "SELECT image_count, total_bytes FROM tenant_image_usage WHERE tenant_id = ?1",
  ).bind(tenantId).first<ImageUsage>();
  const existing = await read();
  if (existing) return existing;
  // Memory storage has no pre-ledger objects across deployments.
  const r2 = (env.OBJECT_STORE || "r2").toLowerCase() === "r2";
  let count = 0;
  let bytes = 0;
  let cursor: string | undefined;
  if (r2) do {
    const page = await env.IMAGES.list({ prefix: `t/${tenantId}/`, limit: 1000, cursor });
    for (const object of page.objects) {
      count += 1;
      bytes += object.size;
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  const initialized = await env.DB.prepare(
    `INSERT OR IGNORE INTO tenant_image_usage (tenant_id, image_count, total_bytes, updated_at)
     VALUES (?1, ?2, ?3, ?4)`,
  ).bind(tenantId, count, bytes, nowIso()).run();
  if (!initialized.success) throw new Error("Could not initialize image usage");
  const winner = await read();
  if (!winner) throw new Error("Image usage row is missing");
  return winner;
}

/**
 * Atomically reserve both dimensions before writing to R2. Never release a
 * reservation on a put error: a timeout may mean the object was stored. A durable upload intent keeps
 * deletion cleanup alive until the object store confirms completion. An operator may reconcile
 * conservative overcounts against R2 only while uploads for the tenant are
 * paused and all in-flight requests have completed. Never delete/reset the
 * accounting row or lower its counters while uploads are running.
 */
export async function putImageWithQuota(
  env: Env,
  tenantId: string,
  key: string,
  data: ArrayBuffer | Uint8Array,
  contentType: string,
): Promise<void> {
  await getImageUsage(env, tenantId);
  const reserved = await env.DB.prepare(
    `UPDATE tenant_image_usage SET image_count = image_count + 1,
       total_bytes = total_bytes + ?2, updated_at = ?3
     WHERE tenant_id = ?1 AND image_count < ?4 AND total_bytes <= ?5 - ?2`,
  ).bind(tenantId, data.byteLength, nowIso(), MAX_IMAGES_PER_TENANT, MAX_IMAGE_BYTES_PER_TENANT).run();
  if (!reserved.success) throw new Error("Could not reserve image quota");
  if (reserved.meta.changes !== 1) {
    throw new ApiError(429, "IMAGE_QUOTA_EXCEEDED", "Image count or storage quota reached for this workspace (500 images / 500 MiB total)");
  }
  // Register before issuing an external write. A deleted tenant cannot start a
  // late upload after its cleanup job has already drained. Do not expire intents:
  // a timeout or worker termination cannot prove that R2 stopped writing.
  const intent = randomId();
  const registered = await env.DB.prepare(
    `INSERT INTO image_upload_intents (id, tenant_id)
     SELECT ?1, id FROM tenants WHERE id = ?2`,
  ).bind(intent, tenantId).run();
  if (!registered.success) throw new Error("Could not register image upload");
  if (registered.meta.changes !== 1) throw notFound("Workspace not found");
  await createObjectStore(env).put(key, data, contentType);
  // Refresh a deleted tenant's cleanup generation before releasing its intent,
  // in one transaction. A cleaner that captured an empty prefix before this put
  // cannot acknowledge the new generation, even if the request stops here.
  // Failed/uncertain D1 completion leaves either the intent or the refreshed job.
  const completed = await env.DB.batch([
    env.DB.prepare(`INSERT INTO object_cleanup (tenant_id, created_at, generation)
      SELECT ?1, ?2, lower(hex(randomblob(16)))
      WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE id = ?1)
      ON CONFLICT(tenant_id) DO UPDATE SET generation = excluded.generation,
        created_at = excluded.created_at`).bind(tenantId, nowIso()),
    env.DB.prepare("DELETE FROM image_upload_intents WHERE id = ?1").bind(intent),
  ]);
  if (completed.some((result) => !result.success)) throw new Error("Could not complete image upload");
}
