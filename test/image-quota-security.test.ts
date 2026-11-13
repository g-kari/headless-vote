import { env } from "cloudflare:test";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { getImageUsage, MAX_IMAGE_BYTES_PER_TENANT, putImageWithQuota } from "../src/image-quota";
import type { Env } from "../src/types";
import { applySchema } from "./fixtures";

beforeAll(async () => { await applySchema(env.DB); });

function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => { release = resolve; });
  return { promise, release };
}

async function seed(count: number, bytes: number): Promise<string> {
  const id = crypto.randomUUID();
  await env.DB.prepare(
    "INSERT INTO tenant_image_usage (tenant_id, image_count, total_bytes, updated_at) VALUES (?1, ?2, ?3, 'test')",
  ).bind(id, count, bytes).run();
  return id;
}

function usage(id: string) {
  return env.DB.prepare(
    "SELECT image_count, total_bytes FROM tenant_image_usage WHERE tenant_id = ?1",
  ).bind(id).first();
}

function bucket() {
  const put = vi.fn(async () => ({ key: "stored" }));
  const list = vi.fn(async () => ({ objects: [], truncated: false }));
  const bindings = { ...env, OBJECT_STORE: "r2", IMAGES: { put, list } as unknown as R2Bucket } as Env;
  return { bindings, put, list };
}

describe("image quota reservation", () => {
  it("allows only one concurrent upload into the last image slot", async () => {
    const id = await seed(499, 100);
    const { bindings, put } = bucket();
    const entered = gate();
    const finish = gate();
    put.mockImplementation(async () => {
      entered.release();
      await finish.promise;
      return { key: "stored" };
    });
    const first = putImageWithQuota(bindings, id, `t/${id}/first.png`, new ArrayBuffer(10), "image/png");
    await entered.promise;
    try {
      const competitors = await Promise.allSettled(Array.from({ length: 8 }, (_, i) =>
        putImageWithQuota(bindings, id, `t/${id}/${i}.png`, new ArrayBuffer(10), "image/png"),
      ));
      for (const result of competitors) {
        expect(result.status).toBe("rejected");
        if (result.status === "rejected") expect(result.reason).toMatchObject({ status: 429, code: "IMAGE_QUOTA_EXCEEDED" });
      }
      expect(put).toHaveBeenCalledTimes(1);
      expect(await usage(id)).toEqual({ image_count: 500, total_bytes: 110 });
    } finally { finish.release(); }
    await first;
  });

  it("atomically enforces byte quota across concurrent uploads", async () => {
    const id = await seed(1, MAX_IMAGE_BYTES_PER_TENANT - 10);
    const { bindings, put } = bucket();
    const outcomes = await Promise.allSettled(Array.from({ length: 8 }, (_, i) =>
      putImageWithQuota(bindings, id, `t/${id}/${i}.png`, new ArrayBuffer(10), "image/png"),
    ));
    expect(outcomes.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(put).toHaveBeenCalledTimes(1);
    expect(await usage(id)).toEqual({ image_count: 2, total_bytes: MAX_IMAGE_BYTES_PER_TENANT });
  });

  it("rereads the winning row when a stale legacy scan loses initialization", async () => {
    const id = crypto.randomUUID();
    const { bindings, list } = bucket();
    const scanning = gate();
    const finish = gate();
    list.mockImplementation(async () => {
      scanning.release();
      await finish.promise;
      return { objects: [], truncated: false };
    });
    const pending = getImageUsage(bindings, id);
    await scanning.promise;
    try {
      await env.DB.prepare(
        "INSERT INTO tenant_image_usage (tenant_id, image_count, total_bytes, updated_at) VALUES (?1, 500, 1234, 'winner')",
      ).bind(id).run();
    } finally { finish.release(); }
    expect(await pending).toEqual({ image_count: 500, total_bytes: 1234 });
    await expect(putImageWithQuota(bindings, id, `t/${id}/late.png`, new ArrayBuffer(10), "image/png"))
      .rejects.toMatchObject({ code: "IMAGE_QUOTA_EXCEEDED" });
  });

  it("keeps the reservation if R2 may have written before returning an error", async () => {
    const id = await seed(499, 100);
    const { bindings, put } = bucket();
    const stored = new Set<string>();
    put.mockImplementation(async () => {
      stored.add(`t/${id}/uncertain.png`);
      throw new Error("R2 response lost after storage");
    });
    await expect(putImageWithQuota(bindings, id, `t/${id}/uncertain.png`, new ArrayBuffer(10), "image/png"))
      .rejects.toThrow("R2 response lost");
    expect(stored.size).toBe(1);
    expect(await usage(id)).toEqual({ image_count: 500, total_bytes: 110 });
    await expect(putImageWithQuota(bindings, id, `t/${id}/retry.png`, new ArrayBuffer(10), "image/png"))
      .rejects.toMatchObject({ code: "IMAGE_QUOTA_EXCEEDED" });
    expect(put).toHaveBeenCalledTimes(1);
  });

  for (const committed of [false, true]) {
    it(`never writes R2 on a failed reservation response (D1 committed: ${committed})`, async () => {
      const id = await seed(1, 100);
      const { bindings, put } = bucket();
      bindings.DB = {
        prepare(sql: string) {
          const statement = env.DB.prepare(sql);
          if (!sql.startsWith("UPDATE tenant_image_usage")) return statement;
          return {
            bind(...args: unknown[]) {
              return { async run() {
                if (committed) await statement.bind(...args).run();
                throw new Error("D1 reservation response failed");
              } };
            },
          };
        },
      } as unknown as D1Database;
      await expect(putImageWithQuota(bindings, id, `t/${id}/fail.png`, new ArrayBuffer(10), "image/png"))
        .rejects.toThrow("D1 reservation response failed");
      expect(put).not.toHaveBeenCalled();
      expect(await usage(id)).toEqual(committed
        ? { image_count: 2, total_bytes: 110 }
        : { image_count: 1, total_bytes: 100 });
    });
  }

  it("retains accounting when R2 does not confirm a stored object", async () => {
    const id = await seed(499, 100);
    const bindings = { ...env, OBJECT_STORE: "r2", IMAGES: {
      put: async () => null,
    } as unknown as R2Bucket } as Env;
    await expect(putImageWithQuota(bindings, id, `t/${id}/null.png`, new ArrayBuffer(10), "image/png"))
      .rejects.toThrow("did not confirm");
    expect(await usage(id)).toEqual({ image_count: 500, total_bytes: 110 });
  });

  it("supports the memory adapter without calling R2", async () => {
    const id = crypto.randomUUID();
    const bindings = { ...env, OBJECT_STORE: "memory", IMAGES: {
      list: async () => { throw new Error("R2 must not be called"); },
      put: async () => { throw new Error("R2 must not be called"); },
    } as unknown as R2Bucket } as Env;
    await expect(putImageWithQuota(bindings, id, `t/${id}/memory.png`, new Uint8Array(10), "image/png"))
      .resolves.toBeUndefined();
    expect(await usage(id)).toEqual({ image_count: 1, total_bytes: 10 });
  });

  it("needs no D1 write after R2 succeeds", async () => {
    const id = await seed(1, 100);
    const { bindings, put } = bucket();
    let stored = false;
    bindings.DB = {
      prepare(sql: string) {
        if (stored) throw new Error("Database unavailable after upload");
        return env.DB.prepare(sql);
      },
    } as unknown as D1Database;
    put.mockImplementation(async () => { stored = true; return { key: "stored" }; });
    await expect(putImageWithQuota(bindings, id, `t/${id}/ok.png`, new ArrayBuffer(10), "image/png"))
      .resolves.toBeUndefined();
    expect(await usage(id)).toEqual({ image_count: 2, total_bytes: 110 });
  });
});
