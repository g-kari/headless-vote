import type { Env } from "../types";
import type { ObjectStore, StoredObject } from "./ports";

export function createR2ObjectStore(env: Env): ObjectStore {
  return {
    id: "r2",
    async deletePrefix(prefix, cursor) {
      assertTenantPrefix(prefix);
      const page = await env.IMAGES.list({ prefix, cursor, limit: 100 });
      if (page.objects.length) await env.IMAGES.delete(page.objects.map((object) => object.key));
      return page.truncated ? page.cursor : null;
    },
    async put(key, body, contentType) {
      const bytes = body instanceof Uint8Array ? body : new Uint8Array(body);
      await env.IMAGES.put(key, bytes, { httpMetadata: { contentType } });
    },
    async get(key): Promise<StoredObject | null> {
      const obj = await env.IMAGES.get(key);
      if (!obj) return null;
      return { body: obj.body, httpEtag: obj.httpEtag, contentType: obj.httpMetadata?.contentType ?? null };
    },
    async head(key) {
      const obj = await env.IMAGES.head(key);
      return obj !== null;
    },
  };
}

export class MemoryObjectStore implements ObjectStore {
  readonly id = "memory";
  private readonly files = new Map<string, { body: Uint8Array; contentType: string }>();

  async deletePrefix(prefix: string, _cursor?: string): Promise<string | null> {
    assertTenantPrefix(prefix);
    let deleted = 0;
    for (const key of this.files.keys()) {
      if (!key.startsWith(prefix)) continue;
      if (deleted === 100) return "more";
      this.files.delete(key);
      deleted++;
    }
    return null;
  }

  async put(key: string, body: ArrayBuffer | Uint8Array, contentType: string): Promise<void> {
    this.files.set(key, { body: body instanceof Uint8Array ? body : new Uint8Array(body), contentType });
  }

  async get(key: string): Promise<StoredObject | null> {
    const file = this.files.get(key);
    if (!file) return null;
    return {
      body: new Blob([file.body]).stream(),
      httpEtag: `"${file.body.byteLength}"`,
      contentType: file.contentType,
    };
  }

  async head(key: string): Promise<boolean> {
    return this.files.has(key);
  }
}

let sharedMemoryObjects: MemoryObjectStore | null = null;

export function createObjectStore(env: Env): ObjectStore {
  const name = (env.OBJECT_STORE || "r2").toLowerCase();
  if (name === "r2") return createR2ObjectStore(env);
  if (name === "memory") {
    sharedMemoryObjects ??= new MemoryObjectStore();
    return sharedMemoryObjects;
  }
  throw new Error(`Unknown OBJECT_STORE "${name}"`);
}

function assertTenantPrefix(prefix: string): void {
  if (!/^t\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/$/.test(prefix)) {
    throw new Error("Object deletion requires an exact tenant prefix");
  }
}
