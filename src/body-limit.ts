import { badRequest, payloadTooLarge } from "./errors";

/** Enforce the cap while reading, including chunked bodies without a length. */
export async function readBodyLimited(request: Request, max: number): Promise<ArrayBuffer> {
  const declared = request.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > max)) {
    throw payloadTooLarge("Request body is too large");
  }
  const reader = request.body?.getReader();
  if (!reader) return new ArrayBuffer(0);
  const chunks: Uint8Array[] = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    length += value.byteLength;
    if (length > max) {
      await reader.cancel();
      throw payloadTooLarge("Request body is too large");
    }
    chunks.push(value);
  }
  const buffer = new ArrayBuffer(length);
  const out = new Uint8Array(buffer);
  let offset = 0;
  for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.byteLength; }
  return buffer;
}

export async function readFormLimited(request: Request): Promise<FormData> {
  const media = request.headers.get("content-type") ?? "";
  if (!/^(application\/x-www-form-urlencoded|multipart\/form-data)(?:;|$)/i.test(media)) {
    throw badRequest("Expected a form submission");
  }
  return new Response(await readBodyLimited(request, 64 * 1024), {
    headers: { "content-type": media },
  }).formData();
}
