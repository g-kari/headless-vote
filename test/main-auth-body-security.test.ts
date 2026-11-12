import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { FLOW_COOKIE, makeFlowCookie, optionalVoterSub, parseCookies, readFlowCookie } from "../src/auth";
import { readBodyLimited, readFormLimited } from "../src/body-limit";
import type { AppContext } from "../src/types";

function cookieContext(cookie: string): AppContext {
  return { env, req: { header: (name: string) => name === "cookie" ? cookie : undefined } } as unknown as AppContext;
}

describe("browser auth boundary and request caps", () => {
  it("uses a host-only OIDC flow cookie and rejects legacy/domain cookie names", async () => {
    const flow = { state: "state", nonce: "nonce", verifier: "verifier", exp: Math.floor(Date.now() / 1000) + 600 };
    const header = await makeFlowCookie(env, flow);
    expect(header.startsWith("__Host-hv_oidc_flow=")).toBe(true);
    expect(header).toContain("; Secure");
    expect(header).toContain("; Path=/");
    expect(header).not.toContain("Domain=");
    const cookie = header.split(";")[0]!;
    expect(await readFlowCookie(cookieContext(cookie))).toEqual(flow);
    expect(await readFlowCookie(cookieContext(cookie.replace(FLOW_COOKIE, "hv_oidc_flow")))).toBeNull();
    expect(await readFlowCookie(cookieContext(`${cookie}; ${cookie}`))).toBeNull();
  });

  it("ignores malformed encodings and does not accept ambiguous cookies", () => {
    const parsed = parseCookies(cookieContext("unrelated=%E0%A4%A; same=one; same=two; safe=value"));
    expect(parsed["unrelated"]).toBeUndefined();
    expect(parsed["same"]).toBeUndefined();
    expect(parsed["safe"]).toBe("value");
  });

  it("fails closed on bearer authentication without a configured audience", async () => {
    const c = { env: { ...env, OIDC_CLIENT_ID: "" }, req: { header: () => "Bearer anything" } } as unknown as AppContext;
    await expect(optionalVoterSub(c)).rejects.toMatchObject({ status: 401 });
  });

  it("rejects a declared oversized body before consuming it", async () => {
    const request = new Request("https://vote.test", { method: "POST", headers: { "content-length": "999999" }, body: "x" });
    await expect(readBodyLimited(request, 4)).rejects.toMatchObject({ status: 413 });
  });

  it("caps chunked bodies and accepts bodies exactly at the cap", async () => {
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new Uint8Array(4)); controller.enqueue(new Uint8Array(4)); },
      cancel() { cancelled = true; },
    });
    await expect(readBodyLimited(new Request("https://vote.test", { method: "POST", body: stream }), 7)).rejects.toMatchObject({ status: 413 });
    expect(cancelled).toBe(true);
    expect((await readBodyLimited(new Request("https://vote.test", { method: "POST", body: "abcd" }), 4)).byteLength).toBe(4);
  });

  it("caps form parsing before handing bytes to the multipart/urlencoded parser", async () => {
    const request = new Request("https://vote.test", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: `x=${"a".repeat(65536)}` });
    await expect(readFormLimited(request)).rejects.toMatchObject({ status: 413 });
  });
});
