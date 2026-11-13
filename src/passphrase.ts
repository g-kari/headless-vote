/** Per-poll voting passphrase, stored only as a salted HMAC. */

import { hmacSha256Base64Url, timingSafeEqual } from "./crypto";
import type { Env } from "./types";

function pepper(env: Env): string {
  return env.VOTER_KEY_SECRET || env.SESSION_SECRET;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

/**
 * Storage format: `v1.<salt>.<mac>` where mac is HMAC-SHA256 over the
 * salt and the passphrase, keyed by the server pepper. Verification
 * recomputes the MAC and compares in constant time.
 */
export async function hashPassphrase(env: Env, passphrase: string): Promise<string> {
  const saltBytes = new Uint8Array(16);
  crypto.getRandomValues(saltBytes);
  const salt = bytesToBase64Url(saltBytes);
  const mac = await hmacSha256Base64Url(
    pepper(env),
    `headless-vote/passphrase/v1\0${salt}\0${passphrase}`,
  );
  return `v1.${salt}.${mac}`;
}

export async function verifyPassphrase(
  env: Env,
  stored: string,
  candidate: string,
): Promise<boolean> {
  const parts = stored.split(".");
  if (parts.length !== 3 || parts[0] !== "v1" || !parts[1] || !parts[2]) return false;
  const mac = await hmacSha256Base64Url(
    pepper(env),
    `headless-vote/passphrase/v1\0${parts[1]}\0${candidate}`,
  );
  return timingSafeEqual(mac, parts[2]);
}
