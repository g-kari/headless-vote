import { randomId } from "../crypto";
import { badRequest, unauthorized } from "../errors";
import { assertPlainText } from "../security";
import type { Env } from "../types";
import type { AuthIdentity, AuthProvider, EmailSender } from "./ports";

const encoder = new TextEncoder();
const PBKDF2_ITERATIONS = 100_000;

export const localAuthProvider: AuthProvider = {
  id: "local",
  label(env) {
    return env.AUTH_LABEL?.trim() || "メールとパスワード";
  },
  capabilities: { localPasswords: true, emailVerification: true },
  async verifyAccessToken(): Promise<AuthIdentity> {
    throw unauthorized("INVALID_TOKEN", "Presented login token is not valid");
  },
};

interface LocalUserRow {
  id: string;
  email: string;
  password_hash: string;
  session_version: number;
  name: string | null;
  email_verified_at: string | null;
}

function b64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromB64(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function assertPassword(password: string): void {
  if (password.length < 10 || password.length > 200) {
    throw badRequest("Password must be 10-200 characters");
  }
  if (/[\u0000-\u001f\u007f]/.test(password)) throw badRequest("Password contains unsupported characters");
}

export function assertEmail(email: string): string {
  assertPlainText(email);
  const normalized = email.trim().toLowerCase();
  if (normalized.length < 3 || normalized.length > 200 || !/^[^\s@]+@[^\s@]+$/.test(normalized)) {
    throw badRequest("Email address is not valid");
  }
  return normalized;
}

export async function hashPassword(password: string): Promise<string> {
  assertPassword(password);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    key,
    256,
  );
  return `pbkdf2$${PBKDF2_ITERATIONS}$${b64(salt)}$${b64(new Uint8Array(bits))}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
  const iterations = Number(parts[1]);
  if (!Number.isFinite(iterations) || iterations < 1) return false;
  const salt = fromB64(parts[2] ?? "");
  const expected = fromB64(parts[3] ?? "");
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      key,
      expected.length * 8,
    ),
  );
  if (bits.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < bits.length; i++) diff |= (bits[i] ?? 0) ^ (expected[i] ?? 0);
  return diff === 0;
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function newToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return b64(bytes);
}

async function saveToken(env: Env, userId: string, purpose: "verify" | "reset", token: string): Promise<void> {
  const expires = new Date(Date.now() + (purpose === "verify" ? 86_400_000 : 3_600_000)).toISOString();
  await env.DB.prepare(
    "INSERT INTO local_tokens (token_hash, user_id, purpose, expires_at) VALUES (?1, ?2, ?3, ?4)",
  )
    .bind(await sha256Hex(token), userId, purpose, expires)
    .run();
}

export async function registerLocalUser(
  env: Env,
  input: { email: string; password: string; name: string; origin: string },
  email: EmailSender,
): Promise<void> {
  const address = assertEmail(input.email);
  const name = input.name.trim();
  assertPlainText(name);
  if (name.length > 120) throw badRequest("Name is too long");
  const existing = await env.DB.prepare("SELECT id FROM local_users WHERE email = ?1")
    .bind(address)
    .first();
  if (existing) throw badRequest("An account with that email already exists");
  const id = randomId();
  await env.DB.prepare(
    `INSERT INTO local_users (id, email, password_hash, name, email_verified_at, created_at)
     VALUES (?1, ?2, ?3, ?4, NULL, ?5)`,
  )
    .bind(id, address, await hashPassword(input.password), name || null, new Date().toISOString())
    .run();
  const token = newToken();
  await saveToken(env, id, "verify", token);
  const link = `${input.origin}/auth/local/verify?token=${encodeURIComponent(token)}`;
  await email.send({
    to: address,
    subject: "Confirm your email",
    text: `Confirm your Hyo account:\n${link}\n`,
  });
}

export async function verifyLocalEmail(env: Env, token: string): Promise<void> {
  const row = await consumeToken(env, token, "verify");
  await env.DB.prepare("UPDATE local_users SET email_verified_at = ?1 WHERE id = ?2 AND email_verified_at IS NULL")
    .bind(new Date().toISOString(), row.user_id)
    .run();
}

export async function requestPasswordReset(
  env: Env,
  emailAddress: string,
  origin: string,
  email: EmailSender,
): Promise<void> {
  const address = assertEmail(emailAddress);
  const user = await env.DB.prepare("SELECT id FROM local_users WHERE email = ?1")
    .bind(address)
    .first<{ id: string }>();
  if (!user) return;
  const token = newToken();
  await saveToken(env, user.id, "reset", token);
  const link = `${origin}/auth/local/reset?token=${encodeURIComponent(token)}`;
  await email.send({
    to: address,
    subject: "Reset your password",
    text: `Reset your Hyo password:\n${link}\n`,
  });
}

export async function resetLocalPassword(env: Env, token: string, password: string): Promise<void> {
  // Validate/hash before the transaction so bad input cannot burn a recovery link.
  if (token.length < 20 || token.length > 200) throw badRequest("That link is not valid");
  const passwordHash = await hashPassword(password);
  const tokenHash = await sha256Hex(token);
  const now = new Date().toISOString();
  // D1 batches are transactional: nobody can reuse the token between the
  // conditional password update and invalidation of every outstanding reset.
  const results = await env.DB.batch([
    env.DB.prepare(`UPDATE local_users
      SET password_hash = ?1, session_version = session_version + 1
      WHERE id = (SELECT user_id FROM local_tokens
        WHERE token_hash = ?2 AND purpose = 'reset' AND expires_at > ?3)`)
      .bind(passwordHash, tokenHash, now),
    env.DB.prepare(`DELETE FROM local_tokens WHERE purpose = 'reset' AND user_id =
      (SELECT user_id FROM local_tokens WHERE token_hash = ?1 AND purpose = 'reset' AND expires_at > ?2)`)
      .bind(tokenHash, now),
  ]);
  if (Number(results[0]?.meta.changes ?? 0) !== 1) throw badRequest("That link is not valid");
}

async function consumeToken(
  env: Env,
  token: string,
  purpose: "verify" | "reset",
): Promise<{ user_id: string }> {
  if (token.length < 20 || token.length > 200) throw badRequest("That link is not valid");
  const hash = await sha256Hex(token);
  const row = await env.DB.prepare(
    "DELETE FROM local_tokens WHERE token_hash = ?1 AND purpose = ?2 AND expires_at > ?3 RETURNING user_id",
  )
    .bind(hash, purpose, new Date().toISOString())
    .first<{ user_id: string }>();
  if (!row) throw badRequest("That link is not valid");
  return row;
}

export async function loginLocalUser(env: Env, emailAddress: string, password: string): Promise<AuthIdentity> {
  const address = assertEmail(emailAddress);
  const user = await env.DB.prepare("SELECT * FROM local_users WHERE email = ?1")
    .bind(address)
    .first<LocalUserRow>();
  if (!user || !(await verifyPassword(password, user.password_hash))) {
    throw unauthorized("UNAUTHORIZED", "Email or password is incorrect");
  }
  if (!user.email_verified_at) {
    throw unauthorized("EMAIL_UNVERIFIED", "Confirm your email before signing in");
  }
  // Capture the version from the same row whose password was verified. A reset
  // during verification must not turn an old password into a fresh session.
  return { sub: `local:${user.id}`, email: user.email, name: user.name ?? undefined, sessionVersion: user.session_version };
}

export async function deleteLocalAccount(env: Env, sub: string): Promise<void> {
  if (!sub.startsWith("local:")) return;
  const id = sub.slice("local:".length);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM local_tokens WHERE user_id = ?1").bind(id),
    env.DB.prepare("DELETE FROM local_users WHERE id = ?1").bind(id),
  ]);
}
