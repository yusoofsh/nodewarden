import type { Env } from '../types';
import { constantTimeEquals } from '../utils/api-key';
import { base64UrlToBytes, bytesToBase64Url } from '../utils/passkey';
import { RateLimitService } from './ratelimit';

// Codes and link tokens sent by email, one live row per user and purpose. A new code
// replaces the old one. Only an HMAC of the code is stored. A code is single use, expires,
// and dies after MAX_ATTEMPTS wrong guesses, after Vaultwarden's email token defaults.
export type EmailCodePurpose = 'login' | 'setup' | 'email-change' | 'otp' | 'verify-email' | 'delete-recover';

export const EMAIL_CODE_TTL_MS = 10 * 60 * 1000;
export const EMAIL_LINK_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_ATTEMPTS = 3;
// Per recipient address, so a public route cannot flood one inbox.
const RECIPIENT_BUDGET = 5;
const RECIPIENT_WINDOW_SECONDS = 10 * 60;

async function hmacHex(secret: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data)));
  return Array.from(mac, (b) => b.toString(16).padStart(2, '0')).join('');
}

const codeHash = (env: Env, userId: string, purpose: EmailCodePurpose, code: string) =>
  hmacHex(env.JWT_SECRET, `email-code:${userId}:${purpose}:${code.trim()}`);

export function randomDigits(length = 6): string {
  let out = '';
  while (out.length < length) {
    for (const byte of crypto.getRandomValues(new Uint8Array(length))) {
      if (byte < 250 && out.length < length) out += String(byte % 10);
    }
  }
  return out;
}

export const randomLinkToken = () => bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));

// Returns false, storing nothing, when the recipient's send budget is spent.
export async function issueEmailCode(
  env: Env,
  userId: string,
  purpose: EmailCodePurpose,
  email: string,
  code: string,
  ttlMs: number
): Promise<boolean> {
  const budget = await new RateLimitService(env.DB).consumeStrictBudgetWithWindow(
    `mail:${email.toLowerCase()}`,
    RECIPIENT_BUDGET,
    RECIPIENT_WINDOW_SECONDS
  );
  if (!budget.allowed) return false;
  const now = Date.now();
  await env.DB.prepare(
    'INSERT INTO email_codes(user_id, purpose, email, code_hash, attempts, expires_at, created_at) VALUES(?, ?, ?, ?, 0, ?, ?) ' +
    'ON CONFLICT(user_id, purpose) DO UPDATE SET email = excluded.email, code_hash = excluded.code_hash, attempts = 0, ' +
    'expires_at = excluded.expires_at, created_at = excluded.created_at'
  ).bind(userId, purpose, email, await codeHash(env, userId, purpose, code), now + ttlMs, now).run();
  return true;
}

export async function deleteEmailCode(env: Env, userId: string, purpose: EmailCodePurpose): Promise<void> {
  await env.DB.prepare('DELETE FROM email_codes WHERE user_id = ? AND purpose = ?').bind(userId, purpose).run();
}

// Consumes the code when it matches (or, with consume false, only checks it).
// Returns the address it was sent to, or null.
export async function consumeEmailCode(
  env: Env,
  userId: string,
  purpose: EmailCodePurpose,
  code: string,
  consume = true
): Promise<string | null> {
  const row = await env.DB.prepare('SELECT email, code_hash, attempts, expires_at FROM email_codes WHERE user_id = ? AND purpose = ?')
    .bind(userId, purpose)
    .first<{ email: string; code_hash: string; attempts: number; expires_at: number }>();
  if (!row || !code.trim()) return null;
  if (row.expires_at < Date.now() || row.attempts >= MAX_ATTEMPTS) {
    await deleteEmailCode(env, userId, purpose);
    return null;
  }
  const hash = await codeHash(env, userId, purpose, code);
  if (!constantTimeEquals(hash, row.code_hash)) {
    await env.DB.prepare('UPDATE email_codes SET attempts = attempts + 1 WHERE user_id = ? AND purpose = ?').bind(userId, purpose).run();
    return null;
  }
  if (!consume) return row.email;
  // The delete is the single-use gate: of two concurrent requests with the code, one wins.
  const deleted = await env.DB.prepare('DELETE FROM email_codes WHERE user_id = ? AND purpose = ? AND code_hash = ?')
    .bind(userId, purpose, hash)
    .run();
  return (deleted.meta.changes ?? 0) > 0 ? row.email : null;
}

// Registration has no user row to hang a code on, so its link carries a signed token
// instead. It is single use in effect: finishing registration takes the address.
export async function signRegisterToken(env: Env, email: string, name: string): Promise<string> {
  const payload = bytesToBase64Url(new TextEncoder().encode(JSON.stringify({ email, name, exp: Date.now() + EMAIL_LINK_TTL_MS })));
  return `${payload}.${await hmacHex(env.JWT_SECRET, `register:${payload}`)}`;
}

export async function verifyRegisterToken(env: Env, token: string, email: string): Promise<{ name: string } | null> {
  const [payload, mac] = String(token || '').split('.');
  if (!payload || !mac || !constantTimeEquals(mac, await hmacHex(env.JWT_SECRET, `register:${payload}`))) return null;
  try {
    const claims = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payload))) as { email?: string; name?: string; exp?: number };
    if (claims.email !== email.toLowerCase().trim() || typeof claims.exp !== 'number' || claims.exp < Date.now()) return null;
    return { name: String(claims.name || '') };
  } catch {
    return null;
  }
}

// Vaultwarden's obscure_email: the first two characters of a name longer than three stay visible.
export function obscureEmail(email: string): string {
  const at = email.lastIndexOf('@');
  if (at < 0) return '*'.repeat([...email].length);
  const name = [...email.slice(0, at)];
  const keep = name.length > 3 ? 2 : 0;
  return `${name.slice(0, keep).join('')}${'*'.repeat(name.length - keep)}${email.slice(at)}`;
}
