import type { Env, User } from '../types';
import type { StorageService } from './storage';

// Duo Universal Prompt (OIDC code flow), per user, as Vaultwarden's duo_oidc.rs.
// See https://duo.com/docs/oauthapi.
//
// users.duo_config holds JSON { host, clientId, secret: { iv, ciphertext } }. The client
// secret is AES-GCM encrypted under a key derived from JWT_SECRET, with the user id as
// additional data. A user without duo_config never reaches any code here that calls Duo.

export const TWO_FACTOR_PROVIDER_DUO = 2;
export const DUO_LOGIN_CHALLENGE_SCOPE = 'DuoLogin';
export const DUO_SECRET_MASK = '************';

const DUO_HOST_PATTERN = /^api-[a-z0-9]+\.duosecurity\.com$/;
const DUO_CLIENT_ID_PATTERN = /^[A-Za-z0-9]{20}$/;
const DUO_CLIENT_SECRET_PATTERN = /^[\x21-\x7e]{40}$/;
const DUO_JWT_TTL_SECONDS = 300;
const DUO_CONTEXT_TTL_MS = 5 * 60 * 1000;
const DUO_REDIRECT_PATH = '/duo-redirect-connector.html';
const SECRET_HKDF_SALT = 'nodewarden.duo.client-secret.v1';
const USER_AGENT = 'nodewarden:Duo/2.0';

export interface DuoCredentials {
  host: string;
  clientId: string;
  clientSecret: string;
}

interface StoredDuoConfig {
  host: string;
  clientId: string;
  secret: { iv: string; ciphertext: string };
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function base64UrlEncode(bytes: Uint8Array): string {
  let text = '';
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '='));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function hex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function randomHex(byteLength: number): string {
  return hex(crypto.getRandomValues(new Uint8Array(byteLength)).buffer);
}

function constantTimeEqual(a: string, b: string): boolean {
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  let diff = left.length ^ right.length;
  for (let i = 0; i < Math.max(left.length, right.length); i++) diff |= (left[i] ?? 0) ^ (right[i] ?? 0);
  return diff === 0;
}

// Accepts "api-xxxx.duosecurity.com", optionally with an https:// prefix or a trailing slash.
export function normalizeDuoHost(raw: unknown): string | null {
  let host = String(raw ?? '').trim().toLowerCase();
  if (host.startsWith('https://')) host = host.slice('https://'.length);
  if (host.endsWith('/')) host = host.slice(0, -1);
  return DUO_HOST_PATTERN.test(host) ? host : null;
}

export function parseDuoCredentials(host: unknown, clientId: unknown, clientSecret: unknown): DuoCredentials | null {
  const normalizedHost = normalizeDuoHost(host);
  const id = String(clientId ?? '').trim();
  const secret = String(clientSecret ?? '').trim();
  if (!normalizedHost || !DUO_CLIENT_ID_PATTERN.test(id) || !DUO_CLIENT_SECRET_PATTERN.test(secret)) return null;
  return { host: normalizedHost, clientId: id, clientSecret: secret };
}

// Vaultwarden's DuoData::obscure: keep the first four characters.
export function maskDuoSecret(secret: string): string {
  return secret.slice(0, 4) + DUO_SECRET_MASK;
}

async function secretKey(env: Env): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey('raw', encoder.encode(env.JWT_SECRET), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: encoder.encode(SECRET_HKDF_SALT), info: encoder.encode('client-secret') },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function sealDuoConfig(env: Env, userId: string, credentials: DuoCredentials): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: encoder.encode(userId) },
    await secretKey(env),
    encoder.encode(credentials.clientSecret)
  );
  const stored: StoredDuoConfig = {
    host: credentials.host,
    clientId: credentials.clientId,
    secret: { iv: base64UrlEncode(iv), ciphertext: base64UrlEncode(new Uint8Array(ciphertext)) },
  };
  return JSON.stringify(stored);
}

export function hasDuoConfig(user: Pick<User, 'duoConfig'>): boolean {
  return !!user.duoConfig;
}

// Null when the user has no Duo config or it cannot be read (for example after JWT_SECRET
// changed). Callers still treat a stored config as "Duo enabled", so this fails closed.
export async function readDuoCredentials(env: Env, user: Pick<User, 'id' | 'duoConfig'>): Promise<DuoCredentials | null> {
  if (!user.duoConfig) return null;
  try {
    const stored = JSON.parse(user.duoConfig) as StoredDuoConfig;
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64UrlDecode(stored.secret.iv), additionalData: encoder.encode(user.id) },
      await secretKey(env),
      base64UrlDecode(stored.secret.ciphertext)
    );
    return parseDuoCredentials(stored.host, stored.clientId, decoder.decode(plaintext));
  } catch {
    return null;
  }
}

async function hmacKey(secret: string, usage: 'sign' | 'verify'): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-512' }, false, [usage]);
}

async function signDuoJwt(payload: Record<string, unknown>, clientSecret: string): Promise<string> {
  const head = base64UrlEncode(encoder.encode(JSON.stringify({ alg: 'HS512', typ: 'JWT' })));
  const body = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
  const signature = await crypto.subtle.sign('HMAC', await hmacKey(clientSecret, 'sign'), encoder.encode(`${head}.${body}`));
  return `${head}.${body}.${base64UrlEncode(new Uint8Array(signature))}`;
}

async function verifyDuoJwt(token: string, clientSecret: string): Promise<Record<string, unknown> | null> {
  const [head, body, signature, extra] = String(token || '').split('.');
  if (!head || !body || !signature || extra !== undefined) return null;
  try {
    const header = JSON.parse(decoder.decode(base64UrlDecode(head))) as { alg?: unknown };
    if (header.alg !== 'HS512') return null;
    const valid = await crypto.subtle.verify(
      'HMAC',
      await hmacKey(clientSecret, 'verify'),
      base64UrlDecode(signature),
      encoder.encode(`${head}.${body}`)
    );
    return valid ? JSON.parse(decoder.decode(base64UrlDecode(body))) as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function clientAssertion(credentials: DuoCredentials, audience: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return signDuoJwt({
    iss: credentials.clientId,
    sub: credentials.clientId,
    aud: audience,
    exp: now + DUO_JWT_TTL_SECONDS,
    jti: randomHex(32),
    iat: now,
  }, credentials.clientSecret);
}

async function postDuoForm(credentials: DuoCredentials, path: string, form: Record<string, string>): Promise<Response> {
  // Re-checked here so a stored host can never point a request anywhere but Duo.
  const host = normalizeDuoHost(credentials.host);
  if (!host) throw new Error('Invalid Duo API host');
  return fetch(`https://${host}${path}`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': USER_AGENT },
    body: new URLSearchParams(form).toString(),
  });
}

// https://duo.com/docs/oauthapi#health-check
export async function duoHealthCheck(credentials: DuoCredentials): Promise<void> {
  const url = `https://${credentials.host}/oauth/v1/health_check`;
  const response = await postDuoForm(credentials, '/oauth/v1/health_check', {
    client_id: credentials.clientId,
    client_assertion: await clientAssertion(credentials, url),
  });
  const body = await response.json().catch(() => null) as { stat?: unknown } | null;
  if (!response.ok || body?.stat !== 'OK') throw new Error('Duo health check failed');
}

export function duoRedirectUri(request: Request, clientName: string): string {
  const url = new URL(DUO_REDIRECT_PATH, new URL(request.url).origin);
  url.searchParams.set('client', clientName);
  return url.toString();
}

// Binds the OIDC nonce to the state, the user and the authenticating device without
// storing it, as Vaultwarden binds its stored nonce to the device identifier.
async function duoNonce(env: Env, state: string, userId: string, deviceIdentifier: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', encoder.encode(env.JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', key, encoder.encode(`duo-nonce\n${userId}\n${deviceIdentifier}\n${state}`)));
}

async function stateHash(state: string): Promise<string> {
  return hex(await crypto.subtle.digest('SHA-256', encoder.encode(`duo-state:${state}`)));
}

export interface DuoLoginContext {
  env: Env;
  storage: StorageService;
  request: Request;
  user: Pick<User, 'id' | 'email'>;
  credentials: DuoCredentials;
  clientName: string;
  deviceIdentifier: string;
}

// First stage: health check, store a single-use state, return the AuthUrl for the client.
export async function startDuoLogin(ctx: DuoLoginContext): Promise<string> {
  const { credentials } = ctx;
  await duoHealthCheck(credentials);
  const state = randomHex(32);
  const now = Date.now();
  await ctx.storage.saveAccountPasskeyChallenge({
    challengeHash: await stateHash(state),
    scope: DUO_LOGIN_CHALLENGE_SCOPE,
    userId: ctx.user.id,
    expiresAt: now + DUO_CONTEXT_TTL_MS,
    usedAt: null,
    createdAt: now,
  });
  const nowSeconds = Math.floor(now / 1000);
  const request = await signDuoJwt({
    response_type: 'code',
    scope: 'openid',
    exp: nowSeconds + DUO_JWT_TTL_SECONDS,
    client_id: credentials.clientId,
    redirect_uri: duoRedirectUri(ctx.request, ctx.clientName),
    state,
    duo_uname: ctx.user.email,
    iss: credentials.clientId,
    aud: `https://${credentials.host}`,
    nonce: await duoNonce(ctx.env, state, ctx.user.id, ctx.deviceIdentifier),
  }, credentials.clientSecret);
  const url = new URL(`https://${credentials.host}/oauth/v1/authorize`);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', credentials.clientId);
  url.searchParams.set('request', request);
  return url.toString();
}

// Second stage: the client sends "<code>|<state>" as the two-factor token. The state is
// consumed before the code exchange, so a failed or replayed exchange cannot reuse it.
export async function verifyDuoLogin(ctx: DuoLoginContext, twoFactorToken: string): Promise<boolean> {
  const parts = String(twoFactorToken || '').split('|');
  if (parts.length !== 2 || !parts[0] || !parts[1]) return false;
  const [code, state] = parts;
  const consumed = await ctx.storage.consumeAccountPasskeyChallenge(await stateHash(state), DUO_LOGIN_CHALLENGE_SCOPE, ctx.user.id, Date.now());
  if (!consumed) return false;

  const { credentials } = ctx;
  const tokenUrl = `https://${credentials.host}/oauth/v1/token`;
  try {
    const response = await postDuoForm(credentials, '/oauth/v1/token', {
      grant_type: 'authorization_code',
      code,
      redirect_uri: duoRedirectUri(ctx.request, ctx.clientName),
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: await clientAssertion(credentials, tokenUrl),
    });
    if (response.status !== 200) return false;
    const body = await response.json() as { id_token?: unknown };
    const claims = await verifyDuoJwt(String(body.id_token ?? ''), credentials.clientSecret);
    if (!claims) return false;
    const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    const expectedNonce = await duoNonce(ctx.env, state, ctx.user.id, ctx.deviceIdentifier);
    return (
      typeof claims.exp === 'number' && claims.exp > Date.now() / 1000 &&
      audience.includes(credentials.clientId) &&
      claims.iss === tokenUrl &&
      constantTimeEqual(String(claims.nonce ?? ''), expectedNonce) &&
      constantTimeEqual(String(claims.preferred_username ?? ''), ctx.user.email)
    );
  } catch {
    return false;
  }
}

// The connector page only accepts plain client names in its query string.
export function duoClientName(clientId: unknown): string {
  const name = String(clientId ?? '').trim().toLowerCase();
  return /^[a-z]{1,32}$/.test(name) ? name : 'web';
}
