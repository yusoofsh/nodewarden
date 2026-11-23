// SSO through OpenID Connect (authorization code flow with PKCE), after Vaultwarden's sso.rs,
// sso_client.rs and the SSO routes of identity.rs. Inert until SSO_ENABLED is true: every entry
// point checks readSsoSetting first and lets the request fall through as before.
//
// SSO signs in to existing accounts only. Accounts still come from invite registration, which sets
// the master password and key material; the token response then carries those keys, so clients
// unlock with the master password, as Vaultwarden does for SSO users that have one. Creating an
// account through SSO, trusted-device encryption and key connector are refused.
import type { Env, User } from '../types';
import { LIMITS } from '../config/limits';
import { normalizeBackupEndpointUrl } from './backup-config';
import { StorageService } from './storage';
import { constantTimeEquals } from '../utils/api-key';
import { errorResponse, jsonResponse } from '../utils/response';

export interface SsoConfig {
  authority: string;
  clientId: string;
  clientSecret: string;
  scope: string;
  pkce: boolean;
  matchEmail: boolean;
  allowUnknownEmailVerification: boolean;
}

export type SsoSetting =
  | { state: 'off' }
  | { state: 'invalid'; reason: string }
  | { state: 'on'; config: SsoConfig };

// A verified ID token, reduced to what account linking needs.
interface SsoIdentity {
  issuer: string;
  subject: string;
  email: string | null;
  emailVerified: boolean | null;
}

// One sso_auth row: a sign-in in progress, keyed by the client's state.
interface SsoAuthRow {
  state: string;
  client_challenge: string;
  nonce: string;
  idp_verifier: string;
  redirect_uri: string;
  callback_uri: string;
  binding_hash: string;
  code_hash: string | null;
  error: string | null;
  identity: string | null;
  expires_at: number;
}

export interface SsoLogin {
  state: string;
  user: User;
  // Set when this sign-in links the identity to the account, on first use after email matching.
  link: { issuer: string; subject: string } | null;
}

type PublicRateLimiter = (category?: string, maxRequests?: number) => Promise<Response | null>;

const SSO_STATE_TTL_MS = 10 * 60 * 1000;
const CACHE_TTL_MS = 5 * 60 * 1000;
const CLOCK_SKEW_SECONDS = 60;
const FETCH_TIMEOUT_MS = 10_000;
const MAX_IDP_RESPONSE_CHARS = 256 * 1024;
const BINDING_COOKIE = 'nodewarden_sso_binding';
// Vaultwarden's FAKE_SSO_IDENTIFIER: one IdP serves the whole server, not one per organization.
const SSO_IDENTIFIER = '00000000-01DC-01DC-01DC-000000000000';

const flag = (value: string | undefined): boolean => /^(true|1|yes)$/i.test(String(value ?? '').trim());

export function readSsoSetting(env: Env): SsoSetting {
  if (!flag(env.SSO_ENABLED)) return { state: 'off' };
  const authority = String(env.SSO_AUTHORITY || '').trim();
  const clientId = String(env.SSO_CLIENT_ID || '').trim();
  const clientSecret = String(env.SSO_CLIENT_SECRET || '');
  if (!authority || !clientId || !clientSecret) {
    return { state: 'invalid', reason: 'SSO_AUTHORITY, SSO_CLIENT_ID and SSO_CLIENT_SECRET must be set' };
  }
  try {
    safeHttpsUrl(authority, 'SSO_AUTHORITY');
  } catch (error) {
    return { state: 'invalid', reason: error instanceof Error ? error.message : String(error) };
  }
  const scopes = String(env.SSO_SCOPES ?? 'email profile').split(/\s+/).filter((s) => s && s !== 'openid');
  return {
    state: 'on',
    config: {
      authority,
      clientId,
      clientSecret,
      scope: ['openid', ...scopes].join(' '),
      pkce: env.SSO_PKCE === undefined || flag(env.SSO_PKCE),
      matchEmail: flag(env.SSO_SIGNUPS_MATCH_EMAIL),
      allowUnknownEmailVerification: flag(env.SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION),
    },
  };
}

// SSO_ONLY counts only when both it and SSO_ENABLED are set explicitly.
export function isSsoOnly(env: Env): boolean {
  return flag(env.SSO_ENABLED) && flag(env.SSO_ONLY);
}

// Every URL the server fetches or sends a browser to: https, and not a private, loopback or link-local host.
function safeHttpsUrl(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new Error(`${label} is missing`);
  normalizeBackupEndpointUrl(value, label);
  if (new URL(value).protocol !== 'https:') throw new Error(`${label} must start with https://`);
  return value;
}

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlBytes(value: string): Uint8Array {
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function randomToken(): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(32)));
}

async function s256(value: string): Promise<string> {
  return base64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))));
}

async function fetchIdpJson(url: string, init: RequestInit = {}): Promise<Record<string, any>> {
  const response = await fetch(url, { ...init, redirect: 'manual', signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  const text = await response.text();
  if (!response.ok) throw new Error(`${url} answered ${response.status}`);
  if (text.length > MAX_IDP_RESPONSE_CHARS) throw new Error(`${url} answered with too large a body`);
  const json = JSON.parse(text);
  if (!json || typeof json !== 'object' || Array.isArray(json)) throw new Error(`${url} did not answer a JSON object`);
  return json;
}

interface Discovery {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  basicAuth: boolean;
}

type Jwk = JsonWebKey & { kid?: string; use?: string };

// Per isolate, keyed by authority and JWKS URI. The JWKS is fetched again when a token names an unknown key.
const discoveryCache = new Map<string, { value: Discovery; at: number }>();
const jwksCache = new Map<string, { keys: Jwk[]; at: number }>();

export function clearSsoCaches(): void {
  discoveryCache.clear();
  jwksCache.clear();
}

async function discover(config: SsoConfig): Promise<Discovery> {
  const cached = discoveryCache.get(config.authority);
  if (cached && Date.now() - cached.at < CACHE_TTL_MS) return cached.value;
  const doc = await fetchIdpJson(`${config.authority.replace(/\/+$/, '')}/.well-known/openid-configuration`);
  if (doc.issuer !== config.authority) throw new Error(`Discovery issuer ${doc.issuer} does not match SSO_AUTHORITY`);
  const methods: unknown = doc.token_endpoint_auth_methods_supported;
  let basicAuth = true;
  if (Array.isArray(methods) && !methods.includes('client_secret_basic')) {
    if (!methods.includes('client_secret_post')) throw new Error('The IdP supports neither client_secret_basic nor client_secret_post');
    basicAuth = false;
  }
  const value: Discovery = {
    issuer: doc.issuer,
    authorizationEndpoint: safeHttpsUrl(doc.authorization_endpoint, 'authorization_endpoint'),
    tokenEndpoint: safeHttpsUrl(doc.token_endpoint, 'token_endpoint'),
    jwksUri: safeHttpsUrl(doc.jwks_uri, 'jwks_uri'),
    basicAuth,
  };
  discoveryCache.set(config.authority, { value, at: Date.now() });
  return value;
}

async function loadJwks(uri: string, refresh: boolean): Promise<Jwk[]> {
  const cached = jwksCache.get(uri);
  if (!refresh && cached && Date.now() - cached.at < CACHE_TTL_MS) return cached.keys;
  const doc = await fetchIdpJson(uri);
  const keys = (Array.isArray(doc.keys) ? doc.keys : []).filter((key: unknown) => key && typeof key === 'object');
  jwksCache.set(uri, { keys, at: Date.now() });
  return keys;
}

const ALGORITHMS = {
  RS256: {
    matches: (key: Jwk) => key.kty === 'RSA',
    publicJwk: (key: Jwk): JsonWebKey => ({ kty: 'RSA', n: key.n, e: key.e }),
    importParams: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    verifyParams: { name: 'RSASSA-PKCS1-v1_5' },
  },
  ES256: {
    matches: (key: Jwk) => key.kty === 'EC' && key.crv === 'P-256',
    publicJwk: (key: Jwk): JsonWebKey => ({ kty: 'EC', crv: 'P-256', x: key.x, y: key.y }),
    importParams: { name: 'ECDSA', namedCurve: 'P-256' },
    verifyParams: { name: 'ECDSA', hash: 'SHA-256' },
  },
} as const;
type Algorithm = keyof typeof ALGORITHMS;

async function findSigningKey(jwksUri: string, alg: Algorithm, kid: string | undefined): Promise<Jwk> {
  const usable = (keys: Jwk[]) => keys.filter((key) =>
    ALGORITHMS[alg].matches(key) && (!key.use || key.use === 'sig') && (!key.alg || key.alg === alg) && (kid === undefined || key.kid === kid));
  let keys = usable(await loadJwks(jwksUri, false));
  if (!keys.length) keys = usable(await loadJwks(jwksUri, true));
  if (kid === undefined ? keys.length !== 1 : keys.length === 0) throw new Error('No matching signing key in the IdP JWKS');
  return keys[0];
}

function decodeJwtPart(part: string): Record<string, any> {
  const value = JSON.parse(new TextDecoder().decode(base64UrlBytes(part)));
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Malformed id_token');
  return value;
}

async function verifyIdToken(idToken: string, config: SsoConfig, discovery: Discovery, nonce: string): Promise<SsoIdentity> {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('Malformed id_token');
  const header = decodeJwtPart(parts[0]);
  const claims = decodeJwtPart(parts[1]);
  const alg = header.alg;
  if (alg !== 'RS256' && alg !== 'ES256') throw new Error(`Unsupported id_token algorithm ${alg}`);
  if (header.crit !== undefined) throw new Error('Unsupported id_token crit header');
  const spec = ALGORITHMS[alg as Algorithm];
  const jwk = await findSigningKey(discovery.jwksUri, alg, typeof header.kid === 'string' ? header.kid : undefined);
  const key = await crypto.subtle.importKey('jwk', spec.publicJwk(jwk), spec.importParams, false, ['verify']);
  const signed = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  if (!(await crypto.subtle.verify(spec.verifyParams, key, base64UrlBytes(parts[2]), signed))) {
    throw new Error('Invalid id_token signature');
  }

  const now = Math.floor(Date.now() / 1000);
  if (claims.iss !== discovery.issuer) throw new Error('Invalid id_token issuer');
  // Like the openidconnect crate's default verifier, any audience other than this client is untrusted.
  const audiences: unknown[] = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.length || audiences.some((aud) => aud !== config.clientId)) throw new Error('Invalid id_token audience');
  if (claims.azp !== undefined && claims.azp !== config.clientId) throw new Error('Invalid id_token azp');
  if (typeof claims.exp !== 'number' || claims.exp + CLOCK_SKEW_SECONDS <= now) throw new Error('Expired id_token');
  if (typeof claims.iat !== 'number') throw new Error('id_token has no iat');
  if (claims.nbf !== undefined && (typeof claims.nbf !== 'number' || claims.nbf - CLOCK_SKEW_SECONDS > now)) {
    throw new Error('id_token is not valid yet');
  }
  if (typeof claims.nonce !== 'string' || !constantTimeEquals(claims.nonce, nonce)) throw new Error('Invalid id_token nonce');
  if (typeof claims.sub !== 'string' || !claims.sub) throw new Error('id_token has no subject');
  return {
    issuer: claims.iss,
    subject: claims.sub,
    email: typeof claims.email === 'string' && claims.email.includes('@') ? claims.email.trim().toLowerCase() : null,
    emailVerified: typeof claims.email_verified === 'boolean' ? claims.email_verified : null,
  };
}

async function exchangeCode(config: SsoConfig, code: string, row: SsoAuthRow): Promise<SsoIdentity> {
  const discovery = await discover(config);
  const form = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: row.callback_uri });
  if (config.pkce) form.set('code_verifier', row.idp_verifier);
  const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' };
  if (discovery.basicAuth) {
    const encode = (value: string) => new URLSearchParams({ v: value }).toString().slice(2);
    headers.Authorization = `Basic ${btoa(`${encode(config.clientId)}:${encode(config.clientSecret)}`)}`;
  } else {
    form.set('client_id', config.clientId);
    form.set('client_secret', config.clientSecret);
  }
  const tokens = await fetchIdpJson(discovery.tokenEndpoint, { method: 'POST', headers, body: form.toString() });
  if (typeof tokens.id_token !== 'string') throw new Error('Token response did not contain an id_token');
  return verifyIdToken(tokens.id_token, config, discovery, row.nonce);
}

// The redirect each client is sent back to is fixed, as in Vaultwarden's sso::authorize_url. Web and
// browser clients finish on the official web vault's sso-connector.html, which this server does not serve.
function clientRedirectUri(clientId: string, requested: string): string | null {
  const localhost = /^http:\/\/localhost:(806[5-9]|8070)$/.test(requested) ? requested : null;
  if (clientId === 'desktop') return localhost ?? 'bitwarden://sso-callback';
  if (clientId === 'mobile') return 'bitwarden://sso-callback';
  if (clientId === 'cli') return localhost;
  return null;
}

function bindingCookie(request: Request, value: string, maxAgeSeconds: number): string {
  const parts = [`${BINDING_COOKIE}=${value}`, 'Path=/identity/connect/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${maxAgeSeconds}`];
  if (new URL(request.url).protocol === 'https:') parts.push('Secure');
  return parts.join('; ');
}

function readBindingCookie(request: Request): string {
  for (const part of String(request.headers.get('Cookie') || '').split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (name === BINDING_COOKIE) return rest.join('=');
  }
  return '';
}

function redirectResponse(location: string, cookie: string): Response {
  return new Response(null, { status: 307, headers: { Location: location, 'Set-Cookie': cookie, 'Cache-Control': 'no-store' } });
}

// GET /identity/connect/authorize
async function handleAuthorize(request: Request, env: Env, config: SsoConfig): Promise<Response> {
  const url = new URL(request.url);
  const query = new Map([...url.searchParams].map(([key, value]) => [key.toLowerCase(), value.trim()]));
  const clientId = query.get('client_id') ?? query.get('clientid') ?? '';
  const redirectUri = clientRedirectUri(clientId, query.get('redirect_uri') ?? query.get('redirecturi') ?? '');
  const state = query.get('state') ?? '';
  const clientChallenge = query.get('code_challenge') ?? '';
  if (!redirectUri) return errorResponse(`Unsupported SSO client ${clientId}`, 400);
  if (query.get('code_challenge_method') !== 'S256') return errorResponse('Unsupported code challenge method', 400);
  if (!/^[A-Za-z0-9_-]{43}$/.test(clientChallenge)) return errorResponse('Invalid code challenge', 400);
  if (!state || state.length > 1024) return errorResponse('Invalid state', 400);

  let discovery: Discovery;
  try {
    discovery = await discover(config);
  } catch (error) {
    console.error('SSO discovery failed:', error instanceof Error ? error.message : error);
    return errorResponse('The SSO provider is unavailable', 502);
  }

  const nonce = randomToken();
  const idpVerifier = randomToken();
  const binding = randomToken();
  const callbackUri = `${url.origin}/identity/connect/oidc-signin`;
  const now = Date.now();
  await env.DB.prepare('DELETE FROM sso_auth WHERE expires_at <= ?').bind(now).run();
  try {
    await env.DB.prepare(
      'INSERT INTO sso_auth (state, client_challenge, nonce, idp_verifier, redirect_uri, callback_uri, binding_hash, expires_at) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(state, clientChallenge, nonce, idpVerifier, redirectUri, callbackUri, await s256(binding), now + SSO_STATE_TTL_MS).run();
  } catch {
    return errorResponse('SSO state is already in use', 400);
  }

  const target = new URL(discovery.authorizationEndpoint);
  target.searchParams.set('response_type', 'code');
  target.searchParams.set('client_id', config.clientId);
  target.searchParams.set('redirect_uri', callbackUri);
  target.searchParams.set('scope', config.scope);
  // The client's state goes to the IdP base64url-encoded, as Vaultwarden does, so any IdP passes it back intact.
  target.searchParams.set('state', base64Url(new TextEncoder().encode(state)));
  target.searchParams.set('nonce', nonce);
  if (config.pkce) {
    target.searchParams.set('code_challenge', await s256(idpVerifier));
    target.searchParams.set('code_challenge_method', 'S256');
  }
  return redirectResponse(target.toString(), bindingCookie(request, binding, SSO_STATE_TTL_MS / 1000));
}

// GET /identity/connect/oidc-signin: the IdP's redirect. Bitwarden clients only read code and state, so an
// IdP error is stored and the encoded state stands in for the code, which the token grant then refuses.
async function handleOidcSignin(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const encodedState = url.searchParams.get('state') ?? '';
  let state: string;
  try {
    state = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(base64UrlBytes(encodedState));
  } catch {
    return errorResponse('Invalid state', 400);
  }
  const row = await env.DB.prepare('SELECT * FROM sso_auth WHERE state = ?').bind(state).first<SsoAuthRow>();
  if (!row || row.expires_at <= Date.now()) return errorResponse('Unknown or expired SSO state', 400);
  const binding = readBindingCookie(request);
  if (!binding || !constantTimeEquals(await s256(binding), row.binding_hash)) return errorResponse('SSO session binding mismatch', 400);

  const idpError = url.searchParams.get('error');
  const code = idpError ? encodedState : url.searchParams.get('code') ?? '';
  if (!code) return errorResponse('Missing authorization code', 400);
  const error = idpError ? JSON.stringify({ error: idpError, description: url.searchParams.get('error_description') }) : null;
  const stored = await env.DB.prepare('UPDATE sso_auth SET code_hash = ?, error = ? WHERE state = ? AND code_hash IS NULL')
    .bind(await s256(code), error, state).run();
  if (!stored.meta.changes) return errorResponse('SSO state was already used', 400);

  const target = new URL(row.redirect_uri);
  target.searchParams.set('code', code);
  target.searchParams.set('state', state);
  target.searchParams.set('scope', 'api offline_access');
  target.searchParams.set('iss', url.origin);
  return redirectResponse(target.toString(), bindingCookie(request, '', 0));
}

const SSO_ROUTES = new Set([
  'GET /identity/sso/prevalidate',
  'GET /identity/connect/authorize',
  'GET /identity/connect/oidc-signin',
  'POST /api/organizations/domain/sso/verified',
]);

// Returns null, so the request falls through unchanged, for every other route and whenever SSO is off.
export async function handleSsoPublicRoute(
  request: Request,
  env: Env,
  path: string,
  method: string,
  enforcePublicRateLimit: PublicRateLimiter
): Promise<Response | null> {
  const route = `${method} ${path}`;
  if (!SSO_ROUTES.has(route)) return null;
  const setting = readSsoSetting(env);
  if (setting.state === 'off') return null;
  const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
  if (blocked) return blocked;
  if (setting.state === 'invalid') {
    console.error('SSO is enabled but its configuration is invalid:', setting.reason);
    return errorResponse('SSO sign-in is not available: the server configuration is invalid', 500);
  }
  if (route === 'GET /identity/sso/prevalidate') {
    // Clients pass this token back to authorize, which ignores it, as Vaultwarden's does.
    return jsonResponse({ token: randomToken() });
  }
  if (route === 'POST /api/organizations/domain/sso/verified') {
    const origin = new URL(request.url).origin;
    return jsonResponse({
      object: 'list',
      data: [{ organizationIdentifier: SSO_IDENTIFIER, organizationName: SSO_IDENTIFIER, domainName: origin }],
      continuationToken: null,
    });
  }
  if (route === 'GET /identity/connect/authorize') return handleAuthorize(request, env, setting.config);
  return handleOidcSignin(request, env);
}

// The authorization_code grant: finds the sign-in by its code, checks the client's PKCE verifier, exchanges
// the code once and keeps the verified identity on the row, so the 2FA retry with the same code works, then
// finds the account. The row is consumed by redeemSsoLogin once 2FA has passed.
export async function resolveSsoLogin(env: Env, body: Record<string, string>): Promise<SsoLogin | { error: string }> {
  const setting = readSsoSetting(env);
  if (setting.state !== 'on') return { error: 'SSO sign-in is not available' };
  const config = setting.config;
  const code = String(body.code || '').trim();
  const verifier = String(body.code_verifier || '').trim();
  if (!code || !verifier) return { error: 'code and code_verifier are required' };

  const db = env.DB;
  const row = await db.prepare('SELECT * FROM sso_auth WHERE code_hash = ?').bind(await s256(code)).first<SsoAuthRow>();
  if (!row) return { error: 'Invalid code' };
  const fail = async (message: string) => {
    await db.prepare('DELETE FROM sso_auth WHERE state = ?').bind(row.state).run();
    return { error: message };
  };
  if (row.expires_at <= Date.now()) return fail('SSO sign-in expired. Try again');
  if (!constantTimeEquals(await s256(verifier), row.client_challenge)) return fail('PKCE client challenge failed');
  if (row.error) {
    const idpError = JSON.parse(row.error) as { error: string; description: string | null };
    return fail(`SSO authorization failed: ${idpError.error}${idpError.description ? `, ${idpError.description}` : ''}`);
  }

  let identity: SsoIdentity;
  if (row.identity) {
    identity = JSON.parse(row.identity);
  } else {
    try {
      identity = await exchangeCode(config, code, row);
    } catch (error) {
      console.warn('SSO code exchange failed:', error instanceof Error ? error.message : error);
      return fail('SSO sign-in failed');
    }
    const saved = await db.prepare('UPDATE sso_auth SET identity = ? WHERE state = ? AND identity IS NULL')
      .bind(JSON.stringify(identity), row.state).run();
    if (!saved.meta.changes) return { error: 'Invalid code' };
  }

  const storage = new StorageService(db);
  const linked = await db.prepare('SELECT user_id FROM sso_users WHERE issuer = ? AND subject = ?')
    .bind(identity.issuer, identity.subject).first<{ user_id: string }>();
  if (linked) {
    const user = await storage.getUserById(linked.user_id);
    return user ? { state: row.state, user, link: null } : fail('Unknown account');
  }

  // Signups stay invite-only: an identity no account is linked to may only match an existing account by
  // an email the IdP asserts as verified, and only when the operator turned matching on.
  const noAccount = 'No account is linked to this SSO identity, and accounts cannot be created through SSO';
  if (!config.matchEmail || !identity.email) return fail(noAccount);
  if (identity.emailVerified === false) return fail('Email is not verified by the SSO provider');
  if (identity.emailVerified === null && !config.allowUnknownEmailVerification) return fail('Email verification status is unknown');
  const user = await storage.getUser(identity.email);
  if (!user) return fail(noAccount);
  if (await db.prepare('SELECT 1 FROM sso_users WHERE user_id = ?').bind(user.id).first()) {
    return fail('Existing SSO user with same email');
  }
  return { state: row.state, user, link: { issuer: identity.issuer, subject: identity.subject } };
}

// Consumes the sign-in exactly once and records a new link. False means another request consumed it first.
export async function redeemSsoLogin(env: Env, login: SsoLogin): Promise<boolean> {
  const consumed = await env.DB.prepare('DELETE FROM sso_auth WHERE state = ?').bind(login.state).run();
  if (!consumed.meta.changes) return false;
  if (!login.link) return true;
  try {
    await env.DB.prepare('INSERT INTO sso_users (issuer, subject, user_id, created_at) VALUES (?, ?, ?, ?)')
      .bind(login.link.issuer, login.link.subject, login.user.id, new Date().toISOString()).run();
    return true;
  } catch {
    return false;
  }
}
