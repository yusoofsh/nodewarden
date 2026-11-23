import assert from 'node:assert/strict';
import test from 'node:test';

import type { Env, User } from '../src/types';
import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { createPasswordVerifier } from '../src/services/password-verifier';
import { clearSsoCaches } from '../src/services/sso';
import { handlePublicRoute } from '../src/router-public';
import { buildBackupArchive } from '../src/services/backup-archive';
import { importBackupArchiveBytes } from '../src/services/backup-import';
import { createRecoveryCode } from '../src/utils/recovery-code';
import { createTestDb } from './lib/d1-sqlite';

// A mocked OpenID provider behind globalThis.fetch: discovery, JWKS and a token endpoint that checks the
// client secret, the server's PKCE verifier and the redirect URI, then signs an ID token with Web Crypto.
const AUTHORITY = 'https://idp.example.com';
const CLIENT_ID = 'nodewarden';
const CLIENT_SECRET = 'idp-secret';
const PASSWORD = 'master-hash';

const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const s256 = async (value: string) => b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))));
const randomString = () => b64url(crypto.getRandomValues(new Uint8Array(32)));

interface SigningKey { kid: string; alg: 'RS256' | 'ES256'; privateKey: CryptoKey; publicJwk: JsonWebKey }

const KEY_PARAMS = {
  RS256: { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
  ES256: { name: 'ECDSA', namedCurve: 'P-256' },
} as const;
const SIGN_PARAMS = { RS256: { name: 'RSASSA-PKCS1-v1_5' }, ES256: { name: 'ECDSA', hash: 'SHA-256' } } as const;

async function newKey(kid: string, alg: 'RS256' | 'ES256' = 'RS256'): Promise<SigningKey> {
  const pair = await crypto.subtle.generateKey(KEY_PARAMS[alg], true, ['sign', 'verify']) as CryptoKeyPair;
  const publicJwk = { ...(await crypto.subtle.exportKey('jwk', pair.publicKey)), kid, use: 'sig', alg };
  return { kid, alg, privateKey: pair.privateKey, publicJwk };
}

interface PendingCode { challenge: string; nonce: string; redirectUri: string }

const idp = {
  published: [] as SigningKey[],
  signer: null as SigningKey | null,
  codes: new Map<string, PendingCode>(),
  subject: 'subject-1',
  email: 'member@example.test' as string | undefined,
  overrides: {} as Record<string, unknown>,
  header: {} as Record<string, unknown>,
  discovery: {} as Record<string, unknown>,
  clientAuth: '',
  fetches: [] as string[],
  tokenCalls: 0,
};

async function signIdToken(claims: Record<string, unknown>): Promise<string> {
  const key = idp.signer!;
  const part = (value: unknown) => b64url(new TextEncoder().encode(JSON.stringify(value)));
  const input = `${part({ alg: key.alg, kid: key.kid, typ: 'JWT', ...idp.header })}.${part(claims)}`;
  const signature = await crypto.subtle.sign(SIGN_PARAMS[key.alg], key.privateKey, new TextEncoder().encode(input));
  return `${input}.${b64url(new Uint8Array(signature))}`;
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input instanceof Request ? input.url : input);
  idp.fetches.push(url);
  if (url === `${AUTHORITY}/.well-known/openid-configuration`) {
    return json({
      issuer: AUTHORITY,
      authorization_endpoint: `${AUTHORITY}/authorize`,
      token_endpoint: `${AUTHORITY}/token`,
      jwks_uri: `${AUTHORITY}/jwks`,
      token_endpoint_auth_methods_supported: ['client_secret_basic'],
      ...idp.discovery,
    });
  }
  if (url === `${AUTHORITY}/jwks`) return json({ keys: idp.published.map((key) => key.publicJwk) });
  if (url === `${AUTHORITY}/token`) {
    idp.tokenCalls++;
    const headers = new Headers(init?.headers);
    const form = new URLSearchParams(String(init?.body));
    if (headers.get('Authorization') === `Basic ${btoa(`${CLIENT_ID}:${CLIENT_SECRET}`)}`) idp.clientAuth = 'basic';
    else if (form.get('client_id') === CLIENT_ID && form.get('client_secret') === CLIENT_SECRET) idp.clientAuth = 'post';
    else return json({ error: 'invalid_client' }, 401);
    const pending = idp.codes.get(form.get('code') ?? '');
    idp.codes.delete(form.get('code') ?? '');
    if (!pending || pending.redirectUri !== form.get('redirect_uri')) return json({ error: 'invalid_grant' }, 400);
    if ((await s256(form.get('code_verifier') ?? '')) !== pending.challenge) return json({ error: 'invalid_grant' }, 400);
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      iss: AUTHORITY, aud: CLIENT_ID, sub: idp.subject, iat: now, exp: now + 300, nonce: pending.nonce,
      email: idp.email, email_verified: true, ...idp.overrides,
    };
    return json({ access_token: 'idp-access', token_type: 'Bearer', expires_in: 300, id_token: await signIdToken(claims) });
  }
  throw new Error(`unexpected fetch ${url}`);
}) as typeof fetch;

let verifier: string;

function makeUser(name: 'admin' | 'member' | 'other', role: 'admin' | 'user'): User {
  return {
    id: crypto.randomUUID(), email: `${name}@example.test`, name, masterPasswordHint: null, masterPasswordHash: verifier,
    key: `2.${name}key|aXY=|bWFj`, privateKey: `2.${name}priv|aXY=|bWFj`, publicKey: `pub-${name}`, kdfType: 0, kdfIterations: 600000,
    securityStamp: 'stamp', role, status: 'active', totpSecret: null, totpRecoveryCode: null,
    createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
  } as User;
}

async function setup(vars: Record<string, string> = { SSO_ENABLED: 'true' }) {
  verifier ??= await createPasswordVerifier(PASSWORD);
  clearSsoCaches();
  const key = await newKey('key-1');
  Object.assign(idp, {
    published: [key], signer: key, codes: new Map(), subject: 'subject-1', email: 'member@example.test',
    overrides: {}, header: {}, discovery: {}, clientAuth: '', fetches: [], tokenCalls: 0,
  });
  const db = createTestDb();
  await ensureStorageSchema(db);
  const env = {
    DB: db, JWT_SECRET: 'x'.repeat(40),
    SSO_AUTHORITY: AUTHORITY, SSO_CLIENT_ID: CLIENT_ID, SSO_CLIENT_SECRET: CLIENT_SECRET, ...vars,
  } as unknown as Env;
  const storage = new StorageService(db);
  const admin = makeUser('admin', 'admin');
  const member = makeUser('member', 'user');
  await storage.createUser(admin);
  await storage.createUser(member);
  return { db, env, storage, admin, member };
}
type Ctx = Awaited<ReturnType<typeof setup>>;

async function call(c: Ctx, method: string, path: string, init: { form?: Record<string, string>; cookie?: string } = {}) {
  const headers: Record<string, string> = { 'CF-Connecting-IP': '203.0.113.9' };
  if (init.cookie) headers.Cookie = init.cookie;
  if (init.form) headers['Content-Type'] = 'application/x-www-form-urlencoded';
  const request = new Request(`https://vault.test${path}`, { method, headers, body: init.form ? new URLSearchParams(init.form).toString() : undefined });
  return handlePublicRoute(request, c.env, new URL(request.url).pathname, method, async () => null);
}

async function rows(c: Ctx, sql: string) {
  return (await c.db.prepare(sql).all()).results.map((row) => ({ ...(row as object) })) as Array<Record<string, unknown>>;
}

// The mobile client's part of the flow: authorize, then the IdP redirects to oidc-signin with a code.
async function startSignIn(c: Ctx) {
  const clientVerifier = randomString();
  const clientState = randomString();
  const authorize = await call(c, 'GET', `/identity/connect/authorize?client_id=mobile&redirect_uri=bitwarden%3A%2F%2Fsso-callback&response_type=code&scope=api%20offline_access&state=${clientState}&code_challenge=${await s256(clientVerifier)}&code_challenge_method=S256&ssoToken=x`);
  assert.equal(authorize?.status, 307, await authorize?.clone().text());
  const location = new URL(authorize!.headers.get('Location')!);
  const cookie = authorize!.headers.get('Set-Cookie')!.split(';')[0];
  const code = `code-${randomString()}`;
  idp.codes.set(code, {
    challenge: location.searchParams.get('code_challenge')!,
    nonce: location.searchParams.get('nonce')!,
    redirectUri: location.searchParams.get('redirect_uri')!,
  });
  const idpState = location.searchParams.get('state')!;
  return { clientVerifier, clientState, cookie, code, idpState, location };
}

async function signIn(c: Ctx) {
  const flow = await startSignIn(c);
  const callback = await call(c, 'GET', `/identity/connect/oidc-signin?code=${flow.code}&state=${flow.idpState}`, { cookie: flow.cookie });
  assert.equal(callback?.status, 307, await callback?.clone().text());
  return { ...flow, callback: callback! };
}

async function token(c: Ctx, code: string, codeVerifier: string, extra: Record<string, string> = {}) {
  const res = await call(c, 'POST', '/identity/connect/token', {
    form: {
      grant_type: 'authorization_code', code, code_verifier: codeVerifier, client_id: 'mobile', scope: 'api offline_access',
      deviceType: '0', deviceIdentifier: '11111111-2222-3333-4444-555555555555', deviceName: 'phone', ...extra,
    },
  });
  return { status: res!.status, json: await res!.json() as Record<string, any> };
}

const passwordLogin = (c: Ctx, email: string) => call(c, 'POST', '/identity/connect/token', {
  form: { grant_type: 'password', username: email, password: PASSWORD, scope: 'api offline_access', client_id: 'web', deviceType: '9', deviceIdentifier: 'dev-1', deviceName: 'web' },
});

const link = (c: Ctx, user: User, subject = 'subject-1') =>
  c.db.prepare('INSERT INTO sso_users (issuer, subject, user_id, created_at) VALUES (?, ?, ?, ?)').bind(AUTHORITY, subject, user.id, '2026-01-01').run();

test('an unconfigured server answers exactly as before', async () => {
  const c = await setup({ SSO_ONLY: 'true' });
  for (const [method, path] of [
    ['GET', '/identity/sso/prevalidate'],
    ['GET', '/identity/connect/authorize?client_id=mobile&state=s&code_challenge=c&code_challenge_method=S256'],
    ['GET', '/identity/connect/oidc-signin?code=c&state=s'],
    ['POST', '/api/organizations/domain/sso/verified'],
  ]) {
    assert.equal(await call(c, method, path), null, `${method} ${path} falls through`);
  }
  const grant = await token(c, 'code', 'verifier');
  assert.equal(grant.status, 400);
  assert.equal(grant.json.error, 'unsupported_grant_type');
  assert.equal((await passwordLogin(c, 'member@example.test'))!.status, 200, 'SSO_ONLY without SSO_ENABLED does nothing');
  assert.deepEqual(idp.fetches, []);
  assert.deepEqual(await rows(c, 'SELECT * FROM sso_auth'), []);
});

test('happy path: verified email links the account once, then the subject signs in and gets the key material', async () => {
  const c = await setup({ SSO_ENABLED: 'true', SSO_SIGNUPS_MATCH_EMAIL: 'true' });
  const prevalidate = await call(c, 'GET', '/identity/sso/prevalidate?domainHint=x');
  assert.equal(prevalidate?.status, 200);
  assert.ok((await prevalidate!.json() as any).token);
  const verified = await call(c, 'POST', '/api/organizations/domain/sso/verified');
  assert.equal((await verified!.json() as any).data[0].organizationIdentifier, '00000000-01DC-01DC-01DC-000000000000');

  const flow = await signIn(c);
  assert.equal(flow.location.origin + flow.location.pathname, `${AUTHORITY}/authorize`);
  assert.equal(flow.location.searchParams.get('client_id'), CLIENT_ID);
  assert.equal(flow.location.searchParams.get('scope'), 'openid email profile');
  assert.equal(flow.location.searchParams.get('redirect_uri'), 'https://vault.test/identity/connect/oidc-signin');
  assert.match(flow.cookie, /^nodewarden_sso_binding=/);
  const back = new URL(flow.callback.headers.get('Location')!);
  assert.equal(`${back.protocol}//${back.host}`, 'bitwarden://sso-callback');
  assert.equal(back.searchParams.get('code'), flow.code);
  assert.equal(back.searchParams.get('state'), flow.clientState);

  const res = await token(c, flow.code, flow.clientVerifier);
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.ok(res.json.access_token && res.json.refresh_token);
  assert.equal(res.json.Key, c.member.key);
  assert.equal(res.json.PrivateKey, c.member.privateKey);
  assert.equal(res.json.UserDecryptionOptions.HasMasterPassword, true);
  assert.equal(res.json.UserDecryptionOptions.MasterPasswordUnlock.MasterKeyEncryptedUserKey, c.member.key);
  assert.equal(res.json.UserDecryptionOptions.TrustedDeviceOption, null);
  assert.equal(res.json.UserDecryptionOptions.KeyConnectorOption, null);
  assert.equal(res.json.ApiUseKeyConnector, false);
  assert.deepEqual(await rows(c, 'SELECT issuer, subject, user_id FROM sso_users'), [{ issuer: AUTHORITY, subject: 'subject-1', user_id: c.member.id }]);
  assert.deepEqual(await rows(c, 'SELECT * FROM sso_auth'), [], 'the sign-in is consumed');

  // The linked subject signs in again even with matching off and a different email at the IdP.
  c.env.SSO_SIGNUPS_MATCH_EMAIL = 'false';
  idp.email = 'renamed@example.test';
  const again = await signIn(c);
  const second = await token(c, again.code, again.clientVerifier);
  assert.equal(second.status, 200, JSON.stringify(second.json));
  assert.equal(second.json.Key, c.member.key);
});

test('a code cannot be redeemed twice and a state cannot be used twice', async () => {
  const c = await setup();
  await link(c, c.member);
  const flow = await signIn(c);
  const replayedState = await call(c, 'GET', `/identity/connect/oidc-signin?code=other&state=${flow.idpState}`, { cookie: flow.cookie });
  assert.equal(replayedState?.status, 400);
  assert.equal((await token(c, flow.code, flow.clientVerifier)).status, 200);
  const replayedCode = await token(c, flow.code, flow.clientVerifier);
  assert.equal(replayedCode.status, 400);
  assert.equal(replayedCode.json.error_description, 'Invalid code');
  assert.equal(idp.tokenCalls, 1);
});

test('the callback needs the binding cookie of the browser that started the flow', async () => {
  const c = await setup();
  const flow = await startSignIn(c);
  const callback = await call(c, 'GET', `/identity/connect/oidc-signin?code=${flow.code}&state=${flow.idpState}`, { cookie: 'nodewarden_sso_binding=forged' });
  assert.equal(callback?.status, 400);
});

test('an expired state is refused at the callback and at the token grant', async () => {
  const c = await setup();
  await link(c, c.member);
  const early = await startSignIn(c);
  await c.db.prepare('UPDATE sso_auth SET expires_at = 1').run();
  assert.equal((await call(c, 'GET', `/identity/connect/oidc-signin?code=${early.code}&state=${early.idpState}`, { cookie: early.cookie }))?.status, 400);

  const late = await signIn(c);
  await c.db.prepare('UPDATE sso_auth SET expires_at = 1 WHERE state = ?').bind(late.clientState).run();
  const res = await token(c, late.code, late.clientVerifier);
  assert.equal(res.status, 400);
  assert.equal(idp.tokenCalls, 0);
});

test('a wrong PKCE verifier is refused before the IdP is contacted and burns the sign-in', async () => {
  const c = await setup();
  await link(c, c.member);
  const flow = await signIn(c);
  const wrong = await token(c, flow.code, randomString());
  assert.equal(wrong.status, 400);
  assert.equal(wrong.json.error_description, 'PKCE client challenge failed');
  assert.equal(idp.tokenCalls, 0);
  assert.equal((await token(c, flow.code, flow.clientVerifier)).status, 400);
});

for (const [name, change] of [
  ['bad signature', async () => { idp.signer = { ...(await newKey('key-1')) }; }],
  ['wrong audience', () => { idp.overrides = { aud: 'someone-else' }; }],
  ['extra untrusted audience', () => { idp.overrides = { aud: [CLIENT_ID, 'someone-else'], azp: CLIENT_ID }; }],
  ['wrong azp', () => { idp.overrides = { azp: 'someone-else' }; }],
  ['wrong issuer', () => { idp.overrides = { iss: 'https://evil.example.com' }; }],
  ['expired token', () => { idp.overrides = { exp: Math.floor(Date.now() / 1000) - 3600 }; }],
  ['nonce mismatch', () => { idp.overrides = { nonce: 'other-nonce' }; }],
  ['missing subject', () => { idp.overrides = { sub: '' }; }],
  ['none algorithm', () => { idp.header = { alg: 'none' }; }],
  ['HS256 algorithm', () => { idp.header = { alg: 'HS256' }; }],
] as const) {
  test(`an ID token with a ${name} is refused`, async () => {
    const c = await setup();
    await link(c, c.member);
    await change();
    const flow = await signIn(c);
    const res = await token(c, flow.code, flow.clientVerifier);
    assert.equal(res.status, 400, JSON.stringify(res.json));
    assert.equal(res.json.error_description, 'SSO sign-in failed');
    assert.equal(res.json.access_token, undefined);
    assert.deepEqual(await rows(c, 'SELECT * FROM sso_auth'), [], 'a failed exchange burns the sign-in');
  });
}

test('an ID token signed with a rotated key is accepted after one JWKS refetch', async () => {
  const c = await setup();
  await link(c, c.member);
  const first = await signIn(c);
  assert.equal((await token(c, first.code, first.clientVerifier)).status, 200);
  const rotated = await newKey('key-2');
  idp.published.push(rotated);
  idp.signer = rotated;
  const jwksFetches = () => idp.fetches.filter((url) => url.endsWith('/jwks')).length;
  const before = jwksFetches();
  const second = await signIn(c);
  assert.equal((await token(c, second.code, second.clientVerifier)).status, 200);
  assert.equal(jwksFetches(), before + 1);
});

test('email matching refuses an email the IdP does not assert as verified', async () => {
  const c = await setup({ SSO_ENABLED: 'true', SSO_SIGNUPS_MATCH_EMAIL: 'true' });
  idp.overrides = { email_verified: false };
  let flow = await signIn(c);
  let res = await token(c, flow.code, flow.clientVerifier);
  assert.equal(res.status, 400);
  assert.equal(res.json.error_description, 'Email is not verified by the SSO provider');

  idp.overrides = { email_verified: undefined };
  flow = await signIn(c);
  res = await token(c, flow.code, flow.clientVerifier);
  assert.equal(res.json.error_description, 'Email verification status is unknown');
  assert.deepEqual(await rows(c, 'SELECT * FROM sso_users'), []);

  c.env.SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION = 'true';
  flow = await signIn(c);
  assert.equal((await token(c, flow.code, flow.clientVerifier)).status, 200);
});

test('an unknown subject gets no account: email matching is off by default and SSO never signs up', async () => {
  const c = await setup();
  const users = (await rows(c, 'SELECT id FROM users')).length;
  let flow = await signIn(c);
  let res = await token(c, flow.code, flow.clientVerifier);
  assert.equal(res.status, 400);
  assert.match(res.json.error_description, /No account is linked/);

  c.env.SSO_SIGNUPS_MATCH_EMAIL = 'true';
  idp.email = 'stranger@example.test';
  flow = await signIn(c);
  res = await token(c, flow.code, flow.clientVerifier);
  assert.match(res.json.error_description, /No account is linked/);
  assert.equal((await rows(c, 'SELECT id FROM users')).length, users);
  assert.deepEqual(await rows(c, 'SELECT * FROM sso_users'), []);
});

test('email matching will not link a second identity to an account', async () => {
  const c = await setup({ SSO_ENABLED: 'true', SSO_SIGNUPS_MATCH_EMAIL: 'true' });
  await link(c, c.member, 'subject-0');
  const flow = await signIn(c);
  const res = await token(c, flow.code, flow.clientVerifier);
  assert.equal(res.json.error_description, 'Existing SSO user with same email');
});

test('SSO keeps 2FA: the challenge comes first, and the retry with the same code finishes without a second exchange', async () => {
  const c = await setup();
  const recovery = createRecoveryCode();
  await c.storage.saveUser({ ...c.member, totpSecret: 'JBSWY3DPEHPK3PXP', totpRecoveryCode: recovery });
  await link(c, c.member);
  const flow = await signIn(c);
  const challenge = await token(c, flow.code, flow.clientVerifier);
  assert.equal(challenge.status, 400);
  assert.deepEqual(challenge.json.TwoFactorProviders, ['0']);
  assert.equal(challenge.json.access_token, undefined);
  const done = await token(c, flow.code, flow.clientVerifier, { twoFactorProvider: '8', twoFactorToken: recovery });
  assert.equal(done.status, 200, JSON.stringify(done.json));
  assert.equal(idp.tokenCalls, 1);
});

test('SSO_ONLY refuses password sign-in except for admins', async () => {
  const c = await setup({ SSO_ENABLED: 'true', SSO_ONLY: 'true' });
  const member = await passwordLogin(c, 'member@example.test');
  assert.equal(member!.status, 400);
  assert.equal((await member!.json() as any).error_description, 'SSO sign-in is required');
  assert.equal((await passwordLogin(c, 'admin@example.test'))!.status, 200);
});

test('web and browser clients and other redirect URIs are refused', async () => {
  const c = await setup();
  const challenge = await s256('v');
  for (const query of [
    `client_id=web&redirect_uri=https%3A%2F%2Fvault.test%2Fsso-connector.html`,
    `client_id=browser&redirect_uri=https%3A%2F%2Fvault.test%2Fsso-connector.html`,
    `client_id=cli&redirect_uri=https%3A%2F%2Fevil.example.com`,
  ]) {
    const res = await call(c, 'GET', `/identity/connect/authorize?${query}&state=s&code_challenge=${challenge}&code_challenge_method=S256`);
    assert.equal(res?.status, 400, query);
  }
  const plain = await call(c, 'GET', `/identity/connect/authorize?client_id=mobile&state=s&code_challenge=${challenge}&code_challenge_method=plain`);
  assert.equal(plain?.status, 400);
  assert.deepEqual(idp.fetches, []);
});

test('a private, loopback or plain-http authority is refused without a fetch', async () => {
  for (const authority of ['https://10.0.0.5', 'https://127.0.0.1', 'https://localhost', 'https://169.254.169.254', 'https://[::1]', 'http://idp.example.com', 'https://idp.internal']) {
    const c = await setup({ SSO_ENABLED: 'true', SSO_AUTHORITY: authority });
    const res = await call(c, 'GET', `/identity/connect/authorize?client_id=mobile&state=s&code_challenge=${await s256('v')}&code_challenge_method=S256`);
    assert.equal(res?.status, 500, authority);
    const grant = await token(c, 'code', 'verifier');
    assert.equal(grant.status, 400, authority);
    assert.deepEqual(idp.fetches, [], authority);
  }
});

test('discovery that points the token endpoint at a private host is refused', async () => {
  const c = await setup();
  idp.discovery = { token_endpoint: 'https://192.168.1.10/token' };
  const res = await call(c, 'GET', `/identity/connect/authorize?client_id=mobile&state=s&code_challenge=${await s256('v')}&code_challenge_method=S256`);
  assert.equal(res?.status, 502);
  assert.ok(!idp.fetches.some((url) => url.includes('192.168.1.10')));
});

test('backups carry the identity links and leave sign-ins in progress behind', async () => {
  const c = await setup();
  await link(c, c.member);
  await startSignIn(c);
  const target = await setup();
  await importBackupArchiveBytes((await buildBackupArchive(c.env)).bytes, target.env, target.admin.id, false);
  assert.deepEqual(await rows(target, 'SELECT issuer, subject, user_id FROM sso_users'), [{ issuer: AUTHORITY, subject: 'subject-1', user_id: c.member.id }]);
  assert.deepEqual(await rows(target, 'SELECT * FROM sso_auth'), []);
});

test('an ES256 ID token is accepted, with client_secret_post when the IdP only offers that', async () => {
  const c = await setup();
  await link(c, c.member);
  const ec = await newKey('ec-1', 'ES256');
  idp.published = [ec];
  idp.signer = ec;
  idp.discovery = { token_endpoint_auth_methods_supported: ['client_secret_post'] };
  const flow = await signIn(c);
  const res = await token(c, flow.code, flow.clientVerifier);
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.equal(idp.clientAuth, 'post');
});

test('an IdP error at the callback reaches the client as a refused grant', async () => {
  const c = await setup();
  await link(c, c.member);
  const flow = await startSignIn(c);
  const callback = await call(c, 'GET', `/identity/connect/oidc-signin?state=${flow.idpState}&error=access_denied&error_description=denied`, { cookie: flow.cookie });
  assert.equal(callback?.status, 307);
  const code = new URL(callback!.headers.get('Location')!).searchParams.get('code')!;
  const res = await token(c, code, flow.clientVerifier);
  assert.equal(res.status, 400);
  assert.equal(res.json.error_description, 'SSO authorization failed: access_denied, denied');
  assert.equal(idp.tokenCalls, 0);
  assert.deepEqual(await rows(c, 'SELECT * FROM sso_auth'), []);
});
