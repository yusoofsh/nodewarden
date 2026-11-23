import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import test, { afterEach } from 'node:test';

import type { Env, User } from '../src/types';
import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { createPasswordVerifier } from '../src/services/password-verifier';
import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { handlePublicRoute } from '../src/router-public';
import { normalizeDuoHost } from '../src/services/duo';
import { resolveDuoAction } from '../webapp/public/duo-redirect-connector.js';
import { createTestDb } from './lib/d1-sqlite';

const USER_ID = '50000000-0000-0000-0000-000000000001';
const EMAIL = 'duo@example.test';
const PASSWORD = 'master-hash';
const DEVICE = '11111111-2222-3333-4444-555555555555';
const HOST = 'api-1234abcd.duosecurity.com';
const CLIENT_ID = 'DIABCDEFGHIJKLMNOPQR';
const CLIENT_SECRET = 'S'.repeat(36) + 'abcd';
let verifier: string;

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

async function setup(extra: Partial<User> = {}) {
  verifier ??= await createPasswordVerifier(PASSWORD);
  const db = createTestDb();
  await ensureStorageSchema(db);
  const env = { DB: db, JWT_SECRET: 'x'.repeat(40) } as unknown as Env;
  const storage = new StorageService(db);
  await storage.createUser({
    id: USER_ID, email: EMAIL, name: 'duo', masterPasswordHint: null, masterPasswordHash: verifier,
    key: '2.a|b|c', privateKey: null, publicKey: null, kdfType: 0, kdfIterations: 600000,
    securityStamp: 'stamp', role: 'user', status: 'active', totpSecret: null, totpRecoveryCode: null,
    yubikeyKey1: null, yubikeyKey2: null, yubikeyKey3: null, yubikeyKey4: null, yubikeyKey5: null, yubikeyNfc: false,
    apiKey: null, createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z', ...extra,
  });
  return { db, env, storage };
}
type Ctx = Awaited<ReturnType<typeof setup>>;

async function call(c: Ctx, method: string, path: string, body?: unknown) {
  const user = (await c.storage.getUserById(USER_ID))!;
  const request = new Request(`https://vault.test${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.9' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const res = await handleAuthenticatedRoute(request, c.env, user.id, user, path, method);
  assert.ok(res, `${method} ${path} was not routed`);
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

async function login(c: Ctx, twoFactor?: { provider: string; token: string }) {
  const form = new URLSearchParams({
    grant_type: 'password', username: EMAIL, password: PASSWORD, scope: 'api offline_access', client_id: 'mobile',
    deviceType: '0', deviceIdentifier: DEVICE, deviceName: 'test',
    ...(twoFactor ? { twoFactorProvider: twoFactor.provider, twoFactorToken: twoFactor.token } : {}),
  });
  const request = new Request('https://vault.test/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'CF-Connecting-IP': '203.0.113.9' },
    body: form.toString(),
  });
  const res = await handlePublicRoute(request, c.env, '/identity/connect/token', 'POST', async () => null);
  assert.ok(res);
  return { status: res.status, json: await res.json() as any };
}

const b64url = (value: Buffer | string) => Buffer.from(value).toString('base64url');
function signHs512(payload: Record<string, unknown>, secret = CLIENT_SECRET): string {
  const head = b64url(JSON.stringify({ alg: 'HS512', typ: 'JWT' }));
  const body = b64url(JSON.stringify(payload));
  return `${head}.${body}.${createHmac('sha512', secret).update(`${head}.${body}`).digest('base64url')}`;
}
function verifyHs512(token: string): Record<string, any> {
  const [head, body, signature] = token.split('.');
  assert.equal(createHmac('sha512', CLIENT_SECRET).update(`${head}.${body}`).digest('base64url'), signature, 'JWT is signed with the client secret');
  assert.equal(JSON.parse(Buffer.from(head, 'base64url').toString()).alg, 'HS512');
  return JSON.parse(Buffer.from(body, 'base64url').toString());
}

interface DuoMock {
  calls: Array<{ url: string; form: URLSearchParams }>;
  health: 'ok' | 'fail';
  // Builds the ID token claims for a token exchange; defaults to a valid answer.
  idToken: (form: URLSearchParams, valid: Record<string, unknown>) => Record<string, unknown>;
  lastAuthRequest?: Record<string, any>;
}

function installDuoMock(): DuoMock {
  const mock: DuoMock = { calls: [], health: 'ok', idToken: (_form, valid) => valid };
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const form = new URLSearchParams(String(init?.body ?? ''));
    mock.calls.push({ url, form });
    assert.equal(init?.redirect, 'manual');
    if (url === `https://${HOST}/oauth/v1/health_check`) {
      const assertion = verifyHs512(form.get('client_assertion')!);
      assert.equal(assertion.aud, url);
      assert.equal(form.get('client_id'), CLIENT_ID);
      return mock.health === 'ok'
        ? Response.json({ stat: 'OK', response: { timestamp: 1 } })
        : Response.json({ stat: 'FAIL', message: 'invalid_client', message_detail: 'bad credentials' }, { status: 400 });
    }
    if (url === `https://${HOST}/oauth/v1/token`) {
      assert.equal(verifyHs512(form.get('client_assertion')!).aud, url);
      assert.equal(form.get('redirect_uri'), mock.lastAuthRequest?.redirect_uri, 'token exchange repeats the redirect_uri');
      const valid = {
        iss: url, aud: CLIENT_ID, exp: Math.floor(Date.now() / 1000) + 300, iat: Math.floor(Date.now() / 1000),
        nonce: mock.lastAuthRequest?.nonce, preferred_username: EMAIL,
      };
      return Response.json({ id_token: signHs512(mock.idToken(form, valid)), access_token: 'a', expires_in: 300, token_type: 'Bearer' });
    }
    throw new Error(`unexpected fetch ${url}`);
  }) as typeof fetch;
  return mock;
}

async function enableDuo(c: Ctx) {
  const res = await call(c, 'PUT', '/api/two-factor/duo', { masterPasswordHash: PASSWORD, host: HOST, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
  assert.equal(res.status, 200, JSON.stringify(res.json));
  return res;
}

// Logs in without a token and returns the state from the AuthUrl Duo would receive.
async function startLogin(c: Ctx, mock: DuoMock) {
  const challenge = await login(c);
  assert.equal(challenge.status, 400);
  const authUrl = new URL(challenge.json.TwoFactorProviders2['2'].AuthUrl);
  assert.equal(authUrl.origin, `https://${HOST}`);
  assert.equal(authUrl.pathname, '/oauth/v1/authorize');
  const request = verifyHs512(authUrl.searchParams.get('request')!);
  assert.equal(request.duo_uname, EMAIL);
  assert.equal(request.redirect_uri, 'https://vault.test/duo-redirect-connector.html?client=mobile');
  mock.lastAuthRequest = request;
  return request.state as string;
}

test('an unconfigured user logs in, sees Duo off and never reaches Duo', async () => {
  const c = await setup();
  const mock = installDuoMock();
  assert.equal((await login(c)).status, 200);
  const duo = await call(c, 'POST', '/api/two-factor/get-duo', { masterPasswordHash: PASSWORD });
  assert.equal(duo.status, 200);
  assert.deepEqual([duo.json.enabled, duo.json.host, duo.json.clientId, duo.json.clientSecret], [false, null, null, null]);
  assert.deepEqual((await call(c, 'GET', '/api/two-factor')).json.Data, []);
  assert.equal((await call(c, 'GET', '/api/accounts/profile')).json.twoFactorEnabled, false);
  assert.equal(mock.calls.length, 0);
});

test('a TOTP-only user gets the same challenge as before, without Duo', async () => {
  const c = await setup({ totpSecret: 'JBSWY3DPEHPK3PXP' });
  const mock = installDuoMock();
  const challenge = await login(c);
  assert.equal(challenge.status, 400);
  assert.deepEqual(challenge.json.TwoFactorProviders, ['0']);
  assert.equal(mock.calls.length, 0);
});

test('config validation rejects non-Duo hosts and malformed keys without calling out', async () => {
  for (const host of [
    'http://api-1234abcd.duosecurity.com', 'api-1234abcd.duosecurity.com.evil.test', 'evil.test', 'api-.duosecurity.com',
    'api-1234abcd.duosecurity.com:8443', 'api-1234abcd.duosecurity.com/path', '169.254.169.254', 'user@api-1234abcd.duosecurity.com',
  ]) assert.equal(normalizeDuoHost(host), null, host);
  assert.equal(normalizeDuoHost('https://API-1234ABCD.duosecurity.com/'), HOST);

  const c = await setup();
  const mock = installDuoMock();
  const base = { masterPasswordHash: PASSWORD, host: HOST, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET };
  for (const bad of [{ host: 'evil.test' }, { clientId: 'short' }, { clientSecret: 'short' }]) {
    assert.equal((await call(c, 'PUT', '/api/two-factor/duo', { ...base, ...bad })).status, 400, JSON.stringify(bad));
  }
  assert.equal((await call(c, 'PUT', '/api/two-factor/duo', { ...base, masterPasswordHash: 'wrong' })).status, 400);
  assert.equal(mock.calls.length, 0);
  assert.equal((await c.storage.getUserById(USER_ID))!.duoConfig, null);
});

test('a failed health check refuses the settings, and at login leaves other providers usable', async () => {
  const c = await setup({ totpSecret: 'JBSWY3DPEHPK3PXP' });
  const mock = installDuoMock();
  mock.health = 'fail';
  const refused = await call(c, 'PUT', '/api/two-factor/duo', { masterPasswordHash: PASSWORD, host: HOST, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
  assert.equal(refused.status, 400);
  assert.equal((await c.storage.getUserById(USER_ID))!.duoConfig, null);

  mock.health = 'ok';
  await enableDuo(c);
  mock.health = 'fail';
  const challenge = await login(c);
  assert.equal(challenge.status, 400, 'Duo being down never skips two-factor');
  assert.deepEqual(challenge.json.TwoFactorProviders, ['0']);

  globalThis.fetch = (async () => { throw new Error('network down'); }) as typeof fetch;
  assert.deepEqual((await login(c)).json.TwoFactorProviders, ['0']);
});

test('the secret is masked, stored encrypted, and kept when the mask is sent back', async () => {
  const c = await setup();
  installDuoMock();
  const enabled = await enableDuo(c);
  assert.equal(enabled.json.clientSecret, 'SSSS************');
  const stored = (await c.storage.getUserById(USER_ID))!.duoConfig!;
  assert.ok(!stored.includes(CLIENT_SECRET));

  const duo = await call(c, 'POST', '/api/two-factor/get-duo', { masterPasswordHash: PASSWORD });
  assert.deepEqual([duo.json.enabled, duo.json.host, duo.json.clientId, duo.json.clientSecret], [true, HOST, CLIENT_ID, 'SSSS************']);
  assert.equal(duo.json.duo.clientSecret, 'SSSS************');
  assert.equal(JSON.stringify(duo.json).includes(CLIENT_SECRET), false);

  const kept = await call(c, 'PUT', '/api/two-factor/duo', {
    userVerificationToken: duo.json.userVerificationToken, host: HOST, clientId: CLIENT_ID, clientSecret: 'SSSS************',
  });
  assert.equal(kept.status, 200, JSON.stringify(kept.json));
  assert.equal((await call(c, 'PUT', '/api/two-factor/duo', {
    masterPasswordHash: PASSWORD, host: HOST, clientId: CLIENT_ID, clientSecret: 'XXXX************',
  })).status, 400);

  assert.deepEqual((await call(c, 'GET', '/api/two-factor')).json.Data.map((p: any) => p.Type), [2]);
  assert.equal((await call(c, 'GET', '/api/accounts/profile')).json.twoFactorEnabled, true);
});

test('a Duo login completes once; a replayed code and state are refused', async () => {
  const c = await setup();
  const mock = installDuoMock();
  await enableDuo(c);
  const state = await startLogin(c, mock);
  const ok = await login(c, { provider: '2', token: `duo-code|${state}` });
  assert.equal(ok.status, 200, JSON.stringify(ok.json));
  assert.ok(ok.json.access_token);
  assert.equal(mock.calls.filter((call) => call.url.endsWith('/token'))[0].form.get('code'), 'duo-code');

  const tokenCalls = mock.calls.length;
  const replay = await login(c, { provider: '2', token: `duo-code|${state}` });
  assert.equal(replay.status, 400);
  assert.equal(mock.calls.length, tokenCalls, 'a replay is refused before Duo is asked');
});

test('an unknown state, a wrong nonce or a wrong username are refused', async () => {
  const c = await setup();
  const mock = installDuoMock();
  await enableDuo(c);

  await startLogin(c, mock);
  assert.equal((await login(c, { provider: '2', token: `code|${'f'.repeat(64)}` })).status, 400);
  assert.equal((await login(c, { provider: '2', token: 'no-separator' })).status, 400);

  mock.idToken = (_form, valid) => ({ ...valid, nonce: 'other-nonce' });
  let state = await startLogin(c, mock);
  assert.equal((await login(c, { provider: '2', token: `code|${state}` })).status, 400);

  mock.idToken = (_form, valid) => ({ ...valid, preferred_username: 'someone@example.test' });
  state = await startLogin(c, mock);
  assert.equal((await login(c, { provider: '2', token: `code|${state}` })).status, 400);

  mock.idToken = (_form, valid) => ({ ...valid, aud: 'another-client' });
  state = await startLogin(c, mock);
  assert.equal((await login(c, { provider: '2', token: `code|${state}` })).status, 400);
});

test('an expired state is refused', async () => {
  const c = await setup();
  const mock = installDuoMock();
  await enableDuo(c);
  const state = await startLogin(c, mock);
  await c.db.prepare("UPDATE webauthn_challenges SET expires_at = ? WHERE scope = 'DuoLogin'").bind(Date.now() - 1).run();
  assert.equal((await login(c, { provider: '2', token: `code|${state}` })).status, 400);
  assert.equal(mock.calls.some((call) => call.url.endsWith('/token')), false);
});

test('DELETE /api/two-factor/duo turns Duo off and leaves TOTP alone', async () => {
  const c = await setup({ totpSecret: 'JBSWY3DPEHPK3PXP' });
  installDuoMock();
  await enableDuo(c);
  assert.equal((await call(c, 'DELETE', '/api/two-factor/duo', { masterPasswordHash: 'wrong' })).status, 400);
  assert.equal((await call(c, 'DELETE', '/api/two-factor/duo', { masterPasswordHash: PASSWORD })).status, 200);
  const user = (await c.storage.getUserById(USER_ID))!;
  assert.equal(user.duoConfig, null);
  assert.equal(user.totpSecret, 'JBSWY3DPEHPK3PXP');
});

test('a Duo-only user stays behind two-factor when Duo is down or its secret cannot be read', async () => {
  const c = await setup();
  const mock = installDuoMock();
  await enableDuo(c);
  const { totpRecoveryCode } = (await c.storage.getUserById(USER_ID))!;
  assert.ok(totpRecoveryCode);

  mock.health = 'fail';
  const down = await login(c);
  assert.equal(down.status, 400);
  assert.equal(down.json.access_token, undefined);
  assert.deepEqual(down.json.TwoFactorProviders, []);
  assert.equal((await login(c, { provider: '0', token: '123456' })).status, 400);

  // A changed JWT_SECRET (or a backup restored elsewhere) makes the secret unreadable.
  mock.health = 'ok';
  c.env = { ...c.env, JWT_SECRET: 'y'.repeat(40) } as Env;
  const unreadable = await login(c);
  assert.equal(unreadable.status, 400);
  assert.equal(unreadable.json.access_token, undefined);
  assert.equal((await login(c, { provider: '2', token: 'code|state' })).status, 400);
  const settings = await call(c, 'POST', '/api/two-factor/get-duo', { masterPasswordHash: PASSWORD });
  assert.deepEqual([settings.status, settings.json.enabled, settings.json.clientSecret], [200, true, null]);

  const recovered = await login(c, { provider: '8', token: totpRecoveryCode! });
  assert.equal(recovered.status, 200, JSON.stringify(recovered.json));
  assert.equal((await c.storage.getUserById(USER_ID))!.duoConfig, null);
});

test('an existing database gains users.duo_config when the schema reruns', async () => {
  const c = await setup();
  await c.db.prepare('ALTER TABLE users DROP COLUMN duo_config').run();
  await ensureStorageSchema(c.db);
  assert.equal((await c.storage.getUserById(USER_ID))!.duoConfig, null);
});

test('the redirect connector hands code and state to each client and only follows Duo URLs', () => {
  assert.deepEqual(resolveDuoAction('?client=web&code=c&state=s'), { kind: 'broadcast', code: 'c', state: 's' });
  assert.deepEqual(resolveDuoAction('?client=mobile&code=c%7C&state=s'), {
    kind: 'redirect', url: 'bitwarden://duo-callback?code=c%7C&state=s', showMessage: false,
  });
  assert.equal(resolveDuoAction(`?duoFramelessUrl=${encodeURIComponent(`https://${HOST}/oauth/v1/authorize?x=1`)}`).kind, 'redirect');
  for (const url of ['https://evil.test/oauth/v1/authorize', `http://${HOST}/oauth/v1/authorize`, `https://${HOST}/other`]) {
    assert.throws(() => resolveDuoAction(`?duoFramelessUrl=${encodeURIComponent(url)}`), url);
  }
});
