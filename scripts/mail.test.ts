import assert from 'node:assert/strict';
import test from 'node:test';

import type { Env, User } from '../src/types';
import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { createPasswordVerifier } from '../src/services/password-verifier';
import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { handlePublicRoute } from '../src/router-public';
import { handleToken } from '../src/handlers/identity';
import { bindingSender, mailConfig } from '../src/services/mail';
import { RateLimitService } from '../src/services/ratelimit';
import { obscureEmail } from '../src/services/email-codes';
import { createTestDb } from './lib/d1-sqlite';

const cacheStore = new Map<string, Response>();
(globalThis as any).caches = {
  default: {
    match: async (req: Request) => cacheStore.get(req.url)?.clone() ?? undefined,
    put: async (req: Request, res: Response) => void cacheStore.set(req.url, res.clone()),
  },
};

// The fake provider: every outbound fetch lands here.
type Sent = { url: string; headers: Record<string, string>; body: { from: string; to: string | string[]; subject: string; text: string; html: string } };
const sent: Sent[] = [];
let providerStatus = 200;
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  sent.push({ url: String(input), headers: Object.fromEntries(new Headers(init?.headers).entries()), body: JSON.parse(String(init?.body)) });
  return new Response('{}', { status: providerStatus });
}) as typeof fetch;

const WEBHOOK = { MAIL_FROM: 'vault@example.test', MAIL_WEBHOOK_URL: 'https://relay.example.test/send', MAIL_WEBHOOK_TOKEN: 'relay-secret' };
const PASSWORD = 'master-hash';
const ID = { owner: '50000000-0000-0000-0000-000000000001', member: '50000000-0000-0000-0000-000000000002' };
type Actor = keyof typeof ID;

async function setup(mail: Record<string, string> | null = WEBHOOK) {
  sent.length = 0;
  providerStatus = 200;
  const db = createTestDb();
  await ensureStorageSchema(db);
  // The service creates its budget table once per isolate; every test here has a fresh database.
  (RateLimitService as any).strictBudgetTableReady = false;
  const env = { DB: db, JWT_SECRET: 'x'.repeat(40), ...(mail ?? {}) } as unknown as Env;
  const storage = new StorageService(db);
  const verifier = await createPasswordVerifier(PASSWORD);
  for (const actor of Object.keys(ID) as Actor[]) {
    await storage.createUser({
      id: ID[actor], email: `${actor}@example.test`, name: actor, masterPasswordHint: null, masterPasswordHash: verifier,
      key: '2.a|b|c', privateKey: '2.p|q|r', publicKey: `pub-${actor}`, kdfType: 0, kdfIterations: 600000,
      securityStamp: 'stamp', role: actor === 'owner' ? 'admin' : 'user', status: 'active', totpSecret: null, totpRecoveryCode: null,
      createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
    } as User);
  }
  return { db, env, storage };
}
type Ctx = Awaited<ReturnType<typeof setup>>;

const headers = { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.7' };
const parse = async (res: Response | null) => {
  assert.ok(res, 'route was not handled');
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
};

async function call(c: Ctx, actor: Actor, method: string, path: string, body?: unknown) {
  const user = (await c.storage.getUserById(ID[actor]))!;
  const request = new Request(`https://vault.test${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  return parse(await handleAuthenticatedRoute(request, c.env, user.id, user, path, method));
}

async function publicCall(c: Ctx, path: string, body: unknown) {
  const request = new Request(`https://vault.test${path}`, { method: 'POST', headers, body: JSON.stringify(body) });
  return parse(await handlePublicRoute(request, c.env, path, 'POST', async () => null));
}

async function token(c: Ctx, fields: Record<string, string>) {
  const form = new URLSearchParams({
    grant_type: 'password', username: 'member@example.test', password: PASSWORD, scope: 'api offline_access',
    client_id: 'web', deviceIdentifier: 'dev-1', deviceName: 'test', deviceType: '9', ...fields,
  });
  const request = new Request('https://vault.test/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'CF-Connecting-IP': '203.0.113.7' },
    body: form,
  });
  return parse(await handleToken(request, c.env));
}

const lastCode = () => /\n\n(\d{6})\n\n/.exec(sent.at(-1)!.body.text)?.[1] ?? assert.fail('no code in the last message');
const lastLink = () => new URL(/https:\/\/\S+/.exec(sent.at(-1)!.body.text)![0].replace('/#/', '/'));

async function enableEmailTwoFactor(c: Ctx, address = 'second@example.test') {
  const info = await call(c, 'member', 'POST', '/api/two-factor/get-email', { masterPasswordHash: PASSWORD });
  assert.equal(info.status, 200);
  assert.equal(info.json.Enabled, false);
  const verification = info.json.UserVerificationToken;
  assert.equal((await call(c, 'member', 'POST', '/api/two-factor/send-email', { email: address, userVerificationToken: verification })).status, 200);
  const code = lastCode();
  const enabled = await call(c, 'member', 'PUT', '/api/two-factor/email', { email: address, token: code, userVerificationToken: verification });
  assert.equal(enabled.status, 200);
  assert.equal(enabled.json.Enabled, true);
}

const MAIL_ROUTES: Array<[kind: 'auth' | 'public', method: string, path: string]> = [
  ['auth', 'POST', '/api/two-factor/get-email'],
  ['auth', 'POST', '/api/two-factor/send-email'],
  ['auth', 'PUT', '/api/two-factor/email'],
  ['auth', 'DELETE', '/api/two-factor/email'],
  ['auth', 'POST', '/api/accounts/email-token'],
  ['auth', 'POST', '/api/accounts/email'],
  ['auth', 'POST', '/api/accounts/verify-email'],
  ['auth', 'POST', '/api/accounts/request-otp'],
  ['auth', 'POST', '/api/accounts/verify-otp'],
  ['public', 'POST', '/api/two-factor/send-email-login'],
  ['public', 'POST', '/api/accounts/verify-email-token'],
  ['public', 'POST', '/api/accounts/delete-recover'],
  ['public', 'POST', '/api/accounts/delete-recover-token'],
  ['public', 'POST', '/identity/accounts/register/send-verification-email'],
  ['public', 'POST', '/identity/accounts/register/verification-email-clicked'],
  ['public', 'POST', '/identity/accounts/register/finish'],
];

test('with mail unconfigured every mail route still answers 501 and nothing is sent', async () => {
  const c = await setup(null);
  for (const [kind, method, path] of MAIL_ROUTES) {
    const body = { email: 'member@example.test', masterPasswordHash: PASSWORD };
    const res = kind === 'auth' ? await call(c, 'member', method, path, body) : await publicCall(c, path, body);
    assert.equal(res.status, 501, `${method} ${path}`);
  }
  // Emergency access invites behave as before: no mail.
  assert.equal((await call(c, 'owner', 'POST', '/api/emergency-access/invite', { email: 'member@example.test', type: 0, waitTimeDays: 7 })).status, 200);
  assert.equal(sent.length, 0);
});

test('mail config needs MAIL_FROM and a provider, and a webhook must be public https', () => {
  const env = (vars: Record<string, string>) => vars as unknown as Env;
  assert.equal(mailConfig(env({})), null);
  assert.equal(mailConfig(env({ RESEND_API_KEY: 're_x' })), null, 'no sender');
  assert.equal(mailConfig(env({ MAIL_FROM: 'a@b.c' })), null, 'no provider');
  for (const url of ['http://relay.example.test/send', 'https://127.0.0.1/send', 'https://[::1]/x', 'https://10.0.0.5/x', 'https://relay.local/x', 'not a url']) {
    assert.equal(mailConfig(env({ MAIL_FROM: 'a@b.c', MAIL_WEBHOOK_URL: url })), null, url);
  }
  assert.deepEqual(mailConfig(env(WEBHOOK))?.provider, { kind: 'webhook', url: 'https://relay.example.test/send', token: 'relay-secret' });
  assert.equal(mailConfig(env({ ...WEBHOOK, RESEND_API_KEY: 're_x' }))?.provider.kind, 'resend');
  const EMAIL = { send: async () => ({ messageId: 'm' }) };
  assert.equal(mailConfig({ EMAIL } as unknown as Env), null, 'binding without sender');
  assert.equal(mailConfig({ MAIL_FROM: 'a@b.c', EMAIL } as unknown as Env)?.provider.kind, 'cloudflare');
  assert.equal(mailConfig({ ...WEBHOOK, EMAIL } as unknown as Env)?.provider.kind, 'webhook', 'an HTTP provider wins');
});

test('MAIL_FROM becomes the sender shape the Email Sending binding takes', () => {
  assert.equal(bindingSender('vault@example.test'), 'vault@example.test');
  assert.equal(bindingSender('<vault@example.test>'), 'vault@example.test');
  assert.deepEqual(bindingSender('Vault <vault@example.test>'), { email: 'vault@example.test', name: 'Vault' });
  assert.deepEqual(bindingSender('"My Vault" <vault@example.test>'), { email: 'vault@example.test', name: 'My Vault' });
});

test('the Email Sending binding receives the message, and a refusal answers 502', async () => {
  const c = await setup(null);
  const messages: Array<Record<string, unknown>> = [];
  let refuse: string | null = null;
  Object.assign(c.env, {
    MAIL_FROM: 'Vault <vault@example.test>',
    EMAIL: {
      send: async (message: Record<string, unknown>) => {
        if (refuse) throw Object.assign(new Error('refused'), { code: refuse });
        messages.push(message);
        return { messageId: 'm1' };
      },
    },
  });
  assert.equal((await call(c, 'member', 'POST', '/api/accounts/request-otp')).status, 200);
  assert.equal(sent.length, 0, 'no HTTP provider was called');
  assert.deepEqual(messages[0].from, { email: 'vault@example.test', name: 'Vault' });
  assert.equal(messages[0].to, 'member@example.test');
  assert.match(String(messages[0].text), /\n\n\d{6}\n\n/);

  refuse = 'E_RECIPIENT_PLAN_RESTRICTED';
  assert.equal((await call(c, 'owner', 'POST', '/api/accounts/request-otp')).status, 502);
});

test('the webhook and Resend receive the message, and the subject cannot carry line breaks', async () => {
  const c = await setup();
  assert.equal((await call(c, 'member', 'POST', '/api/accounts/request-otp')).status, 200);
  const [hook] = sent;
  assert.equal(hook.url, WEBHOOK.MAIL_WEBHOOK_URL);
  assert.equal(hook.headers.authorization, 'Bearer relay-secret');
  assert.deepEqual(Object.keys(hook.body).sort(), ['from', 'html', 'subject', 'text', 'to']);
  assert.equal(hook.body.to, 'member@example.test');
  assert.match(hook.body.html, /<p>/);

  const r = await setup({ MAIL_FROM: 'vault@example.test', RESEND_API_KEY: 're_test' });
  assert.equal((await call(r, 'member', 'POST', '/api/accounts/request-otp')).status, 200);
  assert.equal(sent[0].url, 'https://api.resend.com/emails');
  assert.equal(sent[0].headers.authorization, 'Bearer re_test');
  assert.deepEqual(sent[0].body.to, ['member@example.test']);

  const emergency = await call(r, 'owner', 'POST', '/api/emergency-access/invite', { email: 'member@example.test', type: 0, waitTimeDays: 7 });
  assert.equal(emergency.status, 200);
  assert.doesNotMatch(sent.at(-1)!.body.subject, /[\r\n]/);
});

test('a provider failure answers 502 and leaves no usable code', async () => {
  const c = await setup();
  providerStatus = 500;
  assert.equal((await call(c, 'member', 'POST', '/api/accounts/request-otp')).status, 502);
  assert.equal((await c.db.prepare('SELECT COUNT(*) AS n FROM email_codes').first<{ n: number }>())!.n, 0);
});

test('email two-step login: setup, login challenge, single-use code, attempt limit, disable', async () => {
  const c = await setup();
  await enableEmailTwoFactor(c);
  assert.equal(sent.at(-1)!.body.to, 'second@example.test');
  const providers = await call(c, 'member', 'GET', '/api/two-factor');
  assert.deepEqual(providers.json.Data.map((p: any) => p.Type), [1]);
  assert.ok((await c.storage.getUserById(ID.member))!.totpRecoveryCode, 'enabling makes a recovery code');

  const challenge = await token(c, {});
  assert.equal(challenge.status, 400);
  assert.deepEqual(challenge.json.TwoFactorProviders, ['1']);
  assert.deepEqual(challenge.json.TwoFactorProviders2['1'], { Email: 'se****@example.test' });

  const wrongPassword = await publicCall(c, '/api/two-factor/send-email-login', { email: 'member@example.test', masterPasswordHash: 'nope' });
  assert.equal(wrongPassword.status, 400);
  assert.equal((await publicCall(c, '/api/two-factor/send-email-login', { email: 'member@example.test', masterPasswordHash: PASSWORD })).status, 200);
  const code = lastCode();
  assert.equal(sent.at(-1)!.body.to, 'second@example.test');
  const loggedIn = await token(c, { twoFactorProvider: '1', twoFactorToken: code });
  assert.equal(loggedIn.status, 200, JSON.stringify(loggedIn.json));
  assert.ok(loggedIn.json.access_token);
  assert.equal((await token(c, { twoFactorProvider: '1', twoFactorToken: code })).status, 400, 'a code works once');

  await publicCall(c, '/api/two-factor/send-email-login', { email: 'member@example.test', masterPasswordHash: PASSWORD });
  const fresh = lastCode();
  for (let i = 0; i < 3; i++) assert.equal((await token(c, { twoFactorProvider: '1', twoFactorToken: '000000' === fresh ? '111111' : '000000' })).status, 400);
  assert.equal((await token(c, { twoFactorProvider: '1', twoFactorToken: fresh })).status, 400, 'three wrong guesses kill the code');

  const disabled = await call(c, 'member', 'DELETE', '/api/two-factor/email', { masterPasswordHash: PASSWORD });
  assert.equal(disabled.status, 200);
  assert.equal((await token(c, {})).status, 200, 'no two-step login after disabling');
});

test('email two-step login stays required when mail is turned off, and the recovery code clears it', async () => {
  const c = await setup();
  await enableEmailTwoFactor(c);
  const off = { ...c, env: { DB: c.db, JWT_SECRET: 'x'.repeat(40) } as unknown as Env };
  assert.deepEqual((await token(off, {})).json.TwoFactorProviders, ['1']);
  assert.equal((await publicCall(off, '/api/two-factor/send-email-login', { email: 'member@example.test', masterPasswordHash: PASSWORD })).status, 501);
  const recovery = (await c.storage.getUserById(ID.member))!.totpRecoveryCode!;
  assert.equal((await token(off, { twoFactorProvider: '8', twoFactorToken: recovery })).status, 200);
  assert.equal((await c.storage.getUserById(ID.member))!.emailTwoFactor, null);
});

test('the generic disable route turns email two-step login off even with mail unconfigured', async () => {
  const c = await setup();
  await enableEmailTwoFactor(c);
  const off = { ...c, env: { DB: c.db, JWT_SECRET: 'x'.repeat(40) } as unknown as Env };
  assert.equal((await call(off, 'member', 'POST', '/api/two-factor/disable', { type: 1, masterPasswordHash: PASSWORD })).status, 200);
  assert.equal((await c.storage.getUserById(ID.member))!.emailTwoFactor, null);
});

test('setup refuses a code for another address and a missing verification', async () => {
  const c = await setup();
  assert.equal((await call(c, 'member', 'POST', '/api/two-factor/send-email', { email: 'a@example.test' })).status, 400);
  await call(c, 'member', 'POST', '/api/two-factor/send-email', { email: 'a@example.test', masterPasswordHash: PASSWORD });
  const res = await call(c, 'member', 'PUT', '/api/two-factor/email', { email: 'b@example.test', token: lastCode(), masterPasswordHash: PASSWORD });
  assert.equal(res.status, 400);
  assert.equal((await c.storage.getUserById(ID.member))!.emailTwoFactor ?? null, null);
});

test('change email: token goes to the new address and is needed once', async () => {
  const c = await setup();
  assert.equal((await call(c, 'member', 'POST', '/api/accounts/email-token', { masterPasswordHash: PASSWORD, newEmail: 'owner@example.test' })).status, 400, 'address in use');
  assert.equal((await call(c, 'member', 'POST', '/api/accounts/email-token', { masterPasswordHash: PASSWORD, newEmail: 'New@Example.test' })).status, 200);
  assert.equal(sent.at(-1)!.body.to, 'new@example.test');
  const code = lastCode();
  const change = { masterPasswordHash: PASSWORD, newEmail: 'new@example.test', token: code, newMasterPasswordHash: 'new-hash', key: '2.new|key|mac' };
  assert.equal((await call(c, 'member', 'POST', '/api/accounts/email', { ...change, token: '999999' === code ? '888888' : '999999' })).status, 400);
  assert.equal((await call(c, 'member', 'POST', '/api/accounts/email', change)).status, 200);
  const user = (await c.storage.getUserById(ID.member))!;
  assert.equal(user.email, 'new@example.test');
  assert.equal(user.key, '2.new|key|mac');
  assert.notEqual(user.securityStamp, 'stamp');
  assert.equal((await token(c, { username: 'new@example.test', password: 'new-hash' })).status, 200);
});

test('protected-action codes verify once', async () => {
  const c = await setup();
  await call(c, 'member', 'POST', '/api/accounts/request-otp');
  const otp = lastCode();
  assert.equal((await call(c, 'member', 'POST', '/api/accounts/verify-otp', { otp: '12345' })).status, 400);
  assert.equal((await call(c, 'member', 'POST', '/api/accounts/verify-otp', { OTP: otp })).status, 200);
  assert.equal((await call(c, 'member', 'POST', '/api/accounts/verify-otp', { OTP: otp })).status, 400);
});

test('verify-email and delete-recover links work once; an unknown address gets the same answer', async () => {
  const c = await setup();
  assert.equal((await call(c, 'member', 'POST', '/api/accounts/verify-email')).status, 200);
  let link = lastLink();
  const verify = { userId: link.searchParams.get('userId'), token: link.searchParams.get('token') };
  assert.equal((await publicCall(c, '/api/accounts/verify-email-token', verify)).status, 200);
  assert.equal((await publicCall(c, '/api/accounts/verify-email-token', verify)).status, 400);

  const before = sent.length;
  assert.equal((await publicCall(c, '/api/accounts/delete-recover', { email: 'nobody@example.test' })).status, 200);
  assert.equal(sent.length, before);
  assert.equal((await publicCall(c, '/api/accounts/delete-recover', { email: 'member@example.test' })).status, 200);
  link = lastLink();
  assert.equal(link.pathname, '/verify-recover-delete');
  assert.equal((await publicCall(c, '/api/accounts/delete-recover-token', { userId: ID.member, token: 'forged' })).status, 400);
  assert.equal((await publicCall(c, '/api/accounts/delete-recover-token', { userId: ID.member, token: link.searchParams.get('token') })).status, 200);
  assert.equal(await c.storage.getUserById(ID.member), null);
});

test('a recipient gets at most five messages per ten minutes', async () => {
  const c = await setup();
  for (let i = 0; i < 5; i++) assert.equal((await call(c, 'member', 'POST', '/api/accounts/request-otp')).status, 200);
  assert.equal((await call(c, 'member', 'POST', '/api/accounts/request-otp')).status, 429);
  assert.equal(sent.length, 5);
});

test('a spent budget for one purpose does not block login codes', async () => {
  const c = await setup();
  await enableEmailTwoFactor(c, 'member@example.test');
  for (let i = 0; i < 6; i++) await publicCall(c, '/api/accounts/delete-recover', { email: 'member@example.test' });
  assert.equal((await publicCall(c, '/api/two-factor/send-email-login', { email: 'member@example.test', masterPasswordHash: PASSWORD })).status, 200);
});

test('the generic disable route still refuses type 1 when email two-step login is off', async () => {
  const c = await setup();
  assert.equal((await call(c, 'member', 'POST', '/api/two-factor/disable', { type: 1, masterPasswordHash: PASSWORD })).status, 400);
});

test('registration by email stays closed once an account exists, and works for the first one', async () => {
  const c = await setup();
  const closed = await publicCall(c, '/identity/accounts/register/send-verification-email', { email: 'fresh@example.test', name: 'Fresh' });
  assert.equal(closed.status, 400);
  assert.equal(sent.length, 0);

  const db = createTestDb();
  await ensureStorageSchema(db);
  (RateLimitService as any).strictBudgetTableReady = false;
  const empty = { db, env: { DB: db, JWT_SECRET: 'x'.repeat(40), ...WEBHOOK } as unknown as Env, storage: new StorageService(db) };
  const res = await handlePublicRoute(
    new Request('https://vault.test/identity/accounts/register/send-verification-email', { method: 'POST', headers, body: JSON.stringify({ email: 'First@Example.test', name: 'First' }) }),
    empty.env, '/identity/accounts/register/send-verification-email', 'POST', async () => null
  );
  assert.equal(res?.status, 204);
  const link = lastLink();
  const verificationToken = link.searchParams.get('token')!;
  assert.equal((await publicCall(empty, '/identity/accounts/register/verification-email-clicked', { email: 'first@example.test', emailVerificationToken: verificationToken })).status, 200);
  assert.equal((await publicCall(empty, '/identity/accounts/register/finish', { email: 'first@example.test', emailVerificationToken: 'bad.token' })).status, 400);
  const finish = await publicCall(empty, '/identity/accounts/register/finish', {
    email: 'first@example.test', emailVerificationToken: verificationToken, masterPasswordHash: PASSWORD, userSymmetricKey: '2.a|b|c',
    userAsymmetricKeys: { publicKey: 'pub', encryptedPrivateKey: '2.p|q|r' }, kdf: 0, kdfIterations: 600000,
  });
  assert.equal(finish.status, 200, JSON.stringify(finish.json));
  const user = await empty.storage.getUser('first@example.test');
  assert.equal(user?.name, 'First');
  assert.equal(user?.role, 'admin');
  assert.equal((await publicCall(empty, '/identity/accounts/register/verification-email-clicked', { email: 'first@example.test', emailVerificationToken: verificationToken })).status, 400);
});

test('an emergency access invite sends a notice when mail is configured', async () => {
  const c = await setup();
  assert.equal((await call(c, 'owner', 'POST', '/api/emergency-access/invite', { email: 'member@example.test', type: 0, waitTimeDays: 7 })).status, 200);
  assert.equal(sent.at(-1)!.body.to, 'member@example.test');
  assert.match(sent.at(-1)!.body.text, /owner@example\.test/);
});

test('obscureEmail keeps two characters of names longer than three', () => {
  assert.equal(obscureEmail('bytes@example.ext'), 'by***@example.ext');
  assert.equal(obscureEmail('byt@example.ext'), '***@example.ext');
  assert.equal(obscureEmail('bɏtes@example.ext'), 'bɏ***@example.ext');
  assert.equal(obscureEmail('no_at'), '*****');
});
