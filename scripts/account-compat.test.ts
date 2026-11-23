import assert from 'node:assert/strict';
import test from 'node:test';

import type { Env, User } from '../src/types';
import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import {
  handleDeleteOwnAccount,
  handleGetTasks,
  handleGetUserPublicKey,
  handleHibpBreach,
  handleRotateSecurityStamp,
} from '../src/handlers/account-compat';
import { createPasswordVerifier } from '../src/services/password-verifier';
import { createTestDb } from './lib/d1-sqlite';

function makeUser(id: string, overrides: Partial<User> = {}): User {
  return {
    id,
    email: `${id}@example.test`,
    name: id,
    masterPasswordHint: null,
    masterPasswordHash: 'verifier',
    key: 'k',
    privateKey: 'priv',
    publicKey: `pub-${id}`,
    kdfType: 0,
    kdfIterations: 600000,
    securityStamp: 'stamp-1',
    role: 'user',
    status: 'active',
    totpSecret: null,
    totpRecoveryCode: null,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  } as User;
}

async function setup(extra: Partial<Env> = {}) {
  const db = createTestDb();
  await ensureStorageSchema(db);
  const env = { DB: db, JWT_SECRET: 'x'.repeat(40), ...extra } as unknown as Env;
  const storage = new StorageService(db);
  await storage.createUser(makeUser('11111111-1111-1111-1111-111111111111'));
  await storage.createUser(makeUser('22222222-2222-2222-2222-222222222222', { status: 'banned' }));
  return { env, storage };
}

test('public key lookup returns the key for an active user and 404 otherwise', async () => {
  const { env } = await setup();
  const ok = await handleGetUserPublicKey(env, '11111111-1111-1111-1111-111111111111');
  assert.equal(ok.status, 200);
  assert.deepEqual(await ok.json(), {
    userId: '11111111-1111-1111-1111-111111111111',
    publicKey: 'pub-11111111-1111-1111-1111-111111111111',
    object: 'userKey',
  });
  assert.equal((await handleGetUserPublicKey(env, '22222222-2222-2222-2222-222222222222')).status, 404);
  assert.equal((await handleGetUserPublicKey(env, '33333333-3333-3333-3333-333333333333')).status, 404);
});

test('tasks are an empty list for personal accounts', async () => {
  assert.deepEqual(await handleGetTasks().json(), { data: [], object: 'list', continuationToken: null });
});

test('hibp requires a configured key and a sane username', async () => {
  const { env } = await setup();
  const req = (u: string) => new Request(`https://x.test/api/hibp/breach?username=${encodeURIComponent(u)}`);
  assert.equal((await handleHibpBreach(req('a@b.test'), env)).status, 400);
  const keyed = { ...env, HIBP_API_KEY: 'k' } as Env;
  assert.equal((await handleHibpBreach(req('a b'), keyed)).status, 400);
});

test('hibp maps upstream 404 to an empty list', async () => {
  const { env } = await setup({ HIBP_API_KEY: 'k' });
  const original = globalThis.fetch;
  globalThis.fetch = (async () => new Response('', { status: 404 })) as typeof fetch;
  try {
    const res = await handleHibpBreach(new Request('https://x.test/api/hibp/breach?username=a%40b.test'), env);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), []);
  } finally {
    globalThis.fetch = original;
  }
});

test('security stamp rotation rejects missing or wrong password and leaves the stamp alone', async () => {
  const { env, storage } = await setup();
  const id = '11111111-1111-1111-1111-111111111111';
  const post = (body: unknown) =>
    handleRotateSecurityStamp(new Request('https://x.test', { method: 'POST', body: JSON.stringify(body) }), env, id);
  assert.equal((await post({})).status, 400);
  assert.equal((await post({ masterPasswordHash: 'wrong' })).status, 400);
  assert.equal((await storage.getUserById(id))?.securityStamp, 'stamp-1');
});

test('security stamp rotation with the right password changes the stamp and revokes refresh tokens', async () => {
  const { env, storage } = await setup();
  const id = '33333333-3333-3333-3333-333333333333';
  await storage.createUser(makeUser(id, { masterPasswordHash: await createPasswordVerifier('client-hash') }));
  await storage.saveRefreshToken('tok-1', id, Date.now() + 60_000, 'dev-1');
  const res = await handleRotateSecurityStamp(
    new Request('https://x.test', { method: 'POST', body: JSON.stringify({ masterPasswordHash: 'client-hash' }) }),
    env,
    id
  );
  assert.equal(res.status, 200);
  assert.notEqual((await storage.getUserById(id))?.securityStamp, 'stamp-1');
  assert.equal(await storage.getRefreshTokenRecord('tok-1'), null);
});

async function deleteOwn(env: Env, id: string, masterPasswordHash?: string) {
  return handleDeleteOwnAccount(
    new Request('https://x.test', { method: 'POST', body: JSON.stringify({ masterPasswordHash }) }),
    env,
    id
  );
}

test('account deletion needs the right password and keeps the account otherwise', async () => {
  const { env, storage } = await setup();
  const id = '44444444-4444-4444-4444-444444444444';
  await storage.createUser(makeUser(id, { masterPasswordHash: await createPasswordVerifier('client-hash') }));
  assert.equal((await deleteOwn(env, id)).status, 400);
  assert.equal((await deleteOwn(env, id, 'wrong')).status, 400);
  assert.ok(await storage.getUserById(id));
});

test('account deletion removes the user and cascades their rows', async () => {
  const { env, storage } = await setup();
  const id = '55555555-5555-5555-5555-555555555555';
  await storage.createUser(makeUser(id, { masterPasswordHash: await createPasswordVerifier('client-hash') }));
  await env.DB.prepare('INSERT INTO folders(id, user_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
    .bind('folder-1', id, 'enc', '2026-01-01', '2026-01-01')
    .run();
  assert.equal((await deleteOwn(env, id, 'client-hash')).status, 200);
  assert.equal(await storage.getUserById(id), null);
  const left = await env.DB.prepare('SELECT COUNT(*) AS n FROM folders WHERE user_id = ?').bind(id).first<{ n: number }>();
  assert.equal(left?.n, 0);
});

test('the last active admin cannot delete their own account', async () => {
  const { env, storage } = await setup();
  const id = '66666666-6666-6666-6666-666666666666';
  await storage.createUser(
    makeUser(id, { role: 'admin', masterPasswordHash: await createPasswordVerifier('client-hash') })
  );
  assert.equal((await deleteOwn(env, id, 'client-hash')).status, 400);
  assert.ok(await storage.getUserById(id));
  const second = '77777777-7777-7777-7777-777777777777';
  await storage.createUser(makeUser(second, { role: 'admin' }));
  assert.equal((await deleteOwn(env, id, 'client-hash')).status, 200);
});
