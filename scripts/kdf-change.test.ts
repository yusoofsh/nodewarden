import assert from 'node:assert/strict';
import test from 'node:test';

import type { Env, User } from '../src/types';
import { StorageService } from '../src/services/storage';
import { AuthService } from '../src/services/auth';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { createPasswordVerifier } from '../src/services/password-verifier';
import { handleChangeKdf } from '../src/handlers/accounts';
import { createTestDb } from './lib/d1-sqlite';

const ID = '11111111-1111-1111-1111-111111111111';
const EMAIL = 'kdf@example.test';
const ENC = '2.aXY=|Y3Q=|bWFj';

async function setup() {
  const db = createTestDb();
  await ensureStorageSchema(db);
  const env = { DB: db, JWT_SECRET: 'x'.repeat(40) } as unknown as Env;
  const storage = new StorageService(db);
  await storage.createUser({
    id: ID,
    email: EMAIL,
    name: 'kdf',
    masterPasswordHint: null,
    masterPasswordHash: await createPasswordVerifier('old-hash'),
    key: ENC,
    privateKey: ENC,
    publicKey: 'pub',
    kdfType: 0,
    kdfIterations: 600000,
    securityStamp: 'stamp-1',
    role: 'user',
    status: 'active',
    totpSecret: null,
    totpRecoveryCode: null,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
  } as User);
  await storage.saveRefreshToken('tok-1', ID, Date.now() + 60_000, 'dev-1');
  return { env, storage };
}

const call = (env: Env, body: unknown) =>
  handleChangeKdf(new Request('https://x.test', { method: 'POST', body: JSON.stringify(body) }), env, ID);

const legacy = (over: Record<string, unknown> = {}) => ({
  masterPasswordHash: 'old-hash',
  newMasterPasswordHash: 'new-hash',
  key: ENC,
  kdf: 1,
  kdfIterations: 3,
  kdfMemory: 64,
  kdfParallelism: 4,
  ...over,
});

test('legacy body switches to Argon2id, rotates the stamp and revokes refresh tokens', async () => {
  const { env, storage } = await setup();
  assert.equal((await call(env, legacy())).status, 200);
  const user = await storage.getUserById(ID);
  assert.equal(user?.kdfType, 1);
  assert.equal(user?.kdfIterations, 3);
  assert.equal(user?.kdfMemory, 64);
  assert.equal(user?.kdfParallelism, 4);
  assert.notEqual(user?.securityStamp, 'stamp-1');
  assert.equal(await new AuthService(env).verifyPassword('new-hash', user!.masterPasswordHash, EMAIL), true);
  assert.equal(await storage.getRefreshTokenRecord('tok-1'), null);
});

test('authenticationData and unlockData body is accepted and clears Argon2 fields for PBKDF2', async () => {
  const { env, storage } = await setup();
  const kdf = { kdfType: 0, iterations: 800000 };
  const res = await call(env, {
    masterPasswordHash: 'old-hash',
    authenticationData: { kdf, masterPasswordAuthenticationHash: 'new-hash', salt: EMAIL },
    unlockData: { kdf, masterKeyWrappedUserKey: ENC, salt: EMAIL },
  });
  assert.equal(res.status, 200);
  const user = await storage.getUserById(ID);
  assert.equal(user?.kdfType, 0);
  assert.equal(user?.kdfIterations, 800000);
  assert.equal(user?.kdfMemory, undefined);
});

test('wrong password, weak or oversized parameters and bad keys change nothing', async () => {
  const { env, storage } = await setup();
  const cases: Array<Record<string, unknown>> = [
    legacy({ masterPasswordHash: 'wrong' }),
    legacy({ kdf: 0, kdfIterations: 1000 }),
    legacy({ kdf: 0, kdfIterations: 5_000_000 }),
    legacy({ kdfMemory: undefined }),
    legacy({ kdfMemory: 4096 }),
    legacy({ kdf: 7 }),
    legacy({ key: 'not-an-enc-string' }),
    legacy({ newMasterPasswordHash: '' }),
  ];
  for (const body of cases) assert.equal((await call(env, body)).status, 400, JSON.stringify(body));
  const user = await storage.getUserById(ID);
  assert.equal(user?.kdfType, 0);
  assert.equal(user?.kdfIterations, 600000);
  assert.equal(user?.securityStamp, 'stamp-1');
});

test('a wrong salt in the new body is rejected', async () => {
  const { env } = await setup();
  const kdf = { kdfType: 0, iterations: 800000 };
  const res = await call(env, {
    masterPasswordHash: 'old-hash',
    authenticationData: { kdf, masterPasswordAuthenticationHash: 'new-hash', salt: 'other@example.test' },
    unlockData: { kdf, masterKeyWrappedUserKey: ENC, salt: 'other@example.test' },
  });
  assert.equal(res.status, 400);
});
