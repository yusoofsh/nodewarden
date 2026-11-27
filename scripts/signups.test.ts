import assert from 'node:assert/strict';
import test from 'node:test';

import type { Env, User } from '../src/types';
import { buildConfigResponse } from '../src/config-response';
import { isSignupsAllowed } from '../src/config/signups';
import { handleRegister } from '../src/handlers/accounts';
import { buildWebBootstrapResponse } from '../src/router-public';
import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { createTestDb } from './lib/d1-sqlite';

const env = (extra: Partial<Env> = {}) =>
  ({ DB: createTestDb(), JWT_SECRET: 'x'.repeat(40), ...extra }) as unknown as Env;

const user = (id: string, email: string) =>
  ({
    id,
    email,
    name: email,
    masterPasswordHint: null,
    masterPasswordHash: 'hash',
    key: '2.aXY=|aXY=|bWFj',
    privateKey: '2.cHJp|aXY=|bWFj',
    publicKey: 'pub',
    kdfType: 0,
    kdfIterations: 600000,
    securityStamp: 'stamp',
    role: 'admin',
    status: 'active',
    totpSecret: null,
    totpRecoveryCode: null,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
  }) as User;

async function envWithUser(extra: Partial<Env> = {}) {
  const base = env(extra);
  await ensureStorageSchema(base.DB);
  await new StorageService(base.DB).createUser(user('40000000-0000-0000-0000-000000000001', 'owner@example.test'));
  return base;
}

test('SIGNUPS_ALLOWED defaults to allowed and accepts the usual false spellings', () => {
  assert.equal(isSignupsAllowed(env()), true);
  assert.equal(isSignupsAllowed(env({ SIGNUPS_ALLOWED: 'true' })), true);
  assert.equal(isSignupsAllowed(env({ SIGNUPS_ALLOWED: '' })), true);
  for (const value of ['false', 'FALSE', '0', 'no', 'off', ' false ']) {
    assert.equal(isSignupsAllowed(env({ SIGNUPS_ALLOWED: value })), false, value);
  }
});

test('config advertises disabled registration to official clients', () => {
  assert.equal(buildConfigResponse('https://vault.example.test').settings.disableUserRegistration, false);
  assert.equal(
    buildConfigResponse('https://vault.example.test', { signupsAllowed: false }).settings.disableUserRegistration,
    true
  );
});

test('bootstrap tells the web vault whether signups are allowed', async () => {
  assert.equal((await buildWebBootstrapResponse(await envWithUser())).signupsAllowed, true);
  assert.equal(
    (await buildWebBootstrapResponse(await envWithUser({ SIGNUPS_ALLOWED: 'false' }))).signupsAllowed,
    false
  );
});

test('the register endpoint refuses every new account when signups are disabled', async () => {
  const disabled = await envWithUser({ SIGNUPS_ALLOWED: 'false' });
  const response = await handleRegister(
    new Request('https://vault.test/api/accounts/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.9' },
      body: JSON.stringify({ email: 'new@example.test', inviteCode: 'anything' }),
    }),
    disabled
  );
  assert.equal(response.status, 403);
  assert.equal((await response.json()).error, 'Registration is disabled');
});

test('the register endpoint still parses the body when signups are allowed', async () => {
  const allowed = await envWithUser();
  const response = await handleRegister(
    new Request('https://vault.test/api/accounts/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.9' },
      body: 'not-json',
    }),
    allowed
  );
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, 'Invalid JSON');
});
