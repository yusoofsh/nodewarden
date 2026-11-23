import assert from 'node:assert/strict';
import test from 'node:test';
import { zipSync, unzipSync } from 'fflate';

import type { Cipher, Env, User } from '../src/types';
import { StorageService } from '../src/services/storage';
import { AuthService } from '../src/services/auth';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { createPasswordVerifier } from '../src/services/password-verifier';
import { approveTimedOutEmergencyAccess } from '../src/services/storage-emergency-access-repo';
import { purgeUser } from '../src/services/user-deletion';
import { buildBackupArchive } from '../src/services/backup-archive';
import { importBackupArchiveBytes } from '../src/services/backup-import';
import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { createTestDb } from './lib/d1-sqlite';

const GRANTOR = '11111111-1111-1111-1111-111111111111';
const GRANTEE = '22222222-2222-2222-2222-222222222222';
const STRANGER = '33333333-3333-3333-3333-333333333333';
const CIPHER = 'bbbbbbbb-0000-0000-0000-000000000001';
const ATTACHMENT = 'dddddddd-0000-0000-0000-000000000001';
const enc = (label: string) => `2.aXY=|${label}|bWFj`;

function makeUser(id: string, email: string, over: Partial<User> = {}): User {
  return {
    id, email, name: email.split('@')[0], masterPasswordHint: null, masterPasswordHash: 'x', key: enc('userkey'),
    privateKey: enc('private'), publicKey: 'cHVi', kdfType: 0, kdfIterations: 600000, securityStamp: 'stamp-1',
    role: 'user', status: 'active', totpSecret: null, totpRecoveryCode: null,
    createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z', ...over,
  } as User;
}

async function setup() {
  const db = createTestDb();
  await ensureStorageSchema(db);
  const env = { DB: db, JWT_SECRET: 'x'.repeat(40) } as unknown as Env;
  const storage = new StorageService(db);
  const users = {
    grantor: makeUser(GRANTOR, 'grantor@example.test', {
      role: 'admin', masterPasswordHash: await createPasswordVerifier('grantor-hash'), totpSecret: 'TOTPSECRET',
    }),
    grantee: makeUser(GRANTEE, 'grantee@example.test'),
    stranger: makeUser(STRANGER, 'stranger@example.test'),
  };
  for (const u of Object.values(users)) await storage.createUser(u);
  await storage.saveCipher({
    id: CIPHER, userId: GRANTOR, type: 1, folderId: null, name: enc('name'), notes: null, favorite: false,
    login: { username: enc('u'), password: enc('p'), uris: [] }, card: null, identity: null, secureNote: null, sshKey: null,
    fields: null, passwordHistory: null, reprompt: 0, key: null,
    createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z', archivedAt: null, deletedAt: null,
  } as Cipher);
  await storage.saveAttachment({ id: ATTACHMENT, cipherId: CIPHER, fileName: enc('file'), size: 5, sizeName: '5 Bytes', key: enc('attkey') });
  await storage.saveRefreshToken('grantor-token', GRANTOR, Date.now() + 60_000, 'dev-1');

  const as = (who: keyof typeof users) => async (method: string, path: string, body?: unknown) => {
    const res = await handleAuthenticatedRoute(
      new Request(`https://vault.test${path}`, { method, body: body === undefined ? undefined : JSON.stringify(body) }),
      env, users[who].id, users[who], path, method
    );
    assert.ok(res, `${method} ${path} must be routed`);
    const text = await res.text();
    return { status: res.status, json: text ? JSON.parse(text) : null };
  };
  return { env, db, storage, grantor: as('grantor'), grantee: as('grantee'), stranger: as('stranger') };
}

type Caller = Awaited<ReturnType<typeof setup>>['grantor'];

async function confirmedGrant(grantor: Caller, type: number) {
  assert.equal((await grantor('POST', '/api/emergency-access/invite', { email: 'Grantee@example.test', type, waitTimeDays: 7 })).status, 200);
  const id = (await grantor('GET', '/api/emergency-access/trusted')).json.data[0].id as string;
  assert.equal((await grantor('POST', `/api/emergency-access/${id}/confirm`, { key: '4.wrapped-for-grantee' })).status, 200);
  return id;
}

const status = async (db: D1Database, id: string) =>
  (await db.prepare('SELECT status FROM emergency_access WHERE id = ?').bind(id).first<{ status: number }>())?.status;

test('takeover: invite, confirm, initiate, approve, takeover and password, then reject', async () => {
  const { env, db, storage, grantor, grantee, stranger } = await setup();

  // Mail is off, so inviting an existing account accepts it at once.
  assert.equal((await grantor('POST', '/api/emergency-access/invite', { email: 'grantee@example.test', type: 'Takeover', waitTimeDays: 7 })).status, 200);
  const trusted = (await grantor('GET', '/api/emergency-access/trusted')).json;
  assert.equal(trusted.data.length, 1);
  const id = trusted.data[0].id;
  assert.deepEqual({ ...trusted.data[0], id: undefined }, {
    id: undefined, status: 1, type: 1, waitTimeDays: 7, granteeId: GRANTEE, email: 'grantee@example.test',
    name: 'grantee', avatarColor: null, object: 'emergencyAccessGranteeDetails',
  });
  const granted = (await grantee('GET', '/api/emergency-access/granted')).json;
  assert.equal(granted.data[0].grantorId, GRANTOR);
  assert.equal(granted.data[0].object, 'emergencyAccessGrantorDetails');
  assert.equal((await stranger('GET', '/api/emergency-access/granted')).json.data.length, 0);

  // Grantor-only steps.
  assert.equal((await grantee('POST', `/api/emergency-access/${id}/confirm`, { key: '4.k' })).status, 404);
  assert.equal((await stranger('POST', `/api/emergency-access/${id}/confirm`, { key: '4.k' })).status, 404);
  assert.equal((await grantor('POST', `/api/emergency-access/${id}/confirm`, { key: '4.wrapped' })).json.status, 2);
  assert.equal((await grantor('POST', `/api/emergency-access/${id}/confirm`, { key: '4.again' })).status, 400);
  assert.equal((await grantor('GET', `/api/emergency-access/${id}`)).json.status, 2);
  assert.equal((await grantee('GET', `/api/emergency-access/${id}`)).status, 404);

  // Grantee-only steps.
  assert.equal((await grantor('POST', `/api/emergency-access/${id}/initiate`)).status, 404);
  assert.equal((await stranger('POST', `/api/emergency-access/${id}/initiate`)).status, 404);
  assert.equal((await grantee('POST', `/api/emergency-access/${id}/takeover`)).status, 400, 'not approved yet');
  assert.equal((await grantee('POST', `/api/emergency-access/${id}/password`, { newMasterPasswordHash: 'h', key: enc('k') })).status, 400);
  assert.equal((await grantee('POST', `/api/emergency-access/${id}/initiate`)).json.status, 3);
  assert.equal((await grantee('POST', `/api/emergency-access/${id}/password`, { newMasterPasswordHash: 'h', key: enc('k') })).status, 400);

  assert.equal((await grantee('POST', `/api/emergency-access/${id}/approve`)).status, 404);
  assert.equal((await stranger('POST', `/api/emergency-access/${id}/approve`)).status, 404);
  assert.equal((await grantor('POST', `/api/emergency-access/${id}/approve`)).json.status, 4);

  // A takeover grant cannot view the vault.
  assert.equal((await grantee('POST', `/api/emergency-access/${id}/view`)).status, 400);
  assert.equal((await grantee('GET', `/api/emergency-access/${id}/${CIPHER}/attachment/${ATTACHMENT}`)).status, 400);
  assert.equal((await stranger('POST', `/api/emergency-access/${id}/takeover`)).status, 404);
  assert.equal((await grantor('POST', `/api/emergency-access/${id}/takeover`)).status, 404);
  assert.deepEqual((await grantee('POST', `/api/emergency-access/${id}/takeover`)).json, {
    kdf: 0, kdfIterations: 600000, kdfMemory: null, kdfParallelism: null, keyEncrypted: '4.wrapped',
    salt: 'grantor@example.test', object: 'emergencyAccessTakeover',
  });
  assert.equal((await grantee('GET', `/api/emergency-access/${id}/policies`)).json.object, 'list');
  assert.equal((await stranger('GET', `/api/emergency-access/${id}/policies`)).status, 404);

  // New-style payload with a different KDF is refused; the stranger is refused outright.
  const authData = (iterations: number) => ({
    authenticationData: { salt: 'grantor@example.test', kdf: { kdfType: 0, iterations }, masterPasswordAuthenticationHash: 'new-hash' },
    unlockData: { salt: 'grantor@example.test', kdf: { kdfType: 0, iterations }, masterKeyWrappedUserKey: enc('newkey') },
  });
  assert.equal((await grantee('POST', `/api/emergency-access/${id}/password`, authData(100000))).status, 400);
  assert.equal((await stranger('POST', `/api/emergency-access/${id}/password`, authData(600000))).status, 404);
  assert.equal((await grantee('POST', `/api/emergency-access/${id}/password`, authData(600000))).status, 200);

  const after = (await storage.getUserById(GRANTOR))!;
  assert.equal(after.key, enc('newkey'));
  assert.equal(await new AuthService(env).verifyPassword('new-hash', after.masterPasswordHash, after.email), true);
  assert.equal(await new AuthService(env).verifyPassword('grantor-hash', after.masterPasswordHash, after.email), false);
  assert.notEqual(after.securityStamp, 'stamp-1');
  assert.equal(after.totpSecret, null, 'two-factor is disabled so the new password can log in');
  assert.equal(await storage.getRefreshTokenRecord('grantor-token'), null);

  // Reject ends the recovery; takeover and password are refused again.
  assert.equal((await grantee('POST', `/api/emergency-access/${id}/reject`)).status, 404);
  assert.equal((await grantor('POST', `/api/emergency-access/${id}/reject`)).json.status, 2);
  assert.equal((await grantee('POST', `/api/emergency-access/${id}/password`, authData(600000))).status, 400);
  assert.equal((await grantee('POST', `/api/emergency-access/${id}/takeover`)).status, 400);
  assert.equal(await status(db, id), 2);
});

test('view: an approved view grant reads the grantor vault and attachments, nothing else', async () => {
  const { db, grantor, grantee, stranger } = await setup();
  const id = await confirmedGrant(grantor, 0);
  assert.equal((await grantee('POST', `/api/emergency-access/${id}/view`)).status, 400, 'confirmed is not approved');
  await grantee('POST', `/api/emergency-access/${id}/initiate`);
  assert.equal((await grantor('POST', `/api/emergency-access/${id}/approve`)).status, 200);

  const view = (await grantee('POST', `/api/emergency-access/${id}/view`)).json;
  assert.equal(view.object, 'emergencyAccessView');
  assert.equal(view.keyEncrypted, '4.wrapped-for-grantee');
  assert.deepEqual(view.ciphers.map((c: any) => c.id), [CIPHER]);
  assert.equal(view.ciphers[0].attachments[0].id, ATTACHMENT);
  assert.equal((await stranger('POST', `/api/emergency-access/${id}/view`)).status, 404);
  assert.equal((await grantor('POST', `/api/emergency-access/${id}/view`)).status, 404);

  const attachment = await grantee('GET', `/api/emergency-access/${id}/${CIPHER}/attachment/${ATTACHMENT}`);
  assert.equal(attachment.status, 200);
  assert.match(attachment.json.url, new RegExp(`/api/attachments/${CIPHER}/${ATTACHMENT}\\?token=`));
  assert.equal((await stranger('GET', `/api/emergency-access/${id}/${CIPHER}/attachment/${ATTACHMENT}`)).status, 404);

  // A view grant cannot take over.
  assert.equal((await grantee('POST', `/api/emergency-access/${id}/takeover`)).status, 400);
  assert.equal((await grantee('POST', `/api/emergency-access/${id}/password`, { newMasterPasswordHash: 'h', key: enc('k') })).status, 400);
  assert.equal((await grantee('GET', `/api/emergency-access/${id}/policies`)).status, 400);
  assert.equal(await status(db, id), 4);
});

test('invite validation, settings update and delete by either party', async () => {
  const { db, grantor, grantee, stranger } = await setup();
  const invite = (body: unknown) => grantor('POST', '/api/emergency-access/invite', body);
  assert.equal((await invite({ email: 'nobody@example.test', type: 0, waitTimeDays: 7 })).status, 400, 'no mail, so unknown emails are refused');
  assert.equal((await invite({ email: 'grantor@example.test', type: 0, waitTimeDays: 7 })).status, 400);
  assert.equal((await invite({ email: 'grantee@example.test', type: 0, waitTimeDays: 0 })).status, 400);
  assert.equal((await invite({ email: 'grantee@example.test', type: 0, waitTimeDays: 91 })).status, 400);
  assert.equal((await invite({ email: 'grantee@example.test', type: 7, waitTimeDays: 7 })).status, 400);
  assert.equal((await invite({ email: 'grantee@example.test', type: '0', waitTimeDays: 7 })).status, 200);
  assert.equal((await invite({ email: 'grantee@example.test', type: 1, waitTimeDays: 7 })).status, 400, 'already invited');
  const id = (await grantor('GET', '/api/emergency-access/trusted')).json.data[0].id;

  assert.equal((await grantee('PUT', `/api/emergency-access/${id}`, { type: 1, waitTimeDays: 3 })).status, 404);
  assert.equal((await grantor('PUT', `/api/emergency-access/${id}`, { type: 1, waitTimeDays: 100 })).status, 400);
  assert.deepEqual((await grantor('POST', `/api/emergency-access/${id}`, { type: 1, waitTimeDays: 3 })).json, {
    id, status: 1, type: 1, waitTimeDays: 3, object: 'emergencyAccess',
  });

  assert.equal((await stranger('DELETE', `/api/emergency-access/${id}`)).status, 404);
  assert.equal((await stranger('POST', `/api/emergency-access/${id}/delete`)).status, 404);
  assert.equal((await grantee('POST', `/api/emergency-access/${id}/delete`)).status, 200);
  assert.equal(await status(db, id), undefined);

  assert.equal((await invite({ email: 'grantee@example.test', type: 0, waitTimeDays: 7 })).status, 200);
  const again = (await grantor('GET', '/api/emergency-access/trusted')).json.data[0].id;
  assert.equal((await grantor('DELETE', `/api/emergency-access/${again}`)).status, 200);
  assert.equal(await status(db, again), undefined);
});

test('accept and reinvite act only on an invited row for the caller email', async () => {
  const { db, grantor, grantee, stranger } = await setup();
  const id = 'eeeeeeee-0000-0000-0000-000000000001';
  await db
    .prepare("INSERT INTO emergency_access(id, grantor_id, email, type, status, wait_time_days, created_at, updated_at) VALUES (?, ?, 'grantee@example.test', 0, 0, 7, 'now', 'now')")
    .bind(id, GRANTOR)
    .run();
  assert.equal((await stranger('POST', `/api/emergency-access/${id}/accept`, { token: 't' })).status, 404);
  assert.equal((await grantor('POST', `/api/emergency-access/${id}/accept`, { token: 't' })).status, 404);
  assert.equal((await stranger('POST', `/api/emergency-access/${id}/reinvite`)).status, 404);
  assert.equal((await grantee('POST', `/api/emergency-access/${id}/accept`, { token: 't' })).status, 200);
  assert.equal(await status(db, id), 1);
  assert.equal((await grantee('POST', `/api/emergency-access/${id}/accept`, { token: 't' })).status, 404, 'no longer invited');
  assert.equal((await grantor('POST', `/api/emergency-access/${id}/reinvite`)).status, 400);

  await db.prepare("UPDATE emergency_access SET status = 0, grantee_id = NULL, email = 'grantee@example.test' WHERE id = ?").bind(id).run();
  assert.equal((await grantor('POST', `/api/emergency-access/${id}/reinvite`)).status, 200);
  const row = await db.prepare('SELECT status, grantee_id, email FROM emergency_access WHERE id = ?').bind(id).first<any>();
  assert.deepEqual({ ...row }, { status: 1, grantee_id: GRANTEE, email: null });
});

test('the timeout job approves recoveries whose wait time has passed, and only those', async () => {
  const { db, grantor, grantee } = await setup();
  const id = await confirmedGrant(grantor, 1);
  await grantee('POST', `/api/emergency-access/${id}/initiate`);
  const initiated = (await db.prepare('SELECT recovery_initiated_at AS at FROM emergency_access WHERE id = ?').bind(id).first<{ at: string }>())!.at;
  const day = 24 * 60 * 60 * 1000;
  const at = (ms: number) => new Date(Date.parse(initiated) + ms).toISOString();

  assert.equal(await approveTimedOutEmergencyAccess(db, at(7 * day - 1000)), 0);
  assert.equal(await status(db, id), 3);
  assert.equal(await approveTimedOutEmergencyAccess(db, at(7 * day)), 1);
  assert.equal(await status(db, id), 4);
  assert.equal(await approveTimedOutEmergencyAccess(db, at(8 * day)), 0, 'running it again changes nothing');

  // Without cron, any emergency-access request applies the same rule.
  await grantor('POST', `/api/emergency-access/${id}/reject`);
  await grantee('POST', `/api/emergency-access/${id}/initiate`);
  await db.prepare("UPDATE emergency_access SET recovery_initiated_at = '2020-01-01T00:00:00.000Z' WHERE id = ?").bind(id).run();
  assert.equal((await grantee('POST', `/api/emergency-access/${id}/takeover`)).status, 200);
});

test('deleting either account removes its emergency access rows', async () => {
  const { env, db, storage, grantor } = await setup();
  const count = async () => (await db.prepare('SELECT COUNT(*) AS n FROM emergency_access').first<{ n: number }>())!.n;
  await confirmedGrant(grantor, 1);
  await grantor('POST', '/api/emergency-access/invite', { email: 'stranger@example.test', type: 0, waitTimeDays: 2 });
  assert.equal(await count(), 2);
  await purgeUser(env, storage, (await storage.getUserById(GRANTEE))!);
  assert.equal(await count(), 1, 'grantee deletion removes the row they were granted');
  await purgeUser(env, storage, (await storage.getUserById(GRANTOR))!);
  assert.equal(await count(), 0, 'grantor deletion removes the rows they granted');
});

test('backup export and restore carry emergency access, and older archives still restore', async () => {
  const { env, grantor } = await setup();
  const id = await confirmedGrant(grantor, 1);
  const { bytes } = await buildBackupArchive(env, new Date('2026-11-23T00:00:00.000Z'), { includeAttachments: false });

  const restore = async (archive: Uint8Array) => {
    const db = createTestDb();
    await ensureStorageSchema(db);
    const target = { DB: db, JWT_SECRET: 'x'.repeat(40) } as unknown as Env;
    await importBackupArchiveBytes(archive, target, GRANTOR, false);
    return db;
  };

  const restored = await restore(bytes);
  const row = await restored.prepare('SELECT grantor_id, grantee_id, key_encrypted, type, status FROM emergency_access WHERE id = ?').bind(id).first<any>();
  assert.deepEqual({ ...row }, { grantor_id: GRANTOR, grantee_id: GRANTEE, key_encrypted: '4.wrapped-for-grantee', type: 1, status: 2 });

  // An archive from before this table existed has no emergency_access key.
  const files = unzipSync(bytes);
  const dbJson = JSON.parse(new TextDecoder().decode(files['db.json']));
  delete dbJson.emergency_access;
  files['db.json'] = new TextEncoder().encode(JSON.stringify(dbJson));
  const old = await restore(zipSync(files));
  assert.equal((await old.prepare('SELECT COUNT(*) AS n FROM emergency_access').first<{ n: number }>())!.n, 0);
  assert.equal((await old.prepare('SELECT COUNT(*) AS n FROM users').first<{ n: number }>())!.n, 3);
});
