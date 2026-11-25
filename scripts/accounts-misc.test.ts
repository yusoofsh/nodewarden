import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import type { AccountPasskeyCredential, Env, User } from '../src/types';
import { StorageService, STORAGE_SCHEMA_VERSION } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { createPasswordVerifier } from '../src/services/password-verifier';
import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { handlePublicRoute } from '../src/router-public';
import { buildBackupArchive } from '../src/services/backup-archive';
import { importBackupArchiveBytes } from '../src/services/backup-import';
import { createTestDb } from './lib/d1-sqlite';
import { createFakeBucket } from './lib/fake-r2';

// /api/sync caches responses in caches.default, keyed by the user's revision date.
const cacheStore = new Map<string, Response>();
(globalThis as any).caches = {
  default: {
    match: async (req: Request) => cacheStore.get(req.url)?.clone() ?? undefined,
    put: async (req: Request, res: Response) => void cacheStore.set(req.url, res.clone()),
  },
};

type Actor = 'owner' | 'member' | 'outsider';
const ACTORS: Actor[] = ['owner', 'member', 'outsider'];
const ID = Object.fromEntries(ACTORS.map((a, i) => [a, `40000000-0000-0000-0000-00000000000${i + 1}`])) as Record<Actor, string>;
const PASSWORD = 'master-hash';
let verifier: string;

const enc = (label: string) => `2.${Buffer.from(label).toString('base64')}|aXY=|bWFj`;

function makeUser(actor: Actor): User {
  return {
    id: ID[actor], email: `${actor}@example.test`, name: actor, masterPasswordHint: 'hint', masterPasswordHash: verifier,
    key: enc('userkey'), privateKey: enc('priv'), publicKey: `pub-${actor}`, kdfType: 0, kdfIterations: 600000,
    securityStamp: 'stamp', role: actor === 'owner' ? 'admin' : 'user', status: 'active', totpSecret: null, totpRecoveryCode: null,
    createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
  } as User;
}



async function setup() {
  verifier ??= await createPasswordVerifier(PASSWORD);
  const db = createTestDb();
  await ensureStorageSchema(db);
  const bucket = createFakeBucket();
  const env = { DB: db, JWT_SECRET: 'x'.repeat(40), ATTACHMENTS: bucket } as unknown as Env;
  const storage = new StorageService(db);
  for (const actor of ACTORS) await storage.createUser(makeUser(actor));
  return { db, env, storage, bucket };
}

type Ctx = Awaited<ReturnType<typeof setup>>;

async function call(c: Ctx, actor: Actor, method: string, path: string, body?: unknown) {
  const user = (await c.storage.getUserById(ID[actor]))!;
  const isForm = body instanceof FormData;
  const request = new Request(`https://vault.test${path}`, {
    method,
    headers: isForm ? { 'CF-Connecting-IP': '203.0.113.9' } : { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.9' },
    body: body === undefined ? undefined : isForm ? body : JSON.stringify(body),
  });
  const url = new URL(request.url);
  const res = await handleAuthenticatedRoute(request, c.env, user.id, user, url.pathname, method);
  assert.ok(res, `${method} ${path} was not routed`);
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

async function callPublic(c: Ctx, method: string, path: string, body?: unknown) {
  const request = new Request(`https://vault.test${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.9' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const res = await handlePublicRoute(request, c.env, path, method, async () => null);
  assert.ok(res, `${method} ${path} was not routed`);
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

const rows = async (db: D1Database, sql: string, ...values: unknown[]) => (await db.prepare(sql).bind(...values).all<any>()).results;
const login = (label: string, extra: Record<string, unknown> = {}) => ({
  type: 1, name: enc(label), notes: null, favorite: false, folderId: null,
  login: { username: enc(`${label}-user`), password: enc(`${label}-pass`), uris: [] }, ...extra,
});

function legacyForm(fileName: string | null, key: string | null, content = 'ciphertext') {
  const form = new FormData();
  if (key !== null) form.set('key', key);
  if (fileName !== null) form.set('data', new Blob([content]), fileName);
  return form;
}

test('profile: POST updates like PUT, changing only the fields sent', async () => {
  const c = await setup();
  const posted = await call(c, 'owner', 'POST', '/api/accounts/profile', { name: 'New name', culture: 'en-US' });
  assert.equal(posted.status, 200, JSON.stringify(posted.json));
  assert.deepEqual([posted.json.name, posted.json.masterPasswordHint], ['New name', 'hint']);

  const hint = await call(c, 'owner', 'PUT', '/api/accounts/profile', { masterPasswordHint: 'new hint' });
  assert.deepEqual([hint.json.name, hint.json.masterPasswordHint], ['New name', 'new hint']);

  assert.equal((await call(c, 'owner', 'POST', '/api/accounts/profile', { name: 'x'.repeat(51) })).status, 400);
  assert.equal((await call(c, 'owner', 'POST', '/api/accounts/profile', { name: null })).status, 400);
  assert.equal((await call(c, 'owner', 'GET', '/api/sync')).json.profile.name, 'New name');
});

test('avatar: PUT stores a #rrggbb color or null, and profile and sync report it', async () => {
  const c = await setup();
  assert.equal((await call(c, 'owner', 'GET', '/api/accounts/profile')).json.avatarColor, null);
  const set = await call(c, 'owner', 'PUT', '/api/accounts/avatar', { avatarColor: '#1a2B3c' });
  assert.equal(set.status, 200, JSON.stringify(set.json));
  assert.equal(set.json.avatarColor, '#1a2B3c');
  assert.equal((await call(c, 'owner', 'GET', '/api/accounts/profile')).json.avatarColor, '#1a2B3c');
  assert.equal((await call(c, 'owner', 'GET', '/api/sync')).json.profile.avatarColor, '#1a2B3c');

  for (const bad of ['#abc', 'red', '#12345g', 12]) {
    assert.equal((await call(c, 'owner', 'PUT', '/api/accounts/avatar', { avatarColor: bad })).status, 400, String(bad));
  }
  // A profile save must not reset the color.
  await call(c, 'owner', 'PUT', '/api/accounts/profile', { masterPasswordHint: 'h2' });
  assert.equal((await call(c, 'owner', 'GET', '/api/accounts/profile')).json.avatarColor, '#1a2B3c');

  assert.equal((await call(c, 'owner', 'PUT', '/api/accounts/avatar', { avatarColor: null })).json.avatarColor, null);
  assert.equal((await call(c, 'owner', 'GET', '/api/sync')).json.profile.avatarColor, null);
  assert.equal((await call(c, 'member', 'GET', '/api/accounts/profile')).json.avatarColor, null);
});

test('avatar: backup export and restore carry the color', async () => {
  const c = await setup();
  await call(c, 'member', 'PUT', '/api/accounts/avatar', { avatarColor: '#00ff00' });
  const target = await setup();
  await importBackupArchiveBytes((await buildBackupArchive(c.env)).bytes, target.env, ID.owner, false);
  assert.deepEqual(
    (await rows(target.db, 'SELECT id, avatar_color FROM users ORDER BY id')).map((r) => [r.id, r.avatar_color]),
    [[ID.owner, null], [ID.member, '#00ff00'], [ID.outsider, null]]
  );
});

test('key rotation data lists keyed emergency contacts', async () => {
  const c = await setup();
  const empty = await call(c, 'owner', 'GET', '/api/accounts/key-management/key-rotation-data');
  assert.deepEqual(empty.json, {
    emergencyAccessKeyData: [], trustedDeviceKeyData: [], passkeyKeyData: [], object: 'keyRotationData',
  });

  const insertAccess = (id: string, granteeId: string | null, key: string | null, status: number) =>
    c.db
      .prepare("INSERT INTO emergency_access(id, grantor_id, grantee_id, email, key_encrypted, type, status, wait_time_days, created_at, updated_at) VALUES (?, ?, ?, NULL, ?, 0, ?, 7, '2026-01-02', '2026-01-02')")
      .bind(id, ID.owner, granteeId, key, status)
      .run();
  await insertAccess('ea-keyed', ID.member, '4.wrapped', 2);
  await insertAccess('ea-unkeyed', ID.outsider, null, 1);

  const data = (await call(c, 'owner', 'GET', '/api/accounts/key-management/key-rotation-data')).json;
  assert.deepEqual(data.emergencyAccessKeyData, [
    { id: 'ea-keyed', granteeId: ID.member, granteeName: 'member', granteeEmail: 'member@example.test', publicKey: 'pub-member', object: 'emergencyAccessKeyData' },
  ]);
});

test('mail-backed account routes are refused with 501', async () => {
  const c = await setup();
  assert.equal((await call(c, 'owner', 'POST', '/api/accounts/email', { newEmail: 'x@example.test' })).status, 501);
  assert.equal((await callPublic(c, 'POST', '/api/accounts/delete-recover', { email: 'owner@example.test' })).status, 501);
  assert.equal((await callPublic(c, 'POST', '/api/accounts/delete-recover-token', {})).status, 501);
});

test('now and device verification settings', async () => {
  const c = await setup();
  const now = await callPublic(c, 'GET', '/api/now');
  assert.equal(now.status, 200);
  assert.ok(Math.abs(Date.parse(now.json) - Date.now()) < 60_000, now.json);

  const settings = await call(c, 'owner', 'GET', '/api/two-factor/get-device-verification-settings');
  assert.equal(settings.status, 200);
  assert.equal(settings.json.object, 'deviceVerificationSettings');
  assert.equal(settings.json.unknownDeviceVerificationEnabled, false);
});

test('two-factor webauthn/all removes every WebAuthn key after the master password', async () => {
  const c = await setup();
  const credential = (n: number, purpose: 'twoFactor' | 'login'): AccountPasskeyCredential => ({
    id: `cred-${purpose}-${n}`, userId: ID.owner, purpose, name: `key ${n}`, publicKey: 'pk', credentialId: `cid-${purpose}-${n}`,
    counter: 0, type: 'public-key', aaGuid: null, transports: null, encryptedUserKey: null, encryptedPublicKey: null,
    encryptedPrivateKey: null, supportsPrf: false, createdAt: '2026-01-02', updatedAt: '2026-01-02',
  });
  for (const cred of [credential(1, 'twoFactor'), credential(2, 'twoFactor'), credential(3, 'login')]) {
    await c.storage.saveAccountPasskeyCredential(cred);
  }
  await c.storage.saveRefreshToken('owner-token', ID.owner, Date.now() + 60_000, 'dev-1');

  assert.equal((await call(c, 'owner', 'DELETE', '/api/two-factor/webauthn/all', { masterPasswordHash: 'wrong' })).status, 400);
  assert.equal((await c.storage.getAccountPasskeyCredentialsByUserId(ID.owner, 'twoFactor')).length, 2);

  const res = await call(c, 'owner', 'DELETE', '/api/two-factor/webauthn/all', { masterPasswordHash: PASSWORD });
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.deepEqual([res.json.enabled, res.json.keys, res.json.webAuthn], [false, [], { enabled: false, keys: [] }]);
  assert.equal((await c.storage.getAccountPasskeyCredentialsByUserId(ID.owner, 'twoFactor')).length, 0);
  assert.equal((await c.storage.getAccountPasskeyCredentialsByUserId(ID.owner, 'login')).length, 1, 'login passkeys stay');
  assert.equal((await rows(c.db, 'SELECT COUNT(*) AS n FROM refresh_tokens WHERE user_id = ?', ID.owner))[0].n, 0);
  assert.equal((await call(c, 'owner', 'DELETE', '/api/two-factor/webauthn/all', { masterPasswordHash: PASSWORD })).status, 400);
});

test('two-factor webauthn delete removes the last key and turns the provider off', async () => {
  const c = await setup();
  const credential = (n: number, purpose: 'twoFactor' | 'login'): AccountPasskeyCredential => ({
    id: `cred-${purpose}-${n}`, userId: ID.owner, purpose, name: `key ${n}`, publicKey: 'pk', credentialId: `cid-${purpose}-${n}`,
    counter: 0, type: 'public-key', aaGuid: null, transports: null, encryptedUserKey: null, encryptedPublicKey: null,
    encryptedPrivateKey: null, supportsPrf: false, createdAt: '2026-01-02', updatedAt: '2026-01-02',
  });
  await c.storage.saveAccountPasskeyCredential(credential(1, 'twoFactor'));
  await c.storage.saveAccountPasskeyCredential(credential(1, 'login'));
  await c.storage.saveRefreshToken('owner-token', ID.owner, Date.now() + 60_000, 'dev-1');

  const wrong = await call(c, 'owner', 'DELETE', '/api/two-factor/webauthn', { id: 1, masterPasswordHash: 'wrong' });
  assert.equal(wrong.status, 400);
  assert.equal((await c.storage.getAccountPasskeyCredentialsByUserId(ID.owner, 'twoFactor')).length, 1);

  const stillOne = await call(c, 'owner', 'DELETE', '/api/two-factor/webauthn', { id: 1, masterPasswordHash: PASSWORD });
  assert.equal(stillOne.status, 200, JSON.stringify(stillOne.json));
  assert.deepEqual([stillOne.json.enabled, stillOne.json.keys], [false, []]);
  assert.equal((await c.storage.getAccountPasskeyCredentialsByUserId(ID.owner, 'twoFactor')).length, 0);
  assert.equal((await c.storage.getAccountPasskeyCredentialsByUserId(ID.owner, 'login')).length, 1, 'login passkeys stay');
  assert.equal((await rows(c.db, 'SELECT COUNT(*) AS n FROM refresh_tokens WHERE user_id = ?', ID.owner))[0].n, 0);

  const noneLeft = await call(c, 'owner', 'DELETE', '/api/two-factor/webauthn', { id: 1, masterPasswordHash: PASSWORD });
  assert.equal(noneLeft.status, 400);
});

test('folders: POST /folders/{id} renames and POST /folders/{id}/delete deletes', async () => {
  const c = await setup();
  const id = (await call(c, 'owner', 'POST', '/api/folders', { name: enc('f') })).json.id as string;
  const renamed = await call(c, 'owner', 'POST', `/api/folders/${id}`, { name: enc('g') });
  assert.equal(renamed.status, 200, JSON.stringify(renamed.json));
  assert.equal((await call(c, 'owner', 'GET', `/api/folders/${id}`)).json.name, enc('g'));
  assert.equal((await call(c, 'member', 'POST', `/api/folders/${id}/delete`)).status, 404);
  assert.equal((await call(c, 'owner', 'POST', `/api/folders/${id}/delete`)).status, 204);
  assert.equal((await call(c, 'owner', 'GET', `/api/folders/${id}`)).status, 404);
});

test('purge: the personal vault, trash and folders go; other users stay', async () => {
  const c = await setup();
  const folder = (await call(c, 'owner', 'POST', '/api/folders', { name: enc('f') })).json.id as string;
  const kept = (await call(c, 'owner', 'POST', '/api/ciphers', login('kept', { folderId: folder }))).json.id as string;
  const trashed = (await call(c, 'owner', 'POST', '/api/ciphers', login('trashed'))).json.id as string;
  await call(c, 'owner', 'PUT', `/api/ciphers/${trashed}/delete`);
  const others = (await call(c, 'member', 'POST', '/api/ciphers', login('others'))).json.id as string;
  assert.equal((await call(c, 'owner', 'POST', `/api/ciphers/${kept}/attachment`, legacyForm(enc('a.txt'), enc('k')))).status, 200);
  assert.equal(c.bucket.objects.size, 1);

  assert.equal((await call(c, 'owner', 'POST', '/api/ciphers/purge', { masterPasswordHash: 'wrong' })).status, 400);
  assert.equal((await rows(c.db, 'SELECT id FROM ciphers WHERE user_id = ?', ID.owner)).length, 2);

  const res = await call(c, 'owner', 'POST', '/api/ciphers/purge', { masterPasswordHash: PASSWORD });
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.deepEqual((await rows(c.db, 'SELECT id FROM ciphers ORDER BY id')).map((r) => r.id), [others]);
  assert.equal((await rows(c.db, 'SELECT id FROM folders')).length, 0);
  assert.equal((await rows(c.db, 'SELECT id FROM attachments')).length, 0);
  assert.equal(c.bucket.objects.size, 0);
  const sync = (await call(c, 'owner', 'GET', '/api/sync')).json;
  assert.deepEqual([sync.ciphers.map((x: any) => x.id), sync.folders], [[], []]);
});

test('legacy multipart attachments: /attachment', async () => {
  const c = await setup();
  const personal = (await call(c, 'owner', 'POST', '/api/ciphers', login('p'))).json.id as string;

  // The JSON v2 flow is unchanged.
  const v2 = await call(c, 'owner', 'POST', `/api/ciphers/${personal}/attachment`, { fileName: enc('v2'), key: enc('k'), fileSize: 3 });
  assert.equal(v2.json.object, 'attachment-fileUpload');

  const legacy = await call(c, 'owner', 'POST', `/api/ciphers/${personal}/attachment`, legacyForm(enc('old.txt'), enc('old-key'), 'hello'));
  assert.equal(legacy.status, 200, JSON.stringify(legacy.json));
  const old = legacy.json.attachments.find((a: any) => a.fileName === enc('old.txt'));
  assert.deepEqual([old.key, old.size], [enc('old-key'), '5']);
  assert.equal(new TextDecoder().decode(c.bucket.objects.get(`${personal}/${old.id}`)), 'hello');

});

test('upgrading a 2026-11-23-events database adds users.avatar_color and keeps users', async () => {
  const db = createTestDb();
  await db.exec(readFileSync(new URL('./fixtures/schema-2026-11-23-events.sql', import.meta.url), 'utf8'));
  const columns = async () => (await rows(db, 'PRAGMA table_info(users)')).map((r) => r.name);
  assert.ok(!(await columns()).includes('avatar_color'));
  await db.prepare("INSERT INTO config(key, value) VALUES ('schema.version', '2026-11-23-events')").run();
  await db
    .prepare("INSERT INTO users(id, email, name, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, created_at, updated_at) VALUES (?, 'owner@example.test', 'kept', 'h', 'k', 0, 1, 's', '2026-01-01', '2026-01-01')")
    .bind(ID.owner)
    .run();

  for (let run = 0; run < 2; run++) {
    (StorageService as any).schemaVerified = false;
    await new StorageService(db).initializeDatabase();
  }
  assert.ok((await columns()).includes('avatar_color'));
  assert.equal((await rows(db, "SELECT value FROM config WHERE key = 'schema.version'"))[0].value, STORAGE_SCHEMA_VERSION);
  const storage = new StorageService(db);
  const user = (await storage.getUserById(ID.owner))!;
  assert.deepEqual([user.name, user.avatarColor], ['kept', null]);
  await storage.setAvatarColor(ID.owner, '#abcdef');
  assert.equal((await storage.getUserById(ID.owner))!.avatarColor, '#abcdef');
});
