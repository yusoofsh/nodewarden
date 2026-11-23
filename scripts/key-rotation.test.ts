import assert from 'node:assert/strict';
import test from 'node:test';

import type { Cipher, Env, Send, User } from '../src/types';
import { StorageService } from '../src/services/storage';
import { AuthService } from '../src/services/auth';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { createPasswordVerifier } from '../src/services/password-verifier';
import { handleRotateUserAccountKeys } from '../src/handlers/key-rotation';
import { createTestDb } from './lib/d1-sqlite';

const USER = '11111111-1111-1111-1111-111111111111';
const EMAIL = 'rotate@example.test';
const old = (label: string) => `2.b2xk|${label}|bWFj`;
const fresh = (label: string) => `2.bmV3|${label}|bWFj`;
const FOLDER = 'aaaaaaaa-0000-0000-0000-000000000001';
const CIPHER = 'bbbbbbbb-0000-0000-0000-000000000001';
const TRASHED = 'bbbbbbbb-0000-0000-0000-000000000002';
const SEND = 'cccccccc-0000-0000-0000-000000000001';
const ATTACHMENT = 'dddddddd-0000-0000-0000-000000000001';

function cipher(id: string, over: Partial<Cipher> = {}): Cipher {
  return {
    id,
    userId: USER,
    type: 1,
    folderId: FOLDER,
    name: old('name'),
    notes: old('notes'),
    favorite: false,
    login: { username: old('user'), password: old('pass'), uris: [] },
    card: null,
    identity: null,
    secureNote: null,
    sshKey: null,
    fields: null,
    passwordHistory: null,
    reprompt: 0,
    key: null,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    archivedAt: null,
    deletedAt: null,
    ...over,
  } as Cipher;
}

async function setup() {
  const db = createTestDb();
  await ensureStorageSchema(db);
  const env = { DB: db, JWT_SECRET: 'x'.repeat(40) } as unknown as Env;
  const storage = new StorageService(db);
  await storage.createUser({
    id: USER,
    email: EMAIL,
    name: 'rotate',
    masterPasswordHint: null,
    masterPasswordHash: await createPasswordVerifier('old-hash'),
    key: old('userkey'),
    privateKey: old('private'),
    publicKey: 'public-key',
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
  await db
    .prepare('INSERT INTO folders(id, user_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
    .bind(FOLDER, USER, old('folder'), '2026-01-01', '2026-01-01')
    .run();
  await storage.saveCipher(cipher(CIPHER));
  await storage.saveCipher(cipher(TRASHED, { folderId: null, deletedAt: '2026-02-01T00:00:00.000Z' }));
  await storage.saveAttachment({ id: ATTACHMENT, cipherId: CIPHER, fileName: old('file'), size: 5, sizeName: '5 Bytes', key: old('attkey') });
  await storage.saveSend({
    id: SEND, userId: USER, type: 0, name: old('send'), notes: null, data: '{}', key: old('sendkey'),
    passwordHash: null, passwordSalt: null, passwordIterations: null, authType: 2, emails: null,
    maxAccessCount: null, accessCount: 0, disabled: false, hideEmail: null,
    createdAt: '2026-01-01', updatedAt: '2026-01-01', expirationDate: null, deletionDate: '2030-01-01T00:00:00.000Z',
  } as Send);
  await storage.saveRefreshToken('tok-1', USER, Date.now() + 60_000, 'dev-1');
  for (const id of ['pk-1', 'pk-2']) {
    await db
      .prepare(
        "INSERT INTO webauthn_credentials(id, user_id, purpose, name, public_key, credential_id, encrypted_user_key, encrypted_public_key, encrypted_private_key, created_at, updated_at) VALUES (?, ?, 'login', 'pk', 'pub', ?, '4.oldwrapped', ?, ?, '2026-01-01', '2026-01-01')"
      )
      .bind(id, USER, `cred-${id}`, old(`${id}-pub`), old(`${id}-priv`))
      .run();
  }
  for (const id of ['dev-a', 'dev-b']) {
    await db
      .prepare(
        "INSERT INTO devices(user_id, device_identifier, name, type, encrypted_user_key, encrypted_public_key, encrypted_private_key, created_at, updated_at) VALUES (?, ?, 'd', 1, '4.oldwrapped', ?, ?, '2026-01-01', '2026-01-01')"
      )
      .bind(USER, id, old(`${id}-pub`), old(`${id}-priv`))
      .run();
  }
  await db
    .prepare(
      "INSERT INTO auth_requests(id, user_id, type, request_device_identifier, request_device_type, access_code, public_key, key, creation_date) VALUES ('ar-1', ?, 0, 'dev-x', 1, 'code', 'pub', '4.oldwrapped', '2026-01-01')"
    )
    .bind(USER)
    .run();
  return { env, storage, db };
}

function payload(over: Record<string, unknown> = {}) {
  return {
    oldMasterKeyAuthenticationHash: 'old-hash',
    accountUnlockData: {
      passkeyUnlockData: [{ id: 'pk-1', encryptedUserKey: '4.newwrapped', encryptedPublicKey: fresh('pk-1-pub') }],
      deviceKeyUnlockData: [{ deviceId: 'dev-a', encryptedUserKey: '4.newwrapped', encryptedPublicKey: fresh('dev-a-pub') }],
      masterPasswordUnlockData: {
        kdfType: 0,
        kdfIterations: 600000,
        email: EMAIL,
        masterKeyAuthenticationHash: 'new-hash',
        masterKeyEncryptedUserKey: fresh('userkey'),
      },
    },
    accountKeys: { userKeyEncryptedAccountPrivateKey: fresh('private'), accountPublicKey: 'public-key' },
    accountData: {
      ciphers: [
        {
          id: CIPHER, type: 1, folderId: FOLDER, name: fresh('name'), notes: fresh('notes'),
          login: { username: fresh('user'), password: fresh('pass'), uris: [] },
          attachments: [{ id: ATTACHMENT, fileName: fresh('file'), key: fresh('attkey') }],
        },
        { id: TRASHED, type: 1, folderId: null, name: fresh('tname'), login: { username: fresh('u2'), password: fresh('p2'), uris: [] } },
      ],
      folders: [{ id: FOLDER, name: fresh('folder') }],
      sends: [{ id: SEND, key: fresh('sendkey') }],
    },
    ...over,
  };
}

const call = (env: Env, body: unknown) =>
  handleRotateUserAccountKeys(new Request('https://x.test', { method: 'POST', body: JSON.stringify(body) }), env, USER);

async function snapshot(db: D1Database) {
  const q = async (sql: string) => (await db.prepare(sql).all()).results;
  return JSON.stringify([
    await q('SELECT * FROM users'), await q('SELECT * FROM ciphers ORDER BY id'), await q('SELECT * FROM folders'),
    await q('SELECT * FROM sends'), await q('SELECT * FROM attachments'), await q('SELECT * FROM refresh_tokens'),
    await q('SELECT * FROM webauthn_credentials ORDER BY id'), await q('SELECT * FROM devices ORDER BY device_identifier'),
    await q('SELECT * FROM auth_requests'), await q('SELECT * FROM user_revisions'),
  ]);
}

test('a full rotation re-keys the account, every cipher, folder, send and attachment', async () => {
  const { env, storage, db } = await setup();
  assert.equal((await call(env, payload())).status, 200);

  const user = await storage.getUserById(USER);
  assert.equal(user?.key, fresh('userkey'));
  assert.equal(user?.privateKey, fresh('private'));
  assert.notEqual(user?.securityStamp, 'stamp-1');
  assert.equal(await new AuthService(env).verifyPassword('new-hash', user!.masterPasswordHash, EMAIL), true);
  assert.equal(await storage.getRefreshTokenRecord('tok-1'), null);

  const live = await storage.getCipherForUser(CIPHER, USER);
  assert.equal(live?.name, fresh('name'));
  assert.equal(live?.login?.password, fresh('pass'));
  const trashed = await storage.getCipherForUser(TRASHED, USER);
  assert.equal(trashed?.name, fresh('tname'));
  assert.equal(trashed?.deletedAt, '2026-02-01T00:00:00.000Z');

  const folder = await db.prepare('SELECT name FROM folders WHERE id = ?').bind(FOLDER).first<{ name: string }>();
  assert.equal(folder?.name, fresh('folder'));
  const send = await db.prepare('SELECT key FROM sends WHERE id = ?').bind(SEND).first<{ key: string }>();
  assert.equal(send?.key, fresh('sendkey'));
  const wrapped = async (table: string, idColumn: string, id: string) =>
    ({ ...(await db.prepare(`SELECT encrypted_user_key, encrypted_public_key, encrypted_private_key FROM ${table} WHERE ${idColumn} = ?`).bind(id).first<any>()) });
  assert.deepEqual(await wrapped('webauthn_credentials', 'id', 'pk-1'), {
    encrypted_user_key: '4.newwrapped', encrypted_public_key: fresh('pk-1-pub'), encrypted_private_key: null,
  });
  assert.deepEqual(await wrapped('webauthn_credentials', 'id', 'pk-2'), {
    encrypted_user_key: null, encrypted_public_key: null, encrypted_private_key: null,
  });
  assert.equal((await wrapped('devices', 'device_identifier', 'dev-a')).encrypted_user_key, '4.newwrapped');
  assert.equal((await wrapped('devices', 'device_identifier', 'dev-b')).encrypted_user_key, null);
  const requests = await db.prepare('SELECT COUNT(*) AS n FROM auth_requests').first<{ n: number }>();
  assert.equal(requests?.n, 0);
  const att = await db.prepare('SELECT file_name, key FROM attachments WHERE id = ?').bind(ATTACHMENT).first<any>();
  assert.deepEqual({ ...att }, { file_name: fresh('file'), key: fresh('attkey') });
});

test('missing items, wrong password, changed KDF, other key pair and V2 keys change nothing', async () => {
  const { env, db } = await setup();
  const before = await snapshot(db);
  const base = payload() as any;
  const without = (path: (b: any) => void) => {
    const copy = structuredClone(base);
    path(copy);
    return copy;
  };
  const cases: Array<[string, unknown]> = [
    ['missing cipher', without((b) => b.accountData.ciphers.pop())],
    ['missing folder', without((b) => (b.accountData.folders = []))],
    ['missing send', without((b) => (b.accountData.sends = []))],
    ['wrong password', { ...base, oldMasterKeyAuthenticationHash: 'wrong' }],
    ['changed kdf', without((b) => (b.accountUnlockData.masterPasswordUnlockData.kdfIterations = 700000))],
    ['wrong salt', without((b) => (b.accountUnlockData.masterPasswordUnlockData.email = 'other@example.test'))],
    ['other public key', without((b) => (b.accountKeys.accountPublicKey = 'attacker-key'))],
    ['bad private key', without((b) => (b.accountKeys.userKeyEncryptedAccountPrivateKey = 'garbage'))],
    ['v2 state', without((b) => (b.accountKeys.signatureKeyPair = { verifyingKey: 'x' }))],
    ['bad folder name', without((b) => (b.accountData.folders[0].name = 'plaintext'))],
    ['cipher in unknown folder', without((b) => (b.accountData.ciphers[0].folderId = 'eeeeeeee-0000-0000-0000-000000000009'))],
    ['bad user key', without((b) => (b.accountUnlockData.masterPasswordUnlockData.masterKeyEncryptedUserKey = 'garbage'))],
  ];
  for (const [label, body] of cases) {
    const res = await call(env, body);
    assert.ok(res.status >= 400, `${label} should fail, got ${res.status}`);
    assert.equal(await snapshot(db), before, `${label} must not modify anything`);
  }
});

test('an account change during rotation aborts the whole batch', async () => {
  const { env, db } = await setup();
  const before = await snapshot(db);
  // Simulate another session changing the password between the read and the write.
  const original = AuthService.prototype.hashPasswordServer;
  AuthService.prototype.hashPasswordServer = async function (this: AuthService, hash: string) {
    await db.prepare("UPDATE users SET security_stamp = 'someone-else'").run();
    return original.call(this, hash);
  };
  try {
    const res = await call(env, payload());
    assert.equal(res.status, 409);
  } finally {
    AuthService.prototype.hashPasswordServer = original;
  }
  const after = JSON.parse(await snapshot(db));
  assert.deepEqual(JSON.parse(before)[1], after[1], 'ciphers untouched');
  assert.deepEqual(JSON.parse(before)[2], after[2], 'folders untouched');
  assert.deepEqual(JSON.parse(before)[3], after[3], 'sends untouched');
  assert.deepEqual(JSON.parse(before)[4], after[4], 'attachments untouched');
});

test('an item created after the vault was read aborts the rotation instead of staying under the old key', async () => {
  const { env, storage, db } = await setup();
  const before = await snapshot(db);
  const original = AuthService.prototype.hashPasswordServer;
  AuthService.prototype.hashPasswordServer = async function (this: AuthService, hash: string) {
    await storage.saveCipher(cipher('bbbbbbbb-0000-0000-0000-0000000000ff', { folderId: null }));
    return original.call(this, hash);
  };
  try {
    assert.equal((await call(env, payload())).status, 409);
  } finally {
    AuthService.prototype.hashPasswordServer = original;
  }
  const after = JSON.parse(await snapshot(db));
  const expected = JSON.parse(before);
  assert.equal(after[1].length, expected[1].length + 1);
  const untouched = after[1].filter((c: any) => c.id !== 'bbbbbbbb-0000-0000-0000-0000000000ff');
  assert.deepEqual(untouched, expected[1]);
  assert.deepEqual(after[0], expected[0], 'user row untouched');
});

test('a large vault rotates in a handful of statements', async () => {
  const { env, storage, db } = await setup();
  const items: Array<Record<string, unknown>> = [];
  for (let i = 0; i < 400; i++) {
    const id = `eeeeeeee-0000-0000-0000-${String(i).padStart(12, '0')}`;
    await storage.saveCipher(cipher(id, { folderId: null }));
    items.push({ id, type: 1, folderId: null, name: fresh(`n${i}`), notes: `2.bmV3|${'x'.repeat(2000)}|bWFj`, login: { username: fresh('u'), password: fresh('p'), uris: [] } });
  }
  const body = payload() as any;
  body.accountData.ciphers.push(...items);

  let statements = 0;
  const realBatch = db.batch.bind(db);
  (db as any).batch = async (list: unknown[]) => {
    statements = list.length;
    return realBatch(list as D1PreparedStatement[]);
  };
  assert.equal((await call(env, body)).status, 200);
  assert.ok(statements <= 25, `expected few statements, got ${statements}`);

  const rows = (await db.prepare("SELECT name FROM ciphers WHERE id LIKE 'eeeeeeee-%'").all<{ name: string }>()).results;
  assert.equal(rows.length, 400);
  assert.ok(rows.every((r) => r.name.startsWith('2.bmV3|n')));
});
