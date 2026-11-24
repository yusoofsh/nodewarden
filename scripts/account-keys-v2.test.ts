import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import type { Cipher, Env, Send, User } from '../src/types';
import { StorageService, STORAGE_SCHEMA_VERSION } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { createPasswordVerifier } from '../src/services/password-verifier';
import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { handlePublicRoute } from '../src/router-public';
import { buildBackupArchive } from '../src/services/backup-archive';
import { importBackupArchiveBytes } from '../src/services/backup-import';
import { validateAccountKeys } from '../src/utils/account-keys';
import { isSerializedEncString } from '../src/utils/account-passkeys';
import { createTestDb } from './lib/d1-sqlite';

// /api/sync caches responses in caches.default, keyed by the user's revision date.
const cacheStore = new Map<string, Response>();
(globalThis as any).caches = {
  default: {
    match: async (req: Request) => cacheStore.get(req.url)?.clone() ?? undefined,
    put: async (req: Request, res: Response) => void cacheStore.set(req.url, res.clone()),
  },
};

const USER = '50000000-0000-0000-0000-000000000001';
const ADMIN = '50000000-0000-0000-0000-000000000002';
const EMAIL = 'upgrade@example.test';
const PASSWORD = 'master-hash';
const ORG = '50000000-0000-0000-0000-0000000000a1';
const OTHER_ORG = '50000000-0000-0000-0000-0000000000a2';
const RECOVERY_MEMBER = '50000000-0000-0000-0000-0000000000b1';
const PLAIN_MEMBER = '50000000-0000-0000-0000-0000000000b2';
const FOLDER = '50000000-0000-0000-0000-0000000000c1';
const CIPHERS = ['50000000-0000-0000-0000-0000000000d1', '50000000-0000-0000-0000-0000000000d2'];
const SEND = '50000000-0000-0000-0000-0000000000e1';
const NEW_KEY_ID = 'a'.repeat(32);

// V1 strings are AES-CBC-HMAC (type 2); a V2 user key wraps with COSE Encrypt0 (type 7, one part).
const v1 = (label: string) => `2.${Buffer.from(label).toString('base64')}|aXY=|bWFj`;
const v2 = (label: string) => `7.${Buffer.from(label).toString('base64')}`;
const PUBLIC_KEY = 'public-key';

function v1User(id: string, email: string): User {
  return {
    id, email, name: email, masterPasswordHint: null, masterPasswordHash: '', key: v1('userkey'),
    privateKey: v1('private'), publicKey: id === USER ? PUBLIC_KEY : `pub-${id}`, kdfType: 0, kdfIterations: 600000,
    securityStamp: `stamp-${id}`, role: id === ADMIN ? 'admin' : 'user', status: 'active', totpSecret: null, totpRecoveryCode: null,
    createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
  } as User;
}

function cipher(id: string): Cipher {
  return {
    id, userId: USER, type: 1, folderId: FOLDER, name: v1(`name-${id}`), notes: null, favorite: false,
    login: { username: v1('user'), password: v1('pass'), uris: [] }, card: null, identity: null, secureNote: null,
    sshKey: null, fields: null, passwordHistory: null, reprompt: 0, key: null,
    createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z', archivedAt: null, deletedAt: null,
  } as Cipher;
}

/** A V1 account with a folder, two ciphers, a send, one membership enrolled in account recovery and one not. */
async function setup() {
  const db = createTestDb();
  await ensureStorageSchema(db);
  const env = { DB: db, JWT_SECRET: 'x'.repeat(40) } as unknown as Env;
  const storage = new StorageService(db);
  const verifier = await createPasswordVerifier(PASSWORD);
  for (const [id, email] of [[ADMIN, 'admin@example.test'], [USER, EMAIL]]) {
    await storage.createUser({ ...v1User(id, email), masterPasswordHash: verifier });
  }
  await db.prepare('INSERT INTO folders(id, user_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)').bind(FOLDER, USER, v1('folder'), '2026-01-01', '2026-01-01').run();
  for (const id of CIPHERS) await storage.saveCipher(cipher(id));
  await storage.saveSend({
    id: SEND, userId: USER, type: 0, name: v1('send'), notes: null, data: '{}', key: v1('sendkey'),
    passwordHash: null, passwordSalt: null, passwordIterations: null, authType: 2, emails: null,
    maxAccessCount: null, accessCount: 0, disabled: false, hideEmail: null,
    createdAt: '2026-01-01', updatedAt: '2026-01-01', expirationDate: null, deletionDate: '2030-01-01T00:00:00.000Z',
  } as Send);
  for (const org of [ORG, OTHER_ORG]) {
    await db.prepare("INSERT INTO organizations(id, name, billing_email, private_key, public_key, created_at, updated_at) VALUES (?, 'o', 'b', ?, 'org-pub', '2026-01-01', '2026-01-01')").bind(org, v1('org-private')).run();
    await db.prepare("INSERT INTO organization_members(id, organization_id, user_id, akey, status, type, access_all, created_at, updated_at) VALUES (?, ?, ?, '4.adminorgkey', 2, 0, 1, '2026-01-01', '2026-01-01')").bind(crypto.randomUUID(), org, ADMIN).run();
  }
  await db.prepare("INSERT INTO organization_members(id, organization_id, user_id, akey, status, type, access_all, reset_password_key, created_at, updated_at) VALUES (?, ?, ?, '4.orgkey', 2, 2, 0, '4.v1recovery', '2026-01-01', '2026-01-01')").bind(RECOVERY_MEMBER, ORG, USER).run();
  await db.prepare("INSERT INTO organization_members(id, organization_id, user_id, akey, status, type, access_all, created_at, updated_at) VALUES (?, ?, ?, '4.otherorgkey', 2, 2, 0, '2026-01-01', '2026-01-01')").bind(PLAIN_MEMBER, OTHER_ORG, USER).run();
  return { db, env, storage };
}
type Ctx = Awaited<ReturnType<typeof setup>>;

async function call(c: Ctx, method: string, path: string, body?: unknown, userId = USER) {
  const user = (await c.storage.getUserById(userId))!;
  const request = new Request(`https://vault.test${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.9' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const res = await handleAuthenticatedRoute(request, c.env, user.id, user, new URL(request.url).pathname, method);
  assert.ok(res, `${method} ${path} was not routed`);
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

async function callPublic(env: Env, path: string, body: unknown) {
  const request = new Request(`https://vault.test${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.9', Origin: 'https://vault.test' },
    body: JSON.stringify(body),
  });
  const res = await handlePublicRoute(request, env, path, 'POST', async () => null);
  assert.ok(res);
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

async function login(env: Env, email = EMAIL) {
  const form = new URLSearchParams({
    grant_type: 'password', username: email, password: PASSWORD, scope: 'api offline_access', client_id: 'mobile',
    deviceType: '0', deviceIdentifier: 'device-1', deviceName: 'test',
  });
  const request = new Request('https://vault.test/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'CF-Connecting-IP': '203.0.113.9' },
    body: form.toString(),
  });
  const res = await handlePublicRoute(request, env, '/identity/connect/token', 'POST', async () => null);
  assert.ok(res);
  return { status: res.status, json: (await res.json()) as any };
}

const rows = async (db: D1Database, sql: string, ...values: unknown[]) =>
  (await db.prepare(sql).bind(...values).all<any>()).results.map((row) => ({ ...row }));

function cryptographicState(over: Record<string, unknown> = {}) {
  return {
    publicKeyEncryptionKeyPair: { wrappedPrivateKey: v2('private'), publicKey: PUBLIC_KEY, signedPublicKey: 'signed-public-key' },
    signatureKeyPair: { signatureAlgorithm: 'ed25519', wrappedSigningKey: v2('signing'), verifyingKey: 'verifying-key' },
    securityState: { securityState: 'security-state', securityVersion: 2 },
    ...over,
  };
}

/** A rotate-user-keys body that re-encrypts the whole vault under the new (V2) user key. */
function rotateUserKeys(over: Record<string, unknown> = {}, unlock: Record<string, unknown> = {}) {
  return {
    wrappedAccountCryptographicState: cryptographicState(),
    unlockData: {
      emergencyAccessUnlockData: [],
      organizationAccountRecoveryUnlockData: [{ organizationId: ORG, resetPasswordKey: null }],
      passkeyUnlockData: [],
      deviceKeyUnlockData: [],
      v2UpgradeToken: { wrappedUserKey1: v2('v1-wraps-v2'), wrappedUserKey2: v2('v2-wraps-v1') },
      ...unlock,
    },
    accountData: {
      ciphers: CIPHERS.map((id) => ({
        id, type: 1, folderId: FOLDER, name: v2(`name-${id}`),
        login: { username: v2('user'), password: v2('pass'), uris: [{ uri: v2('uri'), uriChecksum: v2('checksum'), match: null }] },
      })),
      folders: [{ id: FOLDER, name: v2('folder') }],
      sends: [{ id: SEND, key: v2('sendkey') }],
    },
    unlockMethodData: {
      unlockMethod: 1,
      masterPasswordUnlockData: {
        kdf: { kdfType: 0, iterations: 600000, memory: null, parallelism: null },
        salt: EMAIL,
        masterKeyWrappedUserKey: v1('v2-userkey'),
        containedKeyId: NEW_KEY_ID,
      },
      keyConnectorKeyWrappedUserKey: null,
    },
    oldUserKeyId: null,
    newUserKeyId: NEW_KEY_ID,
    ...over,
  };
}

const V2_ACCOUNT_KEYS = {
  publicKeyEncryptionKeyPair: {
    wrappedPrivateKey: v2('private'),
    publicKey: PUBLIC_KEY,
    signedPublicKey: 'signed-public-key',
    object: 'publicKeyEncryptionKeyPair',
    Object: 'publicKeyEncryptionKeyPair',
  },
  securityState: { securityState: 'security-state', securityVersion: 2 },
  signatureKeyPair: { wrappedSigningKey: v2('signing'), verifyingKey: 'verifying-key', object: 'signatureKeyPair' },
  object: 'privateKeys',
  Object: 'privateKeys',
};

const v1AccountKeys = (privateKey: string, publicKey: string) => ({
  publicKeyEncryptionKeyPair: {
    wrappedPrivateKey: privateKey,
    publicKey,
    signedPublicKey: null,
    object: 'publicKeyEncryptionKeyPair',
    Object: 'publicKeyEncryptionKeyPair',
  },
  securityState: null,
  signatureKeyPair: null,
  object: 'privateKeys',
  Object: 'privateKeys',
});

test('a V1 account upgrades in place to V2 and keeps its vault, memberships and password', async () => {
  const c = await setup();
  const before = await call(c, 'GET', '/api/sync');
  assert.deepEqual(before.json.profile.accountKeys, v1AccountKeys(v1('private'), PUBLIC_KEY));

  const res = await call(c, 'POST', '/api/accounts/key-management/rotate-user-keys', rotateUserKeys());
  assert.equal(res.status, 200, JSON.stringify(res.json));

  const sync = await call(c, 'GET', '/api/sync');
  assert.equal(sync.status, 200);
  assert.deepEqual(sync.json.profile.accountKeys, V2_ACCOUNT_KEYS);
  assert.equal(sync.json.profile.key, v1('v2-userkey'));
  assert.equal(sync.json.profile.privateKey, v2('private'));
  // The same ciphers, now under the V2 user key.
  assert.deepEqual(sync.json.ciphers.map((x: any) => [x.id, x.name]).sort(), CIPHERS.map((id) => [id, v2(`name-${id}`)]).sort());
  for (const synced of sync.json.ciphers) {
    assert.deepEqual([synced.login.username, synced.login.password, synced.login.uris[0].uri, synced.login.uris[0].uriChecksum], [v2('user'), v2('pass'), v2('uri'), v2('checksum')]);
    assert.equal(synced.folderId, FOLDER);
  }
  assert.deepEqual(sync.json.folders.map((x: any) => x.name), [v2('folder')]);
  assert.deepEqual(sync.json.sends.map((x: any) => x.key), [v2('sendkey')]);
  // Sessions still holding the V1 user key unwrap the V2 one with the token.
  assert.deepEqual(sync.json.UserDecryption.V2UpgradeToken, { WrappedUserKey1: v2('v1-wraps-v2'), WrappedUserKey2: v2('v2-wraps-v1') });
  assert.deepEqual(sync.json.userDecryption.v2UpgradeToken, { wrappedUserKey1: v2('v1-wraps-v2'), wrappedUserKey2: v2('v2-wraps-v1') });
  assert.equal(sync.json.UserDecryption.UserKeyId, NEW_KEY_ID);
  // Both memberships keep the organization key they hold; the recovery key stays until an admin re-wraps it.
  assert.deepEqual(
    await rows(c.db, 'SELECT id, akey, reset_password_key, v2_upgrade_token FROM organization_members WHERE user_id = ? ORDER BY id', USER),
    [
      { id: RECOVERY_MEMBER, akey: '4.orgkey', reset_password_key: '4.v1recovery', v2_upgrade_token: JSON.stringify({ wrappedUserKey1: v2('v1-wraps-v2'), wrappedUserKey2: v2('v2-wraps-v1') }) },
      { id: PLAIN_MEMBER, akey: '4.otherorgkey', reset_password_key: null, v2_upgrade_token: null },
    ]
  );
  assert.deepEqual(await rows(c.db, 'SELECT user_id, signature_algorithm, signing_key, verifying_key FROM user_signature_key_pairs'), [
    { user_id: USER, signature_algorithm: 0, signing_key: v2('signing'), verifying_key: 'verifying-key' },
  ]);

  // The master password is unchanged, and the token response carries the V2 keys.
  const token = await login(c.env);
  assert.equal(token.status, 200, JSON.stringify(token.json));
  assert.deepEqual(token.json.AccountKeys, V2_ACCOUNT_KEYS);
  assert.equal(token.json.Key, v1('v2-userkey'));
  const profile = await call(c, 'GET', '/api/accounts/profile');
  assert.deepEqual(profile.json.accountKeys, V2_ACCOUNT_KEYS);
  const keys = await call(c, 'GET', `/api/users/${USER}/keys`, undefined, ADMIN);
  assert.deepEqual(keys.json, { publicKey: PUBLIC_KEY, signedPublicKey: 'signed-public-key', verifyingKey: 'verifying-key', object: 'publicKeys' });

  // The admin re-wraps the recovery key with the member's V2 user key, which consumes the token.
  const pending = await call(c, 'GET', `/api/organizations/${ORG}/users/keys/pending-v2-upgrades`, undefined, ADMIN);
  assert.deepEqual(pending.json, {
    object: 'list',
    data: [{
      object: 'organizationUserPendingV2Upgrade',
      organizationUserId: RECOVERY_MEMBER,
      userKeyId: NEW_KEY_ID,
      accountRecoveryKey: '4.v1recovery',
      v2UpgradeToken: { wrappedUserKey1: v2('v1-wraps-v2'), wrappedUserKey2: v2('v2-wraps-v1') },
    }],
    continuationToken: null,
  });
  const stale = await call(c, 'POST', `/api/organizations/${ORG}/users/keys/v2-upgrades`, {
    upgrades: [{ organizationUserId: RECOVERY_MEMBER, userKeyId: 'b'.repeat(32), accountRecoveryKey: '4.djJyZWNvdmVyeQ==' }],
  }, ADMIN);
  assert.equal(stale.status, 200);
  assert.equal((await rows(c.db, 'SELECT reset_password_key FROM organization_members WHERE id = ?', RECOVERY_MEMBER))[0].reset_password_key, '4.v1recovery');
  assert.equal((await call(c, 'POST', `/api/organizations/${ORG}/users/keys/v2-upgrades`, {
    upgrades: [{ organizationUserId: RECOVERY_MEMBER, userKeyId: NEW_KEY_ID, accountRecoveryKey: 'not-rsa' }],
  }, ADMIN)).status, 400);
  const applied = await call(c, 'POST', `/api/organizations/${ORG}/users/keys/v2-upgrades`, {
    upgrades: [{ organizationUserId: RECOVERY_MEMBER, userKeyId: NEW_KEY_ID, accountRecoveryKey: '4.djJyZWNvdmVyeQ==' }],
  }, ADMIN);
  assert.equal(applied.status, 200);
  assert.deepEqual(await rows(c.db, 'SELECT reset_password_key, v2_upgrade_token FROM organization_members WHERE id = ?', RECOVERY_MEMBER), [
    { reset_password_key: '4.djJyZWNvdmVyeQ==', v2_upgrade_token: null },
  ]);
  assert.deepEqual((await call(c, 'GET', `/api/organizations/${ORG}/users/keys/pending-v2-upgrades`, undefined, ADMIN)).json.data, []);

  // The upgraded account keeps writing its vault with COSE (type 7) strings.
  const folder = await call(c, 'POST', '/api/folders', { name: v2('new-folder') });
  assert.equal(folder.status, 200, JSON.stringify(folder.json));
  const created = await call(c, 'POST', '/api/ciphers', {
    type: 1, name: v2('new'), notes: v2('notes'), folderId: folder.json.id, key: v2('cipher-key'),
    login: { username: v2('new-user'), password: v2('new-pass'), uris: [{ uri: v2('new-uri'), uriChecksum: v2('new-checksum'), match: null }] },
  });
  assert.equal(created.status, 200, JSON.stringify(created.json));
  const updated = await call(c, 'PUT', `/api/ciphers/${created.json.id}`, {
    ...created.json, name: v2('renamed'), login: { ...created.json.login, password: v2('changed-pass') },
  });
  assert.equal(updated.status, 200, JSON.stringify(updated.json));
  const send = await call(c, 'POST', '/api/sends', {
    type: 0, name: v2('new-send'), key: v2('new-send-key'), text: { text: v2('text'), hidden: false },
    deletionDate: new Date(Date.now() + 86_400_000).toISOString(),
  });
  assert.equal(send.status, 200, JSON.stringify(send.json));
  const after = await call(c, 'GET', '/api/sync');
  const saved = after.json.ciphers.find((x: any) => x.id === created.json.id);
  assert.deepEqual(
    [saved.name, saved.notes, saved.key, saved.folderId, saved.login.username, saved.login.password, saved.login.uris[0].uri, saved.login.uris[0].uriChecksum],
    [v2('renamed'), v2('notes'), v2('cipher-key'), folder.json.id, v2('new-user'), v2('changed-pass'), v2('new-uri'), v2('new-checksum')]
  );
  assert.equal(after.json.ciphers.length, CIPHERS.length + 1);
  assert.ok(after.json.folders.some((x: any) => x.name === v2('new-folder')));
  assert.ok(after.json.sends.some((x: any) => x.key === v2('new-send-key') && x.name === v2('new-send')));
  assert.equal(isSerializedEncString(v2('passkey-public-key')), true);
});

test('a later V2 rotation clears the upgrade token, re-wraps recovery keys and keeps the verifying key', async () => {
  const c = await setup();
  assert.equal((await call(c, 'POST', '/api/accounts/key-management/rotate-user-keys', rotateUserKeys())).status, 200);
  const stampAfterUpgrade = (await c.storage.getUserById(USER))!.securityStamp;
  const ROTATED_KEY_ID = 'c'.repeat(32);
  const next = (state: Record<string, unknown>, recoveryKey: string | null) => {
    const body = rotateUserKeys({ newUserKeyId: ROTATED_KEY_ID, oldUserKeyId: NEW_KEY_ID }, {
      v2UpgradeToken: null,
      organizationAccountRecoveryUnlockData: [{ organizationId: ORG, resetPasswordKey: recoveryKey }],
    }) as any;
    body.unlockMethodData.masterPasswordUnlockData.containedKeyId = ROTATED_KEY_ID;
    body.wrappedAccountCryptographicState = cryptographicState(state);
    return body;
  };

  const otherVerifier = next({ signatureKeyPair: { signatureAlgorithm: 'ed25519', wrappedSigningKey: v2('signing-2'), verifyingKey: 'other' } }, '4.rotated');
  assert.match((await call(c, 'POST', '/api/accounts/key-management/rotate-user-keys', otherVerifier)).json.error, /verifying key/);
  assert.match((await call(c, 'POST', '/api/accounts/key-management/rotate-user-keys', next({}, null))).json.error, /cannot be null or empty/);

  const rotated = next({ signatureKeyPair: { signatureAlgorithm: 'ed25519', wrappedSigningKey: v2('signing-2'), verifyingKey: 'verifying-key' } }, '4.rotated');
  assert.equal((await call(c, 'POST', '/api/accounts/key-management/rotate-user-keys', rotated)).status, 200);
  const user = (await c.storage.getUserById(USER))!;
  assert.equal(user.v2UpgradeToken, null);
  assert.equal(user.userKeyId, ROTATED_KEY_ID);
  assert.notEqual(user.securityStamp, stampAfterUpgrade);
  assert.equal(user.signatureKeyPair?.signingKey, v2('signing-2'));
  assert.deepEqual(await rows(c.db, 'SELECT reset_password_key, v2_upgrade_token FROM organization_members WHERE id = ?', RECOVERY_MEMBER), [
    { reset_password_key: '4.rotated', v2_upgrade_token: null },
  ]);
  // A V2 account can't go back to V1 keys.
  const downgrade = await call(c, 'POST', '/api/accounts/key-management/rotate-user-account-keys', {
    oldMasterKeyAuthenticationHash: PASSWORD,
    accountUnlockData: {
      masterPasswordUnlockData: { kdfType: 0, kdfIterations: 600000, email: EMAIL, masterKeyAuthenticationHash: 'new', masterKeyEncryptedUserKey: v1('k') },
      organizationAccountRecoveryUnlockData: [{ organizationId: ORG, resetPasswordKey: '4.again' }],
    },
    accountKeys: { userKeyEncryptedAccountPrivateKey: v1('private'), accountPublicKey: PUBLIC_KEY },
    accountData: rotateUserKeys().accountData,
  });
  assert.match(downgrade.json.error, /Cannot downgrade/);
});

test('invalid or partial V2 requests change nothing', async () => {
  const c = await setup();
  const snapshot = async () => JSON.stringify(await Promise.all([
    rows(c.db, 'SELECT * FROM users ORDER BY id'), rows(c.db, 'SELECT * FROM ciphers ORDER BY id'), rows(c.db, 'SELECT * FROM folders'),
    rows(c.db, 'SELECT * FROM sends'), rows(c.db, 'SELECT * FROM organization_members ORDER BY id'), rows(c.db, 'SELECT * FROM user_signature_key_pairs'),
  ]));
  const before = await snapshot();
  const base = rotateUserKeys() as any;
  const edit = (change: (body: any) => void) => {
    const copy = structuredClone(base);
    change(copy);
    return copy;
  };
  const cases: Array<[string, unknown, RegExp]> = [
    ['no signature key pair', edit((b) => delete b.wrappedAccountCryptographicState.signatureKeyPair), /WrappedAccountCryptographicState/],
    ['no signed public key', edit((b) => (b.wrappedAccountCryptographicState.publicKeyEncryptionKeyPair.signedPublicKey = null)), /all be present or all be absent/],
    ['empty verifying key', edit((b) => (b.wrappedAccountCryptographicState.signatureKeyPair.verifyingKey = '')), /VerifyingKey field is required/],
    ['unknown algorithm', edit((b) => (b.wrappedAccountCryptographicState.signatureKeyPair.signatureAlgorithm = 'rsa')), /Unsupported signature algorithm: rsa/],
    ['long security state', edit((b) => (b.wrappedAccountCryptographicState.securityState.securityState = 'x'.repeat(10_001))), /maximum length of 10000/],
    ['private key under a V1 user key', edit((b) => (b.wrappedAccountCryptographicState.publicKeyEncryptionKeyPair.wrappedPrivateKey = v1('private'))), /XChaCha20-Poly1305/],
    ['signing key under a V1 user key', edit((b) => (b.wrappedAccountCryptographicState.signatureKeyPair.wrappedSigningKey = v1('signing'))), /signing key/],
    ['other public key', edit((b) => (b.wrappedAccountCryptographicState.publicKeyEncryptionKeyPair.publicKey = 'attacker')), /asymmetric keypair/],
    ['recovery key in an upgrade', edit((b) => (b.unlockData.organizationAccountRecoveryUnlockData[0].resetPasswordKey = '4.new')), /V1 to V2 upgrade/],
    ['recovery entry left out', edit((b) => (b.unlockData.organizationAccountRecoveryUnlockData = [])), /reset password keys must be included/],
    ['missing cipher', edit((b) => b.accountData.ciphers.pop()), /All existing ciphers/],
    ['trusted device unlock', edit((b) => (b.unlockMethodData.unlockMethod = 0)), /Trusted device/],
    ['key connector unlock', edit((b) => (b.unlockMethodData.unlockMethod = 2)), /Key connector/],
    ['wrong salt', edit((b) => (b.unlockMethodData.masterPasswordUnlockData.salt = 'other@example.test')), /salt/],
    ['changed KDF', edit((b) => (b.unlockMethodData.masterPasswordUnlockData.kdf.iterations = 700000)), /KDF/],
    ['contained key id mismatch', edit((b) => (b.unlockMethodData.masterPasswordUnlockData.containedKeyId = 'b'.repeat(32))), /Invalid user key/],
    ['half an upgrade token', edit((b) => (b.unlockData.v2UpgradeToken = { wrappedUserKey1: v2('x') })), /WrappedUserKey2/],
  ];
  for (const [label, body, message] of cases) {
    const res = await call(c, 'POST', '/api/accounts/key-management/rotate-user-keys', body);
    assert.equal(res.status, 400, label);
    assert.match(res.json.error, message, label);
    assert.equal(await snapshot(), before, `${label} must not modify anything`);
  }

  // A partial V2 state is refused on the password rotation too.
  const v1Rotation = {
    oldMasterKeyAuthenticationHash: PASSWORD,
    accountUnlockData: {
      masterPasswordUnlockData: { kdfType: 0, kdfIterations: 600000, email: EMAIL, masterKeyAuthenticationHash: 'new', masterKeyEncryptedUserKey: v1('k') },
      organizationAccountRecoveryUnlockData: [{ organizationId: ORG, resetPasswordKey: '4.again' }],
    },
    accountKeys: { userKeyEncryptedAccountPrivateKey: v1('private'), accountPublicKey: PUBLIC_KEY, securityState: { securityState: 's', securityVersion: 2 } },
    accountData: base.accountData,
  };
  const partial = await call(c, 'POST', '/api/accounts/key-management/rotate-user-account-keys', v1Rotation);
  assert.equal(partial.status, 400);
  assert.match(partial.json.error, /all be present or all be absent/);
  assert.equal(await snapshot(), before);
});

test('validateAccountKeys follows Vaultwarden: V1, V2, and all-or-none V2 parts', () => {
  const top = { userKeyEncryptedAccountPrivateKey: v1('p'), accountPublicKey: 'pub' };
  assert.deepEqual(validateAccountKeys(top), { privateKey: v1('p'), publicKey: 'pub', v2: null });
  assert.equal(validateAccountKeys({ accountPublicKey: 'pub' }), 'The UserKeyEncryptedAccountPrivateKey field is required.');
  const full = { ...top, ...cryptographicState(), securityState: { securityState: 's', securityVersion: 2 } };
  const valid = validateAccountKeys(full);
  assert.ok(typeof valid !== 'string' && valid.v2);
  assert.deepEqual(valid.v2, {
    signedPublicKey: 'signed-public-key', signingKey: v2('signing'), verifyingKey: 'verifying-key',
    signatureAlgorithm: 0, securityState: 's', securityVersion: 2,
  });
  assert.equal((validateAccountKeys({ ...full, signatureKeyPair: { ...full.signatureKeyPair, signatureAlgorithm: 'mldsa44' } }) as any).v2.signatureAlgorithm, 1);
  assert.match(validateAccountKeys({ ...full, securityState: null }) as string, /all be present or all be absent/);
  assert.match(validateAccountKeys({ ...full, securityState: { securityState: 's' } }) as string, /SecurityVersion/);
  assert.match(validateAccountKeys({ ...full, publicKeyEncryptionKeyPair: { ...full.publicKeyEncryptionKeyPair, signedPublicKey: ' ' } }) as string, /SignedPublicKey/);
  // 10000 UTF-16 code units are allowed, one more is not.
  assert.equal(typeof validateAccountKeys({ ...full, securityState: { securityState: 'x'.repeat(10_000), securityVersion: 2 } }), 'object');
});

test('registration accepts V2 accountKeys, refuses a partial set, and leaves V1 registration as it was', async () => {
  const db = createTestDb();
  await ensureStorageSchema(db);
  const env = { DB: db, JWT_SECRET: 'x'.repeat(40) } as unknown as Env;
  const register = (email: string, extra: Record<string, unknown>) => callPublic(env, '/api/accounts/register', {
    email, masterPasswordHash: PASSWORD, key: v1('userkey'), kdf: 0, kdfIterations: 600000, ...extra,
  });
  const accountKeys = {
    userKeyEncryptedAccountPrivateKey: v2('private'),
    accountPublicKey: PUBLIC_KEY,
    ...cryptographicState(),
  };

  const partial = await register('first@example.test', { accountKeys: { ...accountKeys, securityState: null } });
  assert.equal(partial.status, 400);
  assert.match(partial.json.error, /all be present or all be absent/);
  assert.equal(await new StorageService(db).getUserCount(), 0);

  assert.equal((await register('first@example.test', { accountKeys })).status, 200);
  const token = await login(env, 'first@example.test');
  assert.equal(token.status, 200, JSON.stringify(token.json));
  assert.deepEqual(token.json.AccountKeys, V2_ACCOUNT_KEYS);

  // A V1 registration: the flat keys, the same accountKeys as before.
  const storage = new StorageService(db);
  const admin = (await storage.getUser('first@example.test'))!;
  await storage.createInvite({ code: 'invite-1', createdBy: admin.id, usedBy: null, expiresAt: '2099-01-01T00:00:00.000Z', status: 'active', createdAt: '2026-01-01', updatedAt: '2026-01-01' });
  const v1Reg = await register('second@example.test', { keys: { encryptedPrivateKey: v1('private'), publicKey: 'pub-2' }, inviteCode: 'invite-1' });
  assert.equal(v1Reg.status, 200, JSON.stringify(v1Reg.json));
  const v1Token = await login(env, 'second@example.test');
  assert.equal(v1Token.status, 200, JSON.stringify(v1Token.json));
  assert.deepEqual(v1Token.json.AccountKeys, v1AccountKeys(v1('private'), 'pub-2'));
});

test('POST /api/accounts/keys takes V2 accountKeys only for an account without keys', async () => {
  const c = await setup();
  const accountKeys = { userKeyEncryptedAccountPrivateKey: v2('private'), accountPublicKey: PUBLIC_KEY, ...cryptographicState() };
  const existing = await call(c, 'POST', '/api/accounts/keys', { masterPasswordHash: PASSWORD, accountKeys });
  assert.equal(existing.status, 400);
  assert.match(existing.json.error, /existing keypair/);

  await c.db.prepare('UPDATE users SET private_key = NULL, public_key = NULL WHERE id = ?').bind(USER).run();
  const v1Only = await call(c, 'POST', '/api/accounts/keys', {
    masterPasswordHash: PASSWORD, accountKeys: { userKeyEncryptedAccountPrivateKey: v1('p'), accountPublicKey: 'pub' },
  });
  assert.match(v1Only.json.error, /only supported for V2/);
  const set = await call(c, 'POST', '/api/accounts/keys', { masterPasswordHash: PASSWORD, accountKeys, userKeyId: NEW_KEY_ID });
  assert.equal(set.status, 200, JSON.stringify(set.json));
  assert.deepEqual(set.json.accountKeys, V2_ACCOUNT_KEYS);
  assert.deepEqual((await call(c, 'GET', '/api/sync')).json.profile.accountKeys, V2_ACCOUNT_KEYS);
  assert.equal((await c.storage.getUserById(USER))!.userKeyId, NEW_KEY_ID);

  // Only a key rotation changes the keys of a V2 account.
  const replace = await call(c, 'POST', '/api/accounts/keys', { masterPasswordHash: PASSWORD, encryptedPrivateKey: v1('p'), publicKey: 'pub' });
  assert.equal(replace.status, 400);
  const password = await call(c, 'POST', '/api/accounts/password', {
    masterPasswordHash: PASSWORD, newMasterPasswordHash: 'next', key: v1('userkey'), newEncryptedPrivateKey: v1('p'),
  });
  assert.equal(password.status, 400);
  assert.equal((await c.storage.getUserById(USER))!.privateKey, v2('private'));
});

test('a V1 account is unchanged: same accountKeys, and the V1 rotation still works', async () => {
  const c = await setup();
  assert.deepEqual((await login(c.env)).json.AccountKeys, v1AccountKeys(v1('private'), PUBLIC_KEY));
  assert.deepEqual((await call(c, 'GET', `/api/users/${USER}/keys`, undefined, ADMIN)).json, {
    publicKey: PUBLIC_KEY, signedPublicKey: null, verifyingKey: null, object: 'publicKeys',
  });
  assert.deepEqual((await call(c, 'GET', `/api/users/${USER}/public-key`, undefined, ADMIN)).json, { userId: USER, publicKey: PUBLIC_KEY, object: 'userKey' });

  const rotation = await call(c, 'POST', '/api/accounts/key-management/rotate-user-account-keys', {
    oldMasterKeyAuthenticationHash: PASSWORD,
    accountUnlockData: {
      masterPasswordUnlockData: { kdfType: 0, kdfIterations: 600000, email: EMAIL, masterKeyAuthenticationHash: 'new-hash', masterKeyEncryptedUserKey: v1('userkey-2') },
      organizationAccountRecoveryUnlockData: [{ organizationId: ORG, resetPasswordKey: '4.rotated' }],
      // Never kept on this endpoint: it ends every session.
      v2UpgradeToken: { wrappedUserKey1: v2('a'), wrappedUserKey2: v2('b') },
    },
    accountKeys: { userKeyEncryptedAccountPrivateKey: v1('private-2'), accountPublicKey: PUBLIC_KEY },
    accountData: {
      ciphers: CIPHERS.map((id) => ({ id, type: 1, folderId: FOLDER, name: v1(`n-${id}`), login: { username: v1('u'), password: v1('p'), uris: [] } })),
      folders: [{ id: FOLDER, name: v1('f') }],
      sends: [{ id: SEND, key: v1('s') }],
    },
  });
  assert.equal(rotation.status, 200, JSON.stringify(rotation.json));
  const user = (await c.storage.getUserById(USER))!;
  assert.deepEqual([user.privateKey, user.signedPublicKey, user.securityState, user.securityVersion, user.v2UpgradeToken, user.signatureKeyPair], [v1('private-2'), null, null, null, null, null]);
  assert.deepEqual(await rows(c.db, 'SELECT reset_password_key, v2_upgrade_token FROM organization_members WHERE id = ?', RECOVERY_MEMBER), [
    { reset_password_key: '4.rotated', v2_upgrade_token: null },
  ]);
  assert.deepEqual((await call(c, 'GET', '/api/sync')).json.profile.accountKeys, v1AccountKeys(v1('private-2'), PUBLIC_KEY));
});

test('enrolling in account recovery again drops a pending upgrade token', async () => {
  const c = await setup();
  assert.equal((await call(c, 'POST', '/api/accounts/key-management/rotate-user-keys', rotateUserKeys())).status, 200);
  await c.db.prepare("INSERT INTO organization_policies(id, organization_id, type, enabled, data, updated_at) VALUES ('p1', ?, 8, 1, '{}', '2026-01-01')").bind(ORG).run();
  const enroll = await call(c, 'PUT', `/api/organizations/${ORG}/users/${USER}/reset-password-enrollment`, { resetPasswordKey: '4.fresh', masterPasswordHash: PASSWORD });
  assert.equal(enroll.status, 200, JSON.stringify(enroll.json));
  assert.deepEqual(await rows(c.db, 'SELECT reset_password_key, v2_upgrade_token FROM organization_members WHERE id = ?', RECOVERY_MEMBER), [
    { reset_password_key: '4.fresh', v2_upgrade_token: null },
  ]);
});

test('backups carry the V2 keys, the upgrade tokens and the signature key pair', async () => {
  const c = await setup();
  assert.equal((await call(c, 'POST', '/api/accounts/key-management/rotate-user-keys', rotateUserKeys())).status, 200);
  const target = createTestDb();
  await ensureStorageSchema(target);
  const targetEnv = { DB: target, JWT_SECRET: 'x'.repeat(40) } as unknown as Env;
  await new StorageService(target).createUser({ ...v1User(ADMIN, 'admin@example.test'), masterPasswordHash: await createPasswordVerifier(PASSWORD) });
  await importBackupArchiveBytes((await buildBackupArchive(c.env)).bytes, targetEnv, ADMIN, true);

  const query = 'SELECT signed_public_key, security_state, security_version, v2_upgrade_token, private_key FROM users WHERE id = ?';
  assert.deepEqual(await rows(target, query, USER), await rows(c.db, query, USER));
  assert.deepEqual(await rows(target, 'SELECT * FROM user_signature_key_pairs'), await rows(c.db, 'SELECT * FROM user_signature_key_pairs'));
  assert.deepEqual(
    await rows(target, 'SELECT id, v2_upgrade_token FROM organization_members WHERE user_id = ? ORDER BY id', USER),
    await rows(c.db, 'SELECT id, v2_upgrade_token FROM organization_members WHERE user_id = ? ORDER BY id', USER)
  );
  const restored = await new StorageService(target).getUserById(USER);
  assert.equal(restored?.signatureKeyPair?.verifyingKey, 'verifying-key');
  assert.equal((await login(targetEnv)).json.AccountKeys.signatureKeyPair.verifyingKey, 'verifying-key');
});

test('a database created by the previous schema opens with the new build and keeps its rows', async () => {
  const db = createTestDb();
  await db.exec(readFileSync(new URL('./fixtures/schema-2026-11-23-mail-duo-sso-org-api-key.sql', import.meta.url), 'utf8'));
  await db.prepare("INSERT INTO config(key, value) VALUES ('schema.version', '2026-11-23-mail-duo-sso-org-api-key')").run();
  const verifier = await createPasswordVerifier(PASSWORD);
  await db.prepare("INSERT INTO users(id, email, name, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, security_stamp, role, created_at, updated_at) VALUES (?, ?, 'kept', ?, ?, ?, ?, 0, 600000, 's', 'admin', '2026-01-01', '2026-01-01')")
    .bind(USER, EMAIL, verifier, v1('userkey'), v1('private'), PUBLIC_KEY).run();
  await db.prepare("INSERT INTO ciphers(id, user_id, type, name, data, created_at, updated_at) VALUES (?, ?, 1, ?, '{}', '2026-01-01', '2026-01-01')").bind(CIPHERS[0], USER, v1('n')).run();
  await db.prepare("INSERT INTO organizations(id, name, billing_email, created_at, updated_at) VALUES (?, 'o', 'b', '2026-01-01', '2026-01-01')").bind(ORG).run();
  await db.prepare("INSERT INTO organization_members(id, organization_id, user_id, akey, status, type, access_all, reset_password_key, created_at, updated_at) VALUES (?, ?, ?, '4.orgkey', 2, 2, 0, '4.rec', '2026-01-01', '2026-01-01')").bind(RECOVERY_MEMBER, ORG, USER).run();
  const usersBefore = await rows(db, 'SELECT * FROM users');
  const ciphersBefore = await rows(db, 'SELECT * FROM ciphers');

  for (let run = 0; run < 2; run++) {
    (StorageService as any).schemaVerified = false;
    await new StorageService(db).initializeDatabase();
  }
  const columns = async (table: string) => (await rows(db, `PRAGMA table_info(${table})`)).map((r) => r.name);
  for (const column of ['signed_public_key', 'security_state', 'security_version', 'v2_upgrade_token']) {
    assert.ok((await columns('users')).includes(column), column);
  }
  assert.ok((await columns('organization_members')).includes('v2_upgrade_token'));
  assert.deepEqual(await columns('user_signature_key_pairs'), ['user_id', 'signature_algorithm', 'signing_key', 'verifying_key', 'created_at', 'updated_at']);
  assert.equal((await rows(db, "SELECT value FROM config WHERE key = 'schema.version'"))[0].value, STORAGE_SCHEMA_VERSION);

  // Every earlier column keeps its value; the new ones are null.
  const usersAfter = await rows(db, 'SELECT * FROM users');
  assert.equal(usersAfter.length, 1);
  for (const [column, value] of Object.entries(usersBefore[0])) assert.deepEqual(usersAfter[0][column], value, column);
  assert.deepEqual(await rows(db, 'SELECT * FROM ciphers'), ciphersBefore);
  assert.deepEqual(await rows(db, 'SELECT akey, reset_password_key, v2_upgrade_token FROM organization_members'), [{ akey: '4.orgkey', reset_password_key: '4.rec', v2_upgrade_token: null }]);
  const env = { DB: db, JWT_SECRET: 'x'.repeat(40) } as unknown as Env;
  const token = await login(env);
  assert.equal(token.status, 200, JSON.stringify(token.json));
  assert.deepEqual(token.json.AccountKeys, v1AccountKeys(v1('private'), PUBLIC_KEY));
});
