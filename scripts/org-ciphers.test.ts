import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import type { Env, User } from '../src/types';
import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { createPasswordVerifier } from '../src/services/password-verifier';
import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { buildBackupArchive } from '../src/services/backup-archive';
import { importBackupArchiveBytes } from '../src/services/backup-import';
import { createTestDb } from './lib/d1-sqlite';

// /api/sync caches responses in caches.default, keyed by the user's revision date.
const cacheStore = new Map<string, Response>();
(globalThis as any).caches = {
  default: {
    match: async (req: Request) => cacheStore.get(req.url)?.clone() ?? undefined,
    put: async (req: Request, res: Response) => void cacheStore.set(req.url, res.clone()),
  },
};

// owner, admin: full access to Org A. writer: write access to the team collection. reader: read-only and
// hidden passwords in it. other: an Org A member with no collection. outsider: no organization.
// foreign: owner of Org B.
type Actor = 'owner' | 'admin' | 'writer' | 'reader' | 'other' | 'outsider' | 'foreign';
const ACTORS: Actor[] = ['owner', 'admin', 'writer', 'reader', 'other', 'outsider', 'foreign'];
const ID = Object.fromEntries(ACTORS.map((a, i) => [a, `20000000-0000-0000-0000-00000000000${i + 1}`])) as Record<Actor, string>;
const PASSWORD = 'master-hash';
let verifier: string;

const enc = (label: string) => `2.${Buffer.from(label).toString('base64')}|aXY=|bWFj`;

function makeUser(actor: Actor): User {
  return {
    id: ID[actor], email: `${actor}@example.test`, name: actor, masterPasswordHint: null, masterPasswordHash: verifier,
    key: 'k', privateKey: 'priv', publicKey: `pub-${actor}`, kdfType: 0, kdfIterations: 600000, securityStamp: 'stamp',
    role: actor === 'outsider' ? 'admin' : 'user', status: 'active', totpSecret: null, totpRecoveryCode: null,
    createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
  } as User;
}

async function newDb(): Promise<{ db: D1Database; env: Env; deletedBlobs: string[] }> {
  const db = createTestDb();
  await ensureStorageSchema(db);
  const deletedBlobs: string[] = [];
  const env = {
    DB: db,
    JWT_SECRET: 'x'.repeat(40),
    ATTACHMENTS: { delete: async (key: string) => void deletedBlobs.push(key) },
  } as unknown as Env;
  return { db, env, deletedBlobs };
}

async function call(env: Env, actor: Actor, method: string, path: string, body?: unknown) {
  const user = makeUser(actor);
  const request = new Request(`https://vault.test${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.9' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const url = new URL(request.url);
  const res = await handleAuthenticatedRoute(request, env, user.id, user, url.pathname, method);
  assert.ok(res, `${method} ${path} was not routed`);
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

const rows = async (db: D1Database, sql: string, ...values: unknown[]) => (await db.prepare(sql).bind(...values).all<any>()).results;

async function addMember(db: D1Database, orgId: string, actor: Actor, type: number, accessAll = 0): Promise<string> {
  const id = crypto.randomUUID();
  await db
    .prepare(
      "INSERT INTO organization_members(id, organization_id, user_id, akey, status, type, access_all, created_at, updated_at) VALUES (?, ?, ?, '4.akey', 2, ?, ?, '2026-01-02', '2026-01-02')"
    )
    .bind(id, orgId, ID[actor], type, accessAll)
    .run();
  return id;
}

const login = (label: string, extra: Record<string, unknown> = {}) => ({
  type: 1, name: enc(label), notes: null, favorite: false, folderId: null,
  login: { username: enc(`${label}-user`), password: enc(`${label}-pass`), uris: [] }, ...extra,
});

async function setup() {
  verifier ??= await createPasswordVerifier(PASSWORD);
  const { db, env, deletedBlobs } = await newDb();
  const storage = new StorageService(db);
  for (const actor of ACTORS) await storage.createUser(makeUser(actor));

  const orgA = (await call(env, 'owner', 'POST', '/api/organizations', {
    name: 'Org A', billingEmail: 'a@example.test', collectionName: enc('default'), key: '4.ownerkey',
  })).json.id as string;
  const orgB = (await call(env, 'foreign', 'POST', '/api/organizations', {
    name: 'Org B', billingEmail: 'b@example.test', collectionName: enc('b'), key: '4.bkey',
  })).json.id as string;
  await addMember(db, orgA, 'admin', 1);
  const writerId = await addMember(db, orgA, 'writer', 2);
  const readerId = await addMember(db, orgA, 'reader', 2);
  await addMember(db, orgA, 'other', 2);
  const team = (await call(env, 'owner', 'POST', `/api/organizations/${orgA}/collections`, {
    name: enc('team'),
    users: [
      { id: writerId, readOnly: false, hidePasswords: false, manage: false },
      { id: readerId, readOnly: true, hidePasswords: true, manage: false },
    ],
  })).json.id as string;
  const [general] = await rows(db, 'SELECT id FROM collections WHERE organization_id = ? AND id != ?', orgA, team);
  const [collectionB] = await rows(db, 'SELECT id FROM collections WHERE organization_id = ?', orgB);
  return { db, env, storage, deletedBlobs, orgA, orgB, team, general: general.id as string, collectionB: collectionB.id as string };
}

type Ctx = Awaited<ReturnType<typeof setup>>;

async function createInTeam(c: Ctx, actor: Actor = 'owner', label = 'shared'): Promise<string> {
  const res = await call(c.env, actor, 'POST', '/api/ciphers/create', {
    cipher: login(label, { organizationId: c.orgA }), collectionIds: [c.team],
  });
  assert.equal(res.status, 200, JSON.stringify(res.json));
  return res.json.id;
}

const syncCipher = async (c: Ctx, actor: Actor, id: string) =>
  (await call(c.env, actor, 'GET', '/api/sync')).json.ciphers.find((x: any) => x.id === id) ?? null;

test('a new organization cipher lives in its organization and collections', async () => {
  const c = await setup();
  const id = await createInTeam(c);
  const [row] = await rows(c.db, 'SELECT user_id, organization_id, folder_id FROM ciphers WHERE id = ?', id);
  assert.deepEqual({ ...row }, { user_id: ID.owner, organization_id: c.orgA, folder_id: null });
  assert.deepEqual((await rows(c.db, 'SELECT collection_id FROM collection_ciphers WHERE cipher_id = ?', id)).map((r) => r.collection_id), [c.team]);

  const created = await call(c.env, 'owner', 'GET', `/api/ciphers/${id}`);
  assert.deepEqual(
    [created.json.organizationId, created.json.collectionIds, created.json.edit, created.json.viewPassword, created.json.organizationUseTotp],
    [c.orgA, [c.team], true, true, true]
  );
});

test('who can read an organization cipher, and with which permissions', async () => {
  const c = await setup();
  const id = await createInTeam(c);
  const expected: Record<Actor, [number, boolean?, boolean?]> = {
    owner: [200, true, true], admin: [200, true, true], writer: [200, true, true], reader: [200, false, false],
    other: [404], outsider: [404], foreign: [404],
  };
  for (const actor of ACTORS) {
    const res = await call(c.env, actor, 'GET', `/api/ciphers/${id}`);
    const [status, edit, viewPassword] = expected[actor];
    assert.equal(res.status, status, actor);
    if (status === 200) {
      assert.deepEqual([res.json.edit, res.json.viewPassword, res.json.permissions.delete], [edit, viewPassword, edit], actor);
    }
    const synced = await syncCipher(c, actor, id);
    assert.equal(!!synced, status === 200, `${actor} sync`);
    if (synced) assert.deepEqual([synced.organizationId, synced.collectionIds, synced.edit, synced.folderId], [c.orgA, [c.team], edit, null]);
  }
  const listed = await call(c.env, 'reader', 'GET', '/api/ciphers');
  assert.deepEqual(listed.json.data.map((x: any) => x.id), [id]);
});

test('group collections give access; a direct assignment wins and groups combine to the most permissive', async () => {
  const c = await setup();
  const id = await createInTeam(c);
  const memberId = async (actor: Actor) => (await rows(c.db, 'SELECT id FROM organization_members WHERE user_id = ?', ID[actor]))[0].id;
  const [otherId, readerId] = [await memberId('other'), await memberId('reader')];
  const group = async (name: string, readOnly: boolean, users: string[]) => {
    const res = await call(c.env, 'owner', 'POST', `/api/organizations/${c.orgA}/groups`, {
      name, collections: [{ id: c.team, readOnly, hidePasswords: readOnly, manage: false }], users,
    });
    assert.equal(res.status, 200, JSON.stringify(res.json));
    return res.json.id as string;
  };
  const flags = async (actor: Actor) => {
    const res = await call(c.env, actor, 'GET', `/api/ciphers/${id}`);
    return res.status === 200 ? [res.json.edit, res.json.viewPassword] : res.status;
  };
  const edit = (actor: Actor) => call(c.env, actor, 'PUT', `/api/ciphers/${id}`, login('edited', { organizationId: c.orgA }));

  const viewers = await group('Viewers', true, [otherId]);
  assert.deepEqual(await flags('other'), [false, false]);
  assert.equal((await syncCipher(c, 'other', id))?.collectionIds?.[0], c.team);
  assert.equal((await edit('other')).status, 400);

  const editors = await group('Editors', false, [otherId, readerId]);
  assert.deepEqual(await flags('other'), [true, true]);
  assert.equal((await edit('other')).status, 200);
  // The reader is assigned read-only directly, which outranks the Editors group.
  assert.deepEqual(await flags('reader'), [false, false]);

  for (const groupId of [viewers, editors]) {
    assert.equal((await call(c.env, 'owner', 'DELETE', `/api/organizations/${c.orgA}/groups/${groupId}`)).status, 200);
  }
  assert.equal(await flags('other'), 404);
});

test('an unconfirmed or revoked membership reads nothing', async () => {
  const c = await setup();
  const id = await createInTeam(c);
  await c.db.prepare('UPDATE organization_members SET status = 1 WHERE user_id = ?').bind(ID.writer).run();
  assert.equal((await call(c.env, 'writer', 'GET', `/api/ciphers/${id}`)).status, 404);
  await c.db.prepare('UPDATE organization_members SET status = -1 WHERE user_id = ?').bind(ID.writer).run();
  assert.equal(await syncCipher(c, 'writer', id), null);
});

test('writes need write access; read-only members change nothing', async () => {
  const c = await setup();
  const id = await createInTeam(c);
  const update = (actor: Actor, label: string) => call(c.env, actor, 'PUT', `/api/ciphers/${id}`, login(label, { organizationId: c.orgA }));
  assert.equal((await update('reader', 'x')).json.error, 'Cipher is not write accessible');
  assert.equal((await call(c.env, 'reader', 'PUT', `/api/ciphers/${id}/delete`)).status, 400);
  assert.equal((await call(c.env, 'reader', 'DELETE', `/api/ciphers/${id}`)).status, 400);
  assert.equal((await update('other', 'x')).status, 404);
  assert.equal((await update('writer', 'by-writer')).status, 200);
  // The owner's cached sync shows the writer's change.
  assert.equal((await syncCipher(c, 'owner', id)).name, enc('by-writer'));

  // Organization and per-user fields are the server's, whatever the client sends.
  const moved = await call(c.env, 'writer', 'PUT', `/api/ciphers/${id}`, login('y', { organizationId: c.orgB }));
  assert.equal(moved.json.error, 'Organization mismatch. Please resync the client before updating the cipher');
  const folder = await call(c.env, 'writer', 'POST', '/api/folders', { name: enc('f') });
  const withFolder = await call(c.env, 'writer', 'PUT', `/api/ciphers/${id}`, login('z', { organizationId: c.orgA, folderId: folder.json.id, favorite: true }));
  assert.deepEqual([withFolder.status, withFolder.json.folderId, withFolder.json.favorite], [200, null, false]);
  const partial = await call(c.env, 'writer', 'PUT', `/api/ciphers/${id}/partial`, { folderId: folder.json.id, favorite: true });
  assert.deepEqual([partial.status, partial.json.folderId], [200, null]);
  assert.equal((await call(c.env, 'writer', 'PUT', `/api/ciphers/${id}/archive`)).status, 404, 'archiving is per user');

  // Soft delete, restore and permanent delete, as the admin routes do.
  assert.equal((await call(c.env, 'writer', 'PUT', `/api/ciphers/${id}/delete`)).status, 200);
  assert.ok((await syncCipher(c, 'reader', id)).deletedDate);
  assert.equal((await call(c.env, 'admin', 'PUT', `/api/ciphers/${id}/restore-admin`)).status, 200);
  assert.equal((await syncCipher(c, 'reader', id)).deletedDate, null);
  assert.equal((await call(c.env, 'admin', 'DELETE', `/api/ciphers/${id}/admin`)).status, 204);
  assert.equal((await rows(c.db, 'SELECT * FROM ciphers WHERE id = ?', id)).length, 0);
  assert.equal((await rows(c.db, 'SELECT * FROM collection_ciphers')).length, 0);
});

test('a personal cipher cannot be moved into an organization by an update', async () => {
  const c = await setup();
  const created = await call(c.env, 'owner', 'POST', '/api/ciphers', login('mine'));
  assert.equal(created.json.organizationId, null);
  const res = await call(c.env, 'owner', 'PUT', `/api/ciphers/${created.json.id}`, login('mine', { organizationId: c.orgA }));
  assert.equal(res.status, 400);
  assert.equal((await rows(c.db, 'SELECT organization_id FROM ciphers WHERE id = ?', created.json.id))[0].organization_id, null);
  assert.equal((await call(c.env, 'owner', 'PUT', `/api/ciphers/${created.json.id}/admin`, login('mine'))).status, 404);
});

test('creating checks membership, collections and the right to add without one', async () => {
  const c = await setup();
  const create = (actor: Actor, collectionIds: string[], orgId = c.orgA, path = '/api/ciphers/create') =>
    call(c.env, actor, 'POST', path, { cipher: login('n', { organizationId: orgId }), collectionIds });
  const cases: Array<[Actor, string[], string, string?]> = [
    ['reader', [c.team], 'No rights to modify the collection'],
    ['writer', [c.general], 'No rights to modify the collection'],
    ['writer', [], "You don't have permission to add cipher directly to organization"],
    ['owner', [c.collectionB], 'Invalid collection ID provided'],
    ['outsider', [], "You don't have permission to add item to organization"],
    ['writer', [c.team], 'Cipher is not write accessible', '/api/ciphers/admin'],
  ];
  for (const [actor, ids, error, path] of cases) {
    const res = await create(actor, ids, c.orgA, path);
    assert.deepEqual([res.status, res.json.error], [400, error], `${actor} ${ids} ${path ?? ''}`);
  }
  assert.equal((await call(c.env, 'writer', 'POST', '/api/ciphers', login('n', { organizationId: c.orgA }))).status, 400);
  assert.equal((await rows(c.db, 'SELECT * FROM ciphers')).length, 0, 'nothing was written');

  // Admins may add an item to no collection; only full-access members see it then.
  const unassigned = await create('admin', [], c.orgA, '/api/ciphers/admin');
  assert.equal(unassigned.status, 200);
  assert.equal(await syncCipher(c, 'writer', unassigned.json.id), null);
  assert.ok(await syncCipher(c, 'owner', unassigned.json.id));
  // A clone to the personal vault goes through /create with no organization.
  const personal = await call(c.env, 'writer', 'POST', '/api/ciphers/create', { cipher: login('clone'), collectionIds: [] });
  assert.deepEqual([personal.status, personal.json.organizationId], [200, null]);
});

test('sharing a personal cipher moves it into the organization', async () => {
  const c = await setup();
  const mine = (await call(c.env, 'writer', 'POST', '/api/ciphers', login('mine'))).json;
  const share = (actor: Actor, body: unknown) => call(c.env, actor, 'PUT', `/api/ciphers/${mine.id}/share`, body);
  const cipher = login('mine-org', { organizationId: c.orgA, lastKnownRevisionDate: mine.revisionDate });

  assert.equal((await share('writer', { cipher, collectionIds: [] })).json.error, 'You must select at least one collection.');
  assert.equal((await share('writer', { cipher: login('x'), collectionIds: [c.team] })).json.error, 'Cipher OrganizationId is required.');
  assert.equal((await share('owner', { cipher, collectionIds: [c.team] })).status, 404, "another user's cipher");
  assert.equal((await share('writer', { cipher, collectionIds: [c.general] })).json.error, 'No rights to modify the collection');
  assert.equal((await share('writer', { cipher: { ...cipher, lastKnownRevisionDate: '2020-01-01T00:00:00.000Z' }, collectionIds: [c.team] })).status, 400);
  assert.equal((await rows(c.db, 'SELECT organization_id FROM ciphers WHERE id = ?', mine.id))[0].organization_id, null);

  const shared = await share('writer', { cipher, collectionIds: [c.team] });
  assert.deepEqual([shared.status, shared.json.organizationId, shared.json.collectionIds, shared.json.name], [200, c.orgA, [c.team], enc('mine-org')]);
  assert.equal((await syncCipher(c, 'reader', mine.id)).name, enc('mine-org'));
  assert.equal((await share('writer', { cipher, collectionIds: [c.team] })).status, 404, 'no longer personal');

  // Bulk share answers with cipherMini models.
  const a = (await call(c.env, 'writer', 'POST', '/api/ciphers', login('a'))).json;
  const b = (await call(c.env, 'writer', 'POST', '/api/ciphers', login('b'))).json;
  const bulk = await call(c.env, 'writer', 'PUT', '/api/ciphers/share', {
    ciphers: [{ ...login('a2', { organizationId: c.orgA }), id: a.id }, { ...login('b2', { organizationId: c.orgA }), id: b.id }],
    collectionIds: [c.team],
  });
  assert.equal(bulk.status, 200, JSON.stringify(bulk.json));
  assert.deepEqual(bulk.json.data.map((x: any) => [x.id, x.object, x.organizationId, 'edit' in x]), [[a.id, 'cipherMini', c.orgA, false], [b.id, 'cipherMini', c.orgA, false]]);
  const mixed = await call(c.env, 'writer', 'PUT', '/api/ciphers/share', {
    ciphers: [{ ...login('c', { organizationId: c.orgA }), id: a.id }, { ...login('d', { organizationId: c.orgB }), id: b.id }],
    collectionIds: [c.team],
  });
  assert.equal(mixed.json.error, 'All ciphers must be for the same organization.');
});

test('changing collections needs editable access to the cipher and each collection', async () => {
  const c = await setup();
  const id = await createInTeam(c);
  const put = (actor: Actor, sub: string, collectionIds: string[]) => call(c.env, actor, 'PUT', `/api/ciphers/${id}/${sub}`, { collectionIds });
  assert.equal((await put('reader', 'collections', [])).json.error, 'Collection cannot be changed');
  assert.equal((await put('writer', 'collections', [c.team, c.general])).json.error, 'No rights to modify the collection');
  assert.equal((await put('owner', 'collections', [c.collectionB])).json.error, 'Invalid collection ID provided');

  const v2 = await put('owner', 'collections_v2', [c.team, c.general]);
  assert.deepEqual([v2.json.object, v2.json.cipher.collectionIds.sort()], ['optionalCipherDetails', [c.general, c.team].sort()]);
  // The writer only sees and changes the collections assigned to them.
  assert.deepEqual((await syncCipher(c, 'writer', id)).collectionIds, [c.team]);
  const admin = await put('admin', 'collections-admin', [c.general]);
  assert.deepEqual([admin.status, admin.json.collectionIds], [200, [c.general]]);
  assert.equal(await syncCipher(c, 'writer', id), null, 'the writer lost access with the collection');
});

test('organization details list every cipher of the organization for admins', async () => {
  const c = await setup();
  const id = await createInTeam(c);
  const path = `/api/ciphers/organization-details?organizationId=${c.orgA}`;
  const expected: Record<Actor, number> = { owner: 200, admin: 200, writer: 400, reader: 400, other: 400, outsider: 404, foreign: 404 };
  for (const actor of ACTORS) assert.equal((await call(c.env, actor, 'GET', path)).status, expected[actor], actor);
  const details = await call(c.env, 'admin', 'GET', path);
  assert.deepEqual(details.json.data.map((x: any) => [x.id, x.collectionIds]), [[id, [c.team]]]);
});

test('bulk delete and restore reach organization ciphers the caller can write', async () => {
  const c = await setup();
  const id = await createInTeam(c);
  const mine = (await call(c.env, 'reader', 'POST', '/api/ciphers', login('mine'))).json.id;
  assert.equal((await call(c.env, 'reader', 'PUT', '/api/ciphers/delete', { ids: [id, mine] })).status, 204);
  assert.equal((await syncCipher(c, 'owner', id)).deletedDate, null, 'read-only cannot delete');
  assert.ok((await syncCipher(c, 'reader', mine)).deletedDate);

  assert.equal((await call(c.env, 'writer', 'PUT', '/api/ciphers/delete', { ids: [id, mine] })).status, 204);
  assert.ok((await syncCipher(c, 'reader', id)).deletedDate);
  assert.equal((await syncCipher(c, 'reader', mine)).deletedDate !== null, true, "the writer can't touch the reader's own item");
  const restored = await call(c.env, 'admin', 'PUT', '/api/ciphers/restore-admin', { ids: [id] });
  assert.deepEqual(restored.json.data.map((x: any) => [x.id, x.deletedDate]), [[id, null]]);
  assert.equal((await call(c.env, 'admin', 'POST', '/api/ciphers/delete-admin', { ids: [id] })).status, 204);
  assert.equal((await rows(c.db, 'SELECT * FROM ciphers WHERE id = ?', id)).length, 0);
});

test('attachments of organization ciphers follow cipher access', async () => {
  const c = await setup();
  const id = await createInTeam(c);
  const created = await call(c.env, 'writer', 'POST', `/api/ciphers/${id}/attachment/v2`, { fileName: enc('file'), key: enc('k'), fileSize: 3 });
  assert.equal(created.status, 200, JSON.stringify(created.json));
  assert.equal(created.json.cipherResponse.organizationId, c.orgA);
  const attachmentId = created.json.attachmentId;
  assert.equal((await call(c.env, 'reader', 'GET', `/api/ciphers/${id}/attachment/${attachmentId}`)).status, 200);
  assert.equal((await call(c.env, 'other', 'GET', `/api/ciphers/${id}/attachment/${attachmentId}`)).status, 404);
  assert.equal((await call(c.env, 'reader', 'DELETE', `/api/ciphers/${id}/attachment/${attachmentId}`)).status, 400);
  assert.equal((await call(c.env, 'reader', 'POST', `/api/ciphers/${id}/attachment/v2`, { fileName: enc('f'), key: enc('k') })).status, 400);
  assert.equal((await syncCipher(c, 'reader', id)).attachments.length, 1);

  // Deleting the organization removes its ciphers and their files.
  const res = await call(c.env, 'owner', 'DELETE', `/api/organizations/${c.orgA}`, { masterPasswordHash: PASSWORD });
  assert.equal(res.status, 200);
  assert.equal((await rows(c.db, 'SELECT * FROM ciphers WHERE organization_id IS NOT NULL')).length, 0);
  assert.equal((await rows(c.db, 'SELECT * FROM attachments')).length, 0);
  assert.deepEqual(c.deletedBlobs, [`${id}/${attachmentId}`]);
});

test('deleting a creator hands their organization ciphers to an owner', async () => {
  const c = await setup();
  const byWriter = await createInTeam(c, 'writer', 'w');
  const byReaderLater = await createInTeam(c, 'writer', 'w2');
  const personal = (await call(c.env, 'writer', 'POST', '/api/ciphers', login('p'))).json.id;
  await c.db.prepare('UPDATE ciphers SET user_id = ? WHERE id = ?').bind(ID.reader, byReaderLater).run();

  // The writer leaves the organization, then deletes their account.
  assert.equal((await call(c.env, 'writer', 'POST', `/api/organizations/${c.orgA}/leave`)).status, 200);
  assert.equal((await call(c.env, 'writer', 'POST', '/api/accounts/delete', { masterPasswordHash: PASSWORD })).status, 200);
  assert.deepEqual((await rows(c.db, 'SELECT user_id FROM ciphers WHERE id = ?', byWriter)).map((r) => r.user_id), [ID.owner]);
  assert.equal((await rows(c.db, 'SELECT * FROM ciphers WHERE id = ?', personal)).length, 0, 'personal items go with the account');

  // An instance admin deletes the reader, still a member.
  assert.equal((await call(c.env, 'outsider', 'DELETE', `/api/admin/users/${ID.reader}`, { masterPasswordHash: PASSWORD })).status, 204);
  assert.deepEqual((await rows(c.db, 'SELECT user_id FROM ciphers WHERE id = ?', byReaderLater)).map((r) => r.user_id), [ID.owner]);
  assert.equal((await syncCipher(c, 'admin', byReaderLater)).name, enc('w2'));

  // A co-owner's ciphers pass to the remaining owner.
  await c.db.prepare('UPDATE organization_members SET type = 0 WHERE user_id = ?').bind(ID.admin).run();
  const byAdmin = await createInTeam(c, 'admin', 'a');
  assert.equal((await call(c.env, 'admin', 'POST', '/api/accounts/delete', { masterPasswordHash: PASSWORD })).status, 200);
  assert.deepEqual((await rows(c.db, 'SELECT user_id FROM ciphers WHERE id = ?', byAdmin)).map((r) => r.user_id), [ID.owner]);
});

test('backup export and restore carry the organization column and collection links', async () => {
  const c = await setup();
  const id = await createInTeam(c);
  const personal = (await call(c.env, 'owner', 'POST', '/api/ciphers', login('p'))).json.id;
  const archive = await buildBackupArchive(c.env);
  const target = await newDb();
  await importBackupArchiveBytes(archive.bytes, target.env, ID.owner, false);
  for (const sql of ['SELECT * FROM ciphers ORDER BY id', 'SELECT * FROM collection_ciphers ORDER BY cipher_id']) {
    assert.deepEqual(await rows(target.db, sql), await rows(c.db, sql), sql);
  }
  assert.deepEqual(
    (await rows(target.db, 'SELECT id, organization_id FROM ciphers ORDER BY id')).map((r) => [r.id, r.organization_id]).sort(),
    [[id, c.orgA], [personal, null]].sort()
  );
});

// The schemas main shipped before organization ciphers (fixtures/schema-<version>.sql), with a personal
// cipher and two that an earlier /api/ciphers/create stored with an organizationId only in their JSON.
for (const version of ['2026-11-23-organizations', '2026-11-23-organization-groups-policies'])
test(`upgrading a ${version} database keeps personal ciphers and adopts earlier organization items`, async () => {
  const db = createTestDb();
  await db.exec(readFileSync(new URL(`./fixtures/schema-${version}.sql`, import.meta.url), 'utf8'));
  const columns = async () => (await rows(db, 'PRAGMA table_info(ciphers)')).map((r) => r.name);
  assert.ok(!(await columns()).includes('organization_id'));
  await db.prepare("INSERT INTO config(key, value) VALUES ('schema.version', ?)").bind(version).run();
  for (const [id, email] of [[ID.owner, 'owner@example.test'], [ID.outsider, 'outsider@example.test']]) {
    await db
      .prepare("INSERT INTO users(id, email, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, created_at, updated_at) VALUES (?, ?, 'h', 'k', 0, 1, 's', '2026-01-01', '2026-01-01')")
      .bind(id, email)
      .run();
  }
  const org = '30000000-0000-0000-0000-000000000001';
  await db.prepare("INSERT INTO organizations(id, name, billing_email, created_at, updated_at) VALUES (?, 'o', 'b', '2026-01-01', '2026-01-01')").bind(org).run();
  await db
    .prepare("INSERT INTO organization_members(id, organization_id, user_id, status, type, access_all, created_at, updated_at) VALUES ('m1', ?, ?, 2, 0, 1, '2026-01-01', '2026-01-01')")
    .bind(org, ID.owner)
    .run();
  const insert = (id: string, userId: string, data: Record<string, unknown>) =>
    db
      .prepare("INSERT INTO ciphers(id, user_id, type, name, favorite, data, created_at, updated_at) VALUES (?, ?, 1, ?, 0, ?, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')")
      .bind(id, userId, enc(id), JSON.stringify({ login: { username: enc('u') }, ...data }))
      .run();
  await insert('c-personal', ID.owner, { organizationId: null });
  await insert('c-adopted', ID.owner, { organizationId: org.toUpperCase() });
  await insert('c-not-member', ID.outsider, { organizationId: org });
  await db.prepare("INSERT INTO ciphers(id, user_id, type, data, created_at, updated_at) VALUES ('c-corrupt', ?, 1, 'not json', '2026-01-01', '2026-01-01')").bind(ID.owner).run();

  for (let run = 0; run < 2; run++) {
    (StorageService as any).schemaVerified = false;
    await new StorageService(db).initializeDatabase();
  }
  assert.ok((await columns()).includes('organization_id'));
  assert.equal((await rows(db, "SELECT value FROM config WHERE key = 'schema.version'"))[0].value, '2026-11-23-org-ciphers');
  assert.deepEqual(
    (await rows(db, 'SELECT id, organization_id FROM ciphers ORDER BY id')).map((r) => [r.id, r.organization_id]),
    [['c-adopted', org], ['c-corrupt', null], ['c-not-member', null], ['c-personal', null]]
  );
  const storage = new StorageService(db);
  assert.equal((await storage.getCipherForUser('c-personal', ID.owner))?.name, enc('c-personal'));
  assert.deepEqual((await storage.getAllCiphers(ID.owner)).map((x) => x.id), ['c-personal']);
  assert.equal((await storage.getAccessibleCipher('c-adopted', ID.owner))?.cipher.organizationId, org);

  // The upgraded table, whose organization_id was added by ALTER TABLE, still restores from a backup.
  const env = { DB: db, JWT_SECRET: 'x'.repeat(40) } as unknown as Env;
  const before = await rows(db, 'SELECT * FROM ciphers ORDER BY id');
  await importBackupArchiveBytes((await buildBackupArchive(env)).bytes, env, ID.owner, true);
  assert.deepEqual(await rows(db, 'SELECT * FROM ciphers ORDER BY id'), before);
});
