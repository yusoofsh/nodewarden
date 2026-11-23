import assert from 'node:assert/strict';
import test from 'node:test';
import { unzipSync, zipSync } from 'fflate';

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

type Actor = 'owner' | 'admin' | 'member' | 'outsider' | 'foreign';
const ACTORS: Actor[] = ['owner', 'admin', 'member', 'outsider', 'foreign'];
const ID: Record<Actor, string> = {
  owner: '10000000-0000-0000-0000-000000000001',
  admin: '10000000-0000-0000-0000-000000000002',
  member: '10000000-0000-0000-0000-000000000003',
  outsider: '10000000-0000-0000-0000-000000000004',
  foreign: '10000000-0000-0000-0000-000000000005',
};
const PASSWORD = 'master-hash';
const MISSING_ORG = '99999999-0000-0000-0000-000000000000';
let verifier: string;

function makeUser(actor: Actor): User {
  return {
    id: ID[actor],
    email: `${actor}@example.test`,
    name: actor,
    masterPasswordHint: null,
    masterPasswordHash: verifier,
    key: 'k',
    privateKey: 'priv',
    publicKey: `pub-${actor}`,
    kdfType: 0,
    kdfIterations: 600000,
    securityStamp: 'stamp',
    // The outsider administers the instance, which grants nothing inside an organization.
    role: actor === 'outsider' ? 'admin' : 'user',
    status: 'active',
    totpSecret: null,
    totpRecoveryCode: null,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
  } as User;
}

async function newDb(): Promise<{ db: D1Database; env: Env }> {
  const db = createTestDb();
  await ensureStorageSchema(db);
  return { db, env: { DB: db, JWT_SECRET: 'x'.repeat(40) } as unknown as Env };
}

async function call(env: Env, actor: Actor | User, method: string, path: string, body?: unknown) {
  const user = typeof actor === 'string' ? makeUser(actor) : actor;
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

async function addMember(db: D1Database, orgId: string, actor: Actor, type: number, status = 2, accessAll = 0): Promise<string> {
  const id = crypto.randomUUID();
  await db
    .prepare(
      "INSERT INTO organization_members(id, organization_id, user_id, akey, status, type, access_all, created_at, updated_at) VALUES (?, ?, ?, '4.akey', ?, ?, ?, '2026-01-02', '2026-01-02')"
    )
    .bind(id, orgId, ID[actor], status, type, accessAll)
    .run();
  return id;
}

// Org A: owner, admin, member. Org B: foreign is its owner. outsider belongs to neither.
async function setup() {
  verifier ??= await createPasswordVerifier(PASSWORD);
  const { db, env } = await newDb();
  const storage = new StorageService(db);
  for (const actor of ACTORS) await storage.createUser(makeUser(actor));

  const created = await call(env, 'owner', 'POST', '/api/organizations', {
    name: 'Org A', billingEmail: 'Billing@Example.test', collectionName: '2.coll|a|b', key: '4.ownerkey', planType: 0,
    keys: { encryptedPrivateKey: '2.orgpriv|a|b', publicKey: 'org-public' },
  });
  assert.equal(created.status, 200);
  const orgB = await call(env, 'foreign', 'POST', '/api/organizations', {
    name: 'Org B', billingEmail: 'b@example.test', collectionName: '2.collb|a|b', key: '4.bkey',
  });
  const orgA = created.json.id as string;
  const adminMemberId = await addMember(db, orgA, 'admin', 1);
  const memberId = await addMember(db, orgA, 'member', 2);
  const [defaultCollection] = await rows(db, 'SELECT id FROM collections WHERE organization_id = ?', orgA);
  const [collectionB] = await rows(db, 'SELECT id FROM collections WHERE organization_id = ?', orgB.json.id);
  const [foreignMember] = await rows(db, 'SELECT id FROM organization_members WHERE organization_id = ?', orgB.json.id);
  return {
    db, env, storage, orgA, orgB: orgB.json.id as string, adminMemberId, memberId,
    collection: defaultCollection.id as string, collectionB: collectionB.id as string, foreignMemberId: foreignMember.id as string,
  };
}

type Ctx = Awaited<ReturnType<typeof setup>>;

// Expected status per actor. Members below the role get 400, never 401/403, which log clients out.
const OWNER_ONLY = { owner: 200, admin: 400, member: 400, outsider: 404, foreign: 404 };
const ADMINS = { owner: 200, admin: 200, member: 400, outsider: 404, foreign: 404 };
const MEMBERS = { owner: 200, admin: 200, member: 200, outsider: 404, foreign: 404 };

const MATRIX: Array<{ name: string; expect: Record<Actor, number>; run: (c: Ctx, a: Actor) => ReturnType<typeof call> }> = [
  { name: 'GET org', expect: OWNER_ONLY, run: (c, a) => call(c.env, a, 'GET', `/api/organizations/${c.orgA}`) },
  { name: 'PUT org', expect: OWNER_ONLY, run: (c, a) => call(c.env, a, 'PUT', `/api/organizations/${c.orgA}`, { name: 'Renamed', billingEmail: 'x@example.test' }) },
  { name: 'DELETE org', expect: OWNER_ONLY, run: (c, a) => call(c.env, a, 'DELETE', `/api/organizations/${c.orgA}`, { masterPasswordHash: PASSWORD }) },
  { name: 'POST leave', expect: { ...MEMBERS, owner: 400 }, run: (c, a) => call(c.env, a, 'POST', `/api/organizations/${c.orgA}/leave`) },
  { name: 'GET public-key', expect: MEMBERS, run: (c, a) => call(c.env, a, 'GET', `/api/organizations/${c.orgA}/public-key`) },
  { name: 'GET keys', expect: MEMBERS, run: (c, a) => call(c.env, a, 'GET', `/api/organizations/${c.orgA}/keys`) },
  { name: 'GET users', expect: ADMINS, run: (c, a) => call(c.env, a, 'GET', `/api/organizations/${c.orgA}/users?includeCollections=true`) },
  { name: 'GET collections', expect: ADMINS, run: (c, a) => call(c.env, a, 'GET', `/api/organizations/${c.orgA}/collections`) },
  { name: 'GET collections/details', expect: ADMINS, run: (c, a) => call(c.env, a, 'GET', `/api/organizations/${c.orgA}/collections/details`) },
  { name: 'POST collection', expect: ADMINS, run: (c, a) => call(c.env, a, 'POST', `/api/organizations/${c.orgA}/collections`, { name: '2.new|a|b', users: [], groups: [] }) },
  { name: 'PUT collection', expect: ADMINS, run: (c, a) => call(c.env, a, 'PUT', `/api/organizations/${c.orgA}/collections/${c.collection}`, { name: '2.ren|a|b', users: [] }) },
  { name: 'DELETE collection', expect: ADMINS, run: (c, a) => call(c.env, a, 'DELETE', `/api/organizations/${c.orgA}/collections/${c.collection}`) },
  { name: 'POST users/invite', expect: ADMINS, run: (c, a) => call(c.env, a, 'POST', `/api/organizations/${c.orgA}/users/invite`, { emails: ['outsider@example.test'], type: 2, collections: [], groups: [] }) },
  { name: 'POST users/{id}/reinvite', expect: ADMINS, run: async (c, a) => call(c.env, a, 'POST', `/api/organizations/${c.orgA}/users/${await addMember(c.db, c.orgA, 'outsider', 2, 0)}/reinvite`) },
  { name: 'POST users/reinvite', expect: ADMINS, run: (c, a) => call(c.env, a, 'POST', `/api/organizations/${c.orgA}/users/reinvite`, { ids: [c.memberId] }) },
  { name: 'POST users/{id}/confirm', expect: ADMINS, run: async (c, a) => call(c.env, a, 'POST', `/api/organizations/${c.orgA}/users/${await addMember(c.db, c.orgA, 'outsider', 2, 1)}/confirm`, { key: '4.k' }) },
  { name: 'POST users/confirm', expect: ADMINS, run: (c, a) => call(c.env, a, 'POST', `/api/organizations/${c.orgA}/users/confirm`, { keys: [{ id: c.memberId, key: '4.k' }] }) },
  { name: 'GET users/{id}', expect: ADMINS, run: (c, a) => call(c.env, a, 'GET', `/api/organizations/${c.orgA}/users/${c.memberId}?includeCollections=true`) },
  { name: 'PUT users/{id}', expect: ADMINS, run: (c, a) => call(c.env, a, 'PUT', `/api/organizations/${c.orgA}/users/${c.memberId}`, { type: 2, collections: [{ id: c.collection }], groups: [] }) },
  { name: 'DELETE users/{id}', expect: ADMINS, run: (c, a) => call(c.env, a, 'DELETE', `/api/organizations/${c.orgA}/users/${c.memberId}`) },
  { name: 'DELETE users', expect: ADMINS, run: (c, a) => call(c.env, a, 'DELETE', `/api/organizations/${c.orgA}/users`, { ids: [c.memberId] }) },
  { name: 'POST users/public-keys', expect: ADMINS, run: (c, a) => call(c.env, a, 'POST', `/api/organizations/${c.orgA}/users/public-keys`, { ids: [c.memberId] }) },
];

for (const route of MATRIX) {
  test(`role matrix: ${route.name}`, async () => {
    for (const actor of ACTORS) {
      const ctx = await setup();
      const res = await route.run(ctx, actor);
      assert.equal(res.status, route.expect[actor], `${route.name} as ${actor}: ${JSON.stringify(res.json)}`);
    }
  });
}

test('a missing organization answers like a foreign one', async () => {
  const c = await setup();
  for (const [method, sub] of [['GET', ''], ['PUT', ''], ['GET', '/users'], ['GET', '/public-key'], ['POST', '/leave'], ['GET', '/collections']]) {
    const res = await call(c.env, 'owner', method, `/api/organizations/${MISSING_ORG}${sub}`, method === 'GET' ? undefined : {});
    assert.equal(res.status, 404, `${method} ${sub}`);
    assert.equal(res.json.error, 'Organization not found');
  }
});

test('unimplemented organization routes stay unmatched', async () => {
  const c = await setup();
  const req = new Request(`https://vault.test/api/organizations/${c.orgA}/policies`);
  assert.equal(await handleAuthenticatedRoute(req, c.env, ID.owner, makeUser('owner'), `/api/organizations/${c.orgA}/policies`, 'GET'), null);
});

test('create returns the organization and makes the caller a confirmed owner with access to all', async () => {
  const c = await setup();
  const org = await call(c.env, 'owner', 'GET', `/api/organizations/${c.orgA}`);
  assert.equal(org.json.object, 'organization');
  assert.equal(org.json.name, 'Org A');
  assert.equal(org.json.billingEmail, 'billing@example.test');
  assert.equal(org.json.hasPublicAndPrivateKeys, true);
  assert.equal(org.json.planType, 6);
  const [owner] = await rows(c.db, 'SELECT * FROM organization_members WHERE organization_id = ? AND user_id = ?', c.orgA, ID.owner);
  assert.deepEqual([owner.type, owner.status, owner.access_all, owner.akey], [0, 2, 1, '4.ownerkey']);
  const pub = await call(c.env, 'member', 'GET', `/api/organizations/${c.orgA}/public-key`);
  assert.deepEqual(pub.json, { object: 'organizationPublicKey', publicKey: 'org-public' });
  assert.equal((await call(c.env, 'owner', 'POST', '/api/organizations', { name: 'x' })).status, 400);
});

test('collections reject ids from another organization', async () => {
  const c = await setup();
  const base = `/api/organizations/${c.orgA}/collections`;
  assert.equal((await call(c.env, 'owner', 'PUT', `${base}/${c.collectionB}`, { name: '2.x|a|b', users: [] })).status, 404);
  assert.equal((await call(c.env, 'owner', 'DELETE', `${base}/${c.collectionB}`)).status, 404);
  const bad = await call(c.env, 'owner', 'POST', base, { name: '2.x|a|b', users: [{ id: c.foreignMemberId, readOnly: false, hidePasswords: false, manage: false }] });
  assert.equal(bad.status, 400);
  assert.equal(bad.json.error, 'Invalid member');
  assert.equal((await call(c.env, 'owner', 'POST', base, { name: '2.x|a|b', groups: [{ id: c.orgB }] })).status, 400);
  assert.equal((await rows(c.db, 'SELECT * FROM collections WHERE organization_id = ?', c.orgB)).length, 1);
});

test('collection access drives sync, /api/collections and the admin views', async () => {
  const c = await setup();
  const created = await call(c.env, 'admin', 'POST', `/api/organizations/${c.orgA}/collections`, {
    name: '2.team|a|b',
    externalId: ' ',
    users: [
      { id: c.memberId, readOnly: true, hidePasswords: true, manage: false },
      { id: c.adminMemberId, readOnly: false, hidePasswords: false, manage: true },
    ],
    groups: [],
  });
  assert.equal(created.status, 200);
  assert.deepEqual(
    { object: created.json.object, readOnly: created.json.readOnly, manage: created.json.manage, externalId: created.json.externalId, organizationId: created.json.organizationId },
    { object: 'collectionDetails', readOnly: false, manage: true, externalId: null, organizationId: c.orgA }
  );

  // The owner has access to all; the member sees only the collection assigned to them.
  const ownerSync = await call(c.env, 'owner', 'GET', '/api/sync');
  assert.equal(ownerSync.json.collections.length, 2);
  const memberSync = await call(c.env, 'member', 'GET', '/api/sync');
  assert.deepEqual(
    memberSync.json.collections.map((col: any) => [col.id, col.object, col.readOnly, col.hidePasswords, col.manage]),
    [[created.json.id, 'collectionDetails', true, true, false]]
  );
  const memberCollections = await call(c.env, 'member', 'GET', '/api/collections');
  assert.deepEqual(memberCollections.json.data.map((col: any) => [col.id, col.object, col.type]), [[created.json.id, 'collection', 0]]);
  assert.deepEqual((await call(c.env, 'outsider', 'GET', '/api/collections')).json.data, []);

  // Updating the collection invalidates the cached sync of every member.
  await call(c.env, 'owner', 'PUT', `/api/organizations/${c.orgA}/collections/${created.json.id}`, { name: '2.team2|a|b', users: [] });
  assert.deepEqual((await call(c.env, 'member', 'GET', '/api/sync')).json.collections, []);
  await call(c.env, 'owner', 'PUT', `/api/organizations/${c.orgA}/collections/${created.json.id}`, {
    name: '2.team2|a|b', users: [{ id: c.memberId, readOnly: false, hidePasswords: false, manage: true }],
  });

  const details = await call(c.env, 'admin', 'GET', `/api/organizations/${c.orgA}/collections/details`);
  const team = details.json.data.find((col: any) => col.id === created.json.id);
  assert.equal(team.object, 'collectionAccessDetails');
  assert.equal(team.assigned, true);
  assert.deepEqual(team.groups, []);
  assert.deepEqual(
    team.users.map((u: any) => [u.id, u.manage]).sort(),
    [[c.memberId, true], [c.adminMemberId, true], [await ownerMemberId(c), true]].sort()
  );

  const users = await call(c.env, 'admin', 'GET', `/api/organizations/${c.orgA}/users?includeCollections=true`);
  assert.equal(users.json.data.length, 3);
  const member = users.json.data.find((u: any) => u.id === c.memberId);
  assert.deepEqual(
    [member.object, member.email, member.type, member.status, member.collections],
    ['organizationUserUserDetails', 'member@example.test', 2, 2, [{ id: created.json.id, readOnly: false, hidePasswords: false, manage: true }]]
  );
  assert.deepEqual(users.json.data.find((u: any) => u.userId === ID.owner).collections, []);

  const list = await call(c.env, 'admin', 'GET', `/api/organizations/${c.orgA}/collections`);
  assert.equal(list.json.data.length, 2);
  assert.equal((await call(c.env, 'admin', 'DELETE', `/api/organizations/${c.orgA}/collections/${created.json.id}`)).status, 200);
  assert.equal((await rows(c.db, 'SELECT * FROM collection_members')).length, 0);
});

async function ownerMemberId(c: Ctx): Promise<string> {
  const [row] = await rows(c.db, 'SELECT id FROM organization_members WHERE organization_id = ? AND user_id = ?', c.orgA, ID.owner);
  return row.id;
}

test('profile and sync list the caller organizations', async () => {
  const c = await setup();
  await addMember(c.db, c.orgB, 'member', 2, 1); // accepted, not confirmed, in org B
  const profile = await call(c.env, 'member', 'GET', '/api/accounts/profile');
  assert.deepEqual(profile.json.organizations.map((o: any) => [o.id, o.status]), [[c.orgA, 2]]);
  assert.deepEqual(profile.json.organizationsNew.map((o: any) => [o.id, o.status]).sort(), [[c.orgA, 2], [c.orgB, 1]].sort());
  const org = profile.json.organizations[0];
  assert.deepEqual(
    [org.object, org.name, org.key, org.type, org.organizationUserId, org.userId, org.enabled, org.permissions.manageUsers, org.hasPublicAndPrivateKeys],
    ['profileOrganization', 'Org A', '4.akey', 2, c.memberId, ID.member, true, false, true]
  );
  assert.equal(org.limitCollectionCreation, true);
  // An accepted member is not confirmed, so no organization route answers it.
  assert.equal((await call(c.env, 'member', 'GET', `/api/organizations/${c.orgB}/public-key`)).status, 404);

  const sync = await call(c.env, 'owner', 'GET', '/api/sync');
  assert.deepEqual(
    sync.json.profile.organizations.map((o: any) => [o.id, o.type, o.key, o.limitCollectionCreation]),
    [[c.orgA, 0, '4.ownerkey', false]]
  );
  assert.equal(sync.json.collections[0].manage, true);

  // A user with no organization gets empty lists, as before.
  const outsider = await call(c.env, 'outsider', 'GET', '/api/sync');
  assert.deepEqual([outsider.json.profile.organizations, outsider.json.profile.organizationsNew, outsider.json.collections], [[], [], []]);
});

test('the last owner cannot leave; a second owner lets them', async () => {
  const c = await setup();
  const leave = await call(c.env, 'owner', 'POST', `/api/organizations/${c.orgA}/leave`);
  assert.equal(leave.status, 400);
  assert.equal(leave.json.error, "The last owner can't leave");
  await c.db.prepare('UPDATE organization_members SET type = 0 WHERE id = ?').bind(c.adminMemberId).run();
  assert.equal((await call(c.env, 'owner', 'POST', `/api/organizations/${c.orgA}/leave`)).status, 200);
  assert.equal((await call(c.env, 'owner', 'GET', `/api/organizations/${c.orgA}`)).status, 404);
  assert.deepEqual((await call(c.env, 'owner', 'GET', '/api/accounts/profile')).json.organizations, []);
});

test('deleting an organization needs the password and cascades', async () => {
  const c = await setup();
  await call(c.env, 'owner', 'PUT', `/api/organizations/${c.orgA}/collections/${c.collection}`, {
    name: '2.c|a|b', users: [{ id: c.memberId, readOnly: true, hidePasswords: false, manage: false }],
  });
  const memberSyncBefore = await call(c.env, 'member', 'GET', '/api/sync');
  assert.equal(memberSyncBefore.json.profile.organizations.length, 1);

  assert.equal((await call(c.env, 'owner', 'DELETE', `/api/organizations/${c.orgA}`, { masterPasswordHash: 'wrong' })).status, 400);
  assert.equal((await call(c.env, 'owner', 'DELETE', `/api/organizations/${c.orgA}`, {})).status, 400);
  assert.equal((await call(c.env, 'owner', 'DELETE', `/api/organizations/${c.orgA}`, { masterPasswordHash: PASSWORD })).status, 200);

  for (const table of ['organization_members', 'collections']) {
    assert.equal((await rows(c.db, `SELECT * FROM ${table} WHERE organization_id = ?`, c.orgA)).length, 0, table);
  }
  assert.equal((await rows(c.db, 'SELECT * FROM collection_members')).length, 0);
  assert.equal((await rows(c.db, 'SELECT * FROM organizations')).length, 1, 'org B survives');
  const memberSyncAfter = await call(c.env, 'member', 'GET', '/api/sync');
  assert.deepEqual([memberSyncAfter.json.profile.organizations, memberSyncAfter.json.collections], [[], []]);
});

test('account deletion refuses the last owner and removes other memberships', async () => {
  const c = await setup();
  const self = await call(c.env, 'owner', 'POST', '/api/accounts/delete', { masterPasswordHash: PASSWORD });
  assert.equal(self.status, 400);
  assert.match(self.json.error, /last owner/);
  const byAdmin = await call(c.env, 'outsider', 'DELETE', `/api/admin/users/${ID.owner}`, { masterPasswordHash: PASSWORD });
  assert.equal(byAdmin.status, 400);
  assert.ok(await c.storage.getUserById(ID.owner), 'owner still exists');

  assert.equal((await call(c.env, 'member', 'POST', '/api/accounts/delete', { masterPasswordHash: PASSWORD })).status, 200);
  assert.equal((await rows(c.db, 'SELECT * FROM organization_members WHERE user_id = ?', ID.member)).length, 0);

  // With a second owner, the first can be deleted.
  await c.db.prepare('UPDATE organization_members SET type = 0 WHERE id = ?').bind(c.adminMemberId).run();
  assert.equal((await call(c.env, 'outsider', 'DELETE', `/api/admin/users/${ID.owner}`, { masterPasswordHash: PASSWORD })).status, 204);
  assert.equal((await rows(c.db, 'SELECT * FROM organization_members WHERE organization_id = ?', c.orgA)).length, 1);
});

const ORG_TABLES = {
  organizations: 'SELECT * FROM organizations ORDER BY id',
  organization_members: 'SELECT * FROM organization_members ORDER BY id',
  collections: 'SELECT * FROM collections ORDER BY id',
  collection_members: 'SELECT * FROM collection_members ORDER BY collection_id, member_id',
};

test('backup export and restore round-trip organizations', async () => {
  const c = await setup();
  await call(c.env, 'owner', 'POST', `/api/organizations/${c.orgA}/users/invite`, { emails: ['outsider@example.test'], type: 2 });
  await call(c.env, 'owner', 'PUT', `/api/organizations/${c.orgA}/collections/${c.collection}`, {
    name: '2.c|a|b', users: [{ id: c.memberId, readOnly: true, hidePasswords: true, manage: false }],
  });
  const archive = await buildBackupArchive(c.env);

  const target = await newDb();
  await importBackupArchiveBytes(archive.bytes, target.env, ID.owner, false);
  for (const [table, sql] of Object.entries(ORG_TABLES)) {
    const before = await rows(c.db, sql);
    assert.ok(before.length > 0, `${table} has rows`);
    assert.deepEqual(await rows(target.db, sql), before, table);
  }

  // Restoring an archive without organizations over this instance clears them.
  const files = unzipSync(archive.bytes);
  const db = JSON.parse(new TextDecoder().decode(files['db.json']));
  for (const table of Object.keys(ORG_TABLES)) delete db[table];
  files['db.json'] = new TextEncoder().encode(JSON.stringify(db));
  await importBackupArchiveBytes(zipSync(files), target.env, ID.owner, true);
  for (const sql of Object.values(ORG_TABLES)) assert.deepEqual(await rows(target.db, sql), []);
  assert.equal((await rows(target.db, 'SELECT * FROM users')).length, ACTORS.length);
});

const users = (c: Ctx) => `/api/organizations/${c.orgA}/users`;
const memberRow = async (c: Ctx, actor: Actor) =>
  (await rows(c.db, 'SELECT * FROM organization_members WHERE organization_id = ? AND user_id = ?', c.orgA, ID[actor]))[0];

test('invite, accept and confirm an existing account', async () => {
  const c = await setup();
  const invited = await call(c.env, 'admin', 'POST', `${users(c)}/invite`, {
    emails: [' Outsider@Example.test '], type: '2', collections: [{ id: c.collection, readOnly: true, hidePasswords: false, manage: false }], groups: [],
  });
  assert.equal(invited.status, 200, JSON.stringify(invited.json));
  const row = await memberRow(c, 'outsider');
  assert.deepEqual([row.status, row.type, row.access_all, row.akey], [0, 2, 0, '']);
  const access = await rows(c.db, 'SELECT collection_id, read_only FROM collection_members WHERE member_id = ?', row.id);
  assert.deepEqual(access.map((a: any) => [a.collection_id, a.read_only]), [[c.collection, 1]]);

  // An invited member sees nothing of the organization yet.
  assert.deepEqual((await call(c.env, 'outsider', 'GET', '/api/accounts/profile')).json.organizationsNew, []);
  assert.equal((await call(c.env, 'outsider', 'GET', `/api/organizations/${c.orgA}/public-key`)).status, 404);
  assert.equal((await call(c.env, 'owner', 'POST', `${users(c)}/${row.id}/reinvite`)).status, 200);

  // Confirming needs an accepted member.
  const early = await call(c.env, 'owner', 'POST', `${users(c)}/${row.id}/confirm`, { key: '4.k' });
  assert.deepEqual([early.status, early.json.error], [400, 'User in invalid state']);

  // Only the invited account can accept; anyone else gets the 404 of a missing organization.
  for (const actor of ['member', 'owner', 'foreign'] as Actor[]) {
    assert.equal((await call(c.env, actor, 'POST', `${users(c)}/${row.id}/accept`, { token: 'x' })).status, 404, actor);
  }
  assert.equal((await call(c.env, 'outsider', 'POST', `/api/organizations/${c.orgB}/users/${row.id}/accept`, { token: 'x' })).status, 404);
  assert.equal((await call(c.env, 'outsider', 'POST', `${users(c)}/${row.id}/accept`, { token: 'x' })).status, 200);
  const again = await call(c.env, 'outsider', 'POST', `${users(c)}/${row.id}/accept`, { token: 'x' });
  assert.deepEqual([again.status, again.json.error], [400, 'User already accepted the invitation']);
  assert.deepEqual((await call(c.env, 'outsider', 'GET', '/api/accounts/profile')).json.organizationsNew.map((o: any) => [o.id, o.status]), [[c.orgA, 1]]);
  assert.equal((await call(c.env, 'outsider', 'GET', `/api/organizations/${c.orgA}/public-key`)).status, 404, 'accepted is not confirmed');
  const reinvite = await call(c.env, 'owner', 'POST', `${users(c)}/${row.id}/reinvite`);
  assert.deepEqual([reinvite.status, reinvite.json.error], [400, 'The user is already accepted or confirmed to the organization']);

  // The admin wraps the organization key with the invitee's public key, then confirms.
  const keys = await call(c.env, 'admin', 'POST', `${users(c)}/public-keys`, { ids: [row.id, c.foreignMemberId] });
  assert.deepEqual(keys.json.data, [{ object: 'organizationUserPublicKeyResponseModel', id: row.id, userId: ID.outsider, key: 'pub-outsider' }]);
  assert.equal((await call(c.env, 'admin', 'POST', `${users(c)}/${row.id}/confirm`, {})).status, 400);
  assert.deepEqual((await call(c.env, 'outsider', 'GET', '/api/sync')).json.collections, []);
  assert.equal((await call(c.env, 'admin', 'POST', `${users(c)}/${row.id}/confirm`, { key: '4.wrapped' })).status, 200);
  assert.equal((await call(c.env, 'admin', 'POST', `${users(c)}/${row.id}/confirm`, { key: '4.other' })).status, 400, 'confirm is not repeatable');

  const sync = await call(c.env, 'outsider', 'GET', '/api/sync');
  assert.deepEqual(sync.json.profile.organizations.map((o: any) => [o.id, o.status, o.key, o.type]), [[c.orgA, 2, '4.wrapped', 2]]);
  assert.deepEqual(sync.json.collections.map((col: any) => [col.id, col.readOnly]), [[c.collection, true]]);
  assert.equal((await call(c.env, 'outsider', 'GET', `/api/organizations/${c.orgA}/public-key`)).status, 200);
});

test('bulk confirm reports each member', async () => {
  const c = await setup();
  const accepted = await addMember(c.db, c.orgA, 'outsider', 2, 1);
  const res = await call(c.env, 'owner', 'POST', `${users(c)}/confirm`, {
    keys: [{ id: accepted, key: '4.k' }, { id: c.memberId, key: '4.k' }, { id: c.foreignMemberId, key: '4.k' }],
  });
  assert.deepEqual(res.json.data.map((r: any) => [r.id, r.error]), [
    [accepted, ''],
    [c.memberId, 'User in invalid state'],
    [c.foreignMemberId, "The specified user isn't a member of the organization"],
  ]);
  assert.equal((await rows(c.db, 'SELECT akey FROM organization_members WHERE id = ?', c.foreignMemberId))[0].akey, '4.bkey');
});

test('invites are checked before anything is written', async () => {
  const c = await setup();
  const before = (await rows(c.db, 'SELECT * FROM organization_members')).length;
  const cases: Array<[Actor, unknown, string]> = [
    ['owner', { emails: ['outsider@example.test', 'nobody@example.test'], type: 2 }, 'User does not exist: nobody@example.test'],
    ['owner', { emails: ['outsider@example.test', 'member@example.test'], type: 2 }, 'User already in organization: member@example.test'],
    ['owner', { emails: [], type: 2 }, 'At least one email is required'],
    ['owner', { emails: ['outsider@example.test'], type: 4 }, 'Invalid type'],
    ['owner', { emails: ['outsider@example.test'], type: 3 }, 'Invalid type'],
    ['owner', { emails: ['outsider@example.test'], type: 2, collections: [{ id: c.collectionB }] }, 'Collection not found in Organization'],
    ['owner', { emails: ['outsider@example.test'], type: 2, groups: ['g'] }, 'Invalid group'],
    ['admin', { emails: ['outsider@example.test'], type: 0 }, 'Only Owners can manage Owners'],
  ];
  for (const [actor, body, error] of cases) {
    const res = await call(c.env, actor, 'POST', `${users(c)}/invite`, body);
    assert.deepEqual([res.status, res.json.error], [400, error], JSON.stringify(body));
  }
  assert.equal((await rows(c.db, 'SELECT * FROM organization_members')).length, before);

  // Owners and admins get every collection, so their collection list is ignored.
  assert.equal((await call(c.env, 'owner', 'POST', `${users(c)}/invite`, { emails: ['outsider@example.test'], type: 0, collections: [{ id: c.collection }] })).status, 200);
  const row = await memberRow(c, 'outsider');
  assert.deepEqual([row.type, row.access_all, row.status], [0, 1, 0]);
  assert.equal((await rows(c.db, 'SELECT * FROM collection_members WHERE member_id = ?', row.id)).length, 0);
});

test('role and collection changes', async () => {
  const c = await setup();
  const owner = await ownerMemberId(c);
  const put = (actor: Actor, id: string, body: unknown) => call(c.env, actor, 'PUT', `${users(c)}/${id}`, body);
  const expectError = async (res: ReturnType<typeof call>, error: string) => {
    const r = await res;
    assert.deepEqual([r.status, r.json?.error], [400, error]);
  };

  await expectError(put('admin', owner, { type: 0 }), 'Only Owners can manage Owners');
  await expectError(put('admin', c.memberId, { type: 0 }), 'Only Owners can manage Owners');
  await expectError(put('owner', c.foreignMemberId, { type: 2 }), "The specified user isn't member of the organization");
  await expectError(put('owner', c.memberId, { type: 2, collections: [{ id: c.collectionB }] }), 'Collection not found in Organization');
  await expectError(put('owner', owner, { type: 1 }), "Can't delete the last owner");
  await expectError(put('admin', c.adminMemberId, { type: 2 }), 'You cannot change your own role');

  // Users get the collections in the request; promoting to admin grants all and drops them.
  // A repeated collection keeps its last entry.
  assert.equal((await put('admin', c.memberId, { type: 2, collections: [{ id: c.collection }, { id: c.collection.toUpperCase(), hidePasswords: true }] })).status, 200);
  assert.equal((await call(c.env, 'member', 'GET', '/api/sync')).json.collections[0].hidePasswords, true);
  const detail = await call(c.env, 'admin', 'GET', `${users(c)}/${c.memberId}?includeCollections=true`);
  assert.deepEqual([detail.json.object, detail.json.type, detail.json.collections], [
    'organizationUserDetails', 2, [{ id: c.collection, readOnly: false, hidePasswords: true, manage: false }],
  ]);
  assert.equal((await call(c.env, 'admin', 'GET', `${users(c)}/${c.foreignMemberId}`)).status, 400);
  assert.equal((await put('owner', c.memberId, { type: 1, collections: [{ id: c.collection }] })).status, 200);
  const promoted = await memberRow(c, 'member');
  assert.deepEqual([promoted.type, promoted.access_all], [1, 1]);
  assert.equal((await rows(c.db, 'SELECT * FROM collection_members WHERE member_id = ?', c.memberId)).length, 0);

  // With a second confirmed owner, an owner can be demoted, but never by themselves.
  assert.equal((await put('owner', c.adminMemberId, { type: 0 })).status, 200);
  await expectError(put('owner', owner, { type: 2 }), 'You cannot change your own role');
  assert.equal((await put('admin', owner, { type: 2 })).status, 200, 'the promoted admin is an owner now');
  const demoted = await memberRow(c, 'owner');
  assert.deepEqual([demoted.type, demoted.access_all], [2, 0]);
});

test('removing members', async () => {
  const c = await setup();
  const owner = await ownerMemberId(c);
  await call(c.env, 'owner', 'PUT', `/api/organizations/${c.orgA}/collections/${c.collection}`, { name: '2.c|a|b', users: [{ id: c.memberId }] });
  assert.equal((await call(c.env, 'member', 'GET', '/api/sync')).json.profile.organizations.length, 1);

  const self = await call(c.env, 'owner', 'DELETE', `${users(c)}/${owner}`);
  assert.deepEqual([self.status, self.json.error], [400, 'You cannot remove yourself']);
  assert.equal((await call(c.env, 'admin', 'DELETE', `${users(c)}/${owner}`)).json.error, 'Only Owners can manage Owners');
  assert.equal((await call(c.env, 'owner', 'DELETE', `${users(c)}/${c.foreignMemberId}`)).status, 400);
  assert.equal((await rows(c.db, 'SELECT * FROM organization_members WHERE id = ?', c.foreignMemberId)).length, 1);

  const bulk = await call(c.env, 'admin', 'DELETE', users(c), { ids: [c.memberId, owner] });
  assert.deepEqual(bulk.json.data.map((r: any) => [r.id, r.error]), [[c.memberId, ''], [owner, 'Only Owners can manage Owners']]);
  assert.equal((await rows(c.db, 'SELECT * FROM collection_members')).length, 0);
  const sync = await call(c.env, 'member', 'GET', '/api/sync');
  assert.deepEqual([sync.json.profile.organizations, sync.json.collections], [[], []]);
});
