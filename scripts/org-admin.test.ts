// Organization admin routes: member revoke and restore, bulk collection routes, organization
// cipher import, export and bulk collections, keys, API key, account recovery and the static routes.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';

import type { Env, User } from '../src/types';
import { STORAGE_SCHEMA_VERSION, StorageService } from '../src/services/storage';
import { AuthService } from '../src/services/auth';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { createPasswordVerifier } from '../src/services/password-verifier';
import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { buildBackupArchive } from '../src/services/backup-archive';
import { importBackupArchiveBytes } from '../src/services/backup-import';
import { createTestDb } from './lib/d1-sqlite';

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
const enc = (label: string) => `2.${Buffer.from(label).toString('base64')}|aXY=|bWFj`;
let verifier: string;

function makeUser(actor: Actor): User {
  return {
    id: ID[actor], email: `${actor}@example.test`, name: actor, masterPasswordHint: null, masterPasswordHash: verifier,
    key: 'k', privateKey: 'priv', publicKey: `pub-${actor}`, kdfType: 0, kdfIterations: 600000, securityStamp: 'stamp',
    role: 'user', status: 'active', totpSecret: null, totpRecoveryCode: null,
    createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
  } as User;
}

async function call(env: Env, actor: Actor, method: string, path: string, body?: unknown) {
  const user = (await new StorageService(env.DB).getUserById(ID[actor])) ?? makeUser(actor);
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

const rows = async (db: D1Database, sql: string, ...values: unknown[]) =>
  (await db.prepare(sql).bind(...values).all<any>()).results.map((r) => ({ ...r }));

async function addMember(db: D1Database, orgId: string, actor: Actor, type: number, status = 2): Promise<string> {
  const id = crypto.randomUUID();
  await db
    .prepare(
      "INSERT INTO organization_members(id, organization_id, user_id, akey, status, type, access_all, created_at, updated_at) VALUES (?, ?, ?, '4.akey', ?, ?, ?, '2026-01-02', '2026-01-02')"
    )
    .bind(id, orgId, ID[actor], status, type, type < 2 ? 1 : 0)
    .run();
  return id;
}

// Org A: owner, admin, member (assigned to the team collection). Org B: foreign owns it.
async function setup() {
  verifier ??= await createPasswordVerifier(PASSWORD);
  const db = createTestDb();
  await ensureStorageSchema(db);
  const env = { DB: db, JWT_SECRET: 'x'.repeat(40) } as unknown as Env;
  const storage = new StorageService(db);
  for (const actor of ACTORS) await storage.createUser(makeUser(actor));
  const orgA = (await call(env, 'owner', 'POST', '/api/organizations', {
    name: 'Org A', billingEmail: 'a@example.test', collectionName: enc('general'), key: '4.ownerkey',
    keys: { encryptedPrivateKey: '2.orgpriv|a|b', publicKey: 'org-public' },
  })).json.id as string;
  const orgB = (await call(env, 'foreign', 'POST', '/api/organizations', {
    name: 'Org B', billingEmail: 'b@example.test', collectionName: enc('b'), key: '4.bkey',
  })).json.id as string;
  const adminMemberId = await addMember(db, orgA, 'admin', 1);
  const memberId = await addMember(db, orgA, 'member', 2);
  const [owner] = await rows(db, 'SELECT id FROM organization_members WHERE organization_id = ? AND user_id = ?', orgA, ID.owner);
  const [general] = await rows(db, 'SELECT id FROM collections WHERE organization_id = ?', orgA);
  const [collectionB] = await rows(db, 'SELECT id FROM collections WHERE organization_id = ?', orgB);
  const team = (await call(env, 'owner', 'POST', `/api/organizations/${orgA}/collections`, {
    name: enc('team'), users: [{ id: memberId, readOnly: false, hidePasswords: false, manage: false }],
  })).json.id as string;
  return {
    db, env, storage, orgA, orgB, adminMemberId, memberId, ownerMemberId: owner.id as string,
    general: general.id as string, team, collectionB: collectionB.id as string,
  };
}
type Ctx = Awaited<ReturnType<typeof setup>>;

const login = (label: string, extra: Record<string, unknown> = {}) => ({
  type: 1, name: enc(label), notes: null, favorite: false, folderId: null,
  login: { username: enc(`${label}-user`), password: enc(`${label}-pass`), uris: [] }, ...extra,
});

async function orgCipher(c: Ctx, collectionIds: string[], label = 'item'): Promise<string> {
  const res = await call(c.env, 'owner', 'POST', '/api/ciphers/create', { cipher: login(label, { organizationId: c.orgA }), collectionIds });
  assert.equal(res.status, 200, JSON.stringify(res.json));
  return res.json.id;
}

const enablePolicy = (c: Ctx, data: unknown = { autoEnrollEnabled: false }) =>
  call(c.env, 'owner', 'PUT', `/api/organizations/${c.orgA}/policies/8`, { policy: { enabled: true, data } });

const OWNER_ONLY = { owner: 200, admin: 400, member: 400, outsider: 404, foreign: 404 };
const ADMINS = { owner: 200, admin: 200, member: 400, outsider: 404, foreign: 404 };
const MEMBERS = { owner: 200, admin: 200, member: 200, outsider: 404, foreign: 404 };
const ANYONE = { owner: 200, admin: 200, member: 200, outsider: 200, foreign: 200 };

const MATRIX: Array<{ name: string; expect: Record<Actor, number>; run: (c: Ctx, a: Actor) => ReturnType<typeof call> }> = [
  { name: 'PUT users/{id}/revoke', expect: ADMINS, run: (c, a) => call(c.env, a, 'PUT', `/api/organizations/${c.orgA}/users/${c.memberId}/revoke`) },
  { name: 'PUT users/revoke', expect: ADMINS, run: (c, a) => call(c.env, a, 'PUT', `/api/organizations/${c.orgA}/users/revoke`, { ids: [c.memberId] }) },
  { name: 'PUT users/{id}/restore', expect: ADMINS, run: async (c, a) =>
    call(c.env, a, 'PUT', `/api/organizations/${c.orgA}/users/${await addMember(c.db, c.orgA, 'outsider', 2, -126)}/restore`) },
  { name: 'PUT users/{id}/restore/vnext', expect: ADMINS, run: async (c, a) =>
    call(c.env, a, 'PUT', `/api/organizations/${c.orgA}/users/${await addMember(c.db, c.orgA, 'outsider', 2, -126)}/restore/vnext`, { defaultUserCollectionName: null }) },
  { name: 'PUT users/restore', expect: ADMINS, run: (c, a) => call(c.env, a, 'PUT', `/api/organizations/${c.orgA}/users/restore`, { ids: [c.memberId] }) },
  { name: 'GET users/mini-details', expect: ADMINS, run: (c, a) => call(c.env, a, 'GET', `/api/organizations/${c.orgA}/users/mini-details`) },
  { name: 'GET collections/{id}/details', expect: ADMINS, run: (c, a) => call(c.env, a, 'GET', `/api/organizations/${c.orgA}/collections/${c.team}/details`) },
  { name: 'GET collections/{id}/users', expect: ADMINS, run: (c, a) => call(c.env, a, 'GET', `/api/organizations/${c.orgA}/collections/${c.team}/users`) },
  { name: 'POST collections/bulk-access', expect: ADMINS, run: (c, a) => call(c.env, a, 'POST', `/api/organizations/${c.orgA}/collections/bulk-access`, { collectionIds: [c.team], users: [], groups: [] }) },
  { name: 'DELETE collections', expect: ADMINS, run: (c, a) => call(c.env, a, 'DELETE', `/api/organizations/${c.orgA}/collections`, { ids: [c.team] }) },
  { name: 'GET private-key', expect: ADMINS, run: (c, a) => call(c.env, a, 'GET', `/api/organizations/${c.orgA}/private-key`) },
  { name: 'GET export', expect: ADMINS, run: (c, a) => call(c.env, a, 'GET', `/api/organizations/${c.orgA}/export`) },
  { name: 'POST api-key', expect: OWNER_ONLY, run: (c, a) => call(c.env, a, 'POST', `/api/organizations/${c.orgA}/api-key`, { masterPasswordHash: PASSWORD }) },
  { name: 'POST rotate-api-key', expect: OWNER_ONLY, run: (c, a) => call(c.env, a, 'POST', `/api/organizations/${c.orgA}/rotate-api-key`, { masterPasswordHash: PASSWORD }) },
  { name: 'GET billing warnings', expect: MEMBERS, run: (c, a) => call(c.env, a, 'GET', `/api/organizations/${c.orgA}/billing/vnext/warnings`) },
  { name: 'GET billing metadata', expect: MEMBERS, run: (c, a) => call(c.env, a, 'GET', `/api/organizations/${c.orgA}/billing/vnext/self-host/metadata`) },
  { name: 'GET pending-v2-upgrades', expect: ADMINS, run: (c, a) => call(c.env, a, 'GET', `/api/organizations/${c.orgA}/users/keys/pending-v2-upgrades`) },
  { name: 'POST v2-upgrades', expect: ADMINS, run: (c, a) => call(c.env, a, 'POST', `/api/organizations/${c.orgA}/users/keys/v2-upgrades`, { upgrades: [{ organizationUserId: c.memberId, userKeyId: 'k', accountRecoveryKey: null }] }) },
  { name: 'GET reset-password-details', expect: ADMINS, run: async (c, a) => {
    await enablePolicy(c);
    return call(c.env, a, 'GET', `/api/organizations/${c.orgA}/users/${c.memberId}/reset-password-details`);
  } },
  { name: 'PUT reset-password-enrollment', expect: MEMBERS, run: async (c, a) => {
    await enablePolicy(c);
    return call(c.env, a, 'PUT', `/api/organizations/${c.orgA}/users/${ID[a]}/reset-password-enrollment`, { resetPasswordKey: '4.rk', masterPasswordHash: PASSWORD });
  } },
  { name: 'GET assigned ciphers', expect: MEMBERS, run: (c, a) => call(c.env, a, 'GET', `/api/ciphers/organization-details/assigned?organizationId=${c.orgA}`) },
  { name: 'POST import-organization', expect: MEMBERS, run: (c, a) => call(c.env, a, 'POST', `/api/ciphers/import-organization?organizationId=${c.orgA}`, { ciphers: [], collections: [], collectionRelationships: [] }) },
  { name: 'GET plans', expect: ANYONE, run: (c, a) => call(c.env, a, 'GET', '/api/plans') },
  { name: 'GET auto-enroll-status', expect: ANYONE, run: (c, a) => call(c.env, a, 'GET', `/api/organizations/${c.orgA}/auto-enroll-status`) },
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

test('a revoked member loses the organization until restored to its earlier status', async () => {
  const c = await setup();
  const id = await orgCipher(c, [c.team]);
  assert.ok((await call(c.env, 'member', 'GET', '/api/sync')).json.ciphers.some((x: any) => x.id === id));

  assert.equal((await call(c.env, 'admin', 'PUT', `/api/organizations/${c.orgA}/users/${c.memberId}/revoke`)).status, 200);
  assert.equal((await rows(c.db, 'SELECT status FROM organization_members WHERE id = ?', c.memberId))[0].status, -126);
  const sync = await call(c.env, 'member', 'GET', '/api/sync');
  assert.deepEqual(sync.json.profile.organizations, []);
  assert.deepEqual(sync.json.collections, []);
  assert.ok(!sync.json.ciphers.some((x: any) => x.id === id));
  assert.equal((await call(c.env, 'member', 'GET', `/api/organizations/${c.orgA}/public-key`)).status, 404);
  assert.equal((await call(c.env, 'member', 'GET', `/api/organizations/${c.orgA}/policies/invited-user`)).status, 404);
  assert.equal((await call(c.env, 'member', 'GET', `/api/ciphers/${id}`)).status, 404);
  const listed = await call(c.env, 'admin', 'GET', `/api/organizations/${c.orgA}/users`);
  const row = listed.json.data.find((m: any) => m.id === c.memberId);
  assert.deepEqual([row.status, row.name], [-1, 'member']);
  const mini = await call(c.env, 'admin', 'GET', `/api/organizations/${c.orgA}/users/mini-details`);
  assert.equal(mini.json.data.find((m: any) => m.id === c.memberId).status, -1);

  const again = await call(c.env, 'admin', 'PUT', `/api/organizations/${c.orgA}/users/${c.memberId}/revoke`);
  assert.deepEqual([again.status, again.json.message ?? again.json.error], [400, 'User is already revoked']);
  assert.equal((await call(c.env, 'admin', 'PUT', `/api/organizations/${c.orgA}/users/${c.memberId}/restore`)).status, 200);
  assert.equal((await rows(c.db, 'SELECT status FROM organization_members WHERE id = ?', c.memberId))[0].status, 2);
  assert.ok((await call(c.env, 'member', 'GET', '/api/sync')).json.ciphers.some((x: any) => x.id === id));
  const active = await call(c.env, 'admin', 'PUT', `/api/organizations/${c.orgA}/users/${c.memberId}/restore`);
  assert.equal(active.json.message ?? active.json.error, 'User is already active');

  // An accepted member comes back accepted, an invited one invited.
  const accepted = await addMember(c.db, c.orgA, 'outsider', 2, 1);
  await call(c.env, 'owner', 'PUT', `/api/organizations/${c.orgA}/users/revoke`, { ids: [accepted] });
  assert.equal((await rows(c.db, 'SELECT status FROM organization_members WHERE id = ?', accepted))[0].status, -127);
  const restored = await call(c.env, 'owner', 'PUT', `/api/organizations/${c.orgA}/users/restore`, { ids: [accepted, c.memberId] });
  assert.deepEqual(restored.json.data.map((r: any) => [r.object, r.id, r.error]), [
    ['OrganizationUserBulkResponseModel', accepted, ''],
    ['OrganizationUserBulkResponseModel', c.memberId, 'User is already active'],
  ]);
  assert.equal((await rows(c.db, 'SELECT status FROM organization_members WHERE id = ?', accepted))[0].status, 1);
  assert.deepEqual(
    (await rows(c.db, 'SELECT type FROM events WHERE organization_id = ? AND type IN (1511, 1512) ORDER BY event_date, type', c.orgA)).map((r) => r.type).sort(),
    [1511, 1511, 1512, 1512]
  );
});

// The caller is a confirmed owner whenever the target is one, so the last-owner check cannot trip here;
// it stays as a guard, as in Vaultwarden.
test('revoke refuses self and owners by admins; a revoked owner loses the organization', async () => {
  const c = await setup();
  const err = async (actor: Actor, memberId: string, path = 'revoke') => {
    const res = await call(c.env, actor, 'PUT', `/api/organizations/${c.orgA}/users/${memberId}/${path}`);
    return [res.status, res.json?.message ?? res.json?.error];
  };
  assert.deepEqual(await err('admin', c.adminMemberId), [400, 'You cannot revoke yourself']);
  assert.deepEqual(await err('admin', c.ownerMemberId), [400, 'Only owners can revoke other owners']);
  const second = await addMember(c.db, c.orgA, 'outsider', 0);
  assert.deepEqual(await err('outsider', c.ownerMemberId), [200, undefined]);
  assert.deepEqual(await err('admin', c.ownerMemberId, 'restore'), [400, 'Only owners can restore other owners']);
  assert.deepEqual(await err('owner', second), [404, 'Organization not found']);
  const self = await call(c.env, 'outsider', 'PUT', `/api/organizations/${c.orgA}/users/revoke`, { ids: [second] });
  assert.equal(self.json.data[0].error, 'You cannot revoke yourself');
  assert.deepEqual(await err('outsider', c.ownerMemberId, 'restore'), [200, undefined]);
  assert.deepEqual(await err('owner', second), [200, undefined]);
  assert.deepEqual(await err('outsider', c.ownerMemberId), [404, 'Organization not found']);
});

test('collection details, users, bulk access and bulk delete', async () => {
  const c = await setup();
  const base = `/api/organizations/${c.orgA}/collections`;
  const details = await call(c.env, 'admin', 'GET', `${base}/${c.team}/details`);
  assert.deepEqual([details.json.id, details.json.object, details.json.assigned], [c.team, 'collectionAccessDetails', true]);
  assert.ok(details.json.users.some((u: any) => u.id === c.memberId));
  assert.equal((await call(c.env, 'admin', 'GET', `${base}/${c.collectionB}/details`)).status, 400);
  const users = await call(c.env, 'admin', 'GET', `${base}/${c.team}/users`);
  assert.deepEqual(users.json, [{ id: c.memberId, readOnly: false, hidePasswords: false, manage: false }]);

  const group = (await call(c.env, 'owner', 'POST', `/api/organizations/${c.orgA}/groups`, { name: 'G', collections: [], users: [] })).json.id;
  // Missing or repeated collections are a 404 and write nothing; a foreign member is a 400.
  for (const collectionIds of [[], [c.team, c.team], [c.team, c.collectionB]]) {
    assert.equal((await call(c.env, 'admin', 'POST', `${base}/bulk-access`, { collectionIds, users: [], groups: [] })).status, 404);
  }
  assert.equal((await call(c.env, 'admin', 'POST', `${base}/bulk-access`, { collectionIds: [c.general], users: [{ id: crypto.randomUUID() }], groups: [] })).status, 400);
  const ok = await call(c.env, 'admin', 'POST', `${base}/bulk-access`, {
    collectionIds: [c.general, c.team],
    users: [{ id: c.memberId, readOnly: true, hidePasswords: false, manage: false }, { id: c.adminMemberId, readOnly: true }],
    groups: [{ id: group, readOnly: false, hidePasswords: true, manage: true }],
  });
  assert.equal(ok.status, 200);
  assert.deepEqual(
    await rows(c.db, 'SELECT collection_id, member_id, read_only FROM collection_members ORDER BY collection_id'),
    [[c.general, c.memberId, 1], [c.team, c.memberId, 1]].sort().map(([collection_id, member_id, read_only]) => ({ collection_id, member_id, read_only }))
  );
  assert.equal((await rows(c.db, 'SELECT * FROM collection_groups WHERE group_id = ?', group)).length, 2);
  assert.ok((await call(c.env, 'member', 'GET', '/api/sync')).json.collections.some((x: any) => x.id === c.general));

  const refused = await call(c.env, 'admin', 'DELETE', base, { ids: [c.team, c.collectionB] });
  assert.equal(refused.status, 400);
  assert.equal((await rows(c.db, 'SELECT * FROM collections WHERE organization_id = ?', c.orgA)).length, 2);
  assert.equal((await call(c.env, 'admin', 'DELETE', base, { ids: [c.team, c.general] })).status, 200);
  assert.equal((await rows(c.db, 'SELECT * FROM collections WHERE organization_id = ?', c.orgA)).length, 0);
  assert.equal((await rows(c.db, 'SELECT * FROM events WHERE type = 1302')).length, 2);
});

test('bulk collections adds and removes collections on editable ciphers of the organization', async () => {
  const c = await setup();
  const inTeam = await orgCipher(c, [c.team], 'a');
  const inGeneral = await orgCipher(c, [c.general], 'b');
  const links = async () => (await rows(c.db, 'SELECT cipher_id, collection_id FROM collection_ciphers ORDER BY cipher_id, collection_id')).map((r) => `${r.cipher_id}:${r.collection_id}`);
  const before = await links();

  // The member may not edit the general collection, nor its cipher.
  const refused = await call(c.env, 'member', 'POST', '/api/ciphers/bulk-collections', { organizationId: c.orgA, cipherIds: [inTeam], collectionIds: [c.general], removeCollections: false });
  assert.equal(refused.status, 404);
  assert.equal((await call(c.env, 'outsider', 'POST', '/api/ciphers/bulk-collections', { organizationId: c.orgA, cipherIds: [inTeam], collectionIds: [] })).status, 400);
  assert.equal((await call(c.env, 'member', 'POST', '/api/ciphers/bulk-collections', { organizationId: c.orgA, cipherIds: [inTeam, inGeneral], collectionIds: [c.team], removeCollections: false })).status, 200);
  assert.deepEqual(await links(), before);

  assert.equal((await call(c.env, 'owner', 'POST', '/api/ciphers/bulk-collections', { organizationId: c.orgA, cipherIds: [inTeam, inGeneral], collectionIds: [c.team, c.general] })).status, 200);
  assert.deepEqual(await links(), [`${inTeam}:${c.general}`, `${inTeam}:${c.team}`, `${inGeneral}:${c.general}`, `${inGeneral}:${c.team}`].sort());
  assert.equal((await call(c.env, 'owner', 'POST', '/api/ciphers/bulk-collections', { organizationId: c.orgA, cipherIds: [inTeam], collectionIds: [c.general], removeCollections: true })).status, 200);
  assert.ok(!(await links()).includes(`${inTeam}:${c.general}`));
  // A collection of another organization is never linked.
  assert.equal((await call(c.env, 'owner', 'POST', '/api/ciphers/bulk-collections', { organizationId: c.orgA, cipherIds: [inTeam], collectionIds: [c.collectionB] })).status, 404);
});

test('assigned ciphers and the export follow the caller access', async () => {
  const c = await setup();
  const inTeam = await orgCipher(c, [c.team], 'a');
  const inGeneral = await orgCipher(c, [c.general], 'b');
  const assigned = async (actor: Actor) =>
    (await call(c.env, actor, 'GET', `/api/ciphers/organization-details/assigned?organizationId=${c.orgA}`)).json.data.map((x: any) => x.id).sort();
  assert.deepEqual(await assigned('member'), [inTeam]);
  assert.deepEqual(await assigned('admin'), [inTeam, inGeneral].sort());

  const exported = await call(c.env, 'admin', 'GET', `/api/organizations/${c.orgA}/export`);
  assert.deepEqual(exported.json.collections.map((x: any) => x.id).sort(), [c.general, c.team].sort());
  assert.deepEqual(exported.json.ciphers.map((x: any) => x.id).sort(), [inTeam, inGeneral].sort());
  assert.deepEqual(exported.json.ciphers.find((x: any) => x.id === inTeam).collectionIds, [c.team]);
});

test('organization import creates collections and ciphers, and checks everything before writing', async () => {
  const c = await setup();
  const path = `/api/ciphers/import-organization?organizationId=${c.orgA}`;
  const count = async () => (await rows(c.db, 'SELECT COUNT(*) AS n FROM ciphers WHERE organization_id = ?', c.orgA))[0].n;
  const body = {
    ciphers: [login('one', { organizationId: c.orgB, folderId: crypto.randomUUID(), favorite: true }), login('two')],
    collections: [{ name: enc('new') }, { id: c.team, name: enc('team') }],
    collectionRelationships: [{ key: 0, value: 0 }, { key: 1, value: 1 }, { key: 1, value: 0 }],
  };
  assert.equal((await call(c.env, 'owner', 'POST', path, { ...body, collectionRelationships: [{ key: 2, value: 0 }] })).status, 400);
  const bad = await call(c.env, 'owner', 'POST', path, { ...body, ciphers: [login('one'), { type: 1, name: 'not encrypted' }] });
  assert.equal(bad.status, 400);
  // A member without full access may not create collections, nor import into one they do not manage.
  assert.equal((await call(c.env, 'member', 'POST', path, body)).status, 400);
  assert.equal((await call(c.env, 'member', 'POST', path, { ...body, collections: [{ id: c.team }], collectionRelationships: [{ key: 0, value: 0 }, { key: 1, value: 0 }] })).status, 400);
  assert.equal(await count(), 0);
  assert.equal((await rows(c.db, 'SELECT * FROM collections WHERE organization_id = ?', c.orgA)).length, 2);

  assert.equal((await call(c.env, 'owner', 'POST', path, body)).status, 200);
  assert.equal(await count(), 2);
  const [created] = await rows(c.db, 'SELECT id FROM collections WHERE organization_id = ? AND id NOT IN (?, ?)', c.orgA, c.general, c.team);
  const imported = await rows(c.db, 'SELECT c.id, c.folder_id, c.favorite, c.organization_id FROM ciphers c WHERE organization_id = ? ORDER BY name', c.orgA);
  assert.ok(imported.every((r) => r.folder_id === null && r.favorite === 0 && r.organization_id === c.orgA));
  const links = await rows(c.db, 'SELECT collection_id FROM collection_ciphers ORDER BY collection_id');
  assert.deepEqual(links.map((r) => r.collection_id).sort(), [created.id, created.id, c.team].sort());
  assert.equal((await call(c.env, 'foreign', 'POST', path, body)).status, 404);

  // With manage on a collection, a member may import into it.
  await call(c.env, 'owner', 'PUT', `/api/organizations/${c.orgA}/collections/${c.team}`, { name: enc('team'), users: [{ id: c.memberId, manage: true }] });
  assert.equal((await call(c.env, 'member', 'POST', path, { ciphers: [login('three')], collections: [{ id: c.team }], collectionRelationships: [{ key: 0, value: 0 }] })).status, 200);
  assert.equal(await count(), 3);
});

test('organization keys are set once; the private key goes to admins', async () => {
  const c = await setup();
  const set = await call(c.env, 'admin', 'POST', `/api/organizations/${c.orgA}/keys`, { encryptedPrivateKey: '2.x|y|z', publicKey: 'p' });
  assert.deepEqual([set.status, set.json.message ?? set.json.error], [400, 'Organization Keys already exist']);
  assert.deepEqual((await call(c.env, 'admin', 'GET', `/api/organizations/${c.orgA}/private-key`)).json, { object: 'organizationPrivateKey', privateKey: '2.orgpriv|a|b' });

  const keyless = (await call(c.env, 'owner', 'POST', '/api/organizations', { name: 'K', billingEmail: 'k@example.test', collectionName: enc('k'), key: '4.k' })).json.id;
  assert.equal((await call(c.env, 'owner', 'GET', `/api/organizations/${keyless}`)).json.hasPublicAndPrivateKeys, false);
  const created = await call(c.env, 'owner', 'POST', `/api/organizations/${keyless}/keys`, { encryptedPrivateKey: '2.new|a|b', publicKey: 'new-public' });
  assert.deepEqual(created.json, { object: 'organizationKeys', publicKey: 'new-public', privateKey: '2.new|a|b' });
  assert.equal((await call(c.env, 'owner', 'GET', `/api/organizations/${keyless}`)).json.hasPublicAndPrivateKeys, true);
});

test('the organization API key needs the owner password and rotates', async () => {
  const c = await setup();
  const path = `/api/organizations/${c.orgA}`;
  assert.equal((await call(c.env, 'owner', 'POST', `${path}/api-key`, { masterPasswordHash: 'wrong' })).status, 400);
  assert.equal((await call(c.env, 'owner', 'POST', `${path}/api-key`, {})).status, 400);
  const first = await call(c.env, 'owner', 'POST', `${path}/api-key`, { masterPasswordHash: PASSWORD });
  assert.equal(first.json.object, 'apiKey');
  assert.match(first.json.apiKey, /^[A-Za-z0-9]{30}$/);
  assert.equal((await call(c.env, 'owner', 'POST', `${path}/api-key`, { masterPasswordHash: PASSWORD })).json.apiKey, first.json.apiKey);
  const rotated = await call(c.env, 'owner', 'POST', `${path}/rotate-api-key`, { masterPasswordHash: PASSWORD });
  assert.notEqual(rotated.json.apiKey, first.json.apiKey);
});

test('account recovery: enrollment, details and recovery by an admin', async () => {
  const c = await setup();
  const base = `/api/organizations/${c.orgA}/users`;
  const enroll = (actor: Actor, body: unknown) => call(c.env, actor, 'PUT', `${base}/${ID[actor]}/reset-password-enrollment`, body);
  const message = (res: { json: any }) => res.json?.message ?? res.json?.error;

  assert.equal(message(await enroll('member', { resetPasswordKey: '4.rk', masterPasswordHash: PASSWORD })), 'Policy not found');
  await enablePolicy(c);
  assert.equal(message(await enroll('member', { resetPasswordKey: '4.rk' })), 'No validation provided');
  assert.equal(message(await enroll('member', { resetPasswordKey: '4.rk', masterPasswordHash: 'wrong' })), 'Invalid password');
  assert.equal((await call(c.env, 'member', 'PUT', `${base}/${ID.admin}/reset-password-enrollment`, { resetPasswordKey: '4.rk', masterPasswordHash: PASSWORD })).status, 400);
  assert.equal((await enroll('member', { resetPasswordKey: '4.rk', masterPasswordHash: PASSWORD })).status, 200);
  const profile = await call(c.env, 'member', 'GET', '/api/accounts/profile');
  assert.deepEqual([profile.json.organizations[0].resetPasswordEnrolled, profile.json.organizations[0].useResetPassword], [true, true]);

  // An invitee enrolls while accepting.
  const invited = await addMember(c.db, c.orgA, 'outsider', 2, 0);
  assert.equal((await enroll('outsider', { resetPasswordKey: '4.ork', masterPasswordHash: PASSWORD })).status, 200);
  assert.equal((await rows(c.db, 'SELECT reset_password_key FROM organization_members WHERE id = ?', invited))[0].reset_password_key, '4.ork');

  const details = await call(c.env, 'admin', 'GET', `${base}/${c.memberId}/reset-password-details`);
  assert.deepEqual(details.json, {
    object: 'organizationUserResetPasswordDetails', organizationUserId: c.memberId, kdf: 0, kdfIterations: 600000,
    kdfMemory: null, kdfParallelism: null, masterPasswordSalt: 'member@example.test', resetPasswordKey: '4.rk', encryptedPrivateKey: '2.orgpriv|a|b',
  });
  assert.equal(message(await call(c.env, 'admin', 'GET', `${base}/${c.ownerMemberId}/reset-password-details`)), "No permission to reset this user's password");

  // Recovery: an unenrolled or unconfirmed member is refused; the new password and the 2FA reset apply.
  const recover = (memberId: string, body: unknown, actor: Actor = 'admin') => call(c.env, actor, 'PUT', `${base}/${memberId}/recover-account`, body);
  const newPassword = { resetMasterPassword: true, newMasterPasswordHash: 'new-hash', key: enc('new-user-key') };
  assert.equal(message(await recover(c.adminMemberId, newPassword, 'owner')), 'Password reset not or not correctly enrolled');
  assert.equal(message(await recover(invited, newPassword)), 'Organization user must be confirmed for password reset functionality');
  assert.equal((await recover(c.memberId, { resetMasterPassword: true })).status, 422);
  await c.db.prepare("UPDATE users SET totp_secret = 'secret' WHERE id = ?").bind(ID.member).run();
  await c.storage.saveRefreshToken('member-token', ID.member, Date.now() + 60_000, 'dev');
  assert.equal((await recover(c.memberId, { ...newPassword, resetTwoFactor: true })).status, 200);
  const user = (await c.storage.getUserById(ID.member))!;
  assert.equal(await new AuthService(c.env).verifyPassword('new-hash', user.masterPasswordHash, user.email), true);
  assert.equal(user.key, enc('new-user-key'));
  assert.equal(user.totpSecret, null);
  assert.notEqual(user.securityStamp, 'stamp');
  assert.equal(await c.storage.getRefreshTokenRecord('member-token'), null);
  assert.deepEqual((await rows(c.db, 'SELECT type FROM events WHERE type IN (1506, 1508, 1519) ORDER BY type')).map((r) => r.type), [1506, 1506, 1508, 1519]);

  // Auto-enroll forbids withdrawing; without it, withdrawing clears the key.
  await enablePolicy(c, { autoEnrollEnabled: true });
  assert.equal(message(await enroll('member', { resetPasswordKey: null })), "Reset password can't be withdrawn due to an enterprise policy");
  await enablePolicy(c);
  assert.equal((await enroll('member', { resetPasswordKey: null })).status, 200);
  assert.equal((await rows(c.db, 'SELECT reset_password_key FROM organization_members WHERE id = ?', c.memberId))[0].reset_password_key, null);
});

test('auto-enroll status reads only the caller organizations', async () => {
  const c = await setup();
  const status = (actor: Actor, id: string) => call(c.env, actor, 'GET', `/api/organizations/${id}/auto-enroll-status`);
  assert.deepEqual((await status('member', c.orgA)).json, { id: c.orgA, identifier: c.orgA, resetPasswordEnabled: false });
  await enablePolicy(c, { autoEnrollEnabled: true });
  assert.equal((await status('member', c.orgA)).json.resetPasswordEnabled, true);
  assert.deepEqual((await status('outsider', c.orgA)).json, { id: c.orgA, identifier: c.orgA, resetPasswordEnabled: false });
  assert.deepEqual((await status('outsider', 'some-sso-identifier')).json, { id: 'some-sso-identifier', identifier: 'some-sso-identifier', resetPasswordEnabled: false });
});

test('static routes answer as Vaultwarden does', async () => {
  const c = await setup();
  const plans = await call(c.env, 'member', 'GET', '/api/plans');
  assert.deepEqual(plans.json.data.map((p: any) => [p.object, p.product, p.name]), [['plan', 0, 'Free'], ['plan', 1, 'Free']]);
  assert.deepEqual((await call(c.env, 'member', 'GET', `/api/organizations/${c.orgA}/billing/vnext/warnings`)).json, { freeTrial: null, inactiveSubscription: null, resellerRenewal: null, taxId: null });
  assert.deepEqual((await call(c.env, 'member', 'GET', `/api/organizations/${c.orgA}/billing/vnext/self-host/metadata`)).json, { isOnSecretsManagerStandalone: false, organizationOccupiedSeats: 0 });
  assert.deepEqual((await call(c.env, 'admin', 'GET', `/api/organizations/${c.orgA}/users/keys/pending-v2-upgrades`)).json, { object: 'list', data: [], continuationToken: null });
  const upgrades = `/api/organizations/${c.orgA}/users/keys/v2-upgrades`;
  assert.equal((await call(c.env, 'admin', 'POST', upgrades, { upgrades: [] })).status, 400);
  assert.equal((await call(c.env, 'admin', 'POST', upgrades, { upgrades: [{ organizationUserId: c.memberId }, { organizationUserId: c.memberId }] })).status, 400);
  assert.equal((await call(c.env, 'admin', 'POST', upgrades, { upgrades: [{ organizationUserId: c.ownerMemberId }] })).status, 404);
});

test('backups keep a revoked member revoked and its recovery key, but not the API key', async () => {
  const c = await setup();
  await call(c.env, 'owner', 'PUT', `/api/organizations/${c.orgA}/users/${c.memberId}/revoke`);
  await c.db.prepare("UPDATE organization_members SET reset_password_key = '4.rk' WHERE id = ?").bind(c.adminMemberId).run();
  await call(c.env, 'owner', 'POST', `/api/organizations/${c.orgA}/api-key`, { masterPasswordHash: PASSWORD });
  const archive = await buildBackupArchive(c.env);
  const target = createTestDb();
  await ensureStorageSchema(target);
  const env = { DB: target, JWT_SECRET: 'x'.repeat(40) } as unknown as Env;
  await importBackupArchiveBytes(archive.bytes, env, ID.owner, false);
  const sql = 'SELECT id, status, reset_password_key FROM organization_members WHERE organization_id = ? ORDER BY id';
  assert.deepEqual(await rows(target, sql, c.orgA), await rows(c.db, sql, c.orgA));
  assert.equal((await rows(target, sql, c.orgA)).find((r) => r.id === c.memberId).status, -126);
  assert.deepEqual(await rows(target, 'SELECT api_key FROM organizations WHERE id = ?', c.orgA), [{ api_key: null }]);
});

test('upgrading a 2026-11-23-events database adds the organization API key columns', async () => {
  const db = createTestDb();
  await db.exec(readFileSync(new URL('./fixtures/schema-2026-11-23-events.sql', import.meta.url), 'utf8'));
  await db.prepare("INSERT INTO config(key, value) VALUES ('schema.version', '2026-11-23-events')").run();
  await db.prepare("INSERT INTO organizations(id, name, billing_email, created_at, updated_at) VALUES ('o1', 'o', 'b', '2026-01-01', '2026-01-01')").run();
  const columns = async () => (await rows(db, 'PRAGMA table_info(organizations)')).map((r) => r.name);
  assert.ok(!(await columns()).includes('api_key'));
  for (let run = 0; run < 2; run++) {
    (StorageService as any).schemaVerified = false;
    await new StorageService(db).initializeDatabase();
  }
  assert.ok((await columns()).includes('api_key'));
  assert.ok((await columns()).includes('api_key_revision_date'));
  assert.equal((await rows(db, "SELECT value FROM config WHERE key = 'schema.version'"))[0].value, STORAGE_SCHEMA_VERSION);
  assert.deepEqual(await rows(db, 'SELECT id, api_key FROM organizations'), [{ id: 'o1', api_key: null }]);
});
