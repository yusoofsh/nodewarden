import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { unzipSync, zipSync } from 'fflate';

import type { Env, User } from '../src/types';
import { StorageService } from '../src/services/storage';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { createPasswordVerifier } from '../src/services/password-verifier';
import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { buildBackupArchive } from '../src/services/backup-archive';
import { importBackupArchiveBytes } from '../src/services/backup-import';
import { pruneEvents } from '../src/services/events';
import { createTestDb } from './lib/d1-sqlite';

// owner and admin manage Org A; user is a plain member with the team collection; outsider has no
// organization; foreign owns Org B.
type Actor = 'owner' | 'admin' | 'user' | 'outsider' | 'foreign';
const ACTORS: Actor[] = ['owner', 'admin', 'user', 'outsider', 'foreign'];
const ID = Object.fromEntries(ACTORS.map((a, i) => [a, `40000000-0000-0000-0000-00000000000${i + 1}`])) as Record<Actor, string>;
const PASSWORD = 'master-hash';
const IP = '203.0.113.9';
const START = '2000-01-01T00:00:00.000Z';
const END = '2100-01-01T00:00:00.000Z';
let verifier: string;

const enc = (label: string) => `2.${Buffer.from(label).toString('base64')}|aXY=|bWFj`;
const login = (label: string, extra: Record<string, unknown> = {}) => ({
  type: 1, name: enc(label), notes: null, favorite: false, folderId: null,
  login: { username: enc(`${label}-user`), password: enc(`${label}-pass`), uris: [] }, ...extra,
});

function makeUser(actor: Actor): User {
  return {
    id: ID[actor], email: `${actor}@example.test`, name: actor, masterPasswordHint: null, masterPasswordHash: verifier,
    key: 'k', privateKey: 'priv', publicKey: `pub-${actor}`, kdfType: 0, kdfIterations: 600000, securityStamp: 'stamp',
    role: 'user', status: 'active', totpSecret: null, totpRecoveryCode: null,
    createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
  } as User;
}

async function call(env: Env, actor: Actor, method: string, path: string, body?: unknown) {
  const user = makeUser(actor);
  const request = new Request(`https://vault.test${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': IP, 'X-NodeWarden-Acting-Device-Id': `device-${actor}-1` },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const url = new URL(request.url);
  const res = await handleAuthenticatedRoute(request, env, user.id, user, url.pathname, method);
  assert.ok(res, `${method} ${path} was not routed`);
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

const rows = async (db: D1Database, sql: string, ...values: unknown[]) => (await db.prepare(sql).bind(...values).all<any>()).results;
const range = (extra = '') => `?start=${START}&end=${END}${extra}`;

async function setup() {
  verifier ??= await createPasswordVerifier(PASSWORD);
  const db = createTestDb();
  await ensureStorageSchema(db);
  const env = { DB: db, JWT_SECRET: 'x'.repeat(40), ATTACHMENTS: { delete: async () => undefined } } as unknown as Env;
  const storage = new StorageService(db);
  for (const actor of ACTORS) await storage.createUser(makeUser(actor));
  await db
    .prepare("INSERT INTO devices(user_id, device_identifier, name, type, created_at, updated_at) VALUES (?, ?, 'cli', 8, 'now', 'now')")
    .bind(ID.owner, 'device-owner-1')
    .run();

  const orgA = (await call(env, 'owner', 'POST', '/api/organizations', {
    name: 'Org A', billingEmail: 'a@example.test', collectionName: enc('default'), key: '4.ownerkey',
  })).json.id as string;
  const orgB = (await call(env, 'foreign', 'POST', '/api/organizations', {
    name: 'Org B', billingEmail: 'b@example.test', collectionName: enc('b'), key: '4.bkey',
  })).json.id as string;
  const addMember = async (actor: Actor, type: number) => {
    const id = crypto.randomUUID();
    await db
      .prepare("INSERT INTO organization_members(id, organization_id, user_id, akey, status, type, access_all, created_at, updated_at) VALUES (?, ?, ?, '4.akey', 2, ?, 0, 'now', 'now')")
      .bind(id, orgA, ID[actor], type)
      .run();
    return id;
  };
  const adminMember = await addMember('admin', 1);
  const userMember = await addMember('user', 2);
  const team = (await call(env, 'owner', 'POST', `/api/organizations/${orgA}/collections`, {
    name: enc('team'), users: [{ id: userMember, readOnly: false, hidePasswords: false, manage: false }],
  })).json.id as string;
  return { db, env, storage, orgA, orgB, team, adminMember, userMember };
}

type Ctx = Awaited<ReturnType<typeof setup>>;

const orgEvents = async (c: Ctx, actor: Actor = 'owner', extra = '') =>
  call(c.env, actor, 'GET', `/api/organizations/${c.orgA}/events${range(extra)}`);
const types = async (c: Ctx) => (await rows(c.db, 'SELECT type FROM events ORDER BY event_date, rowid')).map((r) => r.type);

async function createInTeam(c: Ctx, actor: Actor = 'owner', label = 'shared'): Promise<string> {
  const res = await call(c.env, actor, 'POST', '/api/ciphers/create', { cipher: login(label, { organizationId: c.orgA }), collectionIds: [c.team] });
  assert.equal(res.status, 200, JSON.stringify(res.json));
  return res.json.id;
}

test('organization, member, collection, group and policy changes are recorded with who, where and from what', async () => {
  const c = await setup();
  await c.db.prepare('DELETE FROM events').run();
  const base = `/api/organizations/${c.orgA}`;
  assert.equal((await call(c.env, 'owner', 'PUT', base, { name: 'Org A2', billingEmail: 'a@example.test' })).status, 200);
  const collection = (await call(c.env, 'owner', 'POST', `${base}/collections`, { name: enc('c') })).json.id;
  assert.equal((await call(c.env, 'owner', 'PUT', `${base}/collections/${collection}`, { name: enc('c2') })).status, 200);
  assert.equal((await call(c.env, 'owner', 'DELETE', `${base}/collections/${collection}`)).status, 200);
  const group = (await call(c.env, 'owner', 'POST', `${base}/groups`, { name: 'g', users: [c.userMember] })).json.id;
  assert.equal((await call(c.env, 'owner', 'PUT', `${base}/groups/${group}`, { name: 'g2' })).status, 200);
  assert.equal((await call(c.env, 'owner', 'PUT', `${base}/users/${c.userMember}/groups`, { groupIds: [group] })).status, 200);
  assert.equal((await call(c.env, 'owner', 'DELETE', `${base}/groups/${group}`)).status, 200);
  assert.equal((await call(c.env, 'owner', 'PUT', `${base}/users/${c.userMember}`, { type: 2, collections: [] })).status, 200);
  const policy = (await call(c.env, 'owner', 'PUT', `${base}/policies/1`, { enabled: true, data: { minLength: 12 } })).json;
  assert.equal((await call(c.env, 'owner', 'POST', `${base}/users/invite`, { emails: ['outsider@example.test'], type: 2 })).status, 200);
  const [invited] = await rows(c.db, 'SELECT id FROM organization_members WHERE user_id = ?', ID.outsider);
  assert.equal((await call(c.env, 'outsider', 'POST', `${base}/users/${invited.id}/accept`, {})).status, 200);
  assert.equal((await call(c.env, 'owner', 'POST', `${base}/users/${invited.id}/confirm`, { key: '4.k' })).status, 200);
  assert.equal((await call(c.env, 'outsider', 'POST', `${base}/leave`)).status, 200);
  assert.equal((await call(c.env, 'owner', 'DELETE', `${base}/users/${c.adminMember}`)).status, 200);

  assert.deepEqual(await types(c), [1600, 1300, 1301, 1302, 1400, 1504, 1401, 1504, 1402, 1502, 1700, 1500, 1501, 1516, 1503]);
  const res = await orgEvents(c);
  assert.equal(res.status, 200);
  assert.equal(res.json.object, 'list');
  assert.equal(res.json.continuationToken, null);
  const byType = new Map<number, any>(res.json.data.map((e: any) => [e.type, e]));
  assert.deepEqual(
    [byType.get(1301).collectionId, byType.get(1401).groupId, byType.get(1700).policyId, byType.get(1502).organizationUserId, byType.get(1502).userId],
    [collection, group, policy.id, c.userMember, ID.user]
  );
  // The owner's acting device is registered as type 8; the outsider has no device row.
  const owner = byType.get(1600);
  assert.deepEqual(
    [owner.object, owner.organizationId, owner.actingUserId, owner.ipAddress, owner.deviceType],
    ['event', c.orgA, ID.owner, IP, 8]
  );
  assert.deepEqual([byType.get(1516).actingUserId, byType.get(1516).deviceType], [ID.outsider, null]);
});

test('organization cipher changes are recorded; personal ciphers are not', async () => {
  const c = await setup();
  await c.db.prepare('DELETE FROM events').run();
  const id = await createInTeam(c);
  const cipher = (await call(c.env, 'owner', 'GET', `/api/ciphers/${id}`)).json;
  assert.equal((await call(c.env, 'owner', 'PUT', `/api/ciphers/${id}`, { ...cipher, name: enc('renamed') })).status, 200);
  assert.equal((await call(c.env, 'owner', 'PUT', `/api/ciphers/${id}/collections_v2`, { collectionIds: [] })).status, 200);
  assert.equal((await call(c.env, 'owner', 'PUT', `/api/ciphers/${id}/delete`)).status, 200);
  assert.equal((await call(c.env, 'owner', 'PUT', `/api/ciphers/${id}/restore`)).status, 200);
  assert.equal((await call(c.env, 'owner', 'PUT', '/api/ciphers/delete', { ids: [id] })).status, 204);
  assert.equal((await call(c.env, 'owner', 'PUT', '/api/ciphers/restore', { ids: [id] })).status, 200);
  const personal = (await call(c.env, 'owner', 'POST', '/api/ciphers', login('p'))).json;
  const shared = (await call(c.env, 'owner', 'PUT', `/api/ciphers/${personal.id}/share`, {
    cipher: { ...personal, organizationId: c.orgA }, collectionIds: [c.team],
  }));
  assert.equal(shared.status, 200, JSON.stringify(shared.json));
  assert.equal((await call(c.env, 'owner', 'POST', '/api/ciphers/delete-permanent', { ids: [personal.id] })).status, 204);
  assert.equal((await call(c.env, 'owner', 'DELETE', `/api/ciphers/${id}`)).status, 200);
  assert.equal((await call(c.env, 'owner', 'DELETE', `/api/ciphers/${id}`)).status, 204);
  const other = (await call(c.env, 'owner', 'POST', '/api/ciphers', login('other'))).json.id;
  await call(c.env, 'owner', 'PUT', `/api/ciphers/${other}/delete`);

  assert.deepEqual(await types(c), [1100, 1101, 1106, 1115, 1116, 1115, 1116, 1105, 1102, 1115, 1102]);
  assert.deepEqual(
    (await rows(c.db, 'SELECT DISTINCT cipher_id FROM events ORDER BY cipher_id')).map((r) => r.cipher_id),
    [id, personal.id].sort()
  );

  // The cipher route shows a deleted cipher's history only while the row exists; a live one shows its own.
  const live = await createInTeam(c, 'owner', 'live');
  const res = await call(c.env, 'admin', 'GET', `/api/ciphers/${live.toUpperCase()}/events${range()}`);
  assert.deepEqual(res.json.data.map((e: any) => [e.type, e.cipherId]), [[1100, live]]);
});

test('event routes are for owners and admins; the cipher route answers others with an empty list', async () => {
  const c = await setup();
  const id = await createInTeam(c);
  assert.equal((await orgEvents(c, 'admin')).status, 200);
  assert.equal((await orgEvents(c, 'user')).status, 400);
  assert.equal((await orgEvents(c, 'outsider')).status, 404);
  assert.equal((await call(c.env, 'user', 'GET', `/api/organizations/${c.orgA}/users/${c.userMember}/events${range()}`)).status, 400);
  assert.equal((await call(c.env, 'foreign', 'GET', `/api/organizations/${c.orgA}/events${range()}`)).status, 404);
  for (const actor of ['user', 'outsider', 'foreign'] as const) {
    const res = await call(c.env, actor, 'GET', `/api/ciphers/${id}/events${range()}`);
    assert.deepEqual([res.status, res.json.data], [200, []], actor);
  }
  const personal = (await call(c.env, 'owner', 'POST', '/api/ciphers', login('p'))).json.id;
  assert.deepEqual((await call(c.env, 'owner', 'GET', `/api/ciphers/${personal}/events${range()}`)).json.data, []);
  assert.equal((await call(c.env, 'owner', 'GET', `/api/organizations/${c.orgA}/events?start=nope&end=${END}`)).status, 400);
  assert.equal((await call(c.env, 'owner', 'GET', `/api/organizations/${c.orgA}/events?start=${START}`)).status, 400);
  // Clients only show and collect events for an organization that uses them.
  assert.equal((await call(c.env, 'owner', 'GET', `/api/organizations/${c.orgA}`)).json.useEvents, true);
});

test('member events are the member own events and the ones they caused', async () => {
  const c = await setup();
  await c.db.prepare('DELETE FROM events').run();
  const base = `/api/organizations/${c.orgA}`;
  await createInTeam(c, 'user', 'mine');
  await call(c.env, 'owner', 'PUT', `${base}/users/${c.userMember}`, { type: 2, collections: [] });
  await call(c.env, 'owner', 'POST', `${base}/collections`, { name: enc('x') });
  const res = await call(c.env, 'admin', 'GET', `${base}/users/${c.userMember}/events${range()}`);
  assert.deepEqual(res.json.data.map((e: any) => e.type).sort(), [1100, 1502]);
  const unknown = await call(c.env, 'admin', 'GET', `${base}/users/${crypto.randomUUID()}/events${range()}`);
  assert.deepEqual([unknown.status, unknown.json.data], [200, []]);
});

test('pages of 30 continue through events that share one date without repeating or skipping', async () => {
  const c = await setup();
  await c.db.prepare('DELETE FROM events').run();
  const date = '2026-06-01T00:00:00.000Z';
  for (let i = 0; i < 65; i++) {
    await c.db
      .prepare('INSERT INTO events(id, type, organization_id, event_date) VALUES (?, 1600, ?, ?)')
      .bind(`e-${String(i).padStart(3, '0')}`, c.orgA, date)
      .run();
  }
  await c.db.prepare("INSERT INTO events(id, type, organization_id, event_date) VALUES ('early', 1600, ?, '2020-01-01T00:00:00.000Z')").bind(c.orgA).run();
  await c.db.prepare("INSERT INTO events(id, type, organization_id, event_date) VALUES ('late', 1600, ?, '2027-01-01T00:00:00.000Z')").bind(c.orgA).run();
  await c.db.prepare("INSERT INTO events(id, type, organization_id, event_date) VALUES ('other', 1600, ?, ?)").bind(c.orgB, date).run();

  const seen: number[] = [];
  const ids: string[] = [];
  let token: string | null = null;
  let pages = 0;
  do {
    const query = `?start=2026-01-01T00:00:00Z&end=2026-12-31T00:00:00Z${token ? `&continuationToken=${encodeURIComponent(token)}` : ''}`;
    const res = await call(c.env, 'owner', 'GET', `/api/organizations/${c.orgA}/events${query}`);
    assert.equal(res.status, 200);
    seen.push(res.json.data.length);
    for (const e of res.json.data) ids.push(e.date === date ? 'same-date' : e.date);
    token = res.json.continuationToken;
    pages++;
  } while (token && pages < 10);
  assert.deepEqual(seen, [30, 30, 5]);
  assert.deepEqual(ids, Array(65).fill('same-date'), 'only the in-range events of this organization');
});

test('collected client events are kept only for ciphers and organizations the caller can reach', async () => {
  const c = await setup();
  const id = await createInTeam(c);
  const foreignCipher = (await call(c.env, 'foreign', 'POST', '/api/ciphers/create', {
    cipher: login('b', { organizationId: c.orgB }), collectionIds: [],
  })).json.id;
  const personal = (await call(c.env, 'user', 'POST', '/api/ciphers', login('p'))).json.id;
  await c.db.prepare('DELETE FROM events').run();
  const date = '2026-05-05T05:05:05.000Z';
  const res = await call(c.env, 'user', 'POST', '/events/collect', [
    { type: 1107, cipherId: id, date },
    { type: 1111, cipherId: id.toUpperCase(), date },
    { type: 1107, cipherId: foreignCipher, date },
    { type: 1107, cipherId: personal, date },
    { type: 1100, cipherId: id, date },
    { type: 1602, organizationId: c.orgA, date },
    { type: 1602, organizationId: c.orgB, date },
    { type: 1007, date },
    { type: 1522, organizationId: c.orgA, date },
  ]);
  assert.equal(res.status, 200);
  assert.deepEqual(
    (await rows(c.db, 'SELECT type, organization_id, cipher_id, member_id, acting_user_id, event_date FROM events ORDER BY type')).map((r) => ({ ...r })),
    [
      { type: 1007, organization_id: c.orgA, cipher_id: null, member_id: c.userMember, acting_user_id: ID.user, event_date: date },
      { type: 1107, organization_id: c.orgA, cipher_id: id, member_id: null, acting_user_id: ID.user, event_date: date },
      { type: 1111, organization_id: c.orgA, cipher_id: id, member_id: null, acting_user_id: ID.user, event_date: date },
      { type: 1522, organization_id: c.orgA, cipher_id: null, member_id: c.userMember, acting_user_id: ID.user, event_date: date },
      { type: 1602, organization_id: c.orgA, cipher_id: null, member_id: null, acting_user_id: ID.user, event_date: date },
    ]
  );
  assert.equal((await call(c.env, 'user', 'POST', '/events/collect', [{ type: 1107, cipherId: id, date: 'nope' }])).status, 400);
  assert.equal((await call(c.env, 'user', 'POST', '/events/collect', { type: 1107 })).status, 400);
});

test('a failed event write never fails the request', async () => {
  const c = await setup();
  await c.db.prepare('DROP TABLE events').run();
  const res = await call(c.env, 'owner', 'POST', `/api/organizations/${c.orgA}/collections`, { name: enc('still') });
  assert.equal(res.status, 200);
  assert.equal((await createInTeam(c)).length, 36);
  assert.equal((await call(c.env, 'user', 'POST', '/events/collect', [{ type: 1602, organizationId: c.orgA, date: START }])).status, 200);
});

test('deleting an organization removes its events; deleting a user keeps the organization history', async () => {
  const c = await setup();
  await createInTeam(c, 'user', 'u');
  const count = async (org: string) => (await rows(c.db, 'SELECT COUNT(*) AS n FROM events WHERE organization_id = ?', org))[0].n;
  const before = await count(c.orgA);
  assert.ok(before > 0);
  assert.equal((await call(c.env, 'user', 'POST', '/api/accounts/delete', { masterPasswordHash: PASSWORD })).status, 200);
  assert.equal(await c.storage.getUserById(ID.user), null);
  assert.equal(await count(c.orgA), before);
  assert.equal((await rows(c.db, 'SELECT COUNT(*) AS n FROM events WHERE acting_user_id = ?', ID.user))[0].n, 1);

  await call(c.env, 'foreign', 'PUT', `/api/organizations/${c.orgB}`, { name: 'B2', billingEmail: 'b@example.test' });
  assert.ok((await count(c.orgB)) > 0);
  assert.equal((await call(c.env, 'foreign', 'DELETE', `/api/organizations/${c.orgB}`, { masterPasswordHash: PASSWORD })).status, 200);
  assert.equal(await count(c.orgB), 0);
  assert.equal(await count(c.orgA), before);
});

test('retention deletes events older than EVENTS_DAYS_RETAIN, 365 days by default, and 0 keeps them', async () => {
  const c = await setup();
  await c.db.prepare('DELETE FROM events').run();
  const now = Date.parse('2026-11-23T00:00:00.000Z');
  const insert = (id: string, daysAgo: number) =>
    c.db.prepare('INSERT INTO events(id, type, organization_id, event_date) VALUES (?, 1600, ?, ?)')
      .bind(id, c.orgA, new Date(now - daysAgo * 86_400_000).toISOString()).run();
  await insert('old', 400);
  await insert('month', 30);
  await insert('new', 1);
  const ids = async () => (await rows(c.db, 'SELECT id FROM events ORDER BY id')).map((r) => r.id);
  assert.equal(await pruneEvents({ ...c.env, EVENTS_DAYS_RETAIN: '0' }, now), 0);
  assert.deepEqual(await ids(), ['month', 'new', 'old']);
  assert.equal(await pruneEvents(c.env, now), 1);
  assert.deepEqual(await ids(), ['month', 'new']);
  assert.equal(await pruneEvents({ ...c.env, EVENTS_DAYS_RETAIN: '7' }, now), 1);
  assert.deepEqual(await ids(), ['new']);
});

test('backup export leaves events out, and an archive that carries events still restores them', async () => {
  const c = await setup();
  await createInTeam(c);
  const { bytes } = await buildBackupArchive(c.env, new Date('2026-11-23T00:00:00.000Z'), { includeAttachments: false });
  const restore = async (archive: Uint8Array) => {
    const db = createTestDb();
    await ensureStorageSchema(db);
    await importBackupArchiveBytes(archive, { DB: db, JWT_SECRET: 'x'.repeat(40) } as unknown as Env, ID.owner, false);
    return db;
  };
  const sql = 'SELECT * FROM events ORDER BY id';
  const live = await rows(c.db, sql);
  assert.ok(live.length > 0);

  const files = unzipSync(bytes);
  const dbJson = JSON.parse(new TextDecoder().decode(files['db.json']));
  assert.deepEqual(dbJson.events, []);
  const exported = await restore(bytes);
  assert.equal((await rows(exported, 'SELECT COUNT(*) AS n FROM events'))[0].n, 0);
  assert.equal((await rows(exported, 'SELECT COUNT(*) AS n FROM organizations'))[0].n, 2);

  dbJson.events = live;
  files['db.json'] = new TextEncoder().encode(JSON.stringify(dbJson));
  assert.deepEqual(await rows(await restore(zipSync(files)), sql), live);
});

test('upgrading a 2026-11-23-org-ciphers database adds the events table and records into it', async () => {
  const db = createTestDb();
  await db.exec(readFileSync(new URL('./fixtures/schema-2026-11-23-org-ciphers.sql', import.meta.url), 'utf8'));
  await db.prepare("INSERT INTO config(key, value) VALUES ('schema.version', '2026-11-23-org-ciphers')").run();
  const tables = async () => (await rows(db, "SELECT name FROM sqlite_master WHERE type = 'table'")).map((r) => r.name);
  assert.ok(!(await tables()).includes('events'));
  for (let run = 0; run < 2; run++) {
    (StorageService as any).schemaVerified = false;
    await new StorageService(db).initializeDatabase();
  }
  assert.ok((await tables()).includes('events'));
  assert.equal((await rows(db, "SELECT value FROM config WHERE key = 'schema.version'"))[0].value, '2026-11-23-events');

  verifier ??= await createPasswordVerifier(PASSWORD);
  const env = { DB: db, JWT_SECRET: 'x'.repeat(40) } as unknown as Env;
  await new StorageService(db).createUser(makeUser('owner'));
  const org = (await call(env, 'owner', 'POST', '/api/organizations', {
    name: 'Org', billingEmail: 'o@example.test', collectionName: enc('d'), key: '4.k',
  })).json.id;
  assert.equal((await call(env, 'owner', 'PUT', `/api/organizations/${org}`, { name: 'Org 2', billingEmail: 'o@example.test' })).status, 200);
  assert.deepEqual((await call(env, 'owner', 'GET', `/api/organizations/${org}/events${range()}`)).json.data.map((e: any) => e.type), [1600]);
});
