// Organization API key login (client_credentials with client_id organization.<id>) and the
// Directory Connector import it unlocks, POST /api/public/organization/import. Every request goes
// through the full router, so the user-token gate is part of what is tested.
import assert from 'node:assert/strict';
import test from 'node:test';

import type { Env, User } from '../src/types';
import { StorageService } from '../src/services/storage';
import { AuthService } from '../src/services/auth';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { createPasswordVerifier } from '../src/services/password-verifier';
import { handleRequest } from '../src/router';
import { buildBackupArchive } from '../src/services/backup-archive';
import { importBackupArchiveBytes } from '../src/services/backup-import';
import { createTestDb } from './lib/d1-sqlite';

const cacheStore = new Map<string, Response>();
(globalThis as any).caches = {
  default: {
    match: async (req: Request) => cacheStore.get(req.url)?.clone() ?? undefined,
    put: async (req: Request, res: Response) => void cacheStore.set(req.url, res.clone()),
  },
  // The per-minute request budgets keep no count here; the D1-backed login lockout still does.
  open: async () => ({ match: async () => undefined, put: async () => undefined }),
};

const PASSWORD = 'master-hash';
const enc = (label: string) => `2.${Buffer.from(label).toString('base64')}|aXY=|bWFj`;
let ipCounter = 0;

function makeUser(name: string, verifier: string, role = 'user'): User {
  return {
    id: crypto.randomUUID(), email: `${name}@example.test`, name, masterPasswordHint: null, masterPasswordHash: verifier,
    key: 'k', privateKey: 'priv', publicKey: `pub-${name}`, kdfType: 0, kdfIterations: 600000, securityStamp: 'stamp',
    role, status: 'active', totpSecret: null, totpRecoveryCode: null,
    createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
  } as User;
}

async function send(env: Env, method: string, path: string, opts: { token?: string; body?: unknown; form?: Record<string, string>; ip?: string } = {}) {
  const headers: Record<string, string> = { 'CF-Connecting-IP': opts.ip ?? `198.51.100.${(ipCounter++ % 200) + 1}` };
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
  let body: string | undefined;
  if (opts.form) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    body = new URLSearchParams(opts.form).toString();
  } else if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(opts.body);
  }
  const res = await handleRequest(new Request(`https://vault.test${path}`, { method, headers, body }), env);
  const text = await res.text();
  let json: any = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = text;
  }
  return { status: res.status, json };
}

const rows = async (db: D1Database, sql: string, ...values: unknown[]) =>
  (await db.prepare(sql).bind(...values).all<any>()).results.map((r) => ({ ...r }));

async function setup() {
  const verifier = await createPasswordVerifier(PASSWORD);
  const db = createTestDb();
  await ensureStorageSchema(db);
  const hub = { idFromName: (name: string) => name, get: () => ({ fetch: async () => new Response('{}') }) };
  const env = { DB: db, JWT_SECRET: 'x'.repeat(40), NOTIFICATIONS_HUB: hub } as unknown as Env;
  const storage = new StorageService(db);
  const users: Record<string, User> = {};
  for (const name of ['owner', 'bob', 'carol', 'alice', 'dave']) {
    users[name] = makeUser(name, verifier, name === 'owner' ? 'admin' : 'user');
    await storage.createUser(users[name]);
  }
  const auth = new AuthService(env);
  const userToken = await auth.generateAccessToken(users.owner);
  const created = await send(env, 'POST', '/api/organizations', {
    token: userToken,
    body: { name: 'Org', billingEmail: 'org@example.test', collectionName: enc('general'), key: '4.ownerkey' },
  });
  assert.equal(created.status, 200, JSON.stringify(created.json));
  const orgId = created.json.id as string;
  const addMember = async (name: string, type: number, status: number, externalId: string | null = null) => {
    const id = crypto.randomUUID();
    await db
      .prepare(
        "INSERT INTO organization_members(id, organization_id, user_id, akey, status, type, access_all, external_id, created_at, updated_at) VALUES (?, ?, ?, '4.k', ?, ?, 0, ?, '2026-01-02', '2026-01-02')"
      )
      .bind(id, orgId, users[name].id, status, type, externalId)
      .run();
    return id;
  };
  const keyRes = await send(env, 'POST', `/api/organizations/${orgId}/api-key`, { token: userToken, body: { masterPasswordHash: PASSWORD } });
  assert.equal(keyRes.status, 200, JSON.stringify(keyRes.json));
  return { db, env, users, userToken, orgId, apiKey: keyRes.json.apiKey as string, addMember };
}
type Ctx = Awaited<ReturnType<typeof setup>>;

const orgLogin = (c: Ctx, extra: Partial<Record<string, string>> = {}, ip?: string) =>
  send(c.env, 'POST', '/identity/connect/token', {
    ip,
    form: { grant_type: 'client_credentials', client_id: `organization.${c.orgId}`, client_secret: c.apiKey, scope: 'api.organization', ...extra } as Record<string, string>,
  });

async function orgToken(c: Ctx): Promise<string> {
  const res = await orgLogin(c);
  assert.equal(res.status, 200, JSON.stringify(res.json));
  return res.json.access_token;
}

const importBody = (extra: Record<string, unknown> = {}) => ({ members: [], groups: [], overwriteExisting: false, largeImport: false, ...extra });

test('organization client_credentials login issues a bearer token with only the organization scope', async () => {
  const c = await setup();
  const res = await orgLogin(c);
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.deepEqual(Object.keys(res.json).sort(), ['access_token', 'expires_in', 'scope', 'token_type']);
  assert.equal(res.json.scope, 'api.organization');
  assert.equal(res.json.token_type, 'Bearer');
  assert.equal(res.json.expires_in, 3600);
});

test('organization login refuses a wrong secret, an unknown organization and crossed scopes alike', async () => {
  const c = await setup();
  const wrong = await orgLogin(c, { client_secret: 'nope' });
  const unknown = await orgLogin(c, { client_id: `organization.${crypto.randomUUID()}` });
  assert.equal(wrong.status, 400);
  assert.equal(unknown.status, 400);
  assert.equal(wrong.json.error_description, unknown.json.error_description);
  assert.equal((await orgLogin(c, { scope: 'api' })).status, 400);
  const userWithOrgScope = await send(c.env, 'POST', '/identity/connect/token', {
    form: { grant_type: 'client_credentials', client_id: `user.${c.users.owner.id}`, client_secret: c.apiKey, scope: 'api.organization' },
  });
  assert.equal(userWithOrgScope.status, 400);
  assert.equal(userWithOrgScope.json.error, 'invalid_request');
});

test('repeated wrong organization secrets lock the client out, and the right secret is then refused too', async () => {
  const c = await setup();
  const ip = '203.0.113.77';
  let last = 0;
  for (let i = 0; i < 12 && last !== 429; i += 1) last = (await orgLogin(c, { client_secret: `bad-${i}` }, ip)).status;
  assert.equal(last, 429);
  assert.equal((await orgLogin(c, {}, ip)).status, 429);
  assert.equal((await orgLogin(c, {}, '203.0.113.78')).status, 200);
});

test('rotating the organization API key ends tokens issued with the old key', async () => {
  const c = await setup();
  const token = await orgToken(c);
  assert.equal((await send(c.env, 'POST', '/api/public/organization/import', { token, body: importBody() })).status, 200);
  const rotated = await send(c.env, 'POST', `/api/organizations/${c.orgId}/rotate-api-key`, { token: c.userToken, body: { masterPasswordHash: PASSWORD } });
  assert.equal(rotated.status, 200);
  assert.equal((await send(c.env, 'POST', '/api/public/organization/import', { token, body: importBody() })).status, 401);
  assert.equal((await orgLogin(c)).status, 400);
  assert.equal((await orgLogin(c, { client_secret: rotated.json.apiKey })).status, 200);
});

test('an organization token is refused on every user route, and a user token on the import', async () => {
  const c = await setup();
  const token = await orgToken(c);
  const routes: Array<[string, string, unknown?]> = [
    ['GET', '/api/sync'],
    ['GET', '/api/accounts/profile'],
    ['GET', '/api/ciphers'],
    ['POST', '/api/ciphers', { type: 1, name: enc('x'), login: {} }],
    ['GET', '/api/folders'],
    ['GET', '/api/organizations'],
    ['GET', `/api/organizations/${c.orgId}/users`],
    ['POST', `/api/organizations/${c.orgId}/users/invite`, { emails: ['alice@example.test'], type: 2, collections: [] }],
    ['POST', `/api/organizations/${c.orgId}/api-key`, { masterPasswordHash: PASSWORD }],
    ['GET', `/api/organizations/${c.orgId}/export`],
    ['GET', '/api/admin/users'],
    ['GET', '/api/admin/logs'],
    ['POST', '/notifications/hub/negotiate'],
  ];
  for (const [method, path, body] of routes) {
    // The same route answers a user token, so the refusal is the token's, not the route's.
    const asUser = await send(c.env, method, path, { token: c.userToken, body });
    assert.notEqual(asUser.status, 401, `${method} ${path} refused the owner's user token`);
    const asOrg = await send(c.env, method, path, { token, body });
    assert.equal(asOrg.status, 401, `${method} ${path} accepted an organization token: ${asOrg.status}`);
  }
  assert.equal((await send(c.env, 'POST', '/api/public/organization/import', { token: c.userToken, body: importBody() })).status, 401);
  assert.equal((await send(c.env, 'POST', '/api/public/organization/import', { body: importBody() })).status, 401);
});

test('the import invites existing accounts, skips unknown emails, revokes, restores and syncs groups', async () => {
  const c = await setup();
  const bobMember = await c.addMember('bob', 2, 2);
  const carolMember = await c.addMember('carol', 2, -126, 'ext-carol');
  const token = await orgToken(c);
  const res = await send(c.env, 'POST', '/api/public/organization/import', {
    token,
    body: importBody({
      members: [
        { email: 'Alice@Example.test', externalId: 'ext-alice', deleted: false },
        { email: 'bob@example.test', externalId: 'ext-bob', deleted: true },
        { email: 'carol@example.test', externalId: 'ext-carol', deleted: false },
        { email: 'owner@example.test', externalId: 'ext-owner', deleted: true },
        { email: 'nobody@example.test', externalId: 'ext-nobody', deleted: false },
      ],
      groups: [{ name: 'Engineering', externalId: 'grp-eng', memberExternalIds: ['ext-alice', 'ext-carol', 'ext-nobody'] }],
    }),
  });
  assert.equal(res.status, 200, JSON.stringify(res.json));

  const members = await rows(c.db, 'SELECT m.id, u.email, m.status, m.type, m.external_id FROM organization_members m JOIN users u ON u.id = m.user_id WHERE m.organization_id = ? ORDER BY u.email', c.orgId);
  const byEmail = Object.fromEntries(members.map((m) => [m.email, m]));
  assert.equal(byEmail['alice@example.test'].status, 0, 'alice is invited');
  assert.equal(byEmail['alice@example.test'].type, 2);
  assert.equal(byEmail['alice@example.test'].external_id, 'ext-alice');
  assert.equal(byEmail['bob@example.test'].status, -126, 'bob is revoked, keeping his confirmed status');
  assert.equal(byEmail['carol@example.test'].status, 2, 'carol is restored');
  assert.equal(byEmail['owner@example.test'].status, 2, 'an owner is never revoked');
  assert.equal(byEmail['owner@example.test'].external_id, 'ext-owner');
  assert.equal(byEmail['nobody@example.test'], undefined);
  assert.equal((await rows(c.db, "SELECT id FROM users WHERE email = 'nobody@example.test'")).length, 0, 'no placeholder account');

  const [group] = await rows(c.db, 'SELECT id, name, external_id FROM organization_groups WHERE organization_id = ?', c.orgId);
  assert.equal(group.name, 'Engineering');
  const groupMembers = (await rows(c.db, 'SELECT member_id FROM group_members WHERE group_id = ?', group.id)).map((r) => r.member_id).sort();
  assert.deepEqual(groupMembers, [byEmail['alice@example.test'].id, carolMember].sort());

  const events = (await rows(c.db, 'SELECT type, member_id, group_id, acting_user_id FROM events WHERE organization_id = ? ORDER BY type', c.orgId))
    .filter((e) => e.type >= 1400);
  assert.deepEqual(events.map((e) => e.type), [1400, 1500, 1511, 1512]);
  assert.ok(events.every((e) => e.acting_user_id === null));
  assert.equal(events.find((e) => e.type === 1511).member_id, bobMember);

  // A second identical sync changes nothing and logs nothing.
  const before = (await rows(c.db, 'SELECT COUNT(*) AS n FROM events')).at(0).n;
  const again = await send(c.env, 'POST', '/api/public/organization/import', {
    token,
    body: importBody({
      members: [
        { email: 'alice@example.test', externalId: 'ext-alice', deleted: false },
        { email: 'bob@example.test', externalId: 'ext-bob', deleted: true },
        { email: 'carol@example.test', externalId: 'ext-carol', deleted: false },
        { email: 'owner@example.test', externalId: 'ext-owner', deleted: true },
      ],
      groups: [{ name: 'Engineering', externalId: 'grp-eng', memberExternalIds: ['ext-alice', 'ext-carol'] }],
    }),
  });
  assert.equal(again.status, 200);
  assert.equal((await rows(c.db, 'SELECT COUNT(*) AS n FROM events')).at(0).n, before);
});

test('an existing group keeps its collection access; the import renames it and replaces its members', async () => {
  const c = await setup();
  const bob = await c.addMember('bob', 2, 2, 'ext-bob');
  const carol = await c.addMember('carol', 2, 2, 'ext-carol');
  const [collection] = await rows(c.db, 'SELECT id FROM collections WHERE organization_id = ?', c.orgId);
  const groupId = crypto.randomUUID();
  await c.db.prepare("INSERT INTO organization_groups(id, organization_id, name, external_id, created_at, updated_at) VALUES (?, ?, 'Old', 'grp-1', 'x', 'x')").bind(groupId, c.orgId).run();
  await c.db.prepare('INSERT INTO collection_groups(collection_id, group_id) VALUES (?, ?)').bind(collection.id, groupId).run();
  await c.db.prepare('INSERT INTO group_members(group_id, member_id) VALUES (?, ?)').bind(groupId, bob).run();

  const token = await orgToken(c);
  const res = await send(c.env, 'POST', '/api/public/organization/import', {
    token,
    body: importBody({ groups: [{ name: 'New', externalId: 'grp-1', memberExternalIds: ['ext-carol', 'ext-carol'] }] }),
  });
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.equal((await rows(c.db, 'SELECT name FROM organization_groups WHERE id = ?', groupId))[0].name, 'New');
  assert.deepEqual((await rows(c.db, 'SELECT member_id FROM group_members WHERE group_id = ?', groupId)).map((r) => r.member_id), [carol]);
  assert.equal((await rows(c.db, 'SELECT * FROM collection_groups WHERE group_id = ?', groupId)).length, 1);
});

test('overwriteExisting removes unlisted members that have an external id, never owners or unlinked members', async () => {
  const c = await setup();
  await c.addMember('bob', 2, 2, 'ext-bob');
  const carol = await c.addMember('carol', 1, 2, 'ext-carol');
  const dave = await c.addMember('dave', 2, 2);
  await c.db.prepare("UPDATE organization_members SET external_id = 'ext-owner' WHERE organization_id = ? AND type = 0").bind(c.orgId).run();
  const token = await orgToken(c);
  const body = importBody({ members: [{ email: 'bob@example.test', externalId: 'ext-bob', deleted: true }] });
  assert.equal((await send(c.env, 'POST', '/api/public/organization/import', { token, body })).status, 200);
  assert.equal((await rows(c.db, 'SELECT id FROM organization_members WHERE id = ?', carol)).length, 1, 'kept without overwriteExisting');

  const res = await send(c.env, 'POST', '/api/public/organization/import', { token, body: { ...body, overwriteExisting: true } });
  assert.equal(res.status, 200);
  const left = (await rows(c.db, 'SELECT m.id, u.email FROM organization_members m JOIN users u ON u.id = m.user_id WHERE m.organization_id = ?', c.orgId))
    .map((r) => r.email).sort();
  assert.deepEqual(left, ['bob@example.test', 'dave@example.test', 'owner@example.test']);
  assert.ok(!left.includes('carol@example.test'));
  assert.equal((await rows(c.db, 'SELECT id FROM organization_members WHERE id = ?', dave)).length, 1);
  const removed = await rows(c.db, 'SELECT member_id FROM events WHERE type = 1503 AND organization_id = ?', c.orgId);
  assert.deepEqual(removed.map((e) => e.member_id), [carol]);
});

test('more than 2000 listed members needs largeImport', async () => {
  const c = await setup();
  const token = await orgToken(c);
  const members = Array.from({ length: 2001 }, (_, i) => ({ email: `u${i}@nowhere.test`, externalId: `e${i}`, deleted: false }));
  const refused = await send(c.env, 'POST', '/api/public/organization/import', { token, body: importBody({ members }) });
  assert.equal(refused.status, 400);
  const accepted = await send(c.env, 'POST', '/api/public/organization/import', { token, body: importBody({ members, largeImport: true }) });
  assert.equal(accepted.status, 200);
  assert.equal((await send(c.env, 'POST', '/api/public/organization/import', { token, body: { members: 'x' } })).status, 400);
});

test('member external ids survive a backup round trip', async () => {
  const c = await setup();
  await c.addMember('bob', 2, 2, 'ext-bob');
  const archive = await buildBackupArchive(c.env);
  const target = createTestDb();
  await ensureStorageSchema(target);
  await importBackupArchiveBytes(archive.bytes, { DB: target, JWT_SECRET: 'x'.repeat(40) } as unknown as Env, c.users.owner.id, false);
  const [row] = await rows(target, 'SELECT external_id FROM organization_members WHERE external_id IS NOT NULL');
  assert.equal(row?.external_id, 'ext-bob');
});
