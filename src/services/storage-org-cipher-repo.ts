// Organization-owned ciphers: rows of `ciphers` with organization_id set, linked to collections
// through collection_ciphers. user_id on such a row records who created it and grants nothing:
// access comes only from a confirmed membership, as computed here.
import type { Cipher } from '../types';
import { buildCipherData, parseCipherRow, selectCipherColumns } from './storage-cipher-repo';
import { MemberStatus, MemberType } from './storage-organization-repo';

/** What a member may do with an organization cipher, with Vaultwarden's meaning of each flag. */
export interface CipherAccess {
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

/** The owner of a personal cipher, and a member with access to every cipher of its organization. */
export const FULL_ACCESS: CipherAccess = { readOnly: false, hidePasswords: false, manage: true };

export interface AccessibleCipher {
  cipher: Cipher;
  access: CipherAccess;
  /** The cipher's collections the caller can see; empty for a personal cipher. */
  collectionIds: string[];
}

// Must agree with hasFullAccess() in org-access.ts: a confirmed member with access to all,
// and every owner and admin.
const FULL_ACCESS_SQL = `(m.access_all = 1 OR m.type IN (${MemberType.Owner}, ${MemberType.Admin}))`;
const CONFIRMED_MEMBER_JOIN =
  `INNER JOIN organization_members m ON m.organization_id = c.organization_id AND m.user_id = ? AND m.status = ${MemberStatus.Confirmed}`;

// The caller's access to each collection, one row per (collection, member): a direct assignment,
// else the groups' access combined to the most permissive, as listCollectionsForUser() reads it.
// Binds the user id once; every query below binds it again right after CONFIRMED_MEMBER_JOIN's.
const COLLECTION_ACCESS =
  '(SELECT * FROM (SELECT collection_id, member_id, read_only, hide_passwords, manage FROM collection_members ' +
  'UNION ALL SELECT cg.collection_id, gm.member_id, MIN(cg.read_only), MIN(cg.hide_passwords), MAX(cg.manage) ' +
  'FROM collection_groups cg INNER JOIN group_members gm ON gm.group_id = cg.group_id ' +
  'WHERE NOT EXISTS (SELECT 1 FROM collection_members d WHERE d.collection_id = cg.collection_id AND d.member_id = gm.member_id) ' +
  'GROUP BY cg.collection_id, gm.member_id) ' +
  'WHERE member_id IN (SELECT id FROM organization_members WHERE user_id = ?))';

// A cipher in several collections is read-only, or hides passwords, only when every one of the
// caller's collections says so; manage holds when any one does.
const ACCESS_QUERY =
  `SELECT ${selectCipherColumns('c')}, ${FULL_ACCESS_SQL} AS full_access, ` +
  'MIN(cm.read_only) AS ro, MIN(cm.hide_passwords) AS hp, MAX(cm.manage) AS mn, COUNT(cm.member_id) AS assigned ' +
  `FROM ciphers c ${CONFIRMED_MEMBER_JOIN} ` +
  'LEFT JOIN collection_ciphers cc ON cc.cipher_id = c.id ' +
  `LEFT JOIN ${COLLECTION_ACCESS} cm ON cm.collection_id = cc.collection_id AND cm.member_id = m.id ` +
  'WHERE c.organization_id IS NOT NULL';
const ACCESS_GROUP = ' GROUP BY c.id HAVING full_access OR assigned > 0';

const VISIBLE_LINKS_QUERY =
  'SELECT cc.cipher_id, cc.collection_id FROM collection_ciphers cc INNER JOIN ciphers c ON c.id = cc.cipher_id ' +
  `${CONFIRMED_MEMBER_JOIN} ` +
  `LEFT JOIN ${COLLECTION_ACCESS} cm ON cm.collection_id = cc.collection_id AND cm.member_id = m.id ` +
  `WHERE (${FULL_ACCESS_SQL} OR cm.member_id IS NOT NULL)`;

function accessFromRow(row: any): CipherAccess {
  if (row.full_access) return FULL_ACCESS;
  return { readOnly: !!row.ro, hidePasswords: !!row.hp, manage: !!row.mn };
}

function groupLinks(rows: Array<{ cipher_id: string; collection_id: string }>): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const row of rows) {
    const list = out.get(row.cipher_id);
    if (list) list.push(row.collection_id);
    else out.set(row.cipher_id, [row.collection_id]);
  }
  return out;
}

function toAccessible(rows: any[], links: Map<string, string[]>): AccessibleCipher[] {
  return rows.flatMap((row) => {
    const cipher = parseCipherRow(row);
    return cipher ? [{ cipher, access: accessFromRow(row), collectionIds: links.get(cipher.id) ?? [] }] : [];
  });
}

/** An organization cipher the user can see, with their access, or null. Fails closed. */
export async function getOrgCipherForUser(db: D1Database, cipherId: string, userId: string): Promise<AccessibleCipher | null> {
  const [{ results }, links] = await Promise.all([
    db.prepare(`${ACCESS_QUERY} AND c.id = ?${ACCESS_GROUP}`).bind(userId, userId, cipherId).all<any>(),
    db.prepare(`${VISIBLE_LINKS_QUERY} AND cc.cipher_id = ? ORDER BY cc.collection_id`).bind(userId, userId, cipherId).all<any>(),
  ]);
  return toAccessible(results || [], groupLinks(links.results || []))[0] ?? null;
}

/** Every organization cipher the user can see, for /api/sync and /api/ciphers. */
export async function listOrgCiphersForUser(db: D1Database, userId: string): Promise<AccessibleCipher[]> {
  const [{ results }, links] = await Promise.all([
    db.prepare(`${ACCESS_QUERY}${ACCESS_GROUP} ORDER BY c.updated_at DESC`).bind(userId, userId).all<any>(),
    db.prepare(`${VISIBLE_LINKS_QUERY} ORDER BY cc.collection_id`).bind(userId, userId).all<any>(),
  ]);
  return toAccessible(results || [], groupLinks(links.results || []));
}

/** Every cipher of an organization with all its collections, for the admin console. */
export async function listOrgCiphers(db: D1Database, organizationId: string): Promise<AccessibleCipher[]> {
  const [{ results }, links] = await Promise.all([
    db
      .prepare(`SELECT ${selectCipherColumns()}, 1 AS full_access FROM ciphers WHERE organization_id = ? ORDER BY updated_at DESC`)
      .bind(organizationId)
      .all<any>(),
    db
      .prepare(
        'SELECT cc.cipher_id, cc.collection_id FROM collection_ciphers cc INNER JOIN ciphers c ON c.id = cc.cipher_id ' +
        'WHERE c.organization_id = ? ORDER BY cc.collection_id'
      )
      .bind(organizationId)
      .all<any>(),
  ]);
  return toAccessible(results || [], groupLinks(links.results || []));
}

export async function listOrgCipherIds(db: D1Database, organizationId: string): Promise<string[]> {
  const { results } = await db.prepare('SELECT id FROM ciphers WHERE organization_id = ?').bind(organizationId).all<{ id: string }>();
  return (results || []).map((row) => row.id);
}

/** All collection ids of a cipher, whoever can see them. */
export async function listCipherCollectionIds(db: D1Database, cipherId: string): Promise<string[]> {
  const { results } = await db
    .prepare('SELECT collection_id FROM collection_ciphers WHERE cipher_id = ? ORDER BY collection_id')
    .bind(cipherId)
    .all<{ collection_id: string }>();
  return (results || []).map((row) => row.collection_id);
}

/**
 * For each requested id, whether it is a collection of this organization the user may put items in
 * or take them out of: with full access, or assigned to it without read-only. Ids of other
 * organizations are absent from the map.
 */
export async function getCollectionWriteAccess(
  db: D1Database,
  organizationId: string,
  userId: string,
  collectionIds: string[]
): Promise<Map<string, boolean>> {
  const out = new Map<string, boolean>();
  if (!collectionIds.length) return out;
  const { results } = await db
    .prepare(
      `SELECT col.id, ${FULL_ACCESS_SQL} AS full_access, cm.read_only, cm.member_id AS assigned FROM collections col ` +
      `INNER JOIN organization_members m ON m.organization_id = col.organization_id AND m.user_id = ? AND m.status = ${MemberStatus.Confirmed} ` +
      `LEFT JOIN ${COLLECTION_ACCESS} cm ON cm.collection_id = col.id AND cm.member_id = m.id ` +
      `WHERE col.organization_id = ? AND col.id IN (${collectionIds.map(() => '?').join(', ')})`
    )
    .bind(userId, userId, organizationId, ...collectionIds)
    .all<any>();
  for (const row of results || []) {
    out.set(row.id, !!row.full_access || (!!row.assigned && !row.read_only));
  }
  return out;
}

/** The ids among `ids` of organization ciphers the user may delete and restore. */
export async function listWritableOrgCipherIds(db: D1Database, userId: string, ids: string[]): Promise<string[]> {
  const out: string[] = [];
  // One statement per chunk; D1 allows 100 bound values.
  for (let i = 0; i < ids.length; i += 90) {
    const chunk = ids.slice(i, i + 90);
    const { results } = await db
      .prepare(`${ACCESS_QUERY} AND c.id IN (${chunk.map(() => '?').join(', ')})${ACCESS_GROUP}`)
      .bind(userId, userId, ...chunk)
      .all<any>();
    for (const row of results || []) {
      const access = accessFromRow(row);
      if (!access.readOnly || access.manage) out.push(row.id);
    }
  }
  return out;
}

function linkStatements(db: D1Database, cipherId: string, organizationId: string, collectionIds: string[]): D1PreparedStatement[] {
  // Each link is only written while the cipher and the collection belong to the same organization.
  return collectionIds.map((collectionId) =>
    db
      .prepare(
        'INSERT OR IGNORE INTO collection_ciphers(collection_id, cipher_id) SELECT col.id, c.id FROM collections col, ciphers c ' +
        'WHERE col.id = ? AND c.id = ? AND col.organization_id = ? AND c.organization_id = ?'
      )
      .bind(collectionId, cipherId, organizationId, organizationId)
  );
}

const INSERT_CIPHER =
  'INSERT INTO ciphers(id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at, organization_id) ' +
  'VALUES(?, ?, ?, NULL, ?, ?, 0, ?, ?, ?, ?, ?, NULL, NULL, ?)';

/** The statements that insert a new organization cipher and its collection links. */
export function insertOrgCipherStatements(db: D1Database, cipher: Cipher, collectionIds: string[]): D1PreparedStatement[] {
  const organizationId = cipher.organizationId!;
  return [
    db
      .prepare(INSERT_CIPHER)
      .bind(
        cipher.id, cipher.userId, Number(cipher.type) || 1, cipher.name ?? null, cipher.notes ?? null, buildCipherData(cipher, null),
        cipher.reprompt ?? 0, cipher.key ?? null, cipher.createdAt, cipher.updatedAt, organizationId
      ),
    ...linkStatements(db, cipher.id, organizationId, collectionIds),
  ];
}

/** Inserts a new organization cipher and its collection links in one transaction. */
export async function insertOrgCipher(db: D1Database, cipher: Cipher, collectionIds: string[]): Promise<void> {
  await db.batch(insertOrgCipherStatements(db, cipher, collectionIds));
}

/**
 * Moves a personal cipher into an organization with its new content and collections, in one
 * transaction. Returns false, and changes nothing, when the cipher is no longer the user's personal
 * cipher at `expectedUpdatedAt`.
 */
export async function shareCipher(
  db: D1Database,
  cipher: Cipher,
  expectedUpdatedAt: string,
  collectionIds: string[]
): Promise<boolean> {
  const organizationId = cipher.organizationId!;
  const [moved] = await db.batch([
    db
      .prepare(
        'UPDATE ciphers SET type = ?, folder_id = NULL, name = ?, notes = ?, favorite = 0, data = ?, reprompt = ?, key = ?, ' +
        'updated_at = ?, archived_at = NULL, organization_id = ? ' +
        'WHERE id = ? AND user_id = ? AND organization_id IS NULL AND updated_at = ?'
      )
      .bind(
        Number(cipher.type) || 1, cipher.name ?? null, cipher.notes ?? null, buildCipherData(cipher, null), cipher.reprompt ?? 0, cipher.key ?? null,
        cipher.updatedAt, organizationId, cipher.id, cipher.userId, expectedUpdatedAt
      ),
    ...linkStatements(db, cipher.id, organizationId, collectionIds),
  ]);
  return Number(moved.meta?.changes || 0) === 1;
}

function collectionChangeStatements(db: D1Database, cipherId: string, organizationId: string, add: string[], remove: string[]) {
  return [
    ...linkStatements(db, cipherId, organizationId, add),
    ...remove.map((collectionId) =>
      db.prepare('DELETE FROM collection_ciphers WHERE cipher_id = ? AND collection_id = ?').bind(cipherId, collectionId)
    ),
  ];
}

/** Adds and removes collection links of an organization cipher, in one transaction. */
export async function updateCipherCollections(
  db: D1Database,
  cipherId: string,
  organizationId: string,
  add: string[],
  remove: string[]
): Promise<void> {
  const statements = collectionChangeStatements(db, cipherId, organizationId, add, remove);
  if (statements.length) await db.batch(statements);
}

/** Adds or removes the same collection links on several organization ciphers, in one transaction. */
export async function updateCiphersCollections(
  db: D1Database,
  cipherIds: string[],
  organizationId: string,
  collectionIds: string[],
  remove: boolean
): Promise<void> {
  const statements = cipherIds.flatMap((id) =>
    collectionChangeStatements(db, id, organizationId, remove ? [] : collectionIds, remove ? collectionIds : [])
  );
  if (statements.length) await db.batch(statements);
}

/** Soft-deletes (a date) or restores (null) organization ciphers by id. */
export async function setOrgCiphersDeletedAt(db: D1Database, ids: string[], deletedAt: string | null): Promise<void> {
  const now = new Date().toISOString();
  for (let i = 0; i < ids.length; i += 90) {
    const chunk = ids.slice(i, i + 90);
    await db
      .prepare(
        'UPDATE ciphers SET deleted_at = ?, updated_at = ?, ' +
        "data = json_remove(data, '$.deletedAt', '$.deletedDate', '$.updatedAt', '$.revisionDate') " +
        `WHERE organization_id IS NOT NULL AND id IN (${chunk.map(() => '?').join(', ')})`
      )
      .bind(deletedAt, now, ...chunk)
      .run();
  }
}

export async function deleteOrgCiphers(db: D1Database, ids: string[]): Promise<void> {
  for (let i = 0; i < ids.length; i += 90) {
    const chunk = ids.slice(i, i + 90);
    await db
      .prepare(`DELETE FROM ciphers WHERE organization_id IS NOT NULL AND id IN (${chunk.map(() => '?').join(', ')})`)
      .bind(...chunk)
      .run();
  }
}

/** The organizations among these ciphers, for revision bumps. */
export async function listOrganizationsOfCiphers(db: D1Database, ids: string[]): Promise<string[]> {
  const out = new Set<string>();
  for (let i = 0; i < ids.length; i += 90) {
    const chunk = ids.slice(i, i + 90);
    const { results } = await db
      .prepare(`SELECT DISTINCT organization_id FROM ciphers WHERE organization_id IS NOT NULL AND id IN (${chunk.map(() => '?').join(', ')})`)
      .bind(...chunk)
      .all<{ organization_id: string }>();
    for (const row of results || []) out.add(row.organization_id);
  }
  return [...out];
}

/**
 * Hands the organization ciphers this user created to another confirmed owner of each organization,
 * so deleting the user (whose rows cascade) keeps them. Membership of the user is not required: a
 * creator who left still owns the rows. Returns how many organization ciphers still name the user.
 */
export async function reassignOrgCiphersCreatedBy(db: D1Database, userId: string): Promise<number> {
  const otherOwner =
    'SELECT o.user_id FROM organization_members o WHERE o.organization_id = ciphers.organization_id ' +
    `AND o.type = ${MemberType.Owner} AND o.status = ${MemberStatus.Confirmed} AND o.user_id != ? ORDER BY o.created_at ASC, o.id ASC LIMIT 1`;
  await db
    .prepare(`UPDATE ciphers SET user_id = (${otherOwner}) WHERE user_id = ? AND organization_id IS NOT NULL AND EXISTS (${otherOwner})`)
    .bind(userId, userId, userId)
    .run();
  const row = await db
    .prepare('SELECT COUNT(*) AS count FROM ciphers WHERE user_id = ? AND organization_id IS NOT NULL')
    .bind(userId)
    .first<{ count: number }>();
  return Number(row?.count || 0);
}
