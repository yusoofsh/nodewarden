// Organizations, their members and collections. Organization-owned ciphers live in storage-org-cipher-repo.ts.
import { type GroupAccess, type GroupMember, insertGroupAccess, insertGroupMember } from './storage-organization-group-repo';

export const MemberStatus = { Revoked: -1, Invited: 0, Accepted: 1, Confirmed: 2 } as const;

// As in Vaultwarden, a revoked member keeps its earlier status, offset by this, so restoring it returns
// that status: -128 invited, -127 accepted, -126 confirmed. Every check that grants access compares
// with a positive status, so a revoked row grants nothing.
const REVOKED_OFFSET = 128;
export const isRevoked = (status: number): boolean => status < MemberStatus.Invited;
/** The status clients see: every revoked status reads as Revoked. */
export const clientStatus = (status: number): number => (isRevoked(status) ? MemberStatus.Revoked : status);
/** The status a member had before it was revoked, or its status. */
export const activeStatus = (status: number): number => (isRevoked(status) ? status + REVOKED_OFFSET : status);
export const MemberType = { Owner: 0, Admin: 1, User: 2, Custom: 4 } as const;

export interface Organization {
  id: string;
  name: string;
  billingEmail: string;
  privateKey: string | null;
  publicKey: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface OrganizationMember {
  id: string;
  organizationId: string;
  userId: string;
  akey: string;
  status: number;
  type: number;
  accessAll: boolean;
  resetPasswordKey: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface Collection {
  id: string;
  organizationId: string;
  name: string;
  externalId: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CollectionAccess {
  collectionId: string;
  memberId: string;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

/** A member row joined with the user it belongs to, for member lists. */
export interface MemberWithUser extends OrganizationMember {
  name: string | null;
  email: string;
  hasTwoFactor: boolean;
}

const ORG_COLUMNS = 'id, name, billing_email, private_key, public_key, created_at, updated_at';
const MEMBER_COLUMNS = 'm.id, m.organization_id, m.user_id, m.akey, m.status, m.type, m.access_all, m.reset_password_key, m.created_at, m.updated_at';
const COLLECTION_COLUMNS = 'c.id, c.organization_id, c.name, c.external_id, c.created_at, c.updated_at';

function mapOrganization(row: any): Organization {
  return {
    id: row.id,
    name: row.name,
    billingEmail: row.billing_email,
    privateKey: row.private_key ?? null,
    publicKey: row.public_key ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapMember(row: any): OrganizationMember {
  return {
    id: row.id,
    organizationId: row.organization_id,
    userId: row.user_id,
    akey: row.akey ?? '',
    status: Number(row.status),
    type: Number(row.type),
    accessAll: !!row.access_all,
    resetPasswordKey: row.reset_password_key ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapCollection(row: any): Collection {
  return {
    id: row.id,
    organizationId: row.organization_id,
    name: row.name,
    externalId: row.external_id ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapAccess(row: any): CollectionAccess {
  return {
    collectionId: row.collection_id,
    memberId: row.member_id,
    readOnly: !!row.read_only,
    hidePasswords: !!row.hide_passwords,
    manage: !!row.manage,
  };
}

async function all<T>(stmt: D1PreparedStatement, map: (row: any) => T): Promise<T[]> {
  const { results } = await stmt.all<any>();
  return (results || []).map(map);
}

export async function getOrganization(db: D1Database, id: string): Promise<Organization | null> {
  const row = await db.prepare(`SELECT ${ORG_COLUMNS} FROM organizations WHERE id = ?`).bind(id).first<any>();
  return row ? mapOrganization(row) : null;
}

export async function getMember(db: D1Database, organizationId: string, userId: string): Promise<OrganizationMember | null> {
  const row = await db
    .prepare(`SELECT ${MEMBER_COLUMNS} FROM organization_members m WHERE m.organization_id = ? AND m.user_id = ?`)
    .bind(organizationId, userId)
    .first<any>();
  return row ? mapMember(row) : null;
}

/** Writes the organization, its owner and its first collection in one transaction. */
export async function createOrganization(
  db: D1Database,
  org: Organization,
  owner: OrganizationMember,
  collection: Collection
): Promise<void> {
  await db.batch([
    db
      .prepare(`INSERT INTO organizations(${ORG_COLUMNS}) VALUES(?, ?, ?, ?, ?, ?, ?)`)
      .bind(org.id, org.name, org.billingEmail, org.privateKey, org.publicKey, org.createdAt, org.updatedAt),
    db
      .prepare(
        'INSERT INTO organization_members(id, organization_id, user_id, akey, status, type, access_all, reset_password_key, created_at, updated_at) ' +
        'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
      )
      .bind(owner.id, owner.organizationId, owner.userId, owner.akey, owner.status, owner.type, owner.accessAll ? 1 : 0, owner.resetPasswordKey, owner.createdAt, owner.updatedAt),
    insertCollection(db, collection),
  ]);
}

export async function updateOrganization(db: D1Database, id: string, name: string, billingEmail: string): Promise<void> {
  await db
    .prepare('UPDATE organizations SET name = ?, billing_email = ?, updated_at = ? WHERE id = ?')
    .bind(name, billingEmail, new Date().toISOString(), id)
    .run();
}

export async function deleteOrganization(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM organizations WHERE id = ?').bind(id).run();
}

export async function deleteMember(db: D1Database, memberId: string): Promise<void> {
  await db.prepare('DELETE FROM organization_members WHERE id = ?').bind(memberId).run();
}

/** Memberships of a user with these statuses, each with its organization, ordered by type then name. */
export async function listMembershipsByUser(
  db: D1Database,
  userId: string,
  statuses: number[]
): Promise<Array<{ member: OrganizationMember; organization: Organization }>> {
  const { results } = await db
    .prepare(
      `SELECT ${MEMBER_COLUMNS}, o.name AS org_name, o.billing_email AS org_billing_email, o.private_key AS org_private_key, ` +
      'o.public_key AS org_public_key, o.created_at AS org_created_at, o.updated_at AS org_updated_at ' +
      'FROM organization_members m INNER JOIN organizations o ON o.id = m.organization_id ' +
      `WHERE m.user_id = ? AND m.status IN (${statuses.map(() => '?').join(', ')}) ORDER BY m.type ASC, o.name ASC`
    )
    .bind(userId, ...statuses)
    .all<any>();
  return (results || []).map((row) => ({
    member: mapMember(row),
    organization: mapOrganization({
      id: row.organization_id,
      name: row.org_name,
      billing_email: row.org_billing_email,
      private_key: row.org_private_key,
      public_key: row.org_public_key,
      created_at: row.org_created_at,
      updated_at: row.org_updated_at,
    }),
  }));
}

/** The memberships a profile lists: accepted and confirmed. */
export function listProfileMemberships(db: D1Database, userId: string) {
  return listMembershipsByUser(db, userId, [MemberStatus.Accepted, MemberStatus.Confirmed]);
}

export async function listMembersWithUsers(db: D1Database, organizationId: string): Promise<MemberWithUser[]> {
  const { results } = await db
    .prepare(
      `SELECT ${MEMBER_COLUMNS}, u.name AS user_name, u.email AS user_email, ` +
      "(u.totp_secret IS NOT NULL AND u.totp_secret != '') " +
      "OR COALESCE(u.yubikey_key1, u.yubikey_key2, u.yubikey_key3, u.yubikey_key4, u.yubikey_key5, '') != '' " +
      "OR EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id = u.id AND w.purpose = 'twoFactor') AS has_two_factor " +
      'FROM organization_members m INNER JOIN users u ON u.id = m.user_id WHERE m.organization_id = ? ORDER BY m.created_at ASC'
    )
    .bind(organizationId)
    .all<any>();
  return (results || []).map((row) => ({
    ...mapMember(row),
    name: row.user_name ?? null,
    email: row.user_email,
    hasTwoFactor: !!row.has_two_factor,
  }));
}

export async function listMemberUserIds(db: D1Database, organizationId: string): Promise<string[]> {
  const { results } = await db
    .prepare('SELECT user_id FROM organization_members WHERE organization_id = ?')
    .bind(organizationId)
    .all<{ user_id: string }>();
  return (results || []).map((row) => row.user_id);
}

export async function countConfirmedOwners(db: D1Database, organizationId: string): Promise<number> {
  const row = await db
    .prepare('SELECT COUNT(*) AS count FROM organization_members WHERE organization_id = ? AND type = ? AND status = ?')
    .bind(organizationId, MemberType.Owner, MemberStatus.Confirmed)
    .first<{ count: number }>();
  return Number(row?.count || 0);
}

/** Organizations in which this user is the only confirmed owner. */
export async function listOrganizationsSolelyOwnedBy(db: D1Database, userId: string): Promise<string[]> {
  const { results } = await db
    .prepare(
      'SELECT m.organization_id FROM organization_members m WHERE m.user_id = ? AND m.type = ? AND m.status = ? ' +
      'AND NOT EXISTS (SELECT 1 FROM organization_members o WHERE o.organization_id = m.organization_id ' +
      'AND o.user_id != m.user_id AND o.type = ? AND o.status = ?)'
    )
    .bind(userId, MemberType.Owner, MemberStatus.Confirmed, MemberType.Owner, MemberStatus.Confirmed)
    .all<{ organization_id: string }>();
  return (results || []).map((row) => row.organization_id);
}

function insertAccess(db: D1Database, a: CollectionAccess): D1PreparedStatement {
  return db
    .prepare('INSERT INTO collection_members(collection_id, member_id, read_only, hide_passwords, manage) VALUES(?, ?, ?, ?, ?)')
    .bind(a.collectionId, a.memberId, a.readOnly ? 1 : 0, a.hidePasswords ? 1 : 0, a.manage ? 1 : 0);
}

export function insertCollection(db: D1Database, collection: Collection): D1PreparedStatement {
  return db
    .prepare('INSERT INTO collections(id, organization_id, name, external_id, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?)')
    .bind(collection.id, collection.organizationId, collection.name, collection.externalId, collection.createdAt, collection.updatedAt);
}

export async function getCollection(db: D1Database, organizationId: string, id: string): Promise<Collection | null> {
  const row = await db
    .prepare(`SELECT ${COLLECTION_COLUMNS} FROM collections c WHERE c.organization_id = ? AND c.id = ?`)
    .bind(organizationId, id)
    .first<any>();
  return row ? mapCollection(row) : null;
}

export async function listCollections(db: D1Database, organizationId: string): Promise<Collection[]> {
  return all(
    db.prepare(`SELECT ${COLLECTION_COLUMNS} FROM collections c WHERE c.organization_id = ? ORDER BY c.created_at ASC, c.id ASC`).bind(organizationId),
    mapCollection
  );
}

export async function listCollectionAccess(db: D1Database, organizationId: string): Promise<CollectionAccess[]> {
  return all(
    db
      .prepare(
        'SELECT cm.collection_id, cm.member_id, cm.read_only, cm.hide_passwords, cm.manage FROM collection_members cm ' +
        'INNER JOIN collections c ON c.id = cm.collection_id WHERE c.organization_id = ?'
      )
      .bind(organizationId),
    mapAccess
  );
}

/**
 * Collections a user can see across organizations, with that user's access when there is one: every
 * collection of a confirmed membership with access to all, and the collections assigned to the member
 * directly or through its groups. As in Vaultwarden, a direct assignment wins over the groups, and
 * several groups combine to the most permissive access.
 */
export async function listCollectionsForUser(
  db: D1Database,
  userId: string
): Promise<Array<{ collection: Collection; member: OrganizationMember; access: CollectionAccess | null }>> {
  const { results } = await db
    .prepare(
      `SELECT ${MEMBER_COLUMNS}, c.id AS c_id, c.name AS c_name, c.external_id AS c_external_id, c.created_at AS c_created_at, ` +
      'c.updated_at AS c_updated_at, cm.member_id AS cm_member_id, cm.read_only, cm.hide_passwords, cm.manage, ' +
      'ga.member_id AS ga_member_id, ga.read_only AS ga_read_only, ga.hide_passwords AS ga_hide_passwords, ga.manage AS ga_manage ' +
      'FROM collections c INNER JOIN organization_members m ON m.organization_id = c.organization_id AND m.user_id = ? ' +
      'LEFT JOIN collection_members cm ON cm.collection_id = c.id AND cm.member_id = m.id ' +
      'LEFT JOIN (SELECT cg.collection_id, gm.member_id, MIN(cg.read_only) AS read_only, MIN(cg.hide_passwords) AS hide_passwords, MAX(cg.manage) AS manage ' +
      'FROM collection_groups cg INNER JOIN group_members gm ON gm.group_id = cg.group_id ' +
      'WHERE gm.member_id IN (SELECT id FROM organization_members WHERE user_id = ?) GROUP BY cg.collection_id, gm.member_id) ga ' +
      'ON ga.collection_id = c.id AND ga.member_id = m.id ' +
      'WHERE m.status = ? AND (m.access_all = 1 OR cm.member_id IS NOT NULL OR ga.member_id IS NOT NULL) ' +
      'ORDER BY c.organization_id ASC, c.created_at ASC, c.id ASC'
    )
    .bind(userId, userId, MemberStatus.Confirmed)
    .all<any>();
  return (results || []).map((row) => ({
    collection: mapCollection({
      id: row.c_id,
      organization_id: row.organization_id,
      name: row.c_name,
      external_id: row.c_external_id,
      created_at: row.c_created_at,
      updated_at: row.c_updated_at,
    }),
    member: mapMember(row),
    access: row.cm_member_id
      ? mapAccess({ ...row, collection_id: row.c_id, member_id: row.cm_member_id })
      : row.ga_member_id
        ? mapAccess({
            collection_id: row.c_id,
            member_id: row.ga_member_id,
            read_only: row.ga_read_only,
            hide_passwords: row.ga_hide_passwords,
            manage: row.ga_manage,
          })
        : null,
  }));
}

/** Creates or updates a collection and replaces its member and group access lists, in one transaction. */
export async function saveCollection(
  db: D1Database,
  collection: Collection,
  access: CollectionAccess[],
  groupAccess: GroupAccess[],
  isNew: boolean
): Promise<void> {
  const statements: D1PreparedStatement[] = [
    isNew
      ? insertCollection(db, collection)
      : db
          .prepare('UPDATE collections SET name = ?, external_id = ?, updated_at = ? WHERE id = ? AND organization_id = ?')
          .bind(collection.name, collection.externalId, collection.updatedAt, collection.id, collection.organizationId),
    db.prepare('DELETE FROM collection_members WHERE collection_id = ?').bind(collection.id),
    db.prepare('DELETE FROM collection_groups WHERE collection_id = ?').bind(collection.id),
    ...access.map((a) => insertAccess(db, a)),
    ...groupAccess.map((a) => insertGroupAccess(db, a)),
  ];
  await db.batch(statements);
}

export async function deleteCollection(db: D1Database, organizationId: string, id: string): Promise<void> {
  await db.prepare('DELETE FROM collections WHERE id = ? AND organization_id = ?').bind(id, organizationId).run();
}

export async function getMemberById(db: D1Database, organizationId: string, memberId: string): Promise<OrganizationMember | null> {
  const row = await db
    .prepare(`SELECT ${MEMBER_COLUMNS} FROM organization_members m WHERE m.organization_id = ? AND m.id = ?`)
    .bind(organizationId, memberId)
    .first<any>();
  return row ? mapMember(row) : null;
}

/** Inserts invited members, their collection access and their groups, in one transaction. */
export async function inviteMembers(
  db: D1Database,
  members: OrganizationMember[],
  access: CollectionAccess[],
  groups: GroupMember[]
): Promise<void> {
  await db.batch([
    ...members.map((m) =>
      db
        .prepare(
          'INSERT INTO organization_members(id, organization_id, user_id, akey, status, type, access_all, reset_password_key, created_at, updated_at) ' +
          'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
        )
        .bind(m.id, m.organizationId, m.userId, m.akey, m.status, m.type, m.accessAll ? 1 : 0, m.resetPasswordKey, m.createdAt, m.updatedAt)
    ),
    ...access.map((a) => insertAccess(db, a)),
    ...groups.map((g) => insertGroupMember(db, g)),
  ]);
}

/**
 * Moves a member from status `from` to `to`, setting akey when given. Returns false when the member
 * was not in `from`, so a repeated or out-of-order request changes nothing.
 */
export async function transitionMember(
  db: D1Database,
  organizationId: string,
  memberId: string,
  from: number,
  to: number,
  akey: string | null = null
): Promise<boolean> {
  const result = await db
    .prepare('UPDATE organization_members SET status = ?, akey = COALESCE(?, akey), updated_at = ? WHERE id = ? AND organization_id = ? AND status = ?')
    .bind(to, akey, new Date().toISOString(), memberId, organizationId, from)
    .run();
  return Number(result.meta?.changes || 0) > 0;
}

/** Sets a member's role and replaces its collection access, and its groups unless null, in one transaction. */
export async function updateMemberAccess(
  db: D1Database,
  member: OrganizationMember,
  type: number,
  accessAll: boolean,
  access: CollectionAccess[],
  groupIds: string[] | null
): Promise<void> {
  await db.batch([
    db
      .prepare('UPDATE organization_members SET type = ?, access_all = ?, updated_at = ? WHERE id = ? AND organization_id = ?')
      .bind(type, accessAll ? 1 : 0, new Date().toISOString(), member.id, member.organizationId),
    db.prepare('DELETE FROM collection_members WHERE member_id = ?').bind(member.id),
    ...access.map((a) => insertAccess(db, a)),
    ...(groupIds === null ? [] : replaceMemberGroups(db, member.id, groupIds)),
  ]);
}

function replaceMemberGroups(db: D1Database, memberId: string, groupIds: string[]): D1PreparedStatement[] {
  return [
    db.prepare('DELETE FROM group_members WHERE member_id = ?').bind(memberId),
    ...groupIds.map((groupId) => insertGroupMember(db, { groupId, memberId })),
  ];
}

/** Replaces the groups a member is in, in one transaction. */
export async function setMemberGroups(db: D1Database, memberId: string, groupIds: string[]): Promise<void> {
  await db.batch(replaceMemberGroups(db, memberId, groupIds));
}

/**
 * Revokes a member that is not revoked, or restores a revoked one to its earlier status. Returns
 * false when it already was, so a repeated request changes nothing.
 */
export async function setMemberRevoked(db: D1Database, organizationId: string, memberId: string, revoked: boolean): Promise<boolean> {
  const change = revoked
    ? `status = status - ${REVOKED_OFFSET}, updated_at = ? WHERE id = ? AND organization_id = ? AND status >= ${MemberStatus.Invited}`
    : `status = status + ${REVOKED_OFFSET}, updated_at = ? WHERE id = ? AND organization_id = ? ` +
      `AND status BETWEEN ${MemberStatus.Invited - REVOKED_OFFSET} AND ${MemberStatus.Confirmed - REVOKED_OFFSET}`;
  const result = await db.prepare(`UPDATE organization_members SET ${change}`).bind(new Date().toISOString(), memberId, organizationId).run();
  return Number(result.meta?.changes || 0) > 0;
}

export async function setMemberResetPasswordKey(db: D1Database, memberId: string, key: string | null): Promise<void> {
  await db
    .prepare('UPDATE organization_members SET reset_password_key = ?, updated_at = ? WHERE id = ?')
    .bind(key, new Date().toISOString(), memberId)
    .run();
}

/** Sets the organization's key pair when it has none. Returns false when it already had one. */
export async function setOrganizationKeys(db: D1Database, id: string, privateKey: string, publicKey: string): Promise<boolean> {
  const result = await db
    .prepare(
      'UPDATE organizations SET private_key = ?, public_key = ?, updated_at = ? ' +
      'WHERE id = ? AND NOT (private_key IS NOT NULL AND public_key IS NOT NULL)'
    )
    .bind(privateKey, publicKey, new Date().toISOString(), id)
    .run();
  return Number(result.meta?.changes || 0) > 0;
}

export interface OrganizationApiKey {
  apiKey: string;
  revisionDate: string;
}

export async function getOrganizationApiKey(db: D1Database, id: string): Promise<OrganizationApiKey | null> {
  const row = await db
    .prepare('SELECT api_key, api_key_revision_date FROM organizations WHERE id = ?')
    .bind(id)
    .first<{ api_key: string | null; api_key_revision_date: string | null }>();
  return row?.api_key ? { apiKey: row.api_key, revisionDate: row.api_key_revision_date ?? '' } : null;
}

export async function setOrganizationApiKey(db: D1Database, id: string, key: OrganizationApiKey): Promise<void> {
  await db
    .prepare('UPDATE organizations SET api_key = ?, api_key_revision_date = ? WHERE id = ?')
    .bind(key.apiKey, key.revisionDate, id)
    .run();
}

/**
 * Gives these members and groups access to each collection, keeping every other assignment, in one
 * transaction. An existing assignment of a listed member or group takes the new flags.
 */
export async function addCollectionAccess(
  db: D1Database,
  organizationId: string,
  collectionIds: string[],
  access: Omit<CollectionAccess, 'collectionId'>[],
  groupAccess: Omit<GroupAccess, 'collectionId'>[]
): Promise<void> {
  const now = new Date().toISOString();
  await db.batch(
    collectionIds.flatMap((collectionId) => [
      db.prepare('UPDATE collections SET updated_at = ? WHERE id = ? AND organization_id = ?').bind(now, collectionId, organizationId),
      ...access.map((a) =>
        db
          .prepare(
            'INSERT INTO collection_members(collection_id, member_id, read_only, hide_passwords, manage) VALUES(?, ?, ?, ?, ?) ' +
            'ON CONFLICT(collection_id, member_id) DO UPDATE SET read_only = excluded.read_only, ' +
            'hide_passwords = excluded.hide_passwords, manage = excluded.manage'
          )
          .bind(collectionId, a.memberId, a.readOnly ? 1 : 0, a.hidePasswords ? 1 : 0, a.manage ? 1 : 0)
      ),
      ...groupAccess.map((a) =>
        db
          .prepare(
            'INSERT INTO collection_groups(collection_id, group_id, read_only, hide_passwords, manage) VALUES(?, ?, ?, ?, ?) ' +
            'ON CONFLICT(collection_id, group_id) DO UPDATE SET read_only = excluded.read_only, ' +
            'hide_passwords = excluded.hide_passwords, manage = excluded.manage'
          )
          .bind(collectionId, a.groupId, a.readOnly ? 1 : 0, a.hidePasswords ? 1 : 0, a.manage ? 1 : 0)
      ),
    ])
  );
}

export async function deleteCollections(db: D1Database, organizationId: string, ids: string[]): Promise<void> {
  if (!ids.length) return;
  await db.batch(ids.map((id) => db.prepare('DELETE FROM collections WHERE id = ? AND organization_id = ?').bind(id, organizationId)));
}

/** The user's memberships enrolled in account recovery: their reset password key wraps the user key. */
export async function listAccountRecoveryMemberships(db: D1Database, userId: string): Promise<Array<{ id: string; organizationId: string }>> {
  const { results } = await db
    .prepare('SELECT id, organization_id FROM organization_members WHERE user_id = ? AND reset_password_key IS NOT NULL')
    .bind(userId)
    .all<{ id: string; organization_id: string }>();
  return (results || []).map((row) => ({ id: row.id, organizationId: row.organization_id }));
}
