// Organization groups: a named set of members with access to collections. Deleting a group,
// its organization, a member or a collection cascades to the rows that name it.

export interface Group {
  id: string;
  organizationId: string;
  name: string;
  externalId: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface GroupAccess {
  collectionId: string;
  groupId: string;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

export interface GroupMember {
  groupId: string;
  memberId: string;
}

const GROUP_COLUMNS = 'g.id, g.organization_id, g.name, g.external_id, g.created_at, g.updated_at';

function mapGroup(row: any): Group {
  return {
    id: row.id,
    organizationId: row.organization_id,
    name: row.name,
    externalId: row.external_id ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapGroupAccess(row: any): GroupAccess {
  return {
    collectionId: row.collection_id,
    groupId: row.group_id,
    readOnly: !!row.read_only,
    hidePasswords: !!row.hide_passwords,
    manage: !!row.manage,
  };
}

export async function listGroups(db: D1Database, organizationId: string): Promise<Group[]> {
  const { results } = await db
    .prepare(`SELECT ${GROUP_COLUMNS} FROM organization_groups g WHERE g.organization_id = ? ORDER BY g.created_at ASC, g.id ASC`)
    .bind(organizationId)
    .all<any>();
  return (results || []).map(mapGroup);
}

export async function getGroup(db: D1Database, organizationId: string, id: string): Promise<Group | null> {
  const row = await db
    .prepare(`SELECT ${GROUP_COLUMNS} FROM organization_groups g WHERE g.organization_id = ? AND g.id = ?`)
    .bind(organizationId, id)
    .first<any>();
  return row ? mapGroup(row) : null;
}

/** Every group's collection access in an organization. */
export async function listGroupAccess(db: D1Database, organizationId: string): Promise<GroupAccess[]> {
  const { results } = await db
    .prepare(
      'SELECT cg.collection_id, cg.group_id, cg.read_only, cg.hide_passwords, cg.manage FROM collection_groups cg ' +
      'INNER JOIN organization_groups g ON g.id = cg.group_id WHERE g.organization_id = ? ORDER BY cg.group_id ASC, cg.collection_id ASC'
    )
    .bind(organizationId)
    .all<any>();
  return (results || []).map(mapGroupAccess);
}

/** Every group membership in an organization. */
export async function listGroupMembers(db: D1Database, organizationId: string): Promise<GroupMember[]> {
  const { results } = await db
    .prepare(
      'SELECT gm.group_id, gm.member_id FROM group_members gm INNER JOIN organization_groups g ON g.id = gm.group_id ' +
      'WHERE g.organization_id = ? ORDER BY gm.group_id ASC, gm.member_id ASC'
    )
    .bind(organizationId)
    .all<{ group_id: string; member_id: string }>();
  return (results || []).map((row) => ({ groupId: row.group_id, memberId: row.member_id }));
}

export function insertGroupAccess(db: D1Database, a: GroupAccess): D1PreparedStatement {
  return db
    .prepare('INSERT INTO collection_groups(collection_id, group_id, read_only, hide_passwords, manage) VALUES(?, ?, ?, ?, ?)')
    .bind(a.collectionId, a.groupId, a.readOnly ? 1 : 0, a.hidePasswords ? 1 : 0, a.manage ? 1 : 0);
}

export function insertGroupMember(db: D1Database, m: GroupMember): D1PreparedStatement {
  return db.prepare('INSERT INTO group_members(group_id, member_id) VALUES(?, ?)').bind(m.groupId, m.memberId);
}

/** Creates or updates a group and replaces its collection access and members, in one transaction. */
export async function saveGroup(
  db: D1Database,
  group: Group,
  access: GroupAccess[],
  memberIds: string[],
  isNew: boolean
): Promise<void> {
  await db.batch([
    isNew
      ? db
          .prepare('INSERT INTO organization_groups(id, organization_id, name, external_id, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?)')
          .bind(group.id, group.organizationId, group.name, group.externalId, group.createdAt, group.updatedAt)
      : db
          .prepare('UPDATE organization_groups SET name = ?, updated_at = ? WHERE id = ? AND organization_id = ?')
          .bind(group.name, group.updatedAt, group.id, group.organizationId),
    db.prepare('DELETE FROM collection_groups WHERE group_id = ?').bind(group.id),
    db.prepare('DELETE FROM group_members WHERE group_id = ?').bind(group.id),
    ...access.map((a) => insertGroupAccess(db, a)),
    ...memberIds.map((memberId) => insertGroupMember(db, { groupId: group.id, memberId })),
  ]);
}

export async function deleteGroup(db: D1Database, organizationId: string, id: string): Promise<void> {
  await db.prepare('DELETE FROM organization_groups WHERE id = ? AND organization_id = ?').bind(id, organizationId).run();
}
