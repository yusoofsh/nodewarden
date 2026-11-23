// POST /api/public/organization/import: the Directory Connector's member and group sync, after
// Vaultwarden's core/public.rs. It authenticates with an organization API token, never a user's.
//
// Differences from Vaultwarden, with mail off:
// - A listed email with an account and no membership becomes an Invited member, as the invite route
//   makes it; Vaultwarden marks it Accepted when mail is off. An email with no account is skipped:
//   this server does not create placeholder accounts. The audit log records how many were skipped.
// - largeImport is enforced as Bitwarden's cloud does: more than 2000 groups or listed members fails
//   unless it is set. Vaultwarden ignores it.
// - Members that change are written, and logged as events, only when something about them changed,
//   so a periodic sync that finds nothing new writes nothing.
// As in Vaultwarden, Owners are never revoked, restored or removed, and an existing group keeps its
// collection access: the import replaces only its name and members.
import type { Env } from '../types';
import {
  MemberStatus,
  MemberType,
  activeStatus,
  isRevoked,
  revokedStatus,
} from '../services/storage-organization-repo';
import { insertGroupMember, listGroupMembers, listGroups } from '../services/storage-organization-group-repo';
import { EventType, type OrgEvent, logEvents } from '../services/events';
import { auditRequestMetadata, safeWriteAuditEvent } from '../services/audit-events';
import { verifyOrgApiToken } from '../utils/org-api-token';
import { errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { isRecord, readBody, str, touchUsers } from './organizations';

const MAX_IMPORT_WITHOUT_LARGE_IMPORT = 2000;
const IN_CHUNK = 90;

interface ImportMember {
  email: string;
  externalId: string;
  deleted: boolean;
}

interface ImportGroup {
  name: string;
  externalId: string;
  memberExternalIds: string[];
}

interface ImportData {
  members: ImportMember[];
  groups: ImportGroup[];
  overwriteExisting: boolean;
  largeImport: boolean;
}

interface ExistingMember {
  id: string;
  userId: string;
  email: string;
  status: number;
  type: number;
  externalId: string | null;
}

function parseImport(body: Record<string, unknown> | null): ImportData | null {
  if (!body || !Array.isArray(body.members) || !Array.isArray(body.groups)) return null;
  const members: ImportMember[] = [];
  for (const m of body.members) {
    const email = isRecord(m) ? str(m.email).toLowerCase() : '';
    const externalId = isRecord(m) ? str(m.externalId) : '';
    if (!email || !externalId) return null;
    members.push({ email, externalId, deleted: isRecord(m) && m.deleted === true });
  }
  const groups: ImportGroup[] = [];
  for (const g of body.groups) {
    if (!isRecord(g) || !str(g.name) || !str(g.externalId)) return null;
    const ids = Array.isArray(g.memberExternalIds) ? g.memberExternalIds.map(str).filter(Boolean) : [];
    groups.push({ name: str(g.name), externalId: str(g.externalId), memberExternalIds: ids });
  }
  return { members, groups, overwriteExisting: body.overwriteExisting === true, largeImport: body.largeImport === true };
}

async function listExistingMembers(db: D1Database, organizationId: string): Promise<ExistingMember[]> {
  const { results } = await db
    .prepare(
      'SELECT m.id, m.user_id, m.status, m.type, m.external_id, u.email FROM organization_members m ' +
      'INNER JOIN users u ON u.id = m.user_id WHERE m.organization_id = ?'
    )
    .bind(organizationId)
    .all<any>();
  return (results || []).map((row) => ({
    id: row.id,
    userId: row.user_id,
    email: String(row.email).toLowerCase(),
    status: Number(row.status),
    type: Number(row.type),
    externalId: row.external_id ?? null,
  }));
}

/** The user id of each email that has an account. */
async function findUserIds(db: D1Database, emails: string[]): Promise<Map<string, string>> {
  const found = new Map<string, string>();
  for (let i = 0; i < emails.length; i += IN_CHUNK) {
    const chunk = emails.slice(i, i + IN_CHUNK);
    const { results } = await db
      .prepare(`SELECT id, email FROM users WHERE email IN (${chunk.map(() => '?').join(', ')})`)
      .bind(...chunk)
      .all<{ id: string; email: string }>();
    for (const row of results || []) found.set(row.email.toLowerCase(), row.id);
  }
  return found;
}

export async function handleOrganizationImport(request: Request, env: Env): Promise<Response> {
  const organizationId = await verifyOrgApiToken(env, request.headers.get('Authorization'));
  if (!organizationId) return errorResponse('Unauthorized', 401);
  const data = parseImport(await readBody(request));
  if (!data) return errorResponse('Invalid import data', 400);
  const listedMembers = data.members.filter((m) => !m.deleted).length;
  if (!data.largeImport && (data.groups.length > MAX_IMPORT_WITHOUT_LARGE_IMPORT || listedMembers > MAX_IMPORT_WITHOUT_LARGE_IMPORT)) {
    return errorResponse('You cannot import this much data at once.', 400);
  }

  const db = env.DB;
  const now = new Date().toISOString();
  const statements: D1PreparedStatement[] = [];
  const events: OrgEvent[] = [];
  const memberEvent = (type: number, m: ExistingMember): OrgEvent => ({ type, organizationId, memberId: m.id, userId: m.userId });

  // Members: revoke the deleted, restore the listed, invite listed accounts that are not members yet.
  const members = await listExistingMembers(db, organizationId);
  const byEmail = new Map(members.map((m) => [m.email, m]));
  const userIds = await findUserIds(db, [...new Set(data.members.filter((m) => !m.deleted && !byEmail.has(m.email)).map((m) => m.email))]);
  let skipped = 0;
  for (const entry of data.members) {
    const member = byEmail.get(entry.email);
    if (member) {
      let status = member.status;
      if (member.type !== MemberType.Owner && entry.deleted !== isRevoked(status)) {
        status = entry.deleted ? revokedStatus(status) : activeStatus(status);
        events.push(memberEvent(entry.deleted ? EventType.OrganizationUserRevoked : EventType.OrganizationUserRestored, member));
      }
      if (status === member.status && entry.externalId === member.externalId) continue;
      statements.push(
        db
          .prepare('UPDATE organization_members SET status = ?, external_id = ?, updated_at = ? WHERE id = ? AND organization_id = ?')
          .bind(status, entry.externalId, now, member.id, organizationId)
      );
      member.status = status;
      member.externalId = entry.externalId;
      continue;
    }
    if (entry.deleted) continue;
    const userId = userIds.get(entry.email);
    if (!userId) {
      skipped += 1;
      continue;
    }
    const invited: ExistingMember = {
      id: generateUUID(), userId, email: entry.email, status: MemberStatus.Invited, type: MemberType.User, externalId: entry.externalId,
    };
    statements.push(
      db
        .prepare(
          'INSERT INTO organization_members(id, organization_id, user_id, akey, status, type, access_all, external_id, created_at, updated_at) ' +
          "VALUES(?, ?, ?, '', ?, ?, 0, ?, ?, ?)"
        )
        .bind(invited.id, organizationId, userId, invited.status, invited.type, invited.externalId, now, now)
    );
    members.push(invited);
    byEmail.set(entry.email, invited);
    events.push(memberEvent(EventType.OrganizationUserInvited, invited));
  }

  // Groups: create or rename by external id, then set their members to the listed ones.
  const memberIdByExternalId = new Map(members.filter((m) => m.externalId).map((m) => [m.externalId!, m.id]));
  const groupsByExternalId = new Map((await listGroups(db, organizationId)).filter((g) => g.externalId).map((g) => [g.externalId!, g]));
  const currentGroupMembers = new Map<string, Set<string>>();
  for (const gm of await listGroupMembers(db, organizationId)) {
    if (!currentGroupMembers.has(gm.groupId)) currentGroupMembers.set(gm.groupId, new Set());
    currentGroupMembers.get(gm.groupId)!.add(gm.memberId);
  }
  for (const entry of data.groups) {
    const wanted = new Set(entry.memberExternalIds.map((id) => memberIdByExternalId.get(id)).filter((id): id is string => !!id));
    const group = groupsByExternalId.get(entry.externalId);
    const groupId = group?.id ?? generateUUID();
    const current = currentGroupMembers.get(groupId) ?? new Set<string>();
    const membersChanged = current.size !== wanted.size || [...wanted].some((id) => !current.has(id));
    if (!group) {
      statements.push(
        db
          .prepare('INSERT INTO organization_groups(id, organization_id, name, external_id, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?)')
          .bind(groupId, organizationId, entry.name, entry.externalId, now, now)
      );
      groupsByExternalId.set(entry.externalId, { id: groupId, organizationId, name: entry.name, externalId: entry.externalId, createdAt: now, updatedAt: now });
      events.push({ type: EventType.GroupCreated, organizationId, groupId });
    } else if (group.name !== entry.name || membersChanged) {
      statements.push(
        db.prepare('UPDATE organization_groups SET name = ?, updated_at = ? WHERE id = ? AND organization_id = ?').bind(entry.name, now, groupId, organizationId)
      );
      group.name = entry.name;
      events.push({ type: EventType.GroupUpdated, organizationId, groupId });
    }
    if (!membersChanged) continue;
    statements.push(db.prepare('DELETE FROM group_members WHERE group_id = ?').bind(groupId));
    for (const memberId of wanted) statements.push(insertGroupMember(db, { groupId, memberId }));
    currentGroupMembers.set(groupId, wanted);
  }

  // overwriteExisting: remove members with an external id the import does not list, Owners excepted.
  if (data.overwriteExisting) {
    const listed = new Set(data.members.map((m) => m.externalId));
    for (const member of members) {
      if (!member.externalId || listed.has(member.externalId) || member.type === MemberType.Owner) continue;
      statements.push(db.prepare('DELETE FROM organization_members WHERE id = ? AND organization_id = ?').bind(member.id, organizationId));
      events.push(memberEvent(EventType.OrganizationUserRemoved, member));
    }
  }

  if (statements.length) {
    await db.batch(statements);
    // Every member before removal, so a removed member's clients also sync.
    await touchUsers(db, [...new Set(members.map((m) => m.userId))]);
  }
  await logEvents(env, { userId: null, ip: auditRequestMetadata(request).ip as string | null, deviceIdentifier: null }, events);
  await safeWriteAuditEvent(env, {
    action: 'organization.import',
    category: 'data',
    level: 'info',
    targetType: 'organization',
    targetId: organizationId,
    metadata: { changes: statements.length, events: events.length, skippedUnknownEmails: skipped, ...auditRequestMetadata(request) },
  });
  return new Response(null, { status: 200 });
}
