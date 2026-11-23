// Organization groups: create, update, delete and list them, and set which groups a member is in.
// Vaultwarden's organizations.rs. Groups give their members access to collections; the access
// shows in each member's sync. Admins and owners manage groups, as with Vaultwarden's
// ManageGroupsHeaders; custom roles are not offered.
// - A group has no "access all" flag, which current Bitwarden clients no longer send.
// - GET and PUT /users/{memberId}/groups are Bitwarden routes that Vaultwarden does not serve.
import type { Env } from '../types';
import {
  type Group,
  type GroupAccess,
  deleteGroup,
  getGroup,
  listGroupAccess,
  listGroupMembers,
  listGroups,
  saveGroup,
} from '../services/storage-organization-group-repo';
import { type OrganizationMember, getMemberById, listCollections, listMembersWithUsers, setMemberGroups } from '../services/storage-organization-repo';
import { roleManageError } from '../services/org-access';
import { groupDetailsJson, groupJson } from '../utils/organization-response';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { type EventActor, EventType, logEvents } from '../services/events';
import { accessFlags, isRecord, list, readBody, str, touchOrganization } from './organizations';

const ok = () => new Response(null, { status: 200 });
const GROUP_NOT_FOUND = 'Group not found';

// GET /api/organizations/{id}/groups, GET /api/organizations/{id}/groups/details
export async function handleListGroups(env: Env, organizationId: string, details: boolean): Promise<Response> {
  const [groups, access] = await Promise.all([
    listGroups(env.DB, organizationId),
    details ? listGroupAccess(env.DB, organizationId) : Promise.resolve([]),
  ]);
  return list(groups.map((g) => (details ? groupDetailsJson(g, access.filter((a) => a.groupId === g.id)) : groupJson(g))));
}

// GET /api/organizations/{id}/groups/{groupId}, GET /api/organizations/{id}/groups/{groupId}/details
export async function handleGetGroup(env: Env, organizationId: string, groupId: string, details: boolean): Promise<Response> {
  const group = await getGroup(env.DB, organizationId, groupId);
  if (!group) return errorResponse(GROUP_NOT_FOUND, 400);
  if (!details) return jsonResponse(groupJson(group));
  const access = (await listGroupAccess(env.DB, organizationId)).filter((a) => a.groupId === groupId);
  return jsonResponse(groupDetailsJson(group, access));
}

// GET /api/organizations/{id}/groups/{groupId}/users
// A bare array of member ids, as in Vaultwarden.
export async function handleGetGroupMembers(env: Env, organizationId: string, groupId: string): Promise<Response> {
  if (!(await getGroup(env.DB, organizationId, groupId))) return errorResponse('Group could not be found!', 400);
  const members = await listGroupMembers(env.DB, organizationId);
  return jsonResponse(members.filter((m) => m.groupId === groupId).map((m) => m.memberId));
}

/** A group request's name, collection access and members, all checked against this organization. */
async function readGroupBody(
  request: Request,
  db: D1Database,
  organizationId: string
): Promise<{ name: string; externalId: string | null; access: Omit<GroupAccess, 'groupId'>[]; memberIds: string[] } | Response> {
  const body = await readBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);
  const name = str(body.name);
  if (!name) return errorResponse('name is required', 400);

  const collectionIds = new Set((await listCollections(db, organizationId)).map((c) => c.id));
  // Keyed by collection, so a repeated id keeps its last entry instead of failing the insert.
  const access = new Map<string, Omit<GroupAccess, 'groupId'>>();
  for (const entry of Array.isArray(body.collections) ? body.collections : []) {
    const collectionId = isRecord(entry) ? str(entry.id).toLowerCase() : '';
    if (!isRecord(entry) || !collectionIds.has(collectionId)) return errorResponse('Invalid collection', 400);
    access.set(collectionId, { collectionId, ...accessFlags(entry) });
  }

  const memberIds = new Set((await listMembersWithUsers(db, organizationId)).map((m) => m.id));
  const members = new Set<string>();
  for (const entry of Array.isArray(body.users) ? body.users : []) {
    const memberId = str(entry).toLowerCase();
    if (!memberIds.has(memberId)) return errorResponse('Invalid member', 400);
    members.add(memberId);
  }
  return { name, externalId: str(body.externalId) || null, access: [...access.values()], memberIds: [...members] };
}

async function writeGroup(env: Env, group: Group, request: Request, isNew: boolean, actor: EventActor): Promise<Response> {
  const parsed = await readGroupBody(request, env.DB, group.organizationId);
  if (parsed instanceof Response) return parsed;
  // As in Vaultwarden, the external id is set on create and never changed by an update.
  const saved = { ...group, name: parsed.name, externalId: isNew ? parsed.externalId : group.externalId };
  await saveGroup(env.DB, saved, parsed.access.map((a) => ({ ...a, groupId: group.id })), parsed.memberIds, isNew);
  await touchOrganization(env.DB, group.organizationId);
  // As in Vaultwarden, each member the request names gets an event too.
  await logEvents(env, actor, [
    { type: isNew ? EventType.GroupCreated : EventType.GroupUpdated, organizationId: group.organizationId, groupId: group.id },
    ...parsed.memberIds.map((memberId) => ({ type: EventType.OrganizationUserUpdatedGroups, organizationId: group.organizationId, memberId })),
  ]);
  return jsonResponse(groupJson(saved));
}

// POST /api/organizations/{id}/groups
export async function handleCreateGroup(request: Request, env: Env, organizationId: string, actor: EventActor): Promise<Response> {
  const now = new Date().toISOString();
  return writeGroup(env, { id: generateUUID(), organizationId, name: '', externalId: null, createdAt: now, updatedAt: now }, request, true, actor);
}

// PUT /api/organizations/{id}/groups/{groupId}
// Replaces the group's collection access and members.
export async function handleUpdateGroup(
  request: Request,
  env: Env,
  organizationId: string,
  groupId: string,
  actor: EventActor
): Promise<Response> {
  const group = await getGroup(env.DB, organizationId, groupId);
  if (!group) return errorResponse(GROUP_NOT_FOUND, 400);
  return writeGroup(env, { ...group, updatedAt: new Date().toISOString() }, request, false, actor);
}

// DELETE /api/organizations/{id}/groups/{groupId}
export async function handleDeleteGroup(env: Env, organizationId: string, groupId: string, actor: EventActor): Promise<Response> {
  return handleBulkDeleteGroups(env, organizationId, [groupId], actor);
}

// DELETE /api/organizations/{id}/groups
// Every id is checked before any group is deleted.
export async function handleBulkDeleteGroups(env: Env, organizationId: string, groupIds: string[], actor: EventActor): Promise<Response> {
  const known = new Set((await listGroups(env.DB, organizationId)).map((g) => g.id));
  if (groupIds.some((id) => !known.has(id))) return errorResponse(GROUP_NOT_FOUND, 400);
  for (const id of groupIds) await deleteGroup(env.DB, organizationId, id);
  await touchOrganization(env.DB, organizationId);
  await logEvents(env, actor, groupIds.map((groupId) => ({ type: EventType.GroupDeleted, organizationId, groupId })));
  return ok();
}

export async function readGroupIds(request: Request): Promise<string[]> {
  const body = await readBody(request);
  return Array.isArray(body?.ids) ? body.ids.map((id) => str(id).toLowerCase()) : [];
}

// GET /api/organizations/{id}/users/{memberId}/groups
export async function handleGetMemberGroups(env: Env, caller: OrganizationMember, memberId: string): Promise<Response> {
  if (!(await getMemberById(env.DB, caller.organizationId, memberId))) {
    return errorResponse("The specified user isn't a member of the organization", 400);
  }
  const members = await listGroupMembers(env.DB, caller.organizationId);
  return jsonResponse(members.filter((m) => m.memberId === memberId).map((m) => m.groupId));
}

/** The group ids a request names, or the error when one is not a group of this organization. */
export async function readMemberGroupIds(db: D1Database, organizationId: string, value: unknown): Promise<string[] | string> {
  const known = new Set((await listGroups(db, organizationId)).map((g) => g.id));
  const ids = new Set<string>();
  for (const entry of Array.isArray(value) ? value : []) {
    const id = str(entry).toLowerCase();
    if (!known.has(id)) return 'Group not found in Organization';
    ids.add(id);
  }
  return [...ids];
}

// PUT|POST /api/organizations/{id}/users/{memberId}/groups
// Replaces the groups a member is in.
export async function handleUpdateMemberGroups(
  request: Request,
  env: Env,
  caller: OrganizationMember,
  memberId: string,
  actor: EventActor
): Promise<Response> {
  const body = await readBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);
  const member = await getMemberById(env.DB, caller.organizationId, memberId);
  if (!member) return errorResponse("The specified user isn't a member of the organization", 400);
  const manageError = roleManageError(caller, member.type);
  if (manageError) return errorResponse(manageError, 400);
  const groupIds = await readMemberGroupIds(env.DB, caller.organizationId, body.groupIds);
  if (typeof groupIds === 'string') return errorResponse(groupIds, 400);
  await setMemberGroups(env.DB, member.id, groupIds);
  await touchOrganization(env.DB, caller.organizationId);
  await logEvents(env, actor, [{
    type: EventType.OrganizationUserUpdatedGroups,
    organizationId: member.organizationId,
    memberId: member.id,
    userId: member.userId,
  }]);
  return ok();
}
