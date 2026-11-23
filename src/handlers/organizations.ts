import type { Env } from '../types';
import { notifyUserVaultSync } from '../durable/notifications-hub';
import { AuthService } from '../services/auth';
import { StorageService } from '../services/storage';
import { updateRevisionDate } from '../services/storage-revision-repo';
import { listOrgCipherIds } from '../services/storage-org-cipher-repo';
import { deleteAllAttachmentsForCiphers } from './attachments';
import {
  type Collection,
  type CollectionAccess,
  type OrganizationMember,
  MemberStatus,
  MemberType,
  addCollectionAccess,
  createOrganization,
  deleteCollection,
  deleteCollections,
  deleteMember,
  deleteOrganization,
  getCollection,
  getOrganization,
  listCollectionAccess,
  listCollections,
  listCollectionsForUser,
  listMembershipsByUser,
  listMembersWithUsers,
  listMemberUserIds,
  saveCollection,
  updateOrganization,
} from '../services/storage-organization-repo';
import { type GroupAccess, listGroupAccess, listGroupMembers, listGroups } from '../services/storage-organization-group-repo';
import { isAdminOrOwner, isLastConfirmedOwner } from '../services/org-access';
import {
  collectionDetailsJson,
  collectionJson,
  collectionMemberAccessJson,
  groupAccessJson,
  memberDetailsJson,
  organizationJson,
} from '../utils/organization-response';
import { errorResponse, jsonResponse } from '../utils/response';
import { type EventActor, EventType, logEvents } from '../services/events';
import { generateUUID } from '../utils/uuid';

type Json = Record<string, unknown>;

export const isRecord = (value: unknown): value is Json => !!value && typeof value === 'object' && !Array.isArray(value);
export const str = (value: unknown): string => (typeof value === 'string' ? value.trim() : '');
export const list = (data: unknown[]) => jsonResponse({ data, object: 'list', continuationToken: null });

export async function readBody(request: Request): Promise<Json | null> {
  try {
    const body = await request.json();
    return isRecord(body) ? body : null;
  } catch {
    return null;
  }
}

// Sync responses are cached per revision date, so every member must see a new one.
export async function touchUsers(db: D1Database, userIds: string[]): Promise<void> {
  for (const userId of userIds) await updateRevisionDate(db, userId);
}

export async function touchOrganization(db: D1Database, organizationId: string): Promise<void> {
  await touchUsers(db, await listMemberUserIds(db, organizationId));
}

/**
 * After an organization cipher changes: a new revision date for every member, so no cached sync
 * survives (a member who just lost access included), and a vault sync push to each.
 */
export async function touchOrganizationVault(env: Env, organizationId: string, contextId: string | null): Promise<void> {
  for (const userId of await listMemberUserIds(env.DB, organizationId)) {
    notifyUserVaultSync(env, userId, await updateRevisionDate(env.DB, userId), contextId);
  }
}

// POST /api/organizations
export async function handleCreateOrganization(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await readBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);
  const name = str(body.name);
  const billingEmail = str(body.billingEmail).toLowerCase();
  const collectionName = str(body.collectionName);
  const key = str(body.key);
  if (!name || !billingEmail || !collectionName || !key) {
    return errorResponse('name, billingEmail, collectionName and key are required', 400);
  }
  const keys = isRecord(body.keys) ? body.keys : null;

  const now = new Date().toISOString();
  const organization = {
    id: generateUUID(),
    name,
    billingEmail,
    privateKey: str(keys?.encryptedPrivateKey) || null,
    publicKey: str(keys?.publicKey) || null,
    createdAt: now,
    updatedAt: now,
  };
  await createOrganization(
    env.DB,
    organization,
    {
      id: generateUUID(),
      organizationId: organization.id,
      userId,
      akey: key,
      status: MemberStatus.Confirmed,
      type: MemberType.Owner,
      accessAll: true,
      resetPasswordKey: null,
      createdAt: now,
      updatedAt: now,
    },
    { id: generateUUID(), organizationId: organization.id, name: collectionName, externalId: null, createdAt: now, updatedAt: now }
  );
  await touchUsers(env.DB, [userId]);
  return jsonResponse(organizationJson(organization));
}

// GET /api/organizations/{id}
export async function handleGetOrganization(env: Env, organizationId: string): Promise<Response> {
  const organization = await getOrganization(env.DB, organizationId);
  if (!organization) return errorResponse('Organization not found', 404);
  return jsonResponse(organizationJson(organization));
}

// PUT /api/organizations/{id}
export async function handleUpdateOrganization(request: Request, env: Env, organizationId: string, actor: EventActor): Promise<Response> {
  const body = await readBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);
  const name = str(body.name);
  const billingEmail = str(body.billingEmail).toLowerCase();
  if (!name || !billingEmail) return errorResponse('name and billingEmail are required', 400);

  await updateOrganization(env.DB, organizationId, name, billingEmail);
  await touchOrganization(env.DB, organizationId);
  await logEvents(env, actor, [{ type: EventType.OrganizationUpdated, organizationId }]);
  return handleGetOrganization(env, organizationId);
}

// DELETE /api/organizations/{id}
// Deleting cascades to members, collections, collection access and the organization's ciphers.
export async function handleDeleteOrganization(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string
): Promise<Response> {
  const body = await readBody(request);
  const masterPasswordHash = str(body?.masterPasswordHash);
  if (!masterPasswordHash) return errorResponse('masterPasswordHash is required', 400);
  const user = await new StorageService(env.DB).getUserById(userId);
  if (!user || !(await new AuthService(env).verifyPassword(masterPasswordHash, user.masterPasswordHash, user.email))) {
    return errorResponse('Invalid password', 400);
  }

  const memberUserIds = await listMemberUserIds(env.DB, organizationId);
  // The organization's ciphers and their attachment rows cascade; their files do not.
  await deleteAllAttachmentsForCiphers(env, await listOrgCipherIds(env.DB, organizationId));
  await deleteOrganization(env.DB, organizationId);
  await touchUsers(env.DB, memberUserIds);
  return new Response(null, { status: 200 });
}

// POST /api/organizations/{id}/leave
export async function handleLeaveOrganization(env: Env, member: OrganizationMember, actor: EventActor): Promise<Response> {
  if (await isLastConfirmedOwner(env.DB, member)) {
    return errorResponse("The last owner can't leave", 400);
  }
  await deleteMember(env.DB, member.id);
  await logEvents(env, actor, [
    { type: EventType.OrganizationUserLeft, organizationId: member.organizationId, memberId: member.id, userId: member.userId },
  ]);
  await touchUsers(env.DB, [member.userId]);
  return new Response(null, { status: 200 });
}

// GET /api/organizations/{id}/public-key, GET /api/organizations/{id}/keys
export async function handleGetOrganizationPublicKey(env: Env, organizationId: string): Promise<Response> {
  const organization = await getOrganization(env.DB, organizationId);
  if (!organization) return errorResponse('Organization not found', 404);
  return jsonResponse({ object: 'organizationPublicKey', publicKey: organization.publicKey });
}

export const queryFlag = (request: Request, name: string): boolean => /^true$/i.test(new URL(request.url).searchParams.get(name) || '');

// GET /api/organizations/{id}/users?includeCollections=true&includeGroups=true
export async function handleGetOrganizationMembers(request: Request, env: Env, organizationId: string): Promise<Response> {
  const includeCollections = queryFlag(request, 'includeCollections');
  const includeGroups = queryFlag(request, 'includeGroups');
  const [members, access, groupMembers] = await Promise.all([
    listMembersWithUsers(env.DB, organizationId),
    includeCollections ? listCollectionAccess(env.DB, organizationId) : Promise.resolve([]),
    includeGroups ? listGroupMembers(env.DB, organizationId) : Promise.resolve([]),
  ]);
  return list(
    members.map((member) =>
      memberDetailsJson(
        member,
        includeCollections ? access.filter((a) => a.memberId === member.id) : null,
        groupMembers.filter((g) => g.memberId === member.id).map((g) => g.groupId)
      )
    )
  );
}

// GET /api/organizations/invitations
// Not a Bitwarden route. This server sends no invite email, so an invitee finds the member id
// to accept here: the caller's invited memberships, with the organization's name.
export async function handleGetPendingInvitations(env: Env, userId: string): Promise<Response> {
  const invited = await listMembershipsByUser(env.DB, userId, [MemberStatus.Invited]);
  return list(
    invited.map(({ member, organization }) => ({
      id: member.id,
      organizationId: organization.id,
      organizationName: organization.name,
      type: member.type,
      status: member.status,
      object: 'organizationInvitation',
    }))
  );
}

// GET /api/collections
// Every collection the caller can see, across organizations.
export async function handleGetUserCollections(env: Env, userId: string): Promise<Response> {
  const rows = await listCollectionsForUser(env.DB, userId);
  return list(rows.map((row) => collectionJson(row.collection)));
}

// GET /api/organizations/{id}/collections
export async function handleGetOrganizationCollections(env: Env, organizationId: string): Promise<Response> {
  const collections = await listCollections(env.DB, organizationId);
  return list(collections.map(collectionJson));
}

// GET /api/organizations/{id}/collections/details, and with a collection id its /details
// The collections with their member and group access, as the viewer sees them.
async function collectionAccessDetails(env: Env, viewer: OrganizationMember, organizationId: string, collectionId?: string) {
  const [allCollections, access, members, groupAccess, groupMembers] = await Promise.all([
    listCollections(env.DB, organizationId),
    listCollectionAccess(env.DB, organizationId),
    listMembersWithUsers(env.DB, organizationId),
    listGroupAccess(env.DB, organizationId),
    listGroupMembers(env.DB, organizationId),
  ]);
  const collections = collectionId ? allCollections.filter((c) => c.id === collectionId) : allCollections;
  const viewerGroups = new Set(groupMembers.filter((g) => g.memberId === viewer.id).map((g) => g.groupId));
  const typeByMember = new Map(members.map((m) => [m.id, m.type]));
  const manageAll = members
    .filter((m) => m.status === MemberStatus.Confirmed && isAdminOrOwner(m))
    .map((m) => ({ id: m.id, readOnly: false, hidePasswords: false, manage: true }));
  const fullAccess = viewer.accessAll || isAdminOrOwner(viewer);

  return collections.map((collection) => {
    const rows = access.filter((a) => a.collectionId === collection.id);
    const own = rows.find((a) => a.memberId === viewer.id) ?? null;
    const groups = groupAccess.filter((a) => a.collectionId === collection.id);
    return {
      ...collectionDetailsJson(collection, viewer, own),
      assigned: fullAccess || own !== null || groups.some((a) => viewerGroups.has(a.groupId)),
      users: [...rows.map((a) => collectionMemberAccessJson(a, typeByMember.get(a.memberId) ?? MemberType.User)), ...manageAll],
      groups: groups.map(groupAccessJson),
      object: 'collectionAccessDetails',
      unmanaged: false,
    };
  });
}

export async function handleGetOrganizationCollectionDetails(
  env: Env,
  viewer: OrganizationMember,
  organizationId: string
): Promise<Response> {
  return list(await collectionAccessDetails(env, viewer, organizationId));
}

// GET /api/organizations/{id}/collections/{collectionId}/details
export async function handleGetCollectionDetails(
  env: Env,
  viewer: OrganizationMember,
  organizationId: string,
  collectionId: string
): Promise<Response> {
  const [details] = await collectionAccessDetails(env, viewer, organizationId, collectionId);
  return details ? jsonResponse(details) : errorResponse('Collection not found', 400);
}

// GET /api/organizations/{id}/collections/{collectionId}/users
// The members assigned to the collection directly. As in Vaultwarden, a bare array.
export async function handleGetCollectionUsers(env: Env, organizationId: string, collectionId: string): Promise<Response> {
  if (!(await getCollection(env.DB, organizationId, collectionId))) return errorResponse('Collection not found in Organization', 400);
  const rows = (await listCollectionAccess(env.DB, organizationId)).filter((a) => a.collectionId === collectionId);
  return jsonResponse(rows.map((a) => ({ id: a.memberId, readOnly: a.readOnly, hidePasswords: a.hidePasswords, manage: a.manage })));
}

type AccessLists = { access: Omit<CollectionAccess, 'collectionId'>[]; groupAccess: Omit<GroupAccess, 'collectionId'>[] };

// Reads the `users` and `groups` of a collection request body. Member and group ids must belong to
// this organization; members with access to every collection need no row, as in Vaultwarden.
async function readAccessLists(body: Json, db: D1Database, organizationId: string): Promise<AccessLists | Response> {
  const groupIds = new Set((await listGroups(db, organizationId)).map((g) => g.id));
  // Keyed by group, so a repeated id keeps its last entry instead of failing the insert.
  const groupAccess = new Map<string, Omit<GroupAccess, 'collectionId'>>();
  for (const entry of Array.isArray(body.groups) ? body.groups : []) {
    const groupId = isRecord(entry) ? str(entry.id).toLowerCase() : '';
    if (!isRecord(entry) || !groupIds.has(groupId)) return errorResponse('Invalid group', 400);
    groupAccess.set(groupId, { groupId, ...accessFlags(entry) });
  }

  const members = new Map((await listMembersWithUsers(db, organizationId)).map((m) => [m.id, m]));
  const access = new Map<string, Omit<CollectionAccess, 'collectionId'>>();
  for (const entry of Array.isArray(body.users) ? body.users : []) {
    const member = isRecord(entry) ? members.get(str(entry.id).toLowerCase()) : undefined;
    if (!member || !isRecord(entry)) return errorResponse('Invalid member', 400);
    if (member.accessAll) continue;
    access.set(member.id, { memberId: member.id, ...accessFlags(entry) });
  }
  return { access: [...access.values()], groupAccess: [...groupAccess.values()] };
}

// Reads a collection request body.
async function readCollectionBody(
  request: Request,
  db: D1Database,
  organizationId: string
): Promise<({ name: string; externalId: string | null } & AccessLists) | Response> {
  const body = await readBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);
  const name = str(body.name);
  if (!name) return errorResponse('name is required', 400);
  const lists = await readAccessLists(body, db, organizationId);
  if (lists instanceof Response) return lists;
  return { name, externalId: str(body.externalId) || null, ...lists };
}

export const accessFlags = (entry: Json) => ({
  readOnly: entry.readOnly === true,
  hidePasswords: entry.hidePasswords === true,
  manage: entry.manage === true,
});

async function writeCollection(
  env: Env,
  viewer: OrganizationMember,
  collection: Collection,
  parsed: AccessLists,
  isNew: boolean,
  actor: EventActor
): Promise<Response> {
  const rows = parsed.access.map((a) => ({ ...a, collectionId: collection.id }));
  const groupRows = parsed.groupAccess.map((a) => ({ ...a, collectionId: collection.id }));
  await saveCollection(env.DB, collection, rows, groupRows, isNew);
  await touchOrganization(env.DB, collection.organizationId);
  await logEvents(env, actor, [{
    type: isNew ? EventType.CollectionCreated : EventType.CollectionUpdated,
    organizationId: collection.organizationId,
    collectionId: collection.id,
  }]);
  return jsonResponse(collectionDetailsJson(collection, viewer, rows.find((a) => a.memberId === viewer.id) ?? null));
}

// POST /api/organizations/{id}/collections
export async function handleCreateCollection(
  request: Request,
  env: Env,
  viewer: OrganizationMember,
  organizationId: string,
  actor: EventActor
): Promise<Response> {
  const parsed = await readCollectionBody(request, env.DB, organizationId);
  if (parsed instanceof Response) return parsed;
  const now = new Date().toISOString();
  const collection = { id: generateUUID(), organizationId, name: parsed.name, externalId: parsed.externalId, createdAt: now, updatedAt: now };
  return writeCollection(env, viewer, collection, parsed, true, actor);
}

// PUT /api/organizations/{id}/collections/{collectionId}
export async function handleUpdateCollection(
  request: Request,
  env: Env,
  viewer: OrganizationMember,
  organizationId: string,
  collectionId: string,
  actor: EventActor
): Promise<Response> {
  const existing = await getCollection(env.DB, organizationId, collectionId);
  if (!existing) return errorResponse('Collection not found', 404);
  const parsed = await readCollectionBody(request, env.DB, organizationId);
  if (parsed instanceof Response) return parsed;
  const collection = { ...existing, name: parsed.name, externalId: parsed.externalId, updatedAt: new Date().toISOString() };
  return writeCollection(env, viewer, collection, parsed, false, actor);
}

// DELETE /api/organizations/{id}/collections/{collectionId}
export async function handleDeleteCollection(env: Env, organizationId: string, collectionId: string, actor: EventActor): Promise<Response> {
  if (!(await getCollection(env.DB, organizationId, collectionId))) return errorResponse('Collection not found', 404);
  await deleteCollection(env.DB, organizationId, collectionId);
  await touchOrganization(env.DB, organizationId);
  await logEvents(env, actor, [{ type: EventType.CollectionDeleted, organizationId, collectionId }]);
  return new Response(null, { status: 200 });
}

const collectionIdList = (value: unknown): string[] => (Array.isArray(value) ? value.map((id) => str(id).toLowerCase()) : []);

// POST /api/organizations/{id}/collections/bulk-access
// Adds the listed members and groups to every listed collection, keeping their other assignments.
// As in Bitwarden, missing or repeated collections are a 404, checked before the members and groups.
export async function handleBulkCollectionAccess(request: Request, env: Env, organizationId: string, actor: EventActor): Promise<Response> {
  const body = await readBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);
  const collectionIds = collectionIdList(body.collectionIds);
  const known = new Set((await listCollections(env.DB, organizationId)).map((c) => c.id));
  if (!collectionIds.length || new Set(collectionIds).size !== collectionIds.length || collectionIds.some((id) => !known.has(id))) {
    return errorResponse('One or more collections not found.', 404);
  }
  const lists = await readAccessLists(body, env.DB, organizationId);
  if (lists instanceof Response) return lists;

  await addCollectionAccess(env.DB, organizationId, collectionIds, lists.access, lists.groupAccess);
  await touchOrganization(env.DB, organizationId);
  await logEvents(env, actor, collectionIds.map((collectionId) => ({ type: EventType.CollectionUpdated, organizationId, collectionId })));
  return new Response(null, { status: 200 });
}

// DELETE /api/organizations/{id}/collections
// Every id must be a collection of this organization, or nothing is deleted.
export async function handleBulkDeleteCollections(request: Request, env: Env, organizationId: string, actor: EventActor): Promise<Response> {
  const ids = [...new Set(collectionIdList((await readBody(request))?.ids))];
  const known = new Set((await listCollections(env.DB, organizationId)).map((c) => c.id));
  if (ids.some((id) => !known.has(id))) return errorResponse('Collection not found', 400);
  await deleteCollections(env.DB, organizationId, ids);
  await touchOrganization(env.DB, organizationId);
  await logEvents(env, actor, ids.map((collectionId) => ({ type: EventType.CollectionDeleted, organizationId, collectionId })));
  return new Response(null, { status: 200 });
}
