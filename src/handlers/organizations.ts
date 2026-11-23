import type { Env } from '../types';
import { AuthService } from '../services/auth';
import { StorageService } from '../services/storage';
import { updateRevisionDate } from '../services/storage-revision-repo';
import {
  type Collection,
  type CollectionAccess,
  type OrganizationMember,
  MemberStatus,
  MemberType,
  createOrganization,
  deleteCollection,
  deleteMember,
  deleteOrganization,
  getCollection,
  getOrganization,
  listCollectionAccess,
  listCollections,
  listCollectionsForUser,
  listMembersWithUsers,
  listMemberUserIds,
  saveCollection,
  updateOrganization,
} from '../services/storage-organization-repo';
import { isAdminOrOwner, isLastConfirmedOwner } from '../services/org-access';
import {
  collectionDetailsJson,
  collectionJson,
  collectionMemberAccessJson,
  memberDetailsJson,
  organizationJson,
} from '../utils/organization-response';
import { errorResponse, jsonResponse } from '../utils/response';
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

async function touchOrganization(db: D1Database, organizationId: string): Promise<void> {
  await touchUsers(db, await listMemberUserIds(db, organizationId));
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
export async function handleUpdateOrganization(request: Request, env: Env, organizationId: string): Promise<Response> {
  const body = await readBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);
  const name = str(body.name);
  const billingEmail = str(body.billingEmail).toLowerCase();
  if (!name || !billingEmail) return errorResponse('name and billingEmail are required', 400);

  await updateOrganization(env.DB, organizationId, name, billingEmail);
  await touchOrganization(env.DB, organizationId);
  return handleGetOrganization(env, organizationId);
}

// DELETE /api/organizations/{id}
// Deleting cascades to members, collections and collection access.
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
  await deleteOrganization(env.DB, organizationId);
  await touchUsers(env.DB, memberUserIds);
  return new Response(null, { status: 200 });
}

// POST /api/organizations/{id}/leave
export async function handleLeaveOrganization(env: Env, member: OrganizationMember): Promise<Response> {
  if (await isLastConfirmedOwner(env.DB, member)) {
    return errorResponse("The last owner can't leave", 400);
  }
  await deleteMember(env.DB, member.id);
  await touchUsers(env.DB, [member.userId]);
  return new Response(null, { status: 200 });
}

// GET /api/organizations/{id}/public-key, GET /api/organizations/{id}/keys
export async function handleGetOrganizationPublicKey(env: Env, organizationId: string): Promise<Response> {
  const organization = await getOrganization(env.DB, organizationId);
  if (!organization) return errorResponse('Organization not found', 404);
  return jsonResponse({ object: 'organizationPublicKey', publicKey: organization.publicKey });
}

// GET /api/organizations/{id}/users?includeCollections=true
export async function handleGetOrganizationMembers(request: Request, env: Env, organizationId: string): Promise<Response> {
  const includeCollections = /^true$/i.test(new URL(request.url).searchParams.get('includeCollections') || '');
  const [members, access] = await Promise.all([
    listMembersWithUsers(env.DB, organizationId),
    includeCollections ? listCollectionAccess(env.DB, organizationId) : Promise.resolve([]),
  ]);
  return list(
    members.map((member) =>
      memberDetailsJson(member, includeCollections ? access.filter((a) => a.memberId === member.id) : null)
    )
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

// GET /api/organizations/{id}/collections/details
export async function handleGetOrganizationCollectionDetails(
  env: Env,
  viewer: OrganizationMember,
  organizationId: string
): Promise<Response> {
  const [collections, access, members] = await Promise.all([
    listCollections(env.DB, organizationId),
    listCollectionAccess(env.DB, organizationId),
    listMembersWithUsers(env.DB, organizationId),
  ]);
  const typeByMember = new Map(members.map((m) => [m.id, m.type]));
  const manageAll = members
    .filter((m) => m.status === MemberStatus.Confirmed && isAdminOrOwner(m))
    .map((m) => ({ id: m.id, readOnly: false, hidePasswords: false, manage: true }));
  const fullAccess = viewer.accessAll || isAdminOrOwner(viewer);

  const data = collections.map((collection) => {
    const rows = access.filter((a) => a.collectionId === collection.id);
    const own = rows.find((a) => a.memberId === viewer.id) ?? null;
    return {
      ...collectionDetailsJson(collection, viewer, own),
      assigned: fullAccess || own !== null,
      users: [...rows.map((a) => collectionMemberAccessJson(a, typeByMember.get(a.memberId) ?? MemberType.User)), ...manageAll],
      groups: [],
      object: 'collectionAccessDetails',
      unmanaged: false,
    };
  });
  return list(data);
}

// Reads a collection request body. Member ids must belong to this organization; members with
// access to every collection need no row, as in Vaultwarden.
async function readCollectionBody(
  request: Request,
  db: D1Database,
  organizationId: string
): Promise<{ name: string; externalId: string | null; access: Omit<CollectionAccess, 'collectionId'>[] } | Response> {
  const body = await readBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);
  const name = str(body.name);
  if (!name) return errorResponse('name is required', 400);
  if (Array.isArray(body.groups) && body.groups.length > 0) return errorResponse('Invalid group', 400);

  const members = new Map((await listMembersWithUsers(db, organizationId)).map((m) => [m.id, m]));
  const access: Omit<CollectionAccess, 'collectionId'>[] = [];
  for (const entry of Array.isArray(body.users) ? body.users : []) {
    const member = isRecord(entry) ? members.get(str(entry.id).toLowerCase()) : undefined;
    if (!member || !isRecord(entry)) return errorResponse('Invalid member', 400);
    if (member.accessAll) continue;
    access.push({ memberId: member.id, readOnly: entry.readOnly === true, hidePasswords: entry.hidePasswords === true, manage: entry.manage === true });
  }
  return { name, externalId: str(body.externalId) || null, access };
}

async function writeCollection(
  env: Env,
  viewer: OrganizationMember,
  collection: Collection,
  access: Omit<CollectionAccess, 'collectionId'>[],
  isNew: boolean
): Promise<Response> {
  const rows = access.map((a) => ({ ...a, collectionId: collection.id }));
  await saveCollection(env.DB, collection, rows, isNew);
  await touchOrganization(env.DB, collection.organizationId);
  return jsonResponse(collectionDetailsJson(collection, viewer, rows.find((a) => a.memberId === viewer.id) ?? null));
}

// POST /api/organizations/{id}/collections
export async function handleCreateCollection(
  request: Request,
  env: Env,
  viewer: OrganizationMember,
  organizationId: string
): Promise<Response> {
  const parsed = await readCollectionBody(request, env.DB, organizationId);
  if (parsed instanceof Response) return parsed;
  const now = new Date().toISOString();
  const collection = { id: generateUUID(), organizationId, name: parsed.name, externalId: parsed.externalId, createdAt: now, updatedAt: now };
  return writeCollection(env, viewer, collection, parsed.access, true);
}

// PUT /api/organizations/{id}/collections/{collectionId}
export async function handleUpdateCollection(
  request: Request,
  env: Env,
  viewer: OrganizationMember,
  organizationId: string,
  collectionId: string
): Promise<Response> {
  const existing = await getCollection(env.DB, organizationId, collectionId);
  if (!existing) return errorResponse('Collection not found', 404);
  const parsed = await readCollectionBody(request, env.DB, organizationId);
  if (parsed instanceof Response) return parsed;
  const collection = { ...existing, name: parsed.name, externalId: parsed.externalId, updatedAt: new Date().toISOString() };
  return writeCollection(env, viewer, collection, parsed.access, false);
}

// DELETE /api/organizations/{id}/collections/{collectionId}
export async function handleDeleteCollection(env: Env, organizationId: string, collectionId: string): Promise<Response> {
  if (!(await getCollection(env.DB, organizationId, collectionId))) return errorResponse('Collection not found', 404);
  await deleteCollection(env.DB, organizationId, collectionId);
  await touchOrganization(env.DB, organizationId);
  return new Response(null, { status: 200 });
}
