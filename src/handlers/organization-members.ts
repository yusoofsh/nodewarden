// Organization member management: invite, accept, confirm, reinvite, role and collection
// changes, removal, and the public keys admins wrap the organization key with.
//
// Vaultwarden's organizations.rs, with mail off: this server sends no email.
// - Inviting an existing account creates an invited row. The invitee accepts it from their own
//   session, so no token is needed or checked. Inviting an unknown email is refused, since
//   nobody could deliver the invite. Vaultwarden instead accepts at once when mail is off,
//   which joins the invitee without their consent.
// - Reinvite only checks that the member is still invited: there is nothing to resend.
// - Custom roles are not offered, so a role is Owner, Admin or User. Owners and Admins have
//   access to every collection; Users get the collections assigned to them.
import type { Env } from '../types';
import { StorageService } from '../services/storage';
import {
  type CollectionAccess,
  type OrganizationMember,
  MemberStatus,
  MemberType,
  deleteMember,
  getMember,
  getMemberById,
  inviteMembers,
  listCollectionAccess,
  listCollections,
  listMembersWithUsers,
  transitionMember,
  updateMemberAccess,
} from '../services/storage-organization-repo';
import { isLastConfirmedOwner, roleManageError } from '../services/org-access';
import { memberDetailsJson } from '../utils/organization-response';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { isRecord, list, readBody, str, touchUsers } from './organizations';

type Json = Record<string, unknown>;
type AccessTemplate = Omit<CollectionAccess, 'memberId'>;
/** A member action's error message, or null on success. Bulk routes report it per member. */
type ActionResult = Promise<string | null>;

const ok = () => new Response(null, { status: 200 });
const ids = (body: Json | null): string[] => (Array.isArray(body?.ids) ? body.ids.map((id) => str(id).toLowerCase()) : []);
const bulkResult = (id: string, error: string | null) => ({ object: 'OrganizationBulkConfirmResponseModel', id, error: error ?? '' });
const isFullAccessRole = (type: number): boolean => type === MemberType.Owner || type === MemberType.Admin;

function parseRole(value: unknown): number | null {
  const type = typeof value === 'number' ? value : typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : NaN;
  return type === MemberType.Owner || type === MemberType.Admin || type === MemberType.User ? type : null;
}

/** The role and collection access a request asks for, checked against this organization and the caller. */
async function readRoleAndAccess(
  db: D1Database,
  caller: OrganizationMember,
  body: Json
): Promise<{ type: number; accessAll: boolean; access: AccessTemplate[] } | string> {
  const type = parseRole(body.type);
  if (type === null) return 'Invalid type';
  const manageError = roleManageError(caller, type);
  if (manageError) return manageError;
  if (Array.isArray(body.groups) && body.groups.length > 0) return 'Invalid group';

  const collectionIds = new Set((await listCollections(db, caller.organizationId)).map((c) => c.id));
  const access: AccessTemplate[] = [];
  for (const entry of Array.isArray(body.collections) ? body.collections : []) {
    const collectionId = isRecord(entry) ? str(entry.id).toLowerCase() : '';
    if (!isRecord(entry) || !collectionIds.has(collectionId)) return 'Collection not found in Organization';
    access.push({ collectionId, readOnly: entry.readOnly === true, hidePasswords: entry.hidePasswords === true, manage: entry.manage === true });
  }
  const accessAll = isFullAccessRole(type);
  return { type, accessAll, access: accessAll ? [] : access };
}

const withMember = (templates: AccessTemplate[], memberId: string): CollectionAccess[] => templates.map((a) => ({ ...a, memberId }));

// POST /api/organizations/{id}/users/invite
// Every email is checked before any row is written, so a refused request leaves nothing behind.
export async function handleInviteMembers(request: Request, env: Env, caller: OrganizationMember): Promise<Response> {
  const body = await readBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);
  const emails = [...new Set((Array.isArray(body.emails) ? body.emails : []).map((e) => str(e).toLowerCase()).filter(Boolean))];
  if (emails.length === 0) return errorResponse('At least one email is required', 400);
  const parsed = await readRoleAndAccess(env.DB, caller, body);
  if (typeof parsed === 'string') return errorResponse(parsed, 400);

  const storage = new StorageService(env.DB);
  const now = new Date().toISOString();
  const members: OrganizationMember[] = [];
  for (const email of emails) {
    const user = await storage.getUser(email);
    if (!user) return errorResponse(`User does not exist: ${email}`, 400);
    if (await getMember(env.DB, caller.organizationId, user.id)) return errorResponse(`User already in organization: ${email}`, 400);
    members.push({
      id: generateUUID(),
      organizationId: caller.organizationId,
      userId: user.id,
      akey: '',
      status: MemberStatus.Invited,
      type: parsed.type,
      accessAll: parsed.accessAll,
      resetPasswordKey: null,
      createdAt: now,
      updatedAt: now,
    });
  }
  await inviteMembers(env.DB, members, members.flatMap((m) => withMember(parsed.access, m.id)));
  return ok();
}

async function reinvite(env: Env, caller: OrganizationMember, memberId: string): ActionResult {
  const member = await getMemberById(env.DB, caller.organizationId, memberId);
  if (!member) return "The user hasn't been invited to the organization.";
  if (member.status !== MemberStatus.Invited) return 'The user is already accepted or confirmed to the organization';
  return null;
}

async function confirm(env: Env, caller: OrganizationMember, memberId: string, key: string): ActionResult {
  if (!key || !memberId) return 'Key or UserId is not set, unable to process request';
  const member = await getMemberById(env.DB, caller.organizationId, memberId);
  if (!member) return "The specified user isn't a member of the organization";
  if (!(await transitionMember(env.DB, caller.organizationId, memberId, MemberStatus.Accepted, MemberStatus.Confirmed, key))) {
    return 'User in invalid state';
  }
  await touchUsers(env.DB, [member.userId]);
  return null;
}

async function remove(env: Env, caller: OrganizationMember, memberId: string): ActionResult {
  const member = await getMemberById(env.DB, caller.organizationId, memberId);
  if (!member) return "User to delete isn't member of the organization";
  if (member.id === caller.id) return 'You cannot remove yourself';
  const manageError = roleManageError(caller, member.type);
  if (manageError) return manageError;
  if (await isLastConfirmedOwner(env.DB, member)) return "Can't delete the last owner";
  await deleteMember(env.DB, member.id);
  await touchUsers(env.DB, [member.userId]);
  return null;
}

const single = async (result: ActionResult) => {
  const error = await result;
  return error ? errorResponse(error, 400) : ok();
};

// POST /api/organizations/{id}/users/{memberId}/reinvite
export const handleReinviteMember = (env: Env, caller: OrganizationMember, memberId: string) => single(reinvite(env, caller, memberId));

// POST /api/organizations/{id}/users/reinvite
export async function handleBulkReinviteMembers(request: Request, env: Env, caller: OrganizationMember): Promise<Response> {
  const results = [];
  for (const id of ids(await readBody(request))) results.push(bulkResult(id, await reinvite(env, caller, id)));
  return list(results);
}

// POST /api/organizations/{id}/users/{memberId}/confirm
export async function handleConfirmMember(request: Request, env: Env, caller: OrganizationMember, memberId: string): Promise<Response> {
  return single(confirm(env, caller, memberId, str((await readBody(request))?.key)));
}

// POST /api/organizations/{id}/users/confirm
export async function handleBulkConfirmMembers(request: Request, env: Env, caller: OrganizationMember): Promise<Response> {
  const body = await readBody(request);
  const results = [];
  for (const entry of Array.isArray(body?.keys) ? body.keys : []) {
    const id = isRecord(entry) ? str(entry.id).toLowerCase() : '';
    results.push(bulkResult(id, await confirm(env, caller, id, isRecord(entry) ? str(entry.key) : '')));
  }
  return list(results);
}

// DELETE /api/organizations/{id}/users/{memberId}
export const handleDeleteMember = (env: Env, caller: OrganizationMember, memberId: string) => single(remove(env, caller, memberId));

// DELETE /api/organizations/{id}/users
export async function handleBulkDeleteMembers(request: Request, env: Env, caller: OrganizationMember): Promise<Response> {
  const results = [];
  for (const id of ids(await readBody(request))) results.push(bulkResult(id, await remove(env, caller, id)));
  return list(results);
}

// POST /api/organizations/{id}/users/{memberId}/accept
// Not authorized by org-access: the caller is not confirmed yet. Only the invited account can
// accept, and any other caller gets the same 404 as a missing organization.
export async function handleAcceptInvite(env: Env, userId: string, organizationId: string, memberId: string): Promise<Response> {
  const member = await getMemberById(env.DB, organizationId, memberId);
  if (!member || member.userId !== userId) return errorResponse('Organization not found', 404);
  if (!(await transitionMember(env.DB, organizationId, memberId, MemberStatus.Invited, MemberStatus.Accepted))) {
    return errorResponse('User already accepted the invitation', 400);
  }
  await touchUsers(env.DB, [userId]);
  return ok();
}

// GET /api/organizations/{id}/users/{memberId}?includeCollections=true
export async function handleGetMember(request: Request, env: Env, caller: OrganizationMember, memberId: string): Promise<Response> {
  const member = (await listMembersWithUsers(env.DB, caller.organizationId)).find((m) => m.id === memberId);
  if (!member) return errorResponse("The specified user isn't a member of the organization", 400);
  const includeCollections = /^true$/i.test(new URL(request.url).searchParams.get('includeCollections') || '');
  const access = includeCollections ? (await listCollectionAccess(env.DB, caller.organizationId)).filter((a) => a.memberId === memberId) : null;
  return jsonResponse({ ...memberDetailsJson(member, access), object: 'organizationUserDetails' });
}

// PUT /api/organizations/{id}/users/{memberId}
// Sets the member's role and replaces its collection access.
export async function handleUpdateMember(request: Request, env: Env, caller: OrganizationMember, memberId: string): Promise<Response> {
  const body = await readBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);
  const member = await getMemberById(env.DB, caller.organizationId, memberId);
  if (!member) return errorResponse("The specified user isn't member of the organization", 400);
  const currentError = roleManageError(caller, member.type);
  if (currentError) return errorResponse(currentError, 400);
  const parsed = await readRoleAndAccess(env.DB, caller, body);
  if (typeof parsed === 'string') return errorResponse(parsed, 400);

  if (parsed.type !== member.type) {
    if (await isLastConfirmedOwner(env.DB, member)) return errorResponse("Can't delete the last owner", 400);
    if (member.id === caller.id) return errorResponse('You cannot change your own role', 400);
  }
  await updateMemberAccess(env.DB, member, parsed.type, parsed.accessAll, withMember(parsed.access, member.id));
  await touchUsers(env.DB, [member.userId]);
  return ok();
}

// POST /api/organizations/{id}/users/public-keys
// Ids that are not members of this organization are left out, as in Vaultwarden.
export async function handleMemberPublicKeys(request: Request, env: Env, caller: OrganizationMember): Promise<Response> {
  const storage = new StorageService(env.DB);
  const data = [];
  for (const id of ids(await readBody(request))) {
    const member = await getMemberById(env.DB, caller.organizationId, id);
    const user = member ? await storage.getUserById(member.userId) : null;
    if (member && user) data.push({ object: 'organizationUserPublicKeyResponseModel', id: member.id, userId: user.id, key: user.publicKey });
  }
  return list(data);
}
