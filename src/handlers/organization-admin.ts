// Organization keys, export, API key, account recovery and the billing and plan routes the clients
// read, after Vaultwarden's organizations.rs.
//
// Account recovery works without mail here. Vaultwarden refuses it on an instance without mail, since
// it emails the member whose password an admin resets; this server sends no email, so the member
// learns of it from the event log and the logout. The Account recovery administration policy must be
// enabled, as in Vaultwarden.
import type { Env } from '../types';
import { AuthService } from '../services/auth';
import { StorageService } from '../services/storage';
import {
  type OrganizationMember,
  MemberStatus,
  MemberType,
  getMemberById,
  getOrganization,
  getOrganizationApiKey,
  listCollections,
  setMemberResetPasswordKey,
  setOrganizationApiKey,
  setOrganizationKeys,
} from '../services/storage-organization-repo';
import { listOrgCiphers } from '../services/storage-org-cipher-repo';
import { getPolicy } from '../services/storage-organization-policy-repo';
import { authorizeInvitee, isOwner } from '../services/org-access';
import { type EventActor, EventType, logEvents } from '../services/events';
import { collectionJson } from '../utils/organization-response';
import { errorResponse, jsonResponse } from '../utils/response';
import { cipherResponseFor } from './ciphers';
import { readNewMasterPassword, resetUserCredentials } from './master-password-reset';
import { isRecord, list, readBody, str, touchOrganization, touchUsers } from './organizations';
import { notifyUserLogout } from '../durable/notifications-hub';

const ok = () => new Response(null, { status: 200 });
const RESET_PASSWORD_POLICY = 8;

// POST /api/organizations/{id}/keys
// Sets the key pair of an organization created without one.
export async function handleSetOrganizationKeys(request: Request, env: Env, organizationId: string): Promise<Response> {
  const body = await readBody(request);
  const privateKey = str(body?.encryptedPrivateKey);
  const publicKey = str(body?.publicKey);
  if (!privateKey || !publicKey) return errorResponse('encryptedPrivateKey and publicKey are required', 400);
  if (!(await setOrganizationKeys(env.DB, organizationId, privateKey, publicKey))) return errorResponse('Organization Keys already exist', 400);
  await touchOrganization(env.DB, organizationId);
  return jsonResponse({ object: 'organizationKeys', publicKey, privateKey });
}

// GET /api/organizations/{id}/private-key
// The organization's private key, wrapped with the organization key.
export async function handleGetOrganizationPrivateKey(env: Env, organizationId: string): Promise<Response> {
  const organization = await getOrganization(env.DB, organizationId);
  if (!organization) return errorResponse('Resource not found.', 404);
  return jsonResponse({ object: 'organizationPrivateKey', privateKey: organization.privateKey });
}

// GET /api/organizations/{id}/export
// Every collection and every cipher of the organization.
export async function handleExportOrganization(request: Request, env: Env, organizationId: string): Promise<Response> {
  const [collections, ciphers] = await Promise.all([listCollections(env.DB, organizationId), listOrgCiphers(env.DB, organizationId)]);
  const attachments = await new StorageService(env.DB).getAttachmentsByCipherIds(ciphers.map(({ cipher }) => cipher.id));
  return jsonResponse({
    collections: collections.map(collectionJson),
    ciphers: ciphers.map((accessible) => cipherResponseFor(request, accessible, attachments.get(accessible.cipher.id) || [])),
  });
}

/** The caller's own account when the request carries its master password hash, else the response to send. */
async function verifyOwnPassword(env: Env, userId: string, body: Record<string, unknown> | null) {
  const user = await new StorageService(env.DB).getUserById(userId);
  const hash = str(body?.masterPasswordHash);
  if (!user) return errorResponse('User not found', 404);
  if (!hash) return errorResponse('No validation provided', 400);
  if (!(await new AuthService(env).verifyPassword(hash, user.masterPasswordHash, user.email))) return errorResponse('Invalid password', 400);
  return user;
}

const API_KEY_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

function generateApiKey(): string {
  // 62 * 4 = 248, so bytes up to 247 map to a character without bias.
  let out = '';
  while (out.length < 30) {
    for (const byte of crypto.getRandomValues(new Uint8Array(32))) {
      if (byte < 248 && out.length < 30) out += API_KEY_CHARS[byte % 62];
    }
  }
  return out;
}

// POST /api/organizations/{id}/api-key, POST /api/organizations/{id}/rotate-api-key
// The organization API key, created on first view. This server has no organization API login yet,
// so the key authenticates nothing; it is kept for when it does.
export async function handleOrganizationApiKey(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string,
  rotate: boolean
): Promise<Response> {
  const user = await verifyOwnPassword(env, userId, await readBody(request));
  if (user instanceof Response) return user;
  let key = await getOrganizationApiKey(env.DB, organizationId);
  if (!key || rotate) {
    key = { apiKey: generateApiKey(), revisionDate: new Date().toISOString() };
    await setOrganizationApiKey(env.DB, organizationId, key);
  }
  return jsonResponse({ apiKey: key.apiKey, revisionDate: key.revisionDate, object: 'apiKey' });
}

/** Whether the organization's Account recovery administration policy is on, and its auto-enroll option. */
async function readResetPasswordPolicy(db: D1Database, organizationId: string): Promise<{ autoEnroll: boolean } | string> {
  const policy = await getPolicy(db, organizationId, RESET_PASSWORD_POLICY);
  if (!policy) return 'Policy not found';
  if (!policy.enabled) return 'Reset password policy not enabled';
  let data: unknown = null;
  try {
    data = JSON.parse(policy.data);
  } catch {
    data = null;
  }
  return { autoEnroll: isRecord(data) && data.autoEnrollEnabled === true };
}

// GET /api/organizations/{identifier}/auto-enroll-status
// Only the caller's own organizations answer; any other identifier reads as one without auto-enroll,
// so the route reveals nothing about organizations the caller is not in.
export async function handleAutoEnrollStatus(env: Env, userId: string, identifier: string): Promise<Response> {
  const organizationId = identifier.toLowerCase();
  const known = !((await authorizeInvitee(env.DB, organizationId, userId)) instanceof Response);
  const policy = known ? await readResetPasswordPolicy(env.DB, organizationId) : null;
  const id = known ? organizationId : identifier;
  return jsonResponse({ id, identifier: id, resetPasswordEnabled: typeof policy === 'object' && !!policy?.autoEnroll });
}

// PUT /api/organizations/{id}/users/{userId}/reset-password-enrollment
// The caller enrolls, or withdraws, their own membership. An invitee may, since the clients enroll
// while accepting the invitation. Enrolling needs the master password.
export async function handleResetPasswordEnrollment(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string,
  pathUserId: string,
  actor: EventActor
): Promise<Response> {
  const member = await authorizeInvitee(env.DB, organizationId, userId);
  if (member instanceof Response) return member;
  if (pathUserId !== userId) return errorResponse("User to enroll isn't member of required organization", 400);
  const policy = await readResetPasswordPolicy(env.DB, organizationId);
  if (typeof policy === 'string') return errorResponse(policy, 400);
  const body = await readBody(request);
  const key = str(body?.resetPasswordKey) || null;
  if (!key && policy.autoEnroll) return errorResponse("Reset password can't be withdrawn due to an enterprise policy", 400);
  if (key) {
    const user = await verifyOwnPassword(env, userId, body);
    if (user instanceof Response) return user;
  }
  await setMemberResetPasswordKey(env.DB, member.id, key);
  await touchUsers(env.DB, [userId]);
  await logEvents(env, actor, [{
    type: key ? EventType.OrganizationUserResetPasswordEnroll : EventType.OrganizationUserResetPasswordWithdraw,
    organizationId,
    memberId: member.id,
    userId,
  }]);
  return ok();
}

/**
 * The member whose account `caller` may recover, or why not. As in Bitwarden, Owners may recover
 * every member and Admins every member but Owners.
 */
async function recoverableMember(db: D1Database, caller: OrganizationMember, memberId: string): Promise<OrganizationMember | string> {
  const policy = await readResetPasswordPolicy(db, caller.organizationId);
  if (typeof policy === 'string') return policy;
  const member = await getMemberById(db, caller.organizationId, memberId);
  if (!member) return "User to reset isn't member of required organization";
  if (member.type === MemberType.Owner && !isOwner(caller)) return "No permission to reset this user's password";
  return member;
}

// GET /api/organizations/{id}/users/{memberId}/reset-password-details
export async function handleGetResetPasswordDetails(env: Env, caller: OrganizationMember, memberId: string): Promise<Response> {
  const member = await recoverableMember(env.DB, caller, memberId);
  if (typeof member === 'string') return errorResponse(member, 400);
  const [user, organization] = await Promise.all([
    new StorageService(env.DB).getUserById(member.userId),
    getOrganization(env.DB, caller.organizationId),
  ]);
  if (!user || !organization) return errorResponse('User not found', 400);
  return jsonResponse({
    object: 'organizationUserResetPasswordDetails',
    organizationUserId: member.id,
    kdf: user.kdfType,
    kdfIterations: user.kdfIterations,
    kdfMemory: user.kdfMemory ?? null,
    kdfParallelism: user.kdfParallelism ?? null,
    masterPasswordSalt: user.email.trim().toLowerCase(),
    resetPasswordKey: member.resetPasswordKey,
    encryptedPrivateKey: organization.privateKey,
  });
}

// PUT /api/organizations/{id}/users/{memberId}/recover-account
// Sets a new master password on an enrolled, confirmed member's account, turns off their two-step
// login, or both, as the request asks. Every session of the member ends.
export async function handleRecoverAccount(
  request: Request,
  env: Env,
  caller: OrganizationMember,
  memberId: string,
  actor: EventActor
): Promise<Response> {
  const member = await recoverableMember(env.DB, caller, memberId);
  if (typeof member === 'string') return errorResponse(member, 400);
  if (!member.resetPasswordKey) return errorResponse('Password reset not or not correctly enrolled', 400);
  if (member.status !== MemberStatus.Confirmed) {
    return errorResponse('Organization user must be confirmed for password reset functionality', 400);
  }
  const user = await new StorageService(env.DB).getUserById(member.userId);
  if (!user) return errorResponse('User not found', 400);
  const body = (await readBody(request)) ?? {};
  const resetPassword = body.resetMasterPassword === true;
  const resetTwoFactor = body.resetTwoFactor === true;

  const password = resetPassword ? readNewMasterPassword(body, user) : null;
  if (resetPassword && password === null) return errorResponse('Unprocessable request', 422);
  if (typeof password === 'string') return errorResponse(password, 400);
  if (!resetPassword && !resetTwoFactor) return ok();

  await resetUserCredentials(env, user, password, resetTwoFactor);
  notifyUserLogout(env, user.id);
  await touchUsers(env.DB, [user.id]);
  const events = [];
  if (resetPassword) events.push(EventType.OrganizationUserAdminResetPassword);
  if (resetTwoFactor) events.push(EventType.OrganizationUserAdminResetTwoFactor);
  await logEvents(env, actor, events.map((type) => ({ type, organizationId: member.organizationId, memberId: member.id, userId: member.userId })));
  return ok();
}

// GET /api/organizations/{id}/users/keys/pending-v2-upgrades
// The account recovery keys still to be re-wrapped for members whose account moved to a V2 user
// key. This server keeps no upgrade tokens, so none ever is.
export function handlePendingV2Upgrades(): Response {
  return jsonResponse({ object: 'list', data: [], continuationToken: null });
}

const MAX_V2_UPGRADES = 100;

// POST /api/organizations/{id}/users/keys/v2-upgrades
// Checks the request as Vaultwarden does. With nothing pending, every listed member is skipped and
// stays as it was, as Vaultwarden does for a member that changed since the read.
export async function handleV2Upgrades(request: Request, env: Env, caller: OrganizationMember): Promise<Response> {
  const body = await readBody(request);
  const upgrades = Array.isArray(body?.upgrades) ? body.upgrades : [];
  if (!upgrades.length || upgrades.length > MAX_V2_UPGRADES) {
    return errorResponse(`The field Upgrades must contain between 1 and ${MAX_V2_UPGRADES} entries.`, 400);
  }
  const ids = upgrades.map((u) => (isRecord(u) ? str(u.organizationUserId).toLowerCase() : ''));
  if (new Set(ids).size !== ids.length) return errorResponse('An organization user can only be upgraded once per request.', 400);
  for (const id of ids) {
    const member = id ? await getMemberById(env.DB, caller.organizationId, id) : null;
    if (!member || (member.type === MemberType.Owner && !isOwner(caller))) return errorResponse('Resource not found.', 404);
  }
  return ok();
}

// GET /api/plans
export function handleGetPlans(): Response {
  const plan = (product: number) => ({
    object: 'plan',
    type: 0,
    product,
    name: 'Free',
    nameLocalizationKey: 'planNameFree',
    bitwardenProduct: product,
    maxUsers: 0,
    descriptionLocalizationKey: 'planDescFree',
  });
  return list([plan(0), plan(1)]);
}

// GET /api/organizations/{id}/billing/vnext/warnings
export function handleBillingWarnings(): Response {
  return jsonResponse({ freeTrial: null, inactiveSubscription: null, resellerRenewal: null, taxId: null });
}

// GET /api/organizations/{id}/billing/vnext/self-host/metadata
export function handleSelfHostBillingMetadata(): Response {
  return jsonResponse({ isOnSecretsManagerStandalone: false, organizationOccupiedSeats: 0 });
}
