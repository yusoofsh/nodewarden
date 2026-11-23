import { errorResponse } from '../utils/response';
import type { CipherAccess } from './storage-org-cipher-repo';
import { countConfirmedOwners, getMember, getMemberById, MemberStatus, MemberType, type OrganizationMember } from './storage-organization-repo';

export type OrgRole = 'member' | 'admin' | 'owner';

/** The caller's membership when it is confirmed, else null. Every organization route starts here. */
export async function getConfirmedMembership(
  db: D1Database,
  organizationId: string,
  userId: string
): Promise<OrganizationMember | null> {
  const member = await getMember(db, organizationId, userId);
  return member && member.status === MemberStatus.Confirmed ? member : null;
}

export const isOwner = (member: OrganizationMember): boolean => member.type === MemberType.Owner;
export const isAdminOrOwner = (member: OrganizationMember): boolean =>
  member.type === MemberType.Owner || member.type === MemberType.Admin;

/** Reaches every cipher and collection of the organization. Keep in step with FULL_ACCESS_SQL in storage-org-cipher-repo.ts. */
export const hasFullAccess = (member: OrganizationMember): boolean =>
  member.status === MemberStatus.Confirmed && (member.accessAll || isAdminOrOwner(member));

/** May edit, delete and restore a cipher: not read-only, or allowed to manage it. */
export const canWriteCipher = (access: CipherAccess): boolean => !access.readOnly || access.manage;

/** May change a cipher's collections; hidden passwords would otherwise let a member copy the item out. */
export const canEditCipherCollections = (access: CipherAccess): boolean =>
  (!access.readOnly && !access.hidePasswords) || access.manage;

/**
 * The membership `memberId` when it belongs to the caller, else the response to send. Accepting an
 * invite is the one organization route a caller who is not confirmed may use, and only for their own
 * membership: any other caller gets the same 404 as a missing organization.
 */
export async function authorizeOwnMembership(
  db: D1Database,
  organizationId: string,
  memberId: string,
  userId: string
): Promise<OrganizationMember | Response> {
  const member = await getMemberById(db, organizationId, memberId);
  return member && member.userId === userId ? member : errorResponse('Organization not found', 404);
}

/**
 * The caller's own membership in any state but revoked, else the 404 of a missing organization.
 * It authorizes the policy routes an invitee reads before accepting, which reveal nothing else.
 */
export async function authorizeInvitee(
  db: D1Database,
  organizationId: string,
  userId: string
): Promise<OrganizationMember | Response> {
  const member = await getMember(db, organizationId, userId);
  return member && member.status >= MemberStatus.Invited ? member : errorResponse('Organization not found', 404);
}

/** Why `caller` may not manage a member of `targetType`, or null when it may. Only owners manage owners. */
export function roleManageError(caller: OrganizationMember, targetType: number): string | null {
  if (isOwner(caller)) return null;
  if (targetType === MemberType.Owner) return 'Only Owners can manage Owners';
  return isAdminOrOwner(caller) ? null : 'You can only manage Users';
}

/** True when removing or demoting this member would leave the organization without a confirmed owner. */
export async function isLastConfirmedOwner(db: D1Database, member: OrganizationMember): Promise<boolean> {
  if (member.type !== MemberType.Owner || member.status !== MemberStatus.Confirmed) return false;
  return (await countConfirmedOwners(db, member.organizationId)) <= 1;
}

const ROLE_CHECKS: Record<OrgRole, { allows: (member: OrganizationMember) => boolean; message: string }> = {
  member: { allows: () => true, message: '' },
  admin: { allows: isAdminOrOwner, message: 'You need to be Admin or Owner to call this endpoint' },
  owner: { allows: isOwner, message: 'You need to be Owner to call this endpoint' },
};

/**
 * The caller's confirmed membership if it holds `role`, else the response to send.
 * A missing organization and one the caller is not a confirmed member of both answer 404, so a
 * request never reveals whether an organization exists. A member below the role gets a 400: the
 * Bitwarden clients log out on 401 and 403.
 */
export async function authorizeOrgRequest(
  db: D1Database,
  organizationId: string,
  userId: string,
  role: OrgRole
): Promise<OrganizationMember | Response> {
  const member = await getConfirmedMembership(db, organizationId, userId);
  if (!member) return errorResponse('Organization not found', 404);
  const check = ROLE_CHECKS[role];
  if (!check.allows(member)) return errorResponse(check.message, 400);
  return member;
}
