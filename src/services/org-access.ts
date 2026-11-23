import { errorResponse } from '../utils/response';
import { getMember, MemberStatus, MemberType, type OrganizationMember } from './storage-organization-repo';

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
