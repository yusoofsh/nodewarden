import type { Env } from './types';
import { errorResponse } from './utils/response';
import { authorizeInvitee, authorizeOrgRequest, authorizeOwnMembership, type OrgRole } from './services/org-access';
import type { OrganizationMember } from './services/storage-organization-repo';
import {
  handleBulkCollectionAccess,
  handleBulkDeleteCollections,
  handleCreateCollection,
  handleCreateOrganization,
  handleDeleteCollection,
  handleDeleteOrganization,
  handleGetCollectionDetails,
  handleGetCollectionUsers,
  handleGetOrganization,
  handleGetOrganizationCollectionDetails,
  handleGetOrganizationCollections,
  handleGetOrganizationMembers,
  handleGetOrganizationPublicKey,
  handleGetPendingInvitations,
  handleGetUserCollections,
  handleLeaveOrganization,
  handleUpdateCollection,
  handleUpdateOrganization,
} from './handlers/organizations';
import {
  handleAcceptInvite,
  handleBulkConfirmMembers,
  handleBulkDeleteMembers,
  handleBulkReinviteMembers,
  handleBulkRevokeOrRestore,
  handleConfirmMember,
  handleDeleteMember,
  handleGetMember,
  handleGetMemberMiniDetails,
  handleInviteMembers,
  handleMemberPublicKeys,
  handleReinviteMember,
  handleRestoreMember,
  handleRevokeMember,
  handleUpdateMember,
} from './handlers/organization-members';
import {
  handleAutoEnrollStatus,
  handleBillingWarnings,
  handleExportOrganization,
  handleGetOrganizationPrivateKey,
  handleGetPlans,
  handleGetResetPasswordDetails,
  handleOrganizationApiKey,
  handlePendingV2Upgrades,
  handleRecoverAccount,
  handleResetPasswordEnrollment,
  handleSelfHostBillingMetadata,
  handleSetOrganizationKeys,
  handleV2Upgrades,
} from './handlers/organization-admin';
import { handleBulkCipherCollections, handleGetAssignedOrganizationCiphers, handleImportOrganizationCiphers } from './handlers/org-ciphers';
import {
  handleBulkDeleteGroups,
  handleCreateGroup,
  handleDeleteGroup,
  handleGetGroup,
  handleGetGroupMembers,
  handleGetMemberGroups,
  handleListGroups,
  handleUpdateGroup,
  handleUpdateMemberGroups,
  readGroupIds,
} from './handlers/organization-groups';
import { handleGetMasterPasswordPolicy, handleGetPolicy, handleListPolicies, handlePutPolicy } from './handlers/organization-policies';
import { handleGetMemberEvents, handleGetOrganizationEvents } from './handlers/events';
import { type EventActor, eventActor } from './services/events';

interface OrgRoute {
  method: string;
  // Matched against the path after /api/organizations/{id}; groups after the first are passed on.
  sub: RegExp;
  role: OrgRole;
  handle: (ctx: { request: Request; env: Env; userId: string; member: OrganizationMember; orgId: string; params: string[]; actor: EventActor }) => Promise<Response>;
}

const ID = '([a-f0-9-]+)';

// Every route that names an organization is listed here and authorized before its handler runs.
// Anything not listed falls through, so unimplemented routes stay unmatched.
const ORG_ROUTES: OrgRoute[] = [
  { method: 'GET', sub: /^$/, role: 'owner', handle: ({ env, orgId }) => handleGetOrganization(env, orgId) },
  { method: 'PUT', sub: /^$/, role: 'owner', handle: ({ request, env, orgId, actor }) => handleUpdateOrganization(request, env, orgId, actor) },
  { method: 'DELETE', sub: /^$/, role: 'owner', handle: ({ request, env, userId, orgId }) => handleDeleteOrganization(request, env, userId, orgId) },
  { method: 'POST', sub: /^\/leave$/, role: 'member', handle: ({ env, member, actor }) => handleLeaveOrganization(env, member, actor) },
  { method: 'GET', sub: /^\/(?:public-key|keys)$/, role: 'member', handle: ({ env, orgId }) => handleGetOrganizationPublicKey(env, orgId) },
  { method: 'POST', sub: /^\/keys$/, role: 'admin', handle: ({ request, env, orgId }) => handleSetOrganizationKeys(request, env, orgId) },
  { method: 'GET', sub: /^\/private-key$/, role: 'admin', handle: ({ env, orgId }) => handleGetOrganizationPrivateKey(env, orgId) },
  { method: 'GET', sub: /^\/export$/, role: 'admin', handle: ({ request, env, orgId }) => handleExportOrganization(request, env, orgId) },
  { method: 'POST', sub: /^\/api-key$/, role: 'owner', handle: ({ request, env, userId, orgId }) => handleOrganizationApiKey(request, env, userId, orgId, false) },
  { method: 'POST', sub: /^\/rotate-api-key$/, role: 'owner', handle: ({ request, env, userId, orgId }) => handleOrganizationApiKey(request, env, userId, orgId, true) },
  { method: 'GET', sub: /^\/billing\/vnext\/warnings$/, role: 'member', handle: () => Promise.resolve(handleBillingWarnings()) },
  { method: 'GET', sub: /^\/billing\/vnext\/self-host\/metadata$/, role: 'member', handle: () => Promise.resolve(handleSelfHostBillingMetadata()) },
  { method: 'GET', sub: /^\/users$/, role: 'admin', handle: ({ request, env, orgId }) => handleGetOrganizationMembers(request, env, orgId) },
  { method: 'GET', sub: /^\/users\/mini-details$/, role: 'admin', handle: ({ env, member }) => handleGetMemberMiniDetails(env, member) },
  { method: 'PUT', sub: /^\/users\/revoke$/, role: 'admin', handle: ({ request, env, member, actor }) => handleBulkRevokeOrRestore(request, env, member, true, actor) },
  { method: 'PUT', sub: /^\/users\/restore$/, role: 'admin', handle: ({ request, env, member, actor }) => handleBulkRevokeOrRestore(request, env, member, false, actor) },
  { method: 'PUT', sub: new RegExp(`^/users/${ID}/revoke$`, 'i'), role: 'admin', handle: ({ env, member, params, actor }) => handleRevokeMember(env, member, params[0], actor) },
  { method: 'PUT', sub: new RegExp(`^/users/${ID}/restore(?:/vnext)?$`, 'i'), role: 'admin', handle: ({ env, member, params, actor }) => handleRestoreMember(env, member, params[0], actor) },
  { method: 'GET', sub: new RegExp(`^/users/${ID}/reset-password-details$`, 'i'), role: 'admin', handle: ({ env, member, params }) => handleGetResetPasswordDetails(env, member, params[0]) },
  { method: 'PUT', sub: new RegExp(`^/users/${ID}/recover-account$`, 'i'), role: 'admin', handle: ({ request, env, member, params, actor }) => handleRecoverAccount(request, env, member, params[0], actor) },
  { method: 'GET', sub: /^\/users\/keys\/pending-v2-upgrades$/, role: 'admin', handle: () => Promise.resolve(handlePendingV2Upgrades()) },
  { method: 'POST', sub: /^\/users\/keys\/v2-upgrades$/, role: 'admin', handle: ({ request, env, member }) => handleV2Upgrades(request, env, member) },
  { method: 'POST', sub: /^\/users\/invite$/, role: 'admin', handle: ({ request, env, member, actor }) => handleInviteMembers(request, env, member, actor) },
  { method: 'POST', sub: /^\/users\/reinvite$/, role: 'admin', handle: ({ request, env, member }) => handleBulkReinviteMembers(request, env, member) },
  { method: 'POST', sub: /^\/users\/confirm$/, role: 'admin', handle: ({ request, env, member, actor }) => handleBulkConfirmMembers(request, env, member, actor) },
  { method: 'POST', sub: /^\/users\/public-keys$/, role: 'admin', handle: ({ request, env, member }) => handleMemberPublicKeys(request, env, member) },
  { method: 'DELETE', sub: /^\/users$/, role: 'admin', handle: ({ request, env, member, actor }) => handleBulkDeleteMembers(request, env, member, actor) },
  { method: 'POST', sub: new RegExp(`^/users/${ID}/reinvite$`, 'i'), role: 'admin', handle: ({ env, member, params }) => handleReinviteMember(env, member, params[0]) },
  { method: 'POST', sub: new RegExp(`^/users/${ID}/confirm$`, 'i'), role: 'admin', handle: ({ request, env, member, params, actor }) => handleConfirmMember(request, env, member, params[0], actor) },
  { method: 'GET', sub: new RegExp(`^/users/${ID}$`, 'i'), role: 'admin', handle: ({ request, env, member, params }) => handleGetMember(request, env, member, params[0]) },
  { method: 'PUT', sub: new RegExp(`^/users/${ID}$`, 'i'), role: 'admin', handle: ({ request, env, member, params, actor }) => handleUpdateMember(request, env, member, params[0], actor) },
  { method: 'DELETE', sub: new RegExp(`^/users/${ID}$`, 'i'), role: 'admin', handle: ({ env, member, params, actor }) => handleDeleteMember(env, member, params[0], actor) },
  { method: 'GET', sub: /^\/collections$/, role: 'admin', handle: ({ env, orgId }) => handleGetOrganizationCollections(env, orgId) },
  { method: 'GET', sub: /^\/collections\/details$/, role: 'admin', handle: ({ env, member, orgId }) => handleGetOrganizationCollectionDetails(env, member, orgId) },
  { method: 'POST', sub: /^\/collections$/, role: 'admin', handle: ({ request, env, member, orgId, actor }) => handleCreateCollection(request, env, member, orgId, actor) },
  { method: 'PUT', sub: new RegExp(`^/collections/${ID}$`, 'i'), role: 'admin', handle: ({ request, env, member, orgId, params, actor }) => handleUpdateCollection(request, env, member, orgId, params[0], actor) },
  { method: 'DELETE', sub: new RegExp(`^/collections/${ID}$`, 'i'), role: 'admin', handle: ({ env, orgId, params, actor }) => handleDeleteCollection(env, orgId, params[0], actor) },
  { method: 'DELETE', sub: /^\/collections$/, role: 'admin', handle: ({ request, env, orgId, actor }) => handleBulkDeleteCollections(request, env, orgId, actor) },
  { method: 'POST', sub: /^\/collections\/bulk-access$/, role: 'admin', handle: ({ request, env, orgId, actor }) => handleBulkCollectionAccess(request, env, orgId, actor) },
  { method: 'GET', sub: new RegExp(`^/collections/${ID}/details$`, 'i'), role: 'admin', handle: ({ env, member, orgId, params }) => handleGetCollectionDetails(env, member, orgId, params[0]) },
  { method: 'GET', sub: new RegExp(`^/collections/${ID}/users$`, 'i'), role: 'admin', handle: ({ env, orgId, params }) => handleGetCollectionUsers(env, orgId, params[0]) },
  { method: 'GET', sub: /^\/groups$/, role: 'admin', handle: ({ env, orgId }) => handleListGroups(env, orgId, false) },
  { method: 'GET', sub: /^\/groups\/details$/, role: 'admin', handle: ({ env, orgId }) => handleListGroups(env, orgId, true) },
  { method: 'POST', sub: /^\/groups$/, role: 'admin', handle: ({ request, env, orgId, actor }) => handleCreateGroup(request, env, orgId, actor) },
  { method: 'DELETE', sub: /^\/groups$/, role: 'admin', handle: async ({ request, env, orgId, actor }) => handleBulkDeleteGroups(env, orgId, await readGroupIds(request), actor) },
  { method: 'GET', sub: new RegExp(`^/groups/${ID}$`, 'i'), role: 'admin', handle: ({ env, orgId, params }) => handleGetGroup(env, orgId, params[0], false) },
  { method: 'GET', sub: new RegExp(`^/groups/${ID}/details$`, 'i'), role: 'admin', handle: ({ env, orgId, params }) => handleGetGroup(env, orgId, params[0], true) },
  { method: 'GET', sub: new RegExp(`^/groups/${ID}/users$`, 'i'), role: 'admin', handle: ({ env, orgId, params }) => handleGetGroupMembers(env, orgId, params[0]) },
  { method: 'PUT', sub: new RegExp(`^/groups/${ID}$`, 'i'), role: 'admin', handle: ({ request, env, orgId, params, actor }) => handleUpdateGroup(request, env, orgId, params[0], actor) },
  { method: 'DELETE', sub: new RegExp(`^/groups/${ID}$`, 'i'), role: 'admin', handle: ({ env, orgId, params, actor }) => handleDeleteGroup(env, orgId, params[0], actor) },
  { method: 'GET', sub: new RegExp(`^/users/${ID}/groups$`, 'i'), role: 'admin', handle: ({ env, member, params }) => handleGetMemberGroups(env, member, params[0]) },
  { method: 'PUT', sub: new RegExp(`^/users/${ID}/groups$`, 'i'), role: 'admin', handle: ({ request, env, member, params, actor }) => handleUpdateMemberGroups(request, env, member, params[0], actor) },
  { method: 'POST', sub: new RegExp(`^/users/${ID}/groups$`, 'i'), role: 'admin', handle: ({ request, env, member, params, actor }) => handleUpdateMemberGroups(request, env, member, params[0], actor) },
  { method: 'GET', sub: /^\/events$/, role: 'admin', handle: ({ request, env, orgId }) => handleGetOrganizationEvents(request, env, orgId) },
  { method: 'GET', sub: new RegExp(`^/users/${ID}/events$`, 'i'), role: 'admin', handle: ({ request, env, orgId, params }) => handleGetMemberEvents(request, env, orgId, params[0]) },
  { method: 'GET', sub: /^\/policies$/, role: 'admin', handle: ({ env, orgId }) => handleListPolicies(env, orgId) },
  { method: 'GET', sub: /^\/policies\/master-password$/, role: 'member', handle: ({ env, orgId }) => handleGetMasterPasswordPolicy(env, orgId) },
  // After master-password; handleGetPolicy and handlePutPolicy refuse a type that is not a supported number.
  { method: 'GET', sub: /^\/policies\/([^/]+)$/, role: 'admin', handle: ({ env, orgId, params }) => handleGetPolicy(env, orgId, params[0]) },
  { method: 'PUT', sub: /^\/policies\/([^/]+)$/, role: 'admin', handle: ({ request, env, orgId, params, actor }) => handlePutPolicy(request, env, orgId, params[0], actor) },
];

// Policies an invitee reads before accepting, so any membership that is not revoked may read them.
// A query naming another user or membership is refused like a missing organization.
const INVITEE_POLICY_PATH = /^\/policies\/(token|invited-user)$/;

async function handleInviteePolicies(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await authorizeInvitee(env.DB, orgId, userId);
  if (member instanceof Response) return member;
  const query = new URL(request.url).searchParams;
  const namedUser = query.get('userId');
  const namedMember = query.get('organizationUserId');
  if ((namedUser && namedUser.toLowerCase() !== userId) || (namedMember && namedMember.toLowerCase() !== member.id)) {
    return errorResponse('Organization not found', 404);
  }
  return handleListPolicies(env, orgId);
}

const ORG_PATH = new RegExp(`^/api/organizations/${ID}(/.*)?$`, 'i');
// The invitee is not a confirmed member yet, so accepting is authorized by its own handler.
const ACCEPT_PATH = new RegExp(`^/users/${ID}/accept$`, 'i');
// Clients enroll in account recovery while accepting an invitation; authorized by its own handler.
const ENROLL_PATH = new RegExp(`^/users/${ID}/reset-password-enrollment$`, 'i');
// The identifier need not be an organization id, so it is matched before ORG_PATH.
const AUTO_ENROLL_PATH = /^\/api\/organizations\/([^/]+)\/auto-enroll-status$/;

export async function handleOrganizationRoute(
  request: Request,
  env: Env,
  userId: string,
  path: string,
  method: string
): Promise<Response | null> {
  if (path === '/api/organizations' && method === 'POST') return handleCreateOrganization(request, env, userId);
  if (path === '/api/collections' && method === 'GET') return handleGetUserCollections(env, userId);
  if (path === '/api/organizations/invitations' && method === 'GET') return handleGetPendingInvitations(env, userId);
  if (path === '/api/plans' && method === 'GET') return handleGetPlans();
  // Cipher routes of the admin console that name their organization in the query or body.
  if (path === '/api/ciphers/organization-details/assigned' && method === 'GET') return handleGetAssignedOrganizationCiphers(request, env, userId);
  if (path === '/api/ciphers/bulk-collections' && method === 'POST') return handleBulkCipherCollections(request, env, userId);
  if (path === '/api/ciphers/import-organization' && method === 'POST') return handleImportOrganizationCiphers(request, env, userId);
  const autoEnroll = method === 'GET' ? path.match(AUTO_ENROLL_PATH) : null;
  if (autoEnroll) return handleAutoEnrollStatus(env, userId, autoEnroll[1]);

  const match = path.match(ORG_PATH);
  if (!match) return null;
  const orgId = match[1].toLowerCase();
  const sub = match[2] || '';
  const accept = sub.match(ACCEPT_PATH);
  if (accept && method === 'POST') {
    const member = await authorizeOwnMembership(env.DB, orgId, accept[1].toLowerCase(), userId);
    return member instanceof Response ? member : handleAcceptInvite(env, member);
  }
  if (INVITEE_POLICY_PATH.test(sub) && method === 'GET') return handleInviteePolicies(request, env, userId, orgId);
  const enroll = method === 'PUT' ? sub.match(ENROLL_PATH) : null;
  if (enroll) return handleResetPasswordEnrollment(request, env, userId, orgId, enroll[1].toLowerCase(), eventActor(request, userId));
  for (const route of ORG_ROUTES) {
    if (route.method !== method) continue;
    const subMatch = sub.match(route.sub);
    if (!subMatch) continue;
    const member = await authorizeOrgRequest(env.DB, orgId, userId, route.role);
    if (member instanceof Response) return member;
    const params = subMatch.slice(1).map((p) => p.toLowerCase());
    return route.handle({ request, env, userId, member, orgId, params, actor: eventActor(request, userId) });
  }
  return null;
}
