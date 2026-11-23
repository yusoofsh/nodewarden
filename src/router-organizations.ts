import type { Env } from './types';
import { errorResponse } from './utils/response';
import { authorizeInvitee, authorizeOrgRequest, authorizeOwnMembership, type OrgRole } from './services/org-access';
import type { OrganizationMember } from './services/storage-organization-repo';
import {
  handleCreateCollection,
  handleCreateOrganization,
  handleDeleteCollection,
  handleDeleteOrganization,
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
  handleConfirmMember,
  handleDeleteMember,
  handleGetMember,
  handleInviteMembers,
  handleMemberPublicKeys,
  handleReinviteMember,
  handleUpdateMember,
} from './handlers/organization-members';
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

interface OrgRoute {
  method: string;
  // Matched against the path after /api/organizations/{id}; groups after the first are passed on.
  sub: RegExp;
  role: OrgRole;
  handle: (ctx: { request: Request; env: Env; userId: string; member: OrganizationMember; orgId: string; params: string[] }) => Promise<Response>;
}

const ID = '([a-f0-9-]+)';

// Every route that names an organization is listed here and authorized before its handler runs.
// Anything not listed falls through, so unimplemented routes stay unmatched.
const ORG_ROUTES: OrgRoute[] = [
  { method: 'GET', sub: /^$/, role: 'owner', handle: ({ env, orgId }) => handleGetOrganization(env, orgId) },
  { method: 'PUT', sub: /^$/, role: 'owner', handle: ({ request, env, orgId }) => handleUpdateOrganization(request, env, orgId) },
  { method: 'DELETE', sub: /^$/, role: 'owner', handle: ({ request, env, userId, orgId }) => handleDeleteOrganization(request, env, userId, orgId) },
  { method: 'POST', sub: /^\/leave$/, role: 'member', handle: ({ env, member }) => handleLeaveOrganization(env, member) },
  { method: 'GET', sub: /^\/(?:public-key|keys)$/, role: 'member', handle: ({ env, orgId }) => handleGetOrganizationPublicKey(env, orgId) },
  { method: 'GET', sub: /^\/users$/, role: 'admin', handle: ({ request, env, orgId }) => handleGetOrganizationMembers(request, env, orgId) },
  { method: 'POST', sub: /^\/users\/invite$/, role: 'admin', handle: ({ request, env, member }) => handleInviteMembers(request, env, member) },
  { method: 'POST', sub: /^\/users\/reinvite$/, role: 'admin', handle: ({ request, env, member }) => handleBulkReinviteMembers(request, env, member) },
  { method: 'POST', sub: /^\/users\/confirm$/, role: 'admin', handle: ({ request, env, member }) => handleBulkConfirmMembers(request, env, member) },
  { method: 'POST', sub: /^\/users\/public-keys$/, role: 'admin', handle: ({ request, env, member }) => handleMemberPublicKeys(request, env, member) },
  { method: 'DELETE', sub: /^\/users$/, role: 'admin', handle: ({ request, env, member }) => handleBulkDeleteMembers(request, env, member) },
  { method: 'POST', sub: new RegExp(`^/users/${ID}/reinvite$`, 'i'), role: 'admin', handle: ({ env, member, params }) => handleReinviteMember(env, member, params[0]) },
  { method: 'POST', sub: new RegExp(`^/users/${ID}/confirm$`, 'i'), role: 'admin', handle: ({ request, env, member, params }) => handleConfirmMember(request, env, member, params[0]) },
  { method: 'GET', sub: new RegExp(`^/users/${ID}$`, 'i'), role: 'admin', handle: ({ request, env, member, params }) => handleGetMember(request, env, member, params[0]) },
  { method: 'PUT', sub: new RegExp(`^/users/${ID}$`, 'i'), role: 'admin', handle: ({ request, env, member, params }) => handleUpdateMember(request, env, member, params[0]) },
  { method: 'DELETE', sub: new RegExp(`^/users/${ID}$`, 'i'), role: 'admin', handle: ({ env, member, params }) => handleDeleteMember(env, member, params[0]) },
  { method: 'GET', sub: /^\/collections$/, role: 'admin', handle: ({ env, orgId }) => handleGetOrganizationCollections(env, orgId) },
  { method: 'GET', sub: /^\/collections\/details$/, role: 'admin', handle: ({ env, member, orgId }) => handleGetOrganizationCollectionDetails(env, member, orgId) },
  { method: 'POST', sub: /^\/collections$/, role: 'admin', handle: ({ request, env, member, orgId }) => handleCreateCollection(request, env, member, orgId) },
  { method: 'PUT', sub: new RegExp(`^/collections/${ID}$`, 'i'), role: 'admin', handle: ({ request, env, member, orgId, params }) => handleUpdateCollection(request, env, member, orgId, params[0]) },
  { method: 'DELETE', sub: new RegExp(`^/collections/${ID}$`, 'i'), role: 'admin', handle: ({ env, orgId, params }) => handleDeleteCollection(env, orgId, params[0]) },
  { method: 'GET', sub: /^\/groups$/, role: 'admin', handle: ({ env, orgId }) => handleListGroups(env, orgId, false) },
  { method: 'GET', sub: /^\/groups\/details$/, role: 'admin', handle: ({ env, orgId }) => handleListGroups(env, orgId, true) },
  { method: 'POST', sub: /^\/groups$/, role: 'admin', handle: ({ request, env, orgId }) => handleCreateGroup(request, env, orgId) },
  { method: 'DELETE', sub: /^\/groups$/, role: 'admin', handle: async ({ request, env, orgId }) => handleBulkDeleteGroups(env, orgId, await readGroupIds(request)) },
  { method: 'GET', sub: new RegExp(`^/groups/${ID}$`, 'i'), role: 'admin', handle: ({ env, orgId, params }) => handleGetGroup(env, orgId, params[0], false) },
  { method: 'GET', sub: new RegExp(`^/groups/${ID}/details$`, 'i'), role: 'admin', handle: ({ env, orgId, params }) => handleGetGroup(env, orgId, params[0], true) },
  { method: 'GET', sub: new RegExp(`^/groups/${ID}/users$`, 'i'), role: 'admin', handle: ({ env, orgId, params }) => handleGetGroupMembers(env, orgId, params[0]) },
  { method: 'PUT', sub: new RegExp(`^/groups/${ID}$`, 'i'), role: 'admin', handle: ({ request, env, orgId, params }) => handleUpdateGroup(request, env, orgId, params[0]) },
  { method: 'DELETE', sub: new RegExp(`^/groups/${ID}$`, 'i'), role: 'admin', handle: ({ env, orgId, params }) => handleDeleteGroup(env, orgId, params[0]) },
  { method: 'GET', sub: new RegExp(`^/users/${ID}/groups$`, 'i'), role: 'admin', handle: ({ env, member, params }) => handleGetMemberGroups(env, member, params[0]) },
  { method: 'PUT', sub: new RegExp(`^/users/${ID}/groups$`, 'i'), role: 'admin', handle: ({ request, env, member, params }) => handleUpdateMemberGroups(request, env, member, params[0]) },
  { method: 'POST', sub: new RegExp(`^/users/${ID}/groups$`, 'i'), role: 'admin', handle: ({ request, env, member, params }) => handleUpdateMemberGroups(request, env, member, params[0]) },
  { method: 'GET', sub: /^\/policies$/, role: 'admin', handle: ({ env, orgId }) => handleListPolicies(env, orgId) },
  { method: 'GET', sub: /^\/policies\/master-password$/, role: 'member', handle: ({ env, orgId }) => handleGetMasterPasswordPolicy(env, orgId) },
  // After master-password; handleGetPolicy and handlePutPolicy refuse a type that is not a supported number.
  { method: 'GET', sub: /^\/policies\/([^/]+)$/, role: 'admin', handle: ({ env, orgId, params }) => handleGetPolicy(env, orgId, params[0]) },
  { method: 'PUT', sub: /^\/policies\/([^/]+)$/, role: 'admin', handle: ({ request, env, orgId, params }) => handlePutPolicy(request, env, orgId, params[0]) },
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
  for (const route of ORG_ROUTES) {
    if (route.method !== method) continue;
    const subMatch = sub.match(route.sub);
    if (!subMatch) continue;
    const member = await authorizeOrgRequest(env.DB, orgId, userId, route.role);
    if (member instanceof Response) return member;
    const params = subMatch.slice(1).map((p) => p.toLowerCase());
    return route.handle({ request, env, userId, member, orgId, params });
  }
  return null;
}
