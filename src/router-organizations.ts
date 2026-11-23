import type { Env } from './types';
import { authorizeOrgRequest, type OrgRole } from './services/org-access';
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
  handleGetUserCollections,
  handleLeaveOrganization,
  handleUpdateCollection,
  handleUpdateOrganization,
} from './handlers/organizations';

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
  { method: 'GET', sub: /^\/collections$/, role: 'admin', handle: ({ env, orgId }) => handleGetOrganizationCollections(env, orgId) },
  { method: 'GET', sub: /^\/collections\/details$/, role: 'admin', handle: ({ env, member, orgId }) => handleGetOrganizationCollectionDetails(env, member, orgId) },
  { method: 'POST', sub: /^\/collections$/, role: 'admin', handle: ({ request, env, member, orgId }) => handleCreateCollection(request, env, member, orgId) },
  { method: 'PUT', sub: new RegExp(`^/collections/${ID}$`, 'i'), role: 'admin', handle: ({ request, env, member, orgId, params }) => handleUpdateCollection(request, env, member, orgId, params[0]) },
  { method: 'DELETE', sub: new RegExp(`^/collections/${ID}$`, 'i'), role: 'admin', handle: ({ env, orgId, params }) => handleDeleteCollection(env, orgId, params[0]) },
];

const ORG_PATH = new RegExp(`^/api/organizations/${ID}(/.*)?$`, 'i');

export async function handleOrganizationRoute(
  request: Request,
  env: Env,
  userId: string,
  path: string,
  method: string
): Promise<Response | null> {
  if (path === '/api/organizations' && method === 'POST') return handleCreateOrganization(request, env, userId);
  if (path === '/api/collections' && method === 'GET') return handleGetUserCollections(env, userId);

  const match = path.match(ORG_PATH);
  if (!match) return null;
  const orgId = match[1].toLowerCase();
  const sub = match[2] || '';
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
