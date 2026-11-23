import { parseErrorMessage, parseJson, type AuthedFetch } from './shared';
import { t } from '../i18n';
import type { Cipher } from '../types';

// Bitwarden's enums, as this server stores them.
export const OrgRole = { Owner: 0, Admin: 1, User: 2 } as const;
export const MemberStatus = { Revoked: -1, Invited: 0, Accepted: 1, Confirmed: 2 } as const;

/** One entry of the profile's `organizationsNew`: the caller's accepted or confirmed membership. */
export interface ProfileOrganization {
  id: string;
  name: string;
  key: string | null;
  status: number;
  type: number;
  organizationUserId: string;
}

export interface OrganizationInvitation {
  id: string;
  organizationId: string;
  organizationName: string;
  type: number;
}

export interface CollectionAccessEntry {
  id: string;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

export interface OrganizationMember {
  id: string;
  userId: string;
  name: string | null;
  email: string;
  status: number;
  type: number;
  groups: string[];
  collections: CollectionAccessEntry[];
}

export interface CollectionDetails {
  id: string;
  name: string;
  users: CollectionAccessEntry[];
  groups: CollectionAccessEntry[];
}

export interface OrganizationGroup {
  id: string;
  name: string;
  collections: CollectionAccessEntry[];
}

export interface OrganizationPolicy {
  type: number;
  enabled: boolean;
  data: unknown;
}

type ListBody<T> = { data?: T[] };

async function send(authedFetch: AuthedFetch, path: string, method: string, body?: unknown): Promise<Response> {
  const resp = await authedFetch(path, {
    method,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, `${method} ${path} failed (${resp.status})`));
  return resp;
}

async function getJson<T>(authedFetch: AuthedFetch, path: string): Promise<T> {
  const body = await parseJson<T>(await send(authedFetch, path, 'GET'));
  if (body === null) throw new Error(`GET ${path} returned no data`);
  return body;
}

const getList = async <T>(authedFetch: AuthedFetch, path: string): Promise<T[]> =>
  (await getJson<ListBody<T>>(authedFetch, path)).data ?? [];

const org = (orgId: string) => `/api/organizations/${encodeURIComponent(orgId)}`;

export const getUserPublicKey = async (authedFetch: AuthedFetch, userId: string): Promise<string> =>
  (await getJson<{ publicKey: string }>(authedFetch, `/api/users/${encodeURIComponent(userId)}/public-key`)).publicKey;

export const listInvitations = (authedFetch: AuthedFetch) =>
  getList<OrganizationInvitation>(authedFetch, '/api/organizations/invitations');

export const acceptInvitation = (authedFetch: AuthedFetch, orgId: string, memberId: string) =>
  send(authedFetch, `${org(orgId)}/users/${encodeURIComponent(memberId)}/accept`, 'POST', {});

export const leaveOrganization = (authedFetch: AuthedFetch, orgId: string) => send(authedFetch, `${org(orgId)}/leave`, 'POST');

export const createOrganization = (
  authedFetch: AuthedFetch,
  body: { name: string; billingEmail: string; collectionName: string; key: string; keys: { publicKey: string; encryptedPrivateKey: string } }
) => send(authedFetch, '/api/organizations', 'POST', { ...body, planType: 0 });

export const getOrganization = (authedFetch: AuthedFetch, orgId: string) =>
  getJson<{ id: string; name: string; billingEmail: string }>(authedFetch, org(orgId));

export const updateOrganization = (authedFetch: AuthedFetch, orgId: string, name: string, billingEmail: string) =>
  send(authedFetch, org(orgId), 'PUT', { name, billingEmail });

export const deleteOrganization = (authedFetch: AuthedFetch, orgId: string, masterPasswordHash: string) =>
  send(authedFetch, org(orgId), 'DELETE', { masterPasswordHash });

export const listMembers = (authedFetch: AuthedFetch, orgId: string) =>
  getList<OrganizationMember>(authedFetch, `${org(orgId)}/users?includeCollections=true&includeGroups=true`);

export const inviteMember = (authedFetch: AuthedFetch, orgId: string, email: string, type: number, collections: CollectionAccessEntry[]) =>
  send(authedFetch, `${org(orgId)}/users/invite`, 'POST', { emails: [email], type, collections, groups: [] });

/** Sets a member's role and collections. Groups are left as they are, since the body names none. */
export const updateMember = (authedFetch: AuthedFetch, orgId: string, memberId: string, type: number, collections: CollectionAccessEntry[]) =>
  send(authedFetch, `${org(orgId)}/users/${encodeURIComponent(memberId)}`, 'PUT', { type, collections });

export const removeMember = (authedFetch: AuthedFetch, orgId: string, memberId: string) =>
  send(authedFetch, `${org(orgId)}/users/${encodeURIComponent(memberId)}`, 'DELETE');

export async function getMemberPublicKey(authedFetch: AuthedFetch, orgId: string, memberId: string): Promise<string> {
  const resp = await send(authedFetch, `${org(orgId)}/users/public-keys`, 'POST', { ids: [memberId] });
  const key = (await parseJson<ListBody<{ id: string; key: string | null }>>(resp))?.data?.find((entry) => entry.id === memberId)?.key;
  if (!key) throw new Error(t('txt_org_member_no_public_key'));
  return key;
}

export const confirmMember = (authedFetch: AuthedFetch, orgId: string, memberId: string, key: string) =>
  send(authedFetch, `${org(orgId)}/users/${encodeURIComponent(memberId)}/confirm`, 'POST', { key });

/** Collections the caller can see, across organizations. */
export const listMyCollections = (authedFetch: AuthedFetch) =>
  getList<{ id: string; organizationId: string; name: string }>(authedFetch, '/api/collections');

export const listCollectionDetails = (authedFetch: AuthedFetch, orgId: string) =>
  getList<CollectionDetails>(authedFetch, `${org(orgId)}/collections/details`);

/** Creates or replaces a collection; `users` and `groups` replace its access. */
export function saveCollection(
  authedFetch: AuthedFetch,
  orgId: string,
  collectionId: string | null,
  body: { name: string; users: CollectionAccessEntry[]; groups: CollectionAccessEntry[] }
) {
  return collectionId
    ? send(authedFetch, `${org(orgId)}/collections/${encodeURIComponent(collectionId)}`, 'PUT', body)
    : send(authedFetch, `${org(orgId)}/collections`, 'POST', body);
}

export const deleteCollection = (authedFetch: AuthedFetch, orgId: string, collectionId: string) =>
  send(authedFetch, `${org(orgId)}/collections/${encodeURIComponent(collectionId)}`, 'DELETE');

export const listGroups = (authedFetch: AuthedFetch, orgId: string) =>
  getList<OrganizationGroup>(authedFetch, `${org(orgId)}/groups/details`);

export const getGroupMemberIds = (authedFetch: AuthedFetch, orgId: string, groupId: string) =>
  getJson<string[]>(authedFetch, `${org(orgId)}/groups/${encodeURIComponent(groupId)}/users`);

/** Creates or replaces a group; `collections` and `users` replace its access and members. */
export function saveGroup(
  authedFetch: AuthedFetch,
  orgId: string,
  groupId: string | null,
  body: { name: string; collections: CollectionAccessEntry[]; users: string[] }
) {
  return groupId
    ? send(authedFetch, `${org(orgId)}/groups/${encodeURIComponent(groupId)}`, 'PUT', body)
    : send(authedFetch, `${org(orgId)}/groups`, 'POST', body);
}

export const deleteGroup = (authedFetch: AuthedFetch, orgId: string, groupId: string) =>
  send(authedFetch, `${org(orgId)}/groups/${encodeURIComponent(groupId)}`, 'DELETE');

export const listPolicies = (authedFetch: AuthedFetch, orgId: string) => getList<OrganizationPolicy>(authedFetch, `${org(orgId)}/policies`);

export const setPolicy = (authedFetch: AuthedFetch, orgId: string, type: number, enabled: boolean, data: unknown) =>
  send(authedFetch, `${org(orgId)}/policies/${type}`, 'PUT', { policy: { enabled, data } });

export const listOrganizationCiphers = (authedFetch: AuthedFetch, orgId: string) =>
  getList<Cipher & { collectionIds?: string[] }>(authedFetch, `/api/ciphers/organization-details?organizationId=${encodeURIComponent(orgId)}`);
