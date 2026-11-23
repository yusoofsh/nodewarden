// JSON shapes for organizations, members, collections, groups and policies, as Vaultwarden returns them.
// Events and account recovery are not offered, so their flags are false.
import type { Group, GroupAccess } from '../services/storage-organization-group-repo';
import type { Policy } from '../services/storage-organization-policy-repo';
import {
  MemberStatus,
  MemberType,
  type Collection,
  type CollectionAccess,
  type MemberWithUser,
  type Organization,
  type OrganizationMember,
} from '../services/storage-organization-repo';
import { hasFullAccess } from '../services/org-access';

const hasKeys = (org: Organization): boolean => !!org.privateKey && !!org.publicKey;
const isAdminType = (type: number): boolean => type === MemberType.Owner || type === MemberType.Admin;

const PERMISSIONS = {
  manageSso: false,
  manageScim: false,
  manageUsers: false,
  manageGroups: false,
  managePolicies: false,
  createNewCollections: false,
  editAnyCollection: false,
  deleteAnyCollection: false,
  accessEventLogs: false,
  accessImportExport: false,
  accessReports: false,
  manageResetPassword: false,
};

export function organizationJson(org: Organization) {
  return {
    id: org.id,
    name: org.name,
    seats: null,
    maxCollections: null,
    maxStorageGb: 32767,
    use2fa: true,
    useCustomPermissions: false,
    useDirectory: false,
    useEvents: false,
    useGroups: true,
    useTotp: true,
    usePolicies: true,
    useScim: false,
    useSso: false,
    useKeyConnector: false,
    usePasswordManager: true,
    useSecretsManager: false,
    selfHost: true,
    useApi: true,
    useDisableSMAdsForUsers: true,
    useInviteLinks: false,
    useMyItems: false,
    useOrganizationDomains: false,
    usePam: false,
    usePhishingBlocker: false,
    hasPublicAndPrivateKeys: hasKeys(org),
    useResetPassword: false,
    allowAdminAccessToAllCollectionItems: true,
    limitCollectionCreation: true,
    limitCollectionDeletion: true,
    limitItemDeletion: false,
    businessName: org.name,
    businessAddress1: null,
    businessAddress2: null,
    businessAddress3: null,
    businessCountry: null,
    businessTaxNumber: null,
    maxAutoscaleSeats: null,
    maxAutoscaleSmSeats: null,
    maxAutoscaleSmServiceAccounts: null,
    secretsManagerPlan: null,
    smSeats: null,
    smServiceAccounts: null,
    billingEmail: org.billingEmail,
    planType: 6,
    usersGetPremium: true,
    object: 'organization',
  };
}

/** One entry of the profile's `organizations` list (Vaultwarden's Membership::to_json). */
export function profileOrganizationJson(member: OrganizationMember, org: Organization) {
  return {
    id: org.id,
    identifier: null,
    name: org.name,
    seats: 20,
    maxCollections: null,
    usersGetPremium: true,
    use2fa: true,
    useDirectory: false,
    useEvents: false,
    useGroups: true,
    useTotp: true,
    useScim: false,
    usePolicies: true,
    useApi: true,
    selfHost: true,
    hasPublicAndPrivateKeys: hasKeys(org),
    resetPasswordEnrolled: member.resetPasswordKey !== null,
    useResetPassword: false,
    ssoBound: false,
    useSso: false,
    useKeyConnector: false,
    useSecretsManager: false,
    usePasswordManager: true,
    useCustomPermissions: false,
    useActivateAutofillPolicy: false,
    useAdminSponsoredFamilies: false,
    useRiskInsights: false,
    useDisableSMAdsForUsers: true,
    useInviteLinks: false,
    useMyItems: false,
    useOrganizationDomains: false,
    usePam: false,
    usePhishingBlocker: false,
    organizationUserId: member.id,
    providerId: null,
    providerName: null,
    providerType: null,
    familySponsorshipFriendlyName: null,
    familySponsorshipAvailable: false,
    productTierType: 3,
    keyConnectorEnabled: false,
    keyConnectorUrl: null,
    familySponsorshipLastSyncDate: null,
    familySponsorshipValidUntil: null,
    familySponsorshipToDelete: null,
    accessSecretsManager: false,
    // Vaultwarden: `atype < Manager || !access_all`, comparing roles by authority.
    limitCollectionCreation: !(isAdminType(member.type) && member.accessAll),
    limitCollectionDeletion: true,
    limitItemDeletion: false,
    allowAdminAccessToAllCollectionItems: true,
    userIsClaimedByOrganization: false,
    permissions: PERMISSIONS,
    maxStorageGb: 32767,
    userId: member.userId,
    key: member.akey ? member.akey : null,
    status: member.status,
    type: member.type,
    enabled: true,
    object: 'profileOrganization',
  };
}

export function collectionJson(collection: Collection) {
  return {
    externalId: collection.externalId,
    id: collection.id,
    organizationId: collection.organizationId,
    name: collection.name,
    type: 0,
    defaultUserCollectionEmail: null,
    object: 'collection',
  };
}

/** A collection with the viewing member's own access to it (Vaultwarden's Collection::to_json_details). */
export function collectionDetailsJson(collection: Collection, viewer: OrganizationMember, access: CollectionAccess | null) {
  let readOnly = true;
  let hidePasswords = true;
  let manage = false;
  if (hasFullAccess(viewer)) {
    readOnly = false;
    hidePasswords = false;
    manage = isAdminType(viewer.type);
  } else if (access) {
    readOnly = access.readOnly;
    hidePasswords = access.hidePasswords;
    manage = viewer.type === MemberType.Custom && access.manage;
  }
  return { ...collectionJson(collection), object: 'collectionDetails', readOnly, hidePasswords, manage };
}

/** One entry of a collection's `users` list (Vaultwarden's CollectionMembership::to_json_details_for_member). */
export function collectionMemberAccessJson(access: CollectionAccess, memberType: number) {
  return {
    id: access.memberId,
    readOnly: access.readOnly,
    hidePasswords: access.hidePasswords,
    manage: isAdminType(memberType) || access.manage,
  };
}

/** A member as admins see it in the member list (Vaultwarden's Membership::to_json_details_for_admin). */
export function memberDetailsJson(member: MemberWithUser, collections: CollectionAccess[] | null, groupIds: string[] = []) {
  return {
    id: member.id,
    userId: member.userId,
    name: member.status >= MemberStatus.Accepted ? member.name : null,
    email: member.email,
    externalId: null,
    avatarColor: null,
    groups: groupIds,
    collections:
      collections && !member.accessAll
        ? collections.map((c) => ({ id: c.collectionId, readOnly: c.readOnly, hidePasswords: c.hidePasswords, manage: c.manage }))
        : [],
    status: member.status,
    type: member.type,
    twoFactorEnabled: member.hasTwoFactor,
    resetPasswordEnrolled: member.resetPasswordKey !== null,
    hasMasterPassword: true,
    permissions: null,
    ssoBound: false,
    claimedByOrganization: false,
    usesKeyConnector: false,
    accessSecretsManager: false,
    object: 'organizationUserUserDetails',
  };
}

/** One entry of a collection's `groups` list, or of a group's `collections` list (keyed by `id`). */
export function groupAccessJson(access: GroupAccess) {
  return { id: access.groupId, readOnly: access.readOnly, hidePasswords: access.hidePasswords, manage: access.manage };
}

export function groupJson(group: Group) {
  return { id: group.id, organizationId: group.organizationId, name: group.name, externalId: group.externalId, object: 'group' };
}

/** A group with its collection access (Vaultwarden's Group::to_json_details). */
export function groupDetailsJson(group: Group, access: GroupAccess[]) {
  return {
    ...groupJson(group),
    collections: access.map((a) => ({ id: a.collectionId, readOnly: a.readOnly, hidePasswords: a.hidePasswords, manage: a.manage })),
    object: 'groupDetails',
  };
}

const RESET_PASSWORD_POLICY = 8;

/** Vaultwarden's OrgPolicy::to_json. */
export function policyJson(policy: Policy) {
  let data: unknown = null;
  try {
    data = JSON.parse(policy.data);
  } catch {
    data = null;
  }
  return {
    id: policy.id,
    organizationId: policy.organizationId,
    type: policy.type,
    data,
    enabled: policy.enabled,
    revisionDate: policy.updatedAt,
    object: 'policy',
    ...(policy.type === RESET_PASSWORD_POLICY ? { canToggleState: true } : {}),
  };
}
