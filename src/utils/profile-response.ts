import type { Env, ProfileResponse, User } from '../types';
import { buildAccountKeys } from './user-decryption';
import { isYubiKeyEnabled } from './yubico-otp';
import { profileOrganizationJson } from './organization-response';
import { MemberStatus, type Organization, type OrganizationMember } from '../services/storage-organization-repo';

export interface ProfileResponseOptions {
  /** The user has at least one WebAuthn credential registered as a two-factor provider. */
  hasTwoFactorPasskey?: boolean;
  /** The user's accepted and confirmed memberships, from listMembershipsByUser. */
  memberships?: Array<{ member: OrganizationMember; organization: Organization }>;
}

export function buildProfileResponse(user: User, env?: Env, options: ProfileResponseOptions = {}): ProfileResponse {
  void env;
  const memberships = options.memberships ?? [];
  // Like Vaultwarden: `organizations` lists confirmed memberships, `organizationsNew` accepted ones too.
  const organizationsNew = memberships.map(({ member, organization }) => profileOrganizationJson(member, organization));
  const organizations = organizationsNew.filter((org) => org.status === MemberStatus.Confirmed);
  const accountKeys = buildAccountKeys(user);

  return {
    id: user.id,
    name: user.name,
    email: user.email,
    emailVerified: true,
    premium: true,
    premiumFromOrganization: false,
    usesKeyConnector: false,
    masterPasswordHint: user.masterPasswordHint,
    culture: 'en-US',
    twoFactorEnabled: !!user.totpSecret || isYubiKeyEnabled(user) || !!user.emailTwoFactor || !!user.duoConfig || options.hasTwoFactorPasskey === true,
    yubikeyEnabled: isYubiKeyEnabled(user),
    key: user.key,
    privateKey: user.privateKey,
    accountKeys,
    securityStamp: user.securityStamp || user.id,
    organizations,
    organizationsNew,
    providers: [],
    providerOrganizations: [],
    forcePasswordReset: false,
    avatarColor: user.avatarColor ?? null,
    creationDate: user.createdAt,
    // New-device verification is not supported without an email delivery channel.
    // Always report disabled so clients do not present a false security posture.
    verifyDevices: false,
    role: user.role,
    status: user.status,
    object: 'profile',
  };
}
