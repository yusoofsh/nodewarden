import type { Cipher, Env, User } from '../types';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import { applyKeyRotation } from '../services/storage-key-rotation-repo';
import { listKeyedGrantorEmergencyAccess } from '../services/storage-emergency-access-repo';
import { listAccountRecoveryMemberships } from '../services/storage-organization-repo';
import { auditRequestMetadata, safeWriteAuditEvent } from '../services/audit-events';
import { buildFullCipherUpdate, isValidEncString, optionalEncString, readIncomingAttachmentMetadata } from './ciphers';
import { errorResponse, jsonResponse } from '../utils/response';
import { listMembershipsByUser, MemberStatus, REVOKED_ENROLLABLE_STATUSES } from '../services/storage-organization-repo';
import { generateUUID } from '../utils/uuid';
import {
  applyAccountKeys,
  encStringType,
  isV2User,
  validateAccountKeys,
  validateWrappedAccountCryptographicState,
  type ValidatedAccountKeys,
} from '../utils/account-keys';

type Json = Record<string, unknown>;

const isRecord = (value: unknown): value is Json => !!value && typeof value === 'object' && !Array.isArray(value);
const asArray = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);
const str = (value: unknown): string => (typeof value === 'string' ? value.trim() : '');
const num = (value: unknown): number | undefined => (typeof value === 'number' && Number.isFinite(value) ? value : undefined);
const USER_KEY_ID = /^[0-9a-f]{32}$/;
// RSA-wrapped keys are a single base64 part after the type, unlike symmetric EncStrings.
const isWrappedKey = (value: string): boolean => /^\d+\.[^|\s]+$/.test(value);

// POST /api/accounts/key-management/rotate-user-account-keys
//
// Re-keys an account and changes its master password: new master-key-wrapped user key,
// new auth hash, the account keys re-wrapped, and every cipher, folder and send
// re-encrypted by the client. V1 and V2 account keys are both accepted; see rotateAccount.
export async function handleRotateUserAccountKeys(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
  if (!isRecord(body)) return errorResponse('Invalid JSON', 400);

  const oldHash = str(body.oldMasterKeyAuthenticationHash);
  if (!oldHash) return errorResponse('oldMasterKeyAuthenticationHash is required', 400);
  if (!(await auth.verifyPassword(oldHash, user.masterPasswordHash, user.email))) {
    return errorResponse('Invalid password', 400);
  }

  const unlockRoot = isRecord(body.accountUnlockData) ? body.accountUnlockData : {};
  const unlock = isRecord(unlockRoot.masterPasswordUnlockData) ? unlockRoot.masterPasswordUnlockData : null;
  const data = isRecord(body.accountData) ? body.accountData : null;
  if (!unlock || !isRecord(body.accountKeys) || !data) return errorResponse('accountUnlockData, accountKeys and accountData are required', 400);

  // Key rotation changes keys, never the KDF or the salt.
  if (!kdfUnchanged(user, unlock)) {
    return errorResponse('The provided master password unlock data is not valid for this user.', 400);
  }
  const salt = (str(unlock.masterPasswordSalt) || str(unlock.email)).toLowerCase();
  if (salt !== user.email.trim().toLowerCase()) {
    return errorResponse('The provided master password unlock data is not valid for this user.', 400);
  }

  const newHash = str(unlock.masterKeyAuthenticationHash);
  const newUserKey = str(unlock.masterKeyEncryptedUserKey);
  if (!newHash || !isValidEncString(newUserKey)) {
    return errorResponse('New master key authentication hash and encrypted user key are required', 400);
  }

  const keys = validateAccountKeys(body.accountKeys);
  if (typeof keys === 'string') return errorResponse(keys, 400);
  // Like upstream, this endpoint ends every session, so an upgrade token is never kept.
  const upgradeToken = readUpgradeToken(unlockRoot.v2UpgradeToken);
  if (upgradeToken instanceof Error) return errorResponse(upgradeToken.message, 400);

  return rotateAccount(request, env, user, {
    keys,
    unlockRoot,
    data,
    oldUserKeyId: str(body.oldUserKeyId),
    newUserKeyId: str(body.newUserKeyId),
    wrappedUserKey: newUserKey,
    newPasswordHash: newHash,
    upgradeToken: null,
  });
}

// POST /api/accounts/key-management/rotate-user-keys
//
// Rotates the keys of a V2 account, or upgrades a V1 account to V2, without changing the
// master password. As upstream, the session is the only proof; the unlock method must be
// the master password, whose KDF and salt stay as they are.
export async function handleRotateUserKeys(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
  if (!isRecord(body)) return errorResponse('Invalid JSON', 400);
  const unlockRoot = body.unlockData;
  const data = body.accountData;
  const method = body.unlockMethodData;
  if (!isRecord(unlockRoot) || !isRecord(data) || !isRecord(method)) {
    return errorResponse('wrappedAccountCryptographicState, unlockData, accountData and unlockMethodData are required', 400);
  }

  switch (num(method.unlockMethod)) {
    case 1:
      break;
    case 0:
      return errorResponse('Trusted device encryption is not supported', 400);
    case 2:
      return errorResponse('Key connector is not supported', 400);
    default:
      return errorResponse('Unrecognized unlock method', 400);
  }
  const unlock = method.masterPasswordUnlockData;
  if (!isRecord(unlock) || method.keyConnectorKeyWrappedUserKey != null) {
    return errorResponse(
      'Invalid MasterPassword unlock method request, MasterPasswordUnlockData must be provided and KeyConnectorKeyWrappedUserKey must be null',
      400
    );
  }
  const wrappedUserKey = str(unlock.masterKeyWrappedUserKey ?? unlock.key);
  if (!wrappedUserKey) return errorResponse('The MasterKeyWrappedUserKey field is required.', 400);
  if (!isValidEncString(wrappedUserKey)) return errorResponse('MasterKeyWrappedUserKey is not a valid encrypted string', 400);
  const salt = typeof unlock.salt === 'string' ? unlock.salt : '';
  if (!salt.trim()) return errorResponse('The Salt field is required.', 400);
  if (salt.length > 256) return errorResponse('The field Salt must be a string with a maximum length of 256.', 400);
  if (!user.masterPasswordHash || !user.key) {
    return errorResponse('User is in an invalid state for master password key rotation.', 400);
  }
  if (salt !== user.email.trim().toLowerCase()) return errorResponse('Invalid master password salt.', 400);
  if (!kdfUnchanged(user, isRecord(unlock.kdf) ? unlock.kdf : {})) return errorResponse('Invalid KDF settings.', 400);
  const newUserKeyId = str(body.newUserKeyId);
  if (str(unlock.containedKeyId) !== newUserKeyId) {
    return errorResponse('Invalid user key sent in master-password unlock data.', 400);
  }

  const keys = validateWrappedAccountCryptographicState(body.wrappedAccountCryptographicState);
  if (typeof keys === 'string') return errorResponse(keys, 400);
  const upgradeToken = readUpgradeToken(unlockRoot.v2UpgradeToken);
  if (upgradeToken instanceof Error) return errorResponse(upgradeToken.message, 400);

  return rotateAccount(request, env, user, {
    keys,
    unlockRoot,
    data,
    oldUserKeyId: str(body.oldUserKeyId),
    newUserKeyId,
    wrappedUserKey,
    newPasswordHash: null,
    upgradeToken,
  });
}

interface RotationInput {
  keys: ValidatedAccountKeys;
  // emergencyAccessUnlockData, organizationAccountRecoveryUnlockData, passkeyUnlockData, deviceKeyUnlockData
  unlockRoot: Json;
  // ciphers, folders, sends
  data: Json;
  oldUserKeyId: string;
  newUserKeyId: string;
  // The new user key, wrapped by the master key.
  wrappedUserKey: string;
  // The client's new master password hash; null keeps the password.
  newPasswordHash: string | null;
  // JSON of the client's v2UpgradeToken, honored only while the account is still V1.
  upgradeToken: string | null;
}

function kdfUnchanged(user: User, kdf: Json): boolean {
  const kdfType = num(kdf.kdfType ?? kdf.kdf);
  const iterations = num(kdf.kdfIterations ?? kdf.iterations);
  const memory = num(kdf.kdfMemory ?? kdf.memory);
  const parallelism = num(kdf.kdfParallelism ?? kdf.parallelism);
  return (
    kdfType === user.kdfType &&
    iterations === user.kdfIterations &&
    (user.kdfType !== 1 || (memory === user.kdfMemory && parallelism === user.kdfParallelism))
  );
}

/** The upgrade token as stored (JSON), null when absent, or why it is invalid. */
function readUpgradeToken(value: unknown): string | null | Error {
  if (value == null) return null;
  if (!isRecord(value) || !str(value.wrappedUserKey1)) return new Error('The WrappedUserKey1 field is required.');
  if (!str(value.wrappedUserKey2)) return new Error('The WrappedUserKey2 field is required.');
  return JSON.stringify({ wrappedUserKey1: str(value.wrappedUserKey1), wrappedUserKey2: str(value.wrappedUserKey2) });
}

/**
 * The rotation checks on the new keys, as Vaultwarden's validate_rotation_account_keys: the public
 * key never changes, a V2 account never goes back to V1 and keeps its verifying key, and V2 keys are
 * wrapped by a COSE (type 7) user key.
 */
function rotationKeysError(keys: ValidatedAccountKeys, user: User): string | null {
  if (user.publicKey && user.publicKey !== keys.publicKey) {
    return 'Changing the asymmetric keypair is not possible during key rotation';
  }
  if (!keys.v2) {
    if (isV2User(user)) return 'Cannot downgrade an account from v2 to v1 encryption during key rotation';
    if (!isValidEncString(keys.privateKey) || encStringType(keys.privateKey) !== '2') {
      return 'The provided account private key was not wrapped with AES-256-CBC-HMAC';
    }
    return null;
  }
  // Both a V2 rotation and the V1 to V2 upgrade end with a COSE user key wrapping the private keys.
  if (encStringType(keys.v2.signingKey) !== '7') return 'The provided signing key data is not wrapped with XChaCha20-Poly1305.';
  if (encStringType(keys.privateKey) !== '7') return 'The provided private key encryption key is not wrapped with XChaCha20-Poly1305.';
  // The V1 to V2 upgrade is where the signature key pair comes from.
  if (!isV2User(user)) return null;
  if (!user.signatureKeyPair) return 'The account is missing its signature key pair';
  if (user.signatureKeyPair.verifyingKey !== keys.v2.verifyingKey) {
    return 'Changing the verifying key is not possible during key rotation';
  }
  return null;
}

// Both rotation endpoints. All of it is written in one transaction, including the wrapped copies
// of the user key held for passkeys and trusted devices, and the V2 key pair. Every session ends.
async function rotateAccount(request: Request, env: Env, user: User, input: RotationInput): Promise<Response> {
  const storage = new StorageService(env.DB);
  const { keys, unlockRoot, data, oldUserKeyId, newUserKeyId } = input;
  const userId = user.id;

  if (oldUserKeyId && user.userKeyId && oldUserKeyId !== user.userKeyId) {
    return errorResponse('The user key being rotated is not the current user key. Sync and try again.', 409);
  }
  if (newUserKeyId && !USER_KEY_ID.test(newUserKeyId)) {
    return errorResponse('newUserKeyId must be a 32-character lowercase hex string', 400);
  }
  const keysError = rotationKeysError(keys, user);
  if (keysError) return errorResponse(keysError, 400);

  // An upgrade from V1 can't re-wrap the account recovery keys without the member trusting the
  // organization's key, so they are kept and get the token an admin re-wraps them from.
  const isUpgrade = input.upgradeToken !== null && !isV2User(user);
  const upgradeToken = isUpgrade ? input.upgradeToken : null;

  // Copies of the user key wrapped for passkeys and trusted devices. Clients send the
  // ones they can re-wrap. Any row left out has its wrapped key cleared, never kept.
  const passkeys: Array<{ id: string; encryptedUserKey: string; encryptedPublicKey: string | null }> = [];
  for (const item of asArray(unlockRoot.passkeyUnlockData)) {
    if (!isRecord(item)) continue;
    const encryptedUserKey = str(item.encryptedUserKey);
    const encryptedPublicKey = str(item.encryptedPublicKey) || null;
    if (!str(item.id) || !isWrappedKey(encryptedUserKey) || (encryptedPublicKey && !isValidEncString(encryptedPublicKey))) {
      return errorResponse('Invalid passkey unlock data', 400);
    }
    passkeys.push({ id: str(item.id), encryptedUserKey, encryptedPublicKey });
  }
  const devices: Array<{ deviceIdentifier: string; encryptedUserKey: string; encryptedPublicKey: string | null }> = [];
  for (const item of asArray(unlockRoot.deviceKeyUnlockData)) {
    if (!isRecord(item)) continue;
    const encryptedUserKey = str(item.encryptedUserKey);
    const encryptedPublicKey = str(item.encryptedPublicKey) || null;
    if (!str(item.deviceId) || !isWrappedKey(encryptedUserKey) || (encryptedPublicKey && !isValidEncString(encryptedPublicKey))) {
      return errorResponse('Invalid device unlock data', 400);
    }
    devices.push({ deviceIdentifier: str(item.deviceId), encryptedUserKey, encryptedPublicKey });
  }

  const [existingCiphers, existingFolders, existingSends, existingEmergencyAccess, existingAccountRecovery] = await Promise.all([
    storage.getAllCiphers(userId),
    storage.getAllFolders(userId),
    storage.getAllSends(userId),
    listKeyedGrantorEmergencyAccess(env.DB, userId),
    listAccountRecoveryMemberships(env.DB, userId),
  ]);

  // Emergency contacts hold the user key wrapped with their public key. Every confirmed
  // one must be re-wrapped, or the contact would hold a key that no longer exists.
  const incomingEmergencyKeys = new Map<string, string>();
  for (const item of asArray(unlockRoot.emergencyAccessUnlockData)) {
    if (isRecord(item) && str(item.id)) incomingEmergencyKeys.set(str(item.id), str(item.keyEncrypted));
  }
  const emergencyAccess: Array<{ id: string; keyEncrypted: string }> = [];
  for (const access of existingEmergencyAccess) {
    if (!incomingEmergencyKeys.has(access.id)) {
      return errorResponse('All existing emergency access keys must be included in the rotation', 400);
    }
    const keyEncrypted = incomingEmergencyKeys.get(access.id)!;
    if (!isWrappedKey(keyEncrypted)) return errorResponse('Emergency access keys cannot be set to null during rotation.', 400);
    emergencyAccess.push({ id: access.id, keyEncrypted });
  }

  // Each organization the user enrolled in account recovery holds the user key wrapped with its public
  // key. It must be re-wrapped too, or a recovery would install a user key that no longer exists.
  const incomingRecoveryKeys = new Map<string, string>();
  for (const item of asArray(unlockRoot.organizationAccountRecoveryUnlockData)) {
    if (isRecord(item) && str(item.organizationId)) incomingRecoveryKeys.set(str(item.organizationId).toLowerCase(), str(item.resetPasswordKey));
  }
  const accountRecovery: Array<{ id: string; key: string | null }> = [];
  for (const membership of existingAccountRecovery) {
    if (!incomingRecoveryKeys.has(membership.organizationId)) {
      return errorResponse('All existing reset password keys must be included in the rotation', 400);
    }
    const key = incomingRecoveryKeys.get(membership.organizationId)!;
    if (isUpgrade) {
      if (key) return errorResponse('Account recovery keys cannot be rotated during a V1 to V2 upgrade rotation.', 400);
      accountRecovery.push({ id: membership.id, key: null });
      continue;
    }
    if (!isWrappedKey(key)) return errorResponse('Account recovery keys cannot be null or empty during rotation.', 400);
    accountRecovery.push({ id: membership.id, key });
  }

  const incomingCiphers = new Map<string, Json>();
  for (const item of asArray(data.ciphers)) {
    if (!isRecord(item) || item.organizationId) continue;
    const id = str(item.id);
    if (!id) return errorResponse('The Id field is required.', 400);
    incomingCiphers.set(id, item);
  }
  const incomingFolders = new Map<string, string>();
  for (const item of asArray(data.folders)) {
    if (!isRecord(item)) continue; // clients before 2024.4 send a stray null entry
    const id = str(item.id);
    if (id) incomingFolders.set(id, str(item.name));
  }
  const incomingSends = new Map<string, string>();
  for (const item of asArray(data.sends)) {
    if (!isRecord(item)) continue;
    const id = str(item.id);
    if (!id) return errorResponse('The Id field is required.', 400);
    incomingSends.set(id, str(item.key));
  }

  // Anything left out would stay encrypted with a key that no longer exists.
  if (existingCiphers.some((c) => !incomingCiphers.has(c.id))) {
    return errorResponse('All existing ciphers must be included in the rotation', 400);
  }
  if (existingFolders.some((f) => !incomingFolders.has(f.id))) {
    return errorResponse('All existing folders must be included in the rotation', 400);
  }
  if (existingSends.some((s) => !incomingSends.has(s.id))) {
    return errorResponse('All existing sends must be included in the rotation', 400);
  }

  const folderIds = new Set(existingFolders.map((f) => f.id));
  const folders: Array<{ id: string; name: string }> = [];
  for (const folder of existingFolders) {
    const name = incomingFolders.get(folder.id) ?? '';
    if (!isValidEncString(name)) return errorResponse('Folder name is not a valid encrypted string', 400);
    folders.push({ id: folder.id, name });
  }
  const sends: Array<{ id: string; key: string }> = [];
  for (const send of existingSends) {
    const key = incomingSends.get(send.id) ?? '';
    if (!isValidEncString(key)) return errorResponse('Send key is not a valid encrypted string', 400);
    sends.push({ id: send.id, key });
  }

  const ciphers: Cipher[] = [];
  const attachments: Array<{ cipherId: string; id: string; fileName: string | null; key: string | null }> = [];
  for (const existing of existingCiphers) {
    const incoming = incomingCiphers.get(existing.id)!;
    const built = buildFullCipherUpdate(existing, incoming, false);
    if ('error' in built) return errorResponse(built.error, 400);
    if (built.cipher.folderId && !folderIds.has(built.cipher.folderId)) {
      return errorResponse('Folder not found', 404);
    }
    ciphers.push(built.cipher);
    for (const item of readIncomingAttachmentMetadata(incoming)) {
      if (!item.hasKey && !item.hasFileName) continue;
      attachments.push({
        cipherId: existing.id,
        id: item.id,
        fileName: item.hasFileName ? optionalEncString(item.fileName) : null,
        key: item.hasKey ? optionalEncString(item.key) : null,
      });
    }
  }

  const now = new Date().toISOString();
  const nextUser: User = {
    ...user,
    key: input.wrappedUserKey,
    securityStamp: generateUUID(),
    userKeyId: newUserKeyId || user.userKeyId,
    v2UpgradeToken: upgradeToken,
  };
  applyAccountKeys(nextUser, keys);
  nextUser.publicKey = user.publicKey || keys.publicKey;
  const applied = await applyKeyRotation(env.DB, {
    user: nextUser,
    expectedPasswordVerifier: user.masterPasswordHash,
    expectedSecurityStamp: user.securityStamp,
    expectedCounts: {
      ciphers: existingCiphers.length,
      folders: existingFolders.length,
      sends: existingSends.length,
      emergencyAccess: existingEmergencyAccess.length,
    },
    newPasswordVerifier: input.newPasswordHash === null
      ? user.masterPasswordHash
      : await new AuthService(env).hashPasswordServer(input.newPasswordHash),
    ciphers,
    attachments,
    folders,
    sends,
    emergencyAccess,
    accountRecovery,
    signatureKeyPair: nextUser.signatureKeyPair ?? null,
    passkeys,
    devices,
    now,
  });
  AuthService.invalidateUserCache(user.id);
  if (!applied) {
    return errorResponse('The account changed while the keys were rotating. Sync and try again.', 409);
  }

  await safeWriteAuditEvent(env, {
    actorUserId: user.id,
    action: isUpgrade ? 'account.keys.upgrade_v2' : 'account.keys.rotate',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: user.id,
    metadata: {
      ciphers: ciphers.length,
      folders: folders.length,
      sends: sends.length,
      v2: !!keys.v2,
      ...auditRequestMetadata(request),
    },
  });
  return new Response(null, { status: 200 });
}

// GET /api/accounts/key-management/key-rotation-data
// The keys a rotation re-wraps the new user key for, shaped like Vaultwarden. Emergency access
// lists exactly the rows the rotation above requires. Passkey and device lists stay empty:
// the rotation clears any row the client leaves out.
export async function handleGetKeyRotationData(env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const [memberships, emergencyAccess] = await Promise.all([
    // Revoked rows keep their earlier status minus an offset; they stay enrolled, so the rotation below requires their keys too.
    listMembershipsByUser(env.DB, userId, [MemberStatus.Accepted, MemberStatus.Confirmed, ...REVOKED_ENROLLABLE_STATUSES]),
    listKeyedGrantorEmergencyAccess(env.DB, userId),
  ]);

  const organizationPasswordResetKeyData = memberships
    .filter(({ member, organization }) => member.resetPasswordKey && organization.publicKey)
    .map(({ organization }) => ({
      organizationId: organization.id,
      organizationName: organization.name,
      organizationPublicKey: organization.publicKey,
      object: 'organizationPasswordResetKeyData',
    }));

  const emergencyAccessKeyData = [];
  for (const access of emergencyAccess) {
    const grantee = access.granteeId ? await storage.getUserById(access.granteeId) : null;
    if (!grantee?.publicKey) continue;
    emergencyAccessKeyData.push({
      id: access.id,
      granteeId: grantee.id,
      granteeName: grantee.name,
      granteeEmail: grantee.email,
      publicKey: grantee.publicKey,
      object: 'emergencyAccessKeyData',
    });
  }

  return jsonResponse({
    organizationPasswordResetKeyData,
    emergencyAccessKeyData,
    trustedDeviceKeyData: [],
    passkeyKeyData: [],
    object: 'keyRotationData',
  });
}
