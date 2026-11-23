import type { Cipher, Env } from '../types';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import { applyKeyRotation } from '../services/storage-key-rotation-repo';
import { listKeyedGrantorEmergencyAccess } from '../services/storage-emergency-access-repo';
import { auditRequestMetadata, safeWriteAuditEvent } from '../services/audit-events';
import { buildFullCipherUpdate, isValidEncString, optionalEncString, readIncomingAttachmentMetadata } from './ciphers';
import { errorResponse, jsonResponse } from '../utils/response';
import { listMembershipsByUser, MemberStatus } from '../services/storage-organization-repo';
import { generateUUID } from '../utils/uuid';

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
// Re-keys an account with a v1 (AES-CBC-HMAC) user key: new master-key-wrapped user key,
// new auth hash, the private key re-wrapped, and every cipher, folder and send
// re-encrypted by the client. All of it is written in one transaction, including the
// wrapped copies of the user key held for passkeys and trusted devices. Accounts with a
// signature key pair or security state (v2) are refused rather than half rotated.
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
  const keys = isRecord(body.accountKeys) ? body.accountKeys : null;
  const data = isRecord(body.accountData) ? body.accountData : null;
  if (!unlock || !keys || !data) return errorResponse('accountUnlockData, accountKeys and accountData are required', 400);

  // Key rotation changes keys, never the KDF or the salt.
  const kdfType = num(unlock.kdfType ?? unlock.kdf);
  const iterations = num(unlock.kdfIterations ?? unlock.iterations);
  const memory = num(unlock.kdfMemory ?? unlock.memory);
  const parallelism = num(unlock.kdfParallelism ?? unlock.parallelism);
  if (
    kdfType !== user.kdfType ||
    iterations !== user.kdfIterations ||
    (user.kdfType === 1 && (memory !== user.kdfMemory || parallelism !== user.kdfParallelism))
  ) {
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

  if (keys.signatureKeyPair != null || keys.securityState != null) {
    return errorResponse('Rotating accounts with V2 encryption keys is not supported by this server.', 400);
  }
  const privateKey = str(keys.userKeyEncryptedAccountPrivateKey);
  const publicKey = str(keys.accountPublicKey);
  if (!isValidEncString(privateKey) || !privateKey.startsWith('2.') || !publicKey) {
    return errorResponse('The provided account private key was not wrapped with AES-256-CBC-HMAC', 400);
  }
  if (user.publicKey && user.publicKey !== publicKey) {
    return errorResponse('Changing the asymmetric keypair is not possible during key rotation', 400);
  }

  const oldUserKeyId = str(body.oldUserKeyId);
  const newUserKeyId = str(body.newUserKeyId);
  if (oldUserKeyId && user.userKeyId && oldUserKeyId !== user.userKeyId) {
    return errorResponse('The user key being rotated is not the current user key. Sync and try again.', 409);
  }
  if (newUserKeyId && !USER_KEY_ID.test(newUserKeyId)) {
    return errorResponse('newUserKeyId must be a 32-character lowercase hex string', 400);
  }

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

  const [existingCiphers, existingFolders, existingSends, existingEmergencyAccess] = await Promise.all([
    storage.getAllCiphers(userId),
    storage.getAllFolders(userId),
    storage.getAllSends(userId),
    listKeyedGrantorEmergencyAccess(env.DB, userId),
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
  const nextUser = {
    ...user,
    key: newUserKey,
    privateKey,
    publicKey: user.publicKey || publicKey,
    securityStamp: generateUUID(),
    userKeyId: newUserKeyId || user.userKeyId,
  };
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
    newPasswordVerifier: await auth.hashPasswordServer(newHash),
    ciphers,
    attachments,
    folders,
    sends,
    emergencyAccess,
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
    action: 'account.keys.rotate',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: user.id,
    metadata: { ciphers: ciphers.length, folders: folders.length, sends: sends.length, ...auditRequestMetadata(request) },
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
    listMembershipsByUser(env.DB, userId, [MemberStatus.Accepted, MemberStatus.Confirmed]),
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
