import type { Cipher, Env } from '../types';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import { applyKeyRotation } from '../services/storage-key-rotation-repo';
import { auditRequestMetadata, safeWriteAuditEvent } from '../services/audit-events';
import { buildFullCipherUpdate, isValidEncString, optionalEncString, readIncomingAttachmentMetadata } from './ciphers';
import { errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';

type Json = Record<string, unknown>;

const isRecord = (value: unknown): value is Json => !!value && typeof value === 'object' && !Array.isArray(value);
const asArray = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);
const str = (value: unknown): string => (typeof value === 'string' ? value.trim() : '');
const num = (value: unknown): number | undefined => (typeof value === 'number' && Number.isFinite(value) ? value : undefined);
const USER_KEY_ID = /^[0-9a-f]{32}$/;

// POST /api/accounts/key-management/rotate-user-account-keys
//
// Re-keys an account with a v1 (AES-CBC-HMAC) user key: new master-key-wrapped user key,
// new auth hash, the private key re-wrapped, and every cipher, folder and send
// re-encrypted by the client. All of it is written in one transaction. Accounts with a
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

  const [existingCiphers, existingFolders, existingSends] = await Promise.all([
    storage.getAllCiphers(userId),
    storage.getAllFolders(userId),
    storage.getAllSends(userId),
  ]);

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
    newPasswordVerifier: await auth.hashPasswordServer(newHash),
    ciphers,
    attachments,
    folders,
    sends,
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
