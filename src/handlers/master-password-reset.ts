// Setting another user's master password during an emergency access takeover.
import type { Env, User } from '../types';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import { isValidEncString } from './ciphers';
import { generateUUID } from '../utils/uuid';

type Json = Record<string, unknown>;
const isRecord = (value: unknown): value is Json => !!value && typeof value === 'object' && !Array.isArray(value);
const str = (value: unknown): string => (typeof value === 'string' ? value.trim() : '');

export interface NewMasterPassword {
  hash: string;
  key: string;
}

/**
 * The new master password hash and wrapped user key for `user`, or why the request is refused.
 * Current clients send authenticationData and unlockData, whose salt and KDF must be the account's;
 * older ones send newMasterPasswordHash and key. Returns null when the request carries neither.
 */
export function readNewMasterPassword(body: Json, user: User): NewMasterPassword | string | null {
  let hash: string;
  let key: string;
  if (isRecord(body.authenticationData) && isRecord(body.unlockData)) {
    const auth = body.authenticationData;
    const unlock = body.unlockData;
    const salt = user.email.trim().toLowerCase();
    const kdfMatches = (source: Json) => {
      const kdf = isRecord(source.kdf) ? source.kdf : {};
      return (
        kdf.kdfType === user.kdfType &&
        kdf.iterations === user.kdfIterations &&
        (user.kdfType !== 1 || (kdf.memory === user.kdfMemory && kdf.parallelism === user.kdfParallelism))
      );
    };
    if (str(auth.salt) !== salt || str(unlock.salt) !== salt) return 'Invalid master password salt';
    if (!kdfMatches(auth) || !kdfMatches(unlock)) return 'KDF settings do not match the user account';
    hash = str(auth.masterPasswordAuthenticationHash);
    key = str(unlock.masterKeyWrappedUserKey);
  } else {
    hash = str(body.newMasterPasswordHash);
    key = str(body.key);
    if (!hash && !key) return null;
  }
  if (!hash || !key) return 'Invalid request!';
  if (!isValidEncString(key)) return 'key is not a valid encrypted string';
  return { hash, key };
}

/**
 * Sets the new master password and, when asked, turns off every two-step login method, which would
 * otherwise block the login. Either way every session of the user ends.
 */
export async function resetUserCredentials(
  env: Env,
  user: User,
  password: NewMasterPassword | null,
  resetTwoFactor: boolean
): Promise<void> {
  const storage = new StorageService(env.DB);
  if (password) {
    user.masterPasswordHash = await new AuthService(env).hashPasswordServer(password.hash);
    user.key = password.key;
  }
  if (resetTwoFactor) {
    user.totpSecret = null;
    user.totpRecoveryCode = null;
    user.yubikeyKey1 = user.yubikeyKey2 = user.yubikeyKey3 = user.yubikeyKey4 = user.yubikeyKey5 = null;
    user.yubikeyNfc = false;
    user.duoConfig = null;
  }
  user.securityStamp = generateUUID();
  user.updatedAt = new Date().toISOString();
  await storage.saveUser(user);
  if (resetTwoFactor) {
    for (const credential of await storage.getAccountPasskeyCredentialsByUserId(user.id, 'twoFactor')) {
      await storage.deleteAccountPasskeyCredential(user.id, credential.id, 'twoFactor');
    }
    if (user.emailTwoFactor) await storage.setEmailTwoFactor(user.id, null);
  }
  await storage.deleteRefreshTokensByUserId(user.id);
  AuthService.invalidateUserCache(user.id);
}
