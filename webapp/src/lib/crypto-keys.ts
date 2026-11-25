// Key handling for emergency access, in Bitwarden's formats:
// - A symmetric key is 64 bytes, an AES key then a MAC key, and strings it encrypts are type 2.
// - A key wrapped for a user is RSA-OAEP SHA-1 over their SPKI public key, as `4.<base64>`.
import { base64ToBytes, bytesToBase64, decryptBw, decryptStr, encryptBw, toBufferSource } from './crypto';
import { t } from './i18n';
import type { SessionState } from './types';

export interface SymmetricKey {
  enc: Uint8Array;
  mac: Uint8Array;
}

const RSA = { name: 'RSA-OAEP', hash: 'SHA-1' } as const;

function splitKey(bytes: Uint8Array): SymmetricKey {
  if (bytes.length < 64) throw new Error('Invalid key length');
  return { enc: bytes.slice(0, 32), mac: bytes.slice(32, 64) };
}

const joinKey = (key: SymmetricKey): Uint8Array => {
  const bytes = new Uint8Array(64);
  bytes.set(key.enc, 0);
  bytes.set(key.mac, 32);
  return bytes;
};

export function sessionUserKey(session: SessionState | null): SymmetricKey {
  if (!session?.symEncKey || !session.symMacKey) throw new Error(t('txt_vault_key_unavailable'));
  return { enc: base64ToBytes(session.symEncKey), mac: base64ToBytes(session.symMacKey) };
}

/** The user's RSA private key, from the profile's `privateKey` encrypted with the user key. */
export async function importUserPrivateKey(encryptedPrivateKey: string, userKey: SymmetricKey): Promise<CryptoKey> {
  const pkcs8 = await decryptBw(encryptedPrivateKey, userKey.enc, userKey.mac);
  return crypto.subtle.importKey('pkcs8', toBufferSource(pkcs8), RSA, false, ['decrypt']);
}

/** Wraps a 64-byte key for the holder of a base64 SPKI public key. */
export async function wrapKeyForPublicKey(key: SymmetricKey, publicKeyB64: string): Promise<string> {
  const publicKey = await crypto.subtle.importKey('spki', toBufferSource(base64ToBytes(publicKeyB64)), RSA, false, ['encrypt']);
  const wrapped = new Uint8Array(await crypto.subtle.encrypt(RSA, publicKey, toBufferSource(joinKey(key))));
  return `4.${bytesToBase64(wrapped)}`;
}

/** Unwraps a `4.` (or `3.`) RSA-wrapped key with the user's private key. */
export async function unwrapKey(wrapped: string, privateKey: CryptoKey): Promise<SymmetricKey> {
  const body = wrapped.slice(wrapped.indexOf('.') + 1).split('|')[0];
  const bytes = new Uint8Array(await crypto.subtle.decrypt(RSA, privateKey, toBufferSource(base64ToBytes(body))));
  return splitKey(bytes);
}

export async function encryptText(value: string, key: SymmetricKey): Promise<string> {
  return encryptBw(new TextEncoder().encode(value), key.enc, key.mac);
}

/** Decrypts a type 2 string, or returns '' when it is not one this key opens. */
export async function decryptText(value: string | null | undefined, key: SymmetricKey): Promise<string> {
  try {
    return await decryptStr(value, key.enc, key.mac);
  } catch {
    return '';
  }
}

