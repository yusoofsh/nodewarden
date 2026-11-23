import type { User } from '../types';

// The `accountKeys` a client sends: a V1 key pair, or V2 with a signed public key, a signature
// key pair and a security state. Validated as Vaultwarden's AccountKeysData::validate does.

export interface V2AccountKeys {
  signedPublicKey: string;
  signingKey: string;
  verifyingKey: string;
  signatureAlgorithm: number;
  securityState: string;
  securityVersion: number;
}

export interface ValidatedAccountKeys {
  privateKey: string;
  publicKey: string;
  v2: V2AccountKeys | null;
}

const SIGNATURE_ALGORITHMS: Record<string, number> = { ed25519: 0, mldsa44: 1 };
const MAX_SECURITY_STATE_LENGTH = 10_000;

type Json = Record<string, unknown>;
const isRecord = (value: unknown): value is Json => !!value && typeof value === 'object' && !Array.isArray(value);
const filled = (value: unknown): value is string => typeof value === 'string' && value.trim() !== '';

export function isV2User(user: Pick<User, 'signedPublicKey' | 'securityState' | 'securityVersion'>): boolean {
  return !!user.signedPublicKey && !!user.securityState && user.securityVersion != null;
}

/** The validated keys, or the error message to answer with. */
export function validateAccountKeys(raw: unknown): ValidatedAccountKeys | string {
  if (!isRecord(raw)) return 'The AccountKeys field is required.';
  if (!filled(raw.userKeyEncryptedAccountPrivateKey)) return 'The UserKeyEncryptedAccountPrivateKey field is required.';
  if (!filled(raw.accountPublicKey)) return 'The AccountPublicKey field is required.';

  let privateKey = raw.userKeyEncryptedAccountPrivateKey;
  let publicKey = raw.accountPublicKey;
  let signedPublicKey: unknown = null;
  const pair = raw.publicKeyEncryptionKeyPair;
  if (pair != null) {
    if (!isRecord(pair) || !filled(pair.wrappedPrivateKey)) return 'The WrappedPrivateKey field is required.';
    if (!filled(pair.publicKey)) return 'The PublicKey field is required.';
    privateKey = pair.wrappedPrivateKey;
    publicKey = pair.publicKey;
    signedPublicKey = pair.signedPublicKey ?? null;
  }

  const signature = raw.signatureKeyPair ?? null;
  if (signature !== null) {
    if (!isRecord(signature) || !filled(signature.signatureAlgorithm)) return 'The SignatureAlgorithm field is required.';
    if (!filled(signature.wrappedSigningKey)) return 'The WrappedSigningKey field is required.';
    if (!filled(signature.verifyingKey)) return 'The VerifyingKey field is required.';
  }
  const state = raw.securityState ?? null;
  if (state !== null) {
    if (!isRecord(state) || !filled(state.securityState)) return 'The SecurityState field is required.';
    if (state.securityState.length > MAX_SECURITY_STATE_LENGTH) {
      return `The field SecurityState must be a string with a maximum length of ${MAX_SECURITY_STATE_LENGTH}.`;
    }
    if (!Number.isInteger(state.securityVersion)) return 'The SecurityVersion field is required.';
  }

  if (signedPublicKey === null && signature === null && state === null) return { privateKey, publicKey, v2: null };
  if (signedPublicKey === null || signature === null || state === null) {
    return 'Invalid account keys: the signed public key, signature key pair and security state must either all be present or all be absent';
  }
  if (!filled(signedPublicKey)) return 'The SignedPublicKey field is required.';
  const algorithm = SIGNATURE_ALGORITHMS[signature.signatureAlgorithm as string];
  if (algorithm === undefined) return `Unsupported signature algorithm: ${signature.signatureAlgorithm}`;
  return {
    privateKey,
    publicKey,
    v2: {
      signedPublicKey,
      signingKey: signature.wrappedSigningKey as string,
      verifyingKey: signature.verifyingKey as string,
      signatureAlgorithm: algorithm,
      securityState: state.securityState as string,
      securityVersion: state.securityVersion as number,
    },
  };
}

/** `rotate-user-keys`' wrappedAccountCryptographicState: V2 only, every part required. */
export function validateWrappedAccountCryptographicState(raw: unknown): ValidatedAccountKeys | string {
  if (!isRecord(raw) || !isRecord(raw.publicKeyEncryptionKeyPair) || !isRecord(raw.signatureKeyPair) || !isRecord(raw.securityState)) {
    return 'The WrappedAccountCryptographicState field is required.';
  }
  const pair = raw.publicKeyEncryptionKeyPair;
  return validateAccountKeys({
    userKeyEncryptedAccountPrivateKey: pair.wrappedPrivateKey,
    accountPublicKey: pair.publicKey,
    publicKeyEncryptionKeyPair: pair,
    signatureKeyPair: raw.signatureKeyPair,
    securityState: raw.securityState,
  });
}

/** Sets the validated keys on the user; a V1 set clears any V2 state. */
export function applyAccountKeys(user: User, keys: ValidatedAccountKeys): void {
  user.privateKey = keys.privateKey;
  user.publicKey = keys.publicKey;
  user.signedPublicKey = keys.v2?.signedPublicKey ?? null;
  user.securityState = keys.v2?.securityState ?? null;
  user.securityVersion = keys.v2?.securityVersion ?? null;
  user.signatureKeyPair = keys.v2
    ? { algorithm: keys.v2.signatureAlgorithm, signingKey: keys.v2.signingKey, verifyingKey: keys.v2.verifyingKey }
    : null;
}

/** The encryption type of an EncString, the number before the first `.`. */
export function encStringType(value: string): string | null {
  const dot = value.indexOf('.');
  return dot > 0 ? value.slice(0, dot) : null;
}
