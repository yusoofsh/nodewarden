// The web vault only implements V1 encryption (AES-CBC user key). A V2 account holds a COSE user key and a
// signing key pair, so unlocking it here would decrypt with the wrong keys and could write items that no
// official client can read. Callers refuse before any key work.
export function isV2AccountKeys(accountKeys: unknown): boolean {
  if (!accountKeys || typeof accountKeys !== 'object') return false;
  const keys = accountKeys as Record<string, unknown>;
  return keys.signatureKeyPair != null || keys.securityState != null;
}
