import assert from 'node:assert/strict';
import test from 'node:test';
import { isV2AccountKeys } from '../webapp/src/lib/account-keys-v2';
import { buildAccountKeys } from '../src/utils/user-decryption';

const v1User = { privateKey: '2.cHJpdg==|cHJpdg==|bWFj', publicKey: 'cHVi', signedPublicKey: null, securityState: null, securityVersion: null, signatureKeyPair: null };
const v2User = {
  ...v1User,
  signedPublicKey: 'signed',
  securityState: 'state',
  securityVersion: 2,
  signatureKeyPair: { signatureAlgorithm: 0, signingKey: 'wrapped', verifyingKey: 'verifying' },
};

test('the web vault guard lets a V1 account through and refuses a V2 account', () => {
  assert.equal(isV2AccountKeys(buildAccountKeys(v1User as never)), false);
  assert.equal(isV2AccountKeys(buildAccountKeys(v2User as never)), true);
});

test('the web vault guard treats missing account keys as V1', () => {
  assert.equal(isV2AccountKeys(null), false);
  assert.equal(isV2AccountKeys(undefined), false);
  assert.equal(isV2AccountKeys({}), false);
  assert.equal(isV2AccountKeys({ signatureKeyPair: null, securityState: null }), false);
});
