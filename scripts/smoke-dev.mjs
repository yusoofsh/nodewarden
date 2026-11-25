// Drives a running server (wrangler dev or a deployed URL) over HTTP: register, log in,
// sync, create items, then the account routes added for Vaultwarden parity.
// Usage: node scripts/smoke-dev.mjs http://localhost:8787
// Registers throwaway accounts; point it at a scratch instance, not your live vault.
const base = (process.argv[2] || 'http://localhost:8787').replace(/\/$/, '');
const enc = (label) => `2.${btoa('iv-' + label)}|${btoa('ct-' + label)}|${btoa('mac-' + label)}`;
const run = Date.now().toString(36);
let failed = 0;

async function call(method, path, { token, body, form, multipart } = {}) {
  const headers = { 'CF-Connecting-IP': '198.51.100.7', Origin: base };
  if (token) headers.Authorization = `Bearer ${token}`;
  let payload;
  if (multipart) {
    payload = multipart;
  } else if (form) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    payload = new URLSearchParams(form).toString();
  } else if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  }
  const res = await fetch(base + path, { method, headers, body: payload });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, json, text };
}

function check(name, ok, detail = '') {
  if (!ok) failed++;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${ok ? '' : ' ' + detail}`);
}

async function register(email, hash, inviteCode) {
  return call('POST', '/api/accounts/register', {
    body: {
      inviteCode,
      email, name: 'smoke', masterPasswordHash: hash, masterPasswordHint: null, key: enc('userkey'),
      kdf: 0, kdfIterations: 600000, keys: { encryptedPrivateKey: enc('priv'), publicKey: 'cHVibGljLWtleQ==' },
    },
  });
}

async function login(email, hash) {
  return call('POST', '/identity/connect/token', {
    form: {
      grant_type: 'password', username: email, password: hash, scope: 'api offline_access', client_id: 'web',
      deviceType: '9', deviceIdentifier: '11111111-2222-3333-4444-555555555555', deviceName: 'smoke',
    },
  });
}

const email = `smoke-${run}@example.test`;
const email2 = `smoke2-${run}@example.test`;

// Both must answer with a JSON timestamp. A 200 with HTML means the web vault's SPA fallback answered.
for (const path of ['/alive', '/api/alive']) {
  const alive = await call('GET', path);
  check(`GET ${path} returns a timestamp`, alive.status === 200 && typeof alive.json === 'string' && !Number.isNaN(Date.parse(alive.json)), `${alive.status} ${alive.text.slice(0, 60)}`);
}

// SSO is off unless SSO_ENABLED is set: its routes fall through to the authenticated router as before,
// and the authorization_code grant stays unsupported.
for (const [method, path] of [
  ['GET', '/identity/sso/prevalidate'],
  ['GET', '/identity/connect/authorize?client_id=mobile&state=s&code_challenge=c&code_challenge_method=S256'],
  ['GET', '/identity/connect/oidc-signin?code=c&state=s'],
  ['POST', '/api/organizations/domain/sso/verified'],
]) {
  const res = await call(method, path);
  check(`${method} ${path.split('?')[0]} without SSO is 401 as before`, res.status === 401, `${res.status} ${res.text.slice(0, 100)}`);
}
const ssoGrant = await call('POST', '/identity/connect/token', { form: { grant_type: 'authorization_code', code: 'c', code_verifier: 'v', client_id: 'mobile' } });
check('authorization_code grant without SSO stays unsupported', ssoGrant.status === 400 && ssoGrant.json?.error === 'unsupported_grant_type', `${ssoGrant.status} ${ssoGrant.text.slice(0, 100)}`);

const reg = await register(email, 'hash-1');
check('register', reg.status === 200, `${reg.status} ${reg.text}`);
let session = await login(email, 'hash-1');
check('login', session.status === 200 && session.json?.access_token, `${session.status} ${session.text.slice(0, 200)}`);
let token = session.json?.access_token;
if (!token) process.exit(1);

const folder = await call('POST', '/api/folders', { token, body: { name: enc('folder') } });
check('create folder', folder.status === 200, folder.text);
const cipher = await call('POST', '/api/ciphers', {
  token,
  body: { type: 1, folderId: folder.json?.id, name: enc('name'), notes: enc('notes'), login: { username: enc('u'), password: enc('p'), uris: [] } },
});
check('create cipher', cipher.status === 200, cipher.text);
let sync = await call('GET', '/api/sync', { token });
check('sync lists the cipher', sync.status === 200 && sync.json?.ciphers?.length === 1, sync.text.slice(0, 200));

const tasks = await call('GET', '/api/tasks', { token });
check('GET /api/tasks', tasks.status === 200 && tasks.json?.data?.length === 0, tasks.text);
const hibp = await call('GET', '/api/hibp/breach?username=a%40b.test', { token });
check('GET /api/hibp/breach without key is 400', hibp.status === 400, `${hibp.status}`);

const profile = await call('GET', '/api/accounts/profile', { token });
const selfId = profile.json?.id;
const publicKey = await call('GET', `/api/users/${selfId}/public-key`, { token });
check('public key lookup', publicKey.status === 200 && publicKey.json?.publicKey === 'cHVibGljLWtleQ==', publicKey.text);

// Duo stays off until a user saves Duo settings; a bad host is refused before any request to Duo.
const duo = await call('POST', '/api/two-factor/get-duo', { token, body: { masterPasswordHash: 'hash-1' } });
check('get-duo reports Duo off', duo.status === 200 && duo.json?.enabled === false && duo.json?.clientSecret === null, `${duo.status} ${duo.text}`);
const providers = await call('GET', '/api/two-factor', { token });
check('no two-factor provider is listed', providers.status === 200 && providers.json?.Data?.length === 0, providers.text);
const badDuo = await call('PUT', '/api/two-factor/duo', {
  token, body: { masterPasswordHash: 'hash-1', host: 'evil.example.test', clientId: 'DIABCDEFGHIJKLMNOPQR', clientSecret: 'S'.repeat(40) },
});
check('a non-Duo host is refused', badDuo.status === 400, `${badDuo.status} ${badDuo.text}`);
check('DELETE /api/two-factor/duo needs the password', (await call('DELETE', '/api/two-factor/duo', { token, body: { masterPasswordHash: 'wrong' } })).status === 400);

// Key rotation: re-key the account, the folder and the cipher.
const rotate = await call('POST', '/api/accounts/key-management/rotate-user-account-keys', {
  token,
  body: {
    oldMasterKeyAuthenticationHash: 'hash-1',
    accountUnlockData: {
      masterPasswordUnlockData: {
        kdfType: 0, kdfIterations: 600000, email, masterKeyAuthenticationHash: 'hash-2', masterKeyEncryptedUserKey: enc('userkey2'),
      },
    },
    accountKeys: { userKeyEncryptedAccountPrivateKey: enc('priv2'), accountPublicKey: 'cHVibGljLWtleQ==' },
    accountData: {
      ciphers: [{ id: cipher.json?.id, type: 1, folderId: folder.json?.id, name: enc('name2'), notes: enc('notes2'), login: { username: enc('u2'), password: enc('p2'), uris: [] } }],
      folders: [{ id: folder.json?.id, name: enc('folder2') }],
      sends: [],
    },
  },
});
check('rotate user account keys', rotate.status === 200, `${rotate.status} ${rotate.text}`);
const stale = await call('GET', '/api/sync', { token });
check('old token is rejected after rotation', stale.status === 401, `${stale.status}`);
check('old password no longer logs in', (await login(email, 'hash-1')).status !== 200);
session = await login(email, 'hash-2');
check('new password logs in', session.status === 200, session.text.slice(0, 200));
token = session.json?.access_token;
sync = await call('GET', '/api/sync', { token });
check('rotated cipher and folder are served', sync.json?.ciphers?.[0]?.name === enc('name2') && sync.json?.folders?.[0]?.name === enc('folder2'), sync.text.slice(0, 300));

// KDF change to Argon2id.
const kdf = await call('POST', '/api/accounts/kdf', {
  token,
  body: { masterPasswordHash: 'hash-2', newMasterPasswordHash: 'hash-3', key: enc('userkey3'), kdf: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 },
});
check('change KDF', kdf.status === 200, `${kdf.status} ${kdf.text}`);
const prelogin = await call('POST', '/identity/accounts/prelogin', { body: { email } });
check('prelogin reports Argon2id', prelogin.json?.kdf === 1 && prelogin.json?.kdfMemory === 64, prelogin.text);
session = await login(email, 'hash-3');
check('login after KDF change', session.status === 200, session.text.slice(0, 200));
token = session.json?.access_token;

// Security stamp.
const stamp = await call('POST', '/api/accounts/security-stamp', { token, body: { masterPasswordHash: 'hash-3' } });
check('rotate security stamp', stamp.status === 200, `${stamp.status} ${stamp.text}`);
check('token is rejected after the stamp changes', (await call('GET', '/api/sync', { token })).status === 401);

// Self-delete a second account.
// The first account is the admin and later accounts need an invite code.
session = await login(email, 'hash-3');
token = session.json?.access_token;

// Self-delete a second account.
const invite = await call('POST', '/api/admin/invites', { token: session.json?.access_token, body: { masterPasswordHash: 'hash-3' } });
check('admin creates an invite', invite.status === 201 && invite.json?.code, `${invite.status} ${invite.text}`);
const second0 = await register(email2, 'hash-x', invite.json?.code);
check('register second account', second0.status === 200, `${second0.status} ${second0.text}`);
const second = await login(email2, 'hash-x');
const secondToken = second.json?.access_token;
const deleted = await call('POST', '/api/accounts/delete', { token: secondToken, body: { masterPasswordHash: 'hash-x' } });
check('delete own account', deleted.status === 200, `${deleted.status} ${deleted.text}`);
check('deleted account cannot log in', (await login(email2, 'hash-x')).status !== 200);

// Emergency access: the first account grants takeover to a third, which takes it over.
// Runs last because it changes the first account's password.
const email3 = `smoke3-${run}@example.test`;
let grantorToken = session.json?.access_token;
const invite3 = await call('POST', '/api/admin/invites', { token: grantorToken, body: { masterPasswordHash: 'hash-3' } });
check('register grantee account', (await register(email3, 'hash-g', invite3.json?.code)).status === 200);
const granteeToken = (await login(email3, 'hash-g')).json?.access_token;
const ea = (method, path, token, body) => call(method, `/api/emergency-access${path}`, { token, body });
check('invite emergency contact', (await ea('POST', '/invite', grantorToken, { email: email3, type: 1, waitTimeDays: 1 })).status === 200);
const trusted = await ea('GET', '/trusted', grantorToken);
const eaId = trusted.json?.data?.[0]?.id;
check('invite of an existing account is accepted', trusted.json?.data?.[0]?.status === 1, trusted.text);
check('grantee sees the grant', (await ea('GET', '/granted', granteeToken)).json?.data?.[0]?.id === eaId);
check('grantee cannot confirm', (await ea('POST', `/${eaId}/confirm`, granteeToken, { key: '4.x' })).status === 404);
check('grantor confirms', (await ea('POST', `/${eaId}/confirm`, grantorToken, { key: '4.wrapped' })).json?.status === 2);
check('grantee initiates', (await ea('POST', `/${eaId}/initiate`, granteeToken)).json?.status === 3);
check('takeover refused before approval', (await ea('POST', `/${eaId}/takeover`, granteeToken)).status === 400);
check('grantor approves', (await ea('POST', `/${eaId}/approve`, grantorToken)).json?.status === 4);
const takeover = await ea('POST', `/${eaId}/takeover`, granteeToken);
check('takeover returns the grantor KDF and wrapped key', takeover.json?.kdf === 1 && takeover.json?.keyEncrypted === '4.wrapped' && takeover.json?.salt === email, takeover.text);
const takeoverPassword = await ea('POST', `/${eaId}/password`, granteeToken, { newMasterPasswordHash: 'hash-4', key: enc('userkey4') });
check('grantee sets the grantor password', takeoverPassword.status === 200, `${takeoverPassword.status} ${takeoverPassword.text}`);
check('grantor old password no longer logs in', (await login(email, 'hash-3')).status !== 200);
session = await login(email, 'hash-4');
check('grantor logs in with the new password', session.status === 200, session.text.slice(0, 200));
grantorToken = session.json?.access_token;
check('grantor rejects', (await ea('POST', `/${eaId}/reject`, grantorToken)).json?.status === 2);
check('grantor removes the contact', (await ea('DELETE', `/${eaId}`, grantorToken)).status === 200);
check('no contacts left', (await ea('GET', '/trusted', grantorToken)).json?.data?.length === 0);

// Account, folder and cipher routes added for parity: avatar, profile POST, key rotation data,
// folder POST aliases, legacy multipart attachments and attachment share, and vault purge.
const now = await call('GET', '/api/now');
check('GET /api/now returns a timestamp', now.status === 200 && !Number.isNaN(Date.parse(now.json)), `${now.status} ${now.text.slice(0, 60)}`);
const avatar = await call('PUT', '/api/accounts/avatar', { token: grantorToken, body: { avatarColor: '#12ab34' } });
check('set the avatar color', avatar.status === 200 && avatar.json?.avatarColor === '#12ab34', `${avatar.status} ${avatar.text.slice(0, 200)}`);
check('sync reports the avatar color', (await call('GET', '/api/sync', { token: grantorToken })).json?.profile?.avatarColor === '#12ab34');
const named = await call('POST', '/api/accounts/profile', { token: grantorToken, body: { name: 'Renamed', culture: 'en-US' } });
check('POST /api/accounts/profile renames', named.status === 200 && named.json?.name === 'Renamed', `${named.status} ${named.text.slice(0, 200)}`);
const rotationData = await call('GET', '/api/accounts/key-management/key-rotation-data', { token: grantorToken });
check('key rotation data', rotationData.json?.object === 'keyRotationData' && Array.isArray(rotationData.json?.emergencyAccessKeyData), rotationData.text);
check('rotate-user-keys refuses an empty body', (await call('POST', '/api/accounts/key-management/rotate-user-keys', { token: grantorToken, body: {} })).status === 400);
check('GET device verification settings', (await call('GET', '/api/two-factor/get-device-verification-settings', { token: grantorToken })).json?.object === 'deviceVerificationSettings');
check('webauthn/all without keys is 400', (await call('DELETE', '/api/two-factor/webauthn/all', { token: grantorToken, body: { masterPasswordHash: 'hash-4' } })).status === 400);
const miscFolder = await call('POST', '/api/folders', { token: grantorToken, body: { name: enc('misc') } });
const renamedFolder = await call('POST', `/api/folders/${miscFolder.json?.id}`, { token: grantorToken, body: { name: enc('misc2') } });
check('POST /api/folders/{id} renames', renamedFolder.status === 200 && renamedFolder.json?.name === enc('misc2'), `${renamedFolder.status} ${renamedFolder.text}`);
check('POST /api/folders/{id}/delete', (await call('POST', `/api/folders/${miscFolder.json?.id}/delete`, { token: grantorToken })).status === 204);
const attachHost = await call('POST', '/api/ciphers', { token: grantorToken, body: { type: 2, name: enc('attach'), secureNote: { type: 0 } } });
const legacyForm = (name, key, content) => {
  const f = new FormData();
  f.set('key', key);
  f.set('data', new Blob([content]), name);
  return f;
};
const legacy = await call('POST', `/api/ciphers/${attachHost.json?.id}/attachment`, { token: grantorToken, multipart: legacyForm(enc('a.txt'), enc('akey'), 'hello') });
const legacyAttachment = legacy.json?.attachments?.[0];
check('legacy multipart attachment upload', legacy.status === 200 && legacyAttachment?.size === '5', `${legacy.status} ${legacy.text.slice(0, 300)}`);
const shareUpload = await call('POST', `/api/ciphers/${attachHost.json?.id}/attachment/${legacyAttachment?.id}/share`, { token: grantorToken, multipart: legacyForm(enc('b.txt'), enc('bkey'), 'hello2') });
check('attachment share replaces the file', shareUpload.status === 200 && shareUpload.json?.attachments?.length === 1 && shareUpload.json.attachments[0].id !== legacyAttachment?.id, `${shareUpload.status} ${shareUpload.text.slice(0, 300)}`);
const download = await call('GET', `/api/ciphers/${attachHost.json?.id}/attachment/${shareUpload.json?.attachments?.[0]?.id}`, { token: grantorToken });
const downloaded = download.json?.url ? await (await fetch(download.json.url)).text() : null;
check('the replacement downloads', downloaded === 'hello2', `${download.status} ${downloaded}`);
check('purge needs the password', (await call('POST', '/api/ciphers/purge', { token: grantorToken, body: { masterPasswordHash: 'wrong' } })).status === 400);
check('purge the personal vault', (await call('POST', '/api/ciphers/purge', { token: grantorToken, body: { masterPasswordHash: 'hash-4' } })).status === 200);
const purged = await call('GET', '/api/sync', { token: grantorToken });
check('nothing is left after the purge', purged.json?.ciphers?.length === 0 && purged.json?.folders?.length === 0, purged.text.slice(0, 300));

// Upgrade the (now empty) account in place to V2 account keys, keeping the master password.
const v2 = (label) => `7.${btoa('cose-' + label)}`;
const beforeUpgrade = purged.json;
const ownKeys = await call('GET', '/api/accounts/keys', { token: grantorToken });
const unlock = beforeUpgrade?.UserDecryptionOptions?.MasterPasswordUnlock;
const upgradeData = await call('GET', '/api/accounts/key-management/key-rotation-data', { token: grantorToken });
const upgrade = await call('POST', '/api/accounts/key-management/rotate-user-keys', {
  token: grantorToken,
  body: {
    wrappedAccountCryptographicState: {
      publicKeyEncryptionKeyPair: { wrappedPrivateKey: v2('private'), publicKey: ownKeys.json?.publicKey, signedPublicKey: 'c2lnbmVkLXB1YmxpYy1rZXk=' },
      signatureKeyPair: { signatureAlgorithm: 'ed25519', wrappedSigningKey: v2('signing'), verifyingKey: 'dmVyaWZ5aW5nLWtleQ==' },
      securityState: { securityState: 'c2VjdXJpdHktc3RhdGU=', securityVersion: 2 },
    },
    unlockData: {
      emergencyAccessUnlockData: [],
      passkeyUnlockData: [],
      deviceKeyUnlockData: [],
      v2UpgradeToken: { wrappedUserKey1: v2('token-1'), wrappedUserKey2: v2('token-2') },
    },
    accountData: { ciphers: [], folders: [], sends: (beforeUpgrade?.sends || []).map((x) => ({ id: x.id, key: v2('send-' + x.id) })) },
    unlockMethodData: {
      unlockMethod: 1,
      masterPasswordUnlockData: {
        kdf: { kdfType: unlock?.Kdf?.KdfType, iterations: unlock?.Kdf?.Iterations, memory: unlock?.Kdf?.Memory, parallelism: unlock?.Kdf?.Parallelism },
        salt: unlock?.Salt,
        masterKeyWrappedUserKey: enc('v2-userkey'),
      },
      keyConnectorKeyWrappedUserKey: null,
    },
  },
});
check('rotate-user-keys upgrades the account to V2', upgrade.status === 200, `${upgrade.status} ${upgrade.text.slice(0, 300)}`);
session = await login(email, 'hash-4');
check('the upgraded account logs in with the same password', session.status === 200, session.text.slice(0, 200));
grantorToken = session.json?.access_token;
check('the token response carries the V2 keys', session.json?.AccountKeys?.signatureKeyPair?.verifyingKey === 'dmVyaWZ5aW5nLWtleQ==', JSON.stringify(session.json?.AccountKeys));
const upgraded = await call('GET', '/api/sync', { token: grantorToken });
check(
  'sync returns the V2 account keys and the upgrade token',
  upgraded.json?.profile?.accountKeys?.securityState?.securityVersion === 2 &&
    upgraded.json?.profile?.accountKeys?.publicKeyEncryptionKeyPair?.signedPublicKey === 'c2lnbmVkLXB1YmxpYy1rZXk=' &&
    upgraded.json?.UserDecryption?.V2UpgradeToken?.WrappedUserKey1 === v2('token-1'),
  upgraded.text.slice(0, 400)
);

// Mail is off unless MAIL_FROM and a provider are set (src/services/mail.ts). Unconfigured,
// every mail-backed route keeps answering 501. Run with SMOKE_MAIL=on against a server that
// has mail configured to skip these.
if (process.env.SMOKE_MAIL !== 'on') {
  for (const path of ['/api/two-factor/get-email', '/api/accounts/email-token', '/api/accounts/verify-email', '/api/accounts/request-otp']) {
    check(`${path} is refused without mail`, (await call('POST', path, { token: grantorToken, body: { masterPasswordHash: 'hash-4' } })).status === 501);
  }
  for (const path of ['/api/two-factor/send-email-login', '/api/accounts/delete-recover', '/identity/accounts/register/send-verification-email']) {
    check(`${path} is refused without mail`, (await call('POST', path, { body: { email: 'nobody@example.test', masterPasswordHash: 'x' } })).status === 501);
  }
  const providers = await call('GET', '/api/two-factor', { token: grantorToken });
  check('no email provider is listed without mail', !providers.json?.data?.some?.((p) => p.type === 1) && !providers.json?.Data?.some?.((p) => p.Type === 1), providers.text.slice(0, 200));
}

console.log(failed ? `\n${failed} check(s) failed` : '\nall checks passed');
process.exit(failed ? 1 : 0);
