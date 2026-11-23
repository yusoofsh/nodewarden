// Drives a running server (wrangler dev or a deployed URL) over HTTP: register, log in,
// sync, create items, then the account routes added for Vaultwarden parity.
// Usage: node scripts/smoke-dev.mjs http://localhost:8787
// Registers throwaway accounts; point it at a scratch instance, not your live vault.
const base = (process.argv[2] || 'http://localhost:8787').replace(/\/$/, '');
const enc = (label) => `2.${btoa('iv-' + label)}|${btoa('ct-' + label)}|${btoa('mac-' + label)}`;
const run = Date.now().toString(36);
let failed = 0;

async function call(method, path, { token, body, form } = {}) {
  const headers = { 'CF-Connecting-IP': '198.51.100.7', Origin: base };
  if (token) headers.Authorization = `Bearer ${token}`;
  let payload;
  if (form) {
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

// Organizations: create, rename, collections, sync, leave and delete.
const org = await call('POST', '/api/organizations', {
  token,
  body: { name: 'Smoke org', billingEmail: email, collectionName: enc('default'), key: '4.b3JnLWtleQ==', planType: 0, keys: { encryptedPrivateKey: enc('orgpriv'), publicKey: 'b3JnLXB1Yg==' } },
});
check('create organization', org.status === 200 && org.json?.object === 'organization', `${org.status} ${org.text}`);
const orgPath = `/api/organizations/${org.json?.id}`;
const renamed = await call('PUT', orgPath, { token, body: { name: 'Smoke org 2', billingEmail: email } });
check('rename organization', renamed.status === 200 && renamed.json?.name === 'Smoke org 2', `${renamed.status} ${renamed.text}`);
const orgKey = await call('GET', `${orgPath}/public-key`, { token });
check('organization public key', orgKey.json?.publicKey === 'b3JnLXB1Yg==', orgKey.text);
const members = await call('GET', `${orgPath}/users`, { token });
check('member list has the owner', members.json?.data?.length === 1 && members.json.data[0].type === 0 && members.json.data[0].status === 2, members.text);
const coll = await call('POST', `${orgPath}/collections`, { token, body: { name: enc('team'), users: [], groups: [] } });
check('create collection', coll.status === 200 && coll.json?.object === 'collectionDetails', `${coll.status} ${coll.text}`);
const collUpdate = await call('PUT', `${orgPath}/collections/${coll.json?.id}`, { token, body: { name: enc('team2'), users: [], groups: [] } });
check('update collection', collUpdate.status === 200 && collUpdate.json?.name === enc('team2'), `${collUpdate.status} ${collUpdate.text}`);
const details = await call('GET', `${orgPath}/collections/details`, { token });
check('collection details', details.json?.data?.length === 2 && details.json.data.every((c) => c.object === 'collectionAccessDetails'), details.text.slice(0, 300));
const mine = await call('GET', '/api/collections', { token });
check('GET /api/collections', mine.json?.data?.length === 2, mine.text.slice(0, 300));
sync = await call('GET', '/api/sync', { token });
check('sync lists the organization and its collections', sync.json?.profile?.organizations?.[0]?.id === org.json?.id && sync.json?.collections?.length === 2, sync.text.slice(0, 300));
check('the last owner cannot leave', (await call('POST', `${orgPath}/leave`, { token })).status === 400);
check('delete collection', (await call('DELETE', `${orgPath}/collections/${coll.json?.id}`, { token })).status === 200);
check('delete organization needs the password', (await call('DELETE', orgPath, { token, body: { masterPasswordHash: 'wrong' } })).status === 400);
check('delete organization', (await call('DELETE', orgPath, { token, body: { masterPasswordHash: 'hash-3' } })).status === 200);
sync = await call('GET', '/api/sync', { token });
check('sync no longer lists it', sync.json?.profile?.organizations?.length === 0 && sync.json?.collections?.length === 0, sync.text.slice(0, 300));
check('deleted organization answers 404', (await call('GET', orgPath, { token })).status === 404);

const invite = await call('POST', '/api/admin/invites', { token: session.json?.access_token, body: { masterPasswordHash: 'hash-3' } });
check('admin creates an invite', invite.status === 201 && invite.json?.code, `${invite.status} ${invite.text}`);
const second0 = await register(email2, 'hash-x', invite.json?.code);
check('register second account', second0.status === 200, `${second0.status} ${second0.text}`);
const second = await login(email2, 'hash-x');
const secondToken = second.json?.access_token;
const secondOrg = await call('POST', '/api/organizations', {
  token: secondToken, body: { name: 'Second org', billingEmail: email2, collectionName: enc('default'), key: '4.b3JnLWtleQ==' },
});
const blocked = await call('POST', '/api/accounts/delete', { token: secondToken, body: { masterPasswordHash: 'hash-x' } });
check('the last owner of an organization cannot delete their account', blocked.status === 400 && /organization/.test(blocked.json?.error || ''), `${blocked.status} ${blocked.text}`);
check('the other account cannot see that organization', (await call('GET', `/api/organizations/${secondOrg.json?.id}`, { token })).status === 404);
await call('DELETE', `/api/organizations/${secondOrg.json?.id}`, { token: secondToken, body: { masterPasswordHash: 'hash-x' } });
const deleted = await call('POST', '/api/accounts/delete', { token: second.json?.access_token, body: { masterPasswordHash: 'hash-x' } });
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

console.log(failed ? `\n${failed} check(s) failed` : '\nall checks passed');
process.exit(failed ? 1 : 0);
