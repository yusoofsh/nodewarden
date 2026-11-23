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
const invite = await call('POST', '/api/admin/invites', { token: session.json?.access_token, body: { masterPasswordHash: 'hash-3' } });
check('admin creates an invite', invite.status === 201 && invite.json?.code, `${invite.status} ${invite.text}`);
const second0 = await register(email2, 'hash-x', invite.json?.code);
check('register second account', second0.status === 200, `${second0.status} ${second0.text}`);
const second = await login(email2, 'hash-x');
const deleted = await call('POST', '/api/accounts/delete', { token: second.json?.access_token, body: { masterPasswordHash: 'hash-x' } });
check('delete own account', deleted.status === 200, `${deleted.status} ${deleted.text}`);
check('deleted account cannot log in', (await login(email2, 'hash-x')).status !== 200);

console.log(failed ? `\n${failed} check(s) failed` : '\nall checks passed');
process.exit(failed ? 1 : 0);
