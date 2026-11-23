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

// Members: invite the second account, accept from its session, confirm, change its role, remove it.
const teamOrg = await call('POST', '/api/organizations', {
  token, body: { name: 'Team org', billingEmail: email, collectionName: enc('default'), key: '4.b3JnLWtleQ==' },
});
const teamPath = `/api/organizations/${teamOrg.json?.id}`;
check('unknown email cannot be invited', (await call('POST', `${teamPath}/users/invite`, { token, body: { emails: [`nobody-${run}@example.test`], type: 2 } })).status === 400);
const inviteMember = await call('POST', `${teamPath}/users/invite`, { token, body: { emails: [email2], type: 2, collections: [], groups: [] } });
check('invite an existing account', inviteMember.status === 200, `${inviteMember.status} ${inviteMember.text}`);
const invitedRow = (await call('GET', `${teamPath}/users`, { token })).json?.data?.find((m) => m.email === email2.toLowerCase());
check('the invitee is listed as invited', invitedRow?.status === 0, JSON.stringify(invitedRow));
const pendingInvites = await call('GET', '/api/organizations/invitations', { token: secondToken });
check('the invitee finds the invite to accept', pendingInvites.json?.data?.some((i) => i.id === invitedRow?.id && i.organizationId === teamOrg.json?.id), pendingInvites.text);
const passwordPolicy = await call('PUT', `${teamPath}/policies/1`, { token, body: { policy: { enabled: true, data: { minLength: 14 } } } });
check('store a master password policy', passwordPolicy.status === 200 && passwordPolicy.json?.enabled === true && passwordPolicy.json?.data?.minLength === 14, passwordPolicy.text);
const tokenPolicies = await call('GET', `${teamPath}/policies/token?token=x&organizationUserId=${invitedRow?.id}`, { token: secondToken });
check('the invitee reads the policies', tokenPolicies.json?.data?.[0]?.type === 1, `${tokenPolicies.status} ${tokenPolicies.text}`);
check('the invitee reads no admin policy route', (await call('GET', `${teamPath}/policies`, { token: secondToken })).status === 404);
check('the owner cannot accept for the invitee', (await call('POST', `${teamPath}/users/${invitedRow?.id}/accept`, { token, body: { token: 'x' } })).status === 404);
const accepted = await call('POST', `${teamPath}/users/${invitedRow?.id}/accept`, { token: secondToken, body: { token: 'x' } });
check('the invitee accepts', accepted.status === 200, `${accepted.status} ${accepted.text}`);
const memberKeys = await call('POST', `${teamPath}/users/public-keys`, { token, body: { ids: [invitedRow?.id] } });
check('invitee public key', memberKeys.json?.data?.[0]?.id === invitedRow?.id, memberKeys.text);
const confirmed = await call('POST', `${teamPath}/users/${invitedRow?.id}/confirm`, { token, body: { key: '4.d3JhcHBlZA==' } });
check('confirm the member', confirmed.status === 200, `${confirmed.status} ${confirmed.text}`);
const memberSync = await call('GET', '/api/sync', { token: secondToken });
check('the member syncs the organization', memberSync.json?.profile?.organizations?.some((o) => o.id === teamOrg.json?.id && o.status === 2), memberSync.text.slice(0, 300));
check('the member syncs its policies', memberSync.json?.policies?.some((p) => p.organizationId === teamOrg.json?.id && p.type === 1), JSON.stringify(memberSync.json?.policies));
const teamCollections = (body) => (body?.collections || []).filter((c) => c.organizationId === teamOrg.json?.id);
check('the member sees no team collection yet', teamCollections(memberSync.json).length === 0, JSON.stringify(memberSync.json?.collections));
const teamCollection = (await call('GET', `${teamPath}/collections`, { token })).json?.data?.[0];
const group = await call('POST', `${teamPath}/groups`, {
  token, body: { name: 'Readers', collections: [{ id: teamCollection?.id, readOnly: true, hidePasswords: false, manage: false }], users: [invitedRow?.id] },
});
check('create a group', group.status === 200 && group.json?.object === 'group', `${group.status} ${group.text}`);
const groupDetails = await call('GET', `${teamPath}/groups/details`, { token });
check('group details list its collection', groupDetails.json?.data?.[0]?.collections?.[0]?.id === teamCollection?.id, groupDetails.text);
check('group members', JSON.stringify((await call('GET', `${teamPath}/groups/${group.json?.id}/users`, { token })).json) === JSON.stringify([invitedRow?.id]));
const groupSync = await call('GET', '/api/sync', { token: secondToken });
check('the group gives the member its collection', teamCollections(groupSync.json).length === 1 && teamCollections(groupSync.json)[0].readOnly === true, JSON.stringify(groupSync.json?.collections));
check('delete the group', (await call('DELETE', `${teamPath}/groups/${group.json?.id}`, { token })).status === 200);
check('the member loses the collection', teamCollections((await call('GET', '/api/sync', { token: secondToken })).json).length === 0);

// Organization ciphers: create one in a collection, give the member read-only access, share a
// personal cipher, move collections, list them for the admin console and delete them.
const teamCollectionId = teamCollection?.id;
const orgItem = await call('POST', '/api/ciphers/create', {
  token,
  body: { cipher: { type: 1, organizationId: teamOrg.json?.id, name: enc('org-item'), login: { username: enc('ou'), password: enc('op'), uris: [] } }, collectionIds: [teamCollectionId] },
});
check('create an organization cipher', orgItem.status === 200 && orgItem.json?.organizationId === teamOrg.json?.id && orgItem.json?.collectionIds?.[0] === teamCollectionId, `${orgItem.status} ${orgItem.text}`);
check('the member cannot see it without a collection', !(await call('GET', '/api/sync', { token: secondToken })).json?.ciphers?.some((c) => c.id === orgItem.json?.id));
const editors = await call('POST', `${teamPath}/groups`, {
  token, body: { name: 'Editors', collections: [{ id: teamCollectionId, readOnly: false, hidePasswords: false, manage: false }], users: [invitedRow?.id] },
});
const groupItem = (await call('GET', '/api/sync', { token: secondToken })).json?.ciphers?.find((c) => c.id === orgItem.json?.id);
check('a group collection gives the member the cipher', groupItem?.edit === true && groupItem?.viewPassword === true, JSON.stringify(groupItem));
await call('DELETE', `${teamPath}/groups/${editors.json?.id}`, { token });
await call('PUT', `${teamPath}/collections/${teamCollectionId}`, { token, body: { name: enc('default'), users: [{ id: invitedRow?.id, readOnly: true, hidePasswords: true, manage: false }], groups: [] } });
const memberItem = (await call('GET', '/api/sync', { token: secondToken })).json?.ciphers?.find((c) => c.id === orgItem.json?.id);
check('a read-only member syncs it without edit or passwords', memberItem?.edit === false && memberItem?.viewPassword === false, JSON.stringify(memberItem));
const memberEdit = await call('PUT', `/api/ciphers/${orgItem.json?.id}`, { token: secondToken, body: { type: 1, organizationId: teamOrg.json?.id, name: enc('x'), login: {} } });
check('a read-only member cannot edit it', memberEdit.status === 400, `${memberEdit.status} ${memberEdit.text}`);
const personalItem = await call('POST', '/api/ciphers', { token, body: { type: 2, name: enc('to-share'), secureNote: { type: 0 } } });
const shared = await call('PUT', `/api/ciphers/${personalItem.json?.id}/share`, {
  token, body: { cipher: { type: 2, organizationId: teamOrg.json?.id, name: enc('shared'), secureNote: { type: 0 } }, collectionIds: [teamCollectionId] },
});
check('share a personal cipher', shared.status === 200 && shared.json?.organizationId === teamOrg.json?.id, `${shared.status} ${shared.text}`);
const moved = await call('PUT', `/api/ciphers/${shared.json?.id}/collections-admin`, { token, body: { collectionIds: [] } });
check('remove it from its collection', moved.status === 200 && moved.json?.collectionIds?.length === 0, `${moved.status} ${moved.text}`);
const orgDetails = await call('GET', `/api/ciphers/organization-details?organizationId=${teamOrg.json?.id}`, { token });
check('organization details list both', orgDetails.json?.data?.length === 2, orgDetails.text.slice(0, 300));
check('the member cannot list organization details', (await call('GET', `/api/ciphers/organization-details?organizationId=${teamOrg.json?.id}`, { token: secondToken })).status === 400);
check('trash an organization cipher as admin', (await call('PUT', `/api/ciphers/${shared.json?.id}/delete-admin`, { token })).status === 200);
check('delete organization ciphers in bulk as admin', (await call('DELETE', '/api/ciphers/admin', { token, body: { ids: [orgItem.json?.id, shared.json?.id], organizationId: teamOrg.json?.id } })).status === 204);
check('they are gone', (await call('GET', `/api/ciphers/organization-details?organizationId=${teamOrg.json?.id}`, { token })).json?.data?.length === 0);
const eventRange = `?start=2000-01-01T00:00:00.000Z&end=${encodeURIComponent(new Date(Date.now() + 60_000).toISOString())}`;
const collected = await call('POST', '/events/collect', { token: secondToken, body: [{ type: 1602, organizationId: teamOrg.json?.id, date: new Date().toISOString() }] });
check('a member reports a client event', collected.status === 200, `${collected.status} ${collected.text}`);
const orgEventList = await call('GET', `${teamPath}/events${eventRange}`, { token });
const eventTypes = new Set((orgEventList.json?.data || []).map((e) => e.type));
check('the event log records organization, group and cipher changes', [1100, 1102, 1105, 1106, 1400, 1402, 1500, 1602].every((t) => eventTypes.has(t)), orgEventList.text.slice(0, 300));
const ownEvent = (orgEventList.json?.data || []).find((e) => e.type === 1400);
check('an event names the acting user, device type and IP', ownEvent?.actingUserId && ownEvent?.deviceType === 9 && ownEvent?.ipAddress === '198.51.100.7', JSON.stringify(ownEvent));
check('a member cannot read the event log', (await call('GET', `${teamPath}/events${eventRange}`, { token: secondToken })).status === 400);
check('the member event log lists their invite', (await call('GET', `${teamPath}/users/${invitedRow?.id}/events${eventRange}`, { token })).json?.data?.some((e) => e.type === 1500));
check('promote the member to admin', (await call('PUT', `${teamPath}/users/${invitedRow?.id}`, { token, body: { type: 1, collections: [], groups: [] } })).status === 200);
check('remove the member', (await call('DELETE', `${teamPath}/users/${invitedRow?.id}`, { token })).status === 200);
await call('DELETE', teamPath, { token, body: { masterPasswordHash: 'hash-3' } });
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
check('rotate-user-keys is refused', (await call('POST', '/api/accounts/key-management/rotate-user-keys', { token: grantorToken, body: {} })).status === 501);
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

console.log(failed ? `\n${failed} check(s) failed` : '\nall checks passed');
process.exit(failed ? 1 : 0);
