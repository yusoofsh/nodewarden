import type { Env, User } from '../types';
import { StorageService } from '../services/storage';
import { auditRequestMetadata, safeWriteAuditEvent } from '../services/audit-events';
import {
  EmergencyAccessStatus as Status,
  EmergencyAccessType as Type,
  approveTimedOutEmergencyAccess,
  deleteEmergencyAccess,
  findEmergencyAccess,
  findInvitedEmergencyAccess,
  insertEmergencyAccess,
  listEmergencyAccessWithUsers,
  transitionEmergencyAccess,
  updateEmergencyAccessSettings,
  type EmergencyAccess,
  type EmergencyAccessRole,
} from '../services/storage-emergency-access-repo';
import { cipherToResponse, isCipherResponseSyncCompatible } from './ciphers';
import { readNewMasterPassword, resetUserCredentials } from './master-password-reset';
import { handleGetAttachment } from './attachments';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { mailConfig, mailTemplates, sendMail } from '../services/mail';

// Vaultwarden's emergency_access.rs, with mail disabled: this server sends no email.
// - Inviting an existing account accepts the invite at once, like Vaultwarden does
//   for existing users when mail is off. Inviting an unknown email is refused, like
//   Vaultwarden with invitations off, since nobody could deliver the invite.
// - So rows are never left invited, and /accept and /reinvite only act on an invited
//   row whose email is the caller's own (rows restored from elsewhere).
// - A row the caller is not part of, or holds in the other role, is a 404.
// - With mail configured, the grantee also gets an email saying they were added. The
//   invite still accepts at once; a failed send does not undo it.

const NOT_VALID = 'Emergency access not valid.';
const notFound = () => errorResponse(NOT_VALID, 404);
const ID = '([a-f0-9-]+)';
const ITEM = new RegExp(`^/api/emergency-access/${ID}(?:/(delete|reinvite|accept|confirm|initiate|approve|reject|view|takeover|password|policies))?$`, 'i');
const ATTACHMENT = new RegExp(`^/api/emergency-access/${ID}/${ID}/attachment/${ID}$`, 'i');

type Json = Record<string, unknown>;
const isRecord = (value: unknown): value is Json => !!value && typeof value === 'object' && !Array.isArray(value);
const str = (value: unknown): string => (typeof value === 'string' ? value.trim() : '');

async function readJson(request: Request): Promise<Json> {
  try {
    const body = await request.json();
    return isRecord(body) ? body : {};
  } catch {
    return {};
  }
}

function parseType(value: unknown): number | null {
  const s = String(value ?? '');
  if (s === '0' || s === 'View') return Type.View;
  if (s === '1' || s === 'Takeover') return Type.Takeover;
  return null;
}

function parseWaitTimeDays(value: unknown): number | null {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= 90 ? value : null;
}

const toJson = (a: EmergencyAccess) => ({
  id: a.id, status: a.status, type: a.type, waitTimeDays: a.waitTimeDays, object: 'emergencyAccess',
});

function detailsJson(a: EmergencyAccess & { otherId: string; otherEmail: string; otherName: string | null }, role: EmergencyAccessRole) {
  return role === 'grantor'
    ? { ...toJson(a), granteeId: a.otherId, email: a.otherEmail, name: a.otherName, avatarColor: null, object: 'emergencyAccessGranteeDetails' }
    : { ...toJson(a), grantorId: a.otherId, email: a.otherEmail, name: a.otherName, avatarColor: null, object: 'emergencyAccessGrantorDetails' };
}

// Vaultwarden's is_valid_request: an approved recovery of exactly the requested type.
const isValidRequest = (a: EmergencyAccess, type: number) => a.status === Status.RecoveryApproved && a.type === type;

export async function handleEmergencyAccessRoute(
  request: Request,
  env: Env,
  user: User,
  path: string,
  method: string
): Promise<Response | null> {
  if (!/^\/api\/emergency-access(\/|$)/i.test(path)) return null;
  const db = env.DB;
  const now = new Date().toISOString();
  // There is no cron trigger on every deployment, so due recoveries are approved here too.
  await approveTimedOutEmergencyAccess(db, now);

  if (path === '/api/emergency-access/trusted' && method === 'GET') {
    const rows = await listEmergencyAccessWithUsers(db, user.id, 'grantor');
    return jsonResponse({ data: rows.map((r) => detailsJson(r, 'grantor')), object: 'list', continuationToken: null });
  }
  if (path === '/api/emergency-access/granted' && method === 'GET') {
    const rows = await listEmergencyAccessWithUsers(db, user.id, 'grantee');
    return jsonResponse({ data: rows.map((r) => detailsJson(r, 'grantee')), object: 'list', continuationToken: null });
  }
  if (path === '/api/emergency-access/invite' && method === 'POST') return invite(request, env, user, now);

  const attachment = path.match(ATTACHMENT);
  if (attachment && method === 'GET') {
    const found = await findEmergencyAccess(db, attachment[1], user.id, ['grantee']);
    if (!found) return notFound();
    if (!isValidRequest(found.access, Type.View)) return errorResponse(NOT_VALID, 400);
    return handleGetAttachment(request, env, found.access.grantorId, attachment[2], attachment[3]);
  }

  const item = path.match(ITEM);
  if (!item) return null;
  const [, id, action = ''] = item;

  switch (`${method} ${action.toLowerCase()}`) {
    case 'GET ': {
      const rows = await listEmergencyAccessWithUsers(db, user.id, 'grantor');
      const row = rows.find((r) => r.id === id);
      return row ? jsonResponse(detailsJson(row, 'grantor')) : notFound();
    }
    case 'PUT ':
    case 'POST ': {
      const found = await findEmergencyAccess(db, id, user.id, ['grantor']);
      if (!found) return notFound();
      const body = await readJson(request);
      const type = parseType(body.type);
      const wait = parseWaitTimeDays(body.waitTimeDays);
      if (type === null) return errorResponse('Invalid emergency access type.', 400);
      if (wait === null) return errorResponse('Emergency access wait time is out-of-bounds!', 400);
      const key = str(body.keyEncrypted) || null;
      await updateEmergencyAccessSettings(db, id, type, wait, key, now);
      return jsonResponse(toJson({ ...found.access, type, waitTimeDays: wait }));
    }
    case 'DELETE ':
    case 'POST delete': {
      const found = await findEmergencyAccess(db, id, user.id, ['grantor', 'grantee']);
      if (!found) return notFound();
      await deleteEmergencyAccess(db, id);
      return new Response(null, { status: 200 });
    }
    case 'POST reinvite': {
      const found = await findEmergencyAccess(db, id, user.id, ['grantor']);
      if (!found) return notFound();
      if (found.access.status !== Status.Invited) {
        return errorResponse('The grantee user is already accepted or confirmed for emergency access', 400);
      }
      const grantee = found.access.email ? await new StorageService(db).getUser(found.access.email) : null;
      if (!grantee) return errorResponse('Grantee user not found.', 400);
      await transitionEmergencyAccess(db, id, [Status.Invited], Status.Accepted, now, { granteeId: grantee.id, clearEmail: true });
      return new Response(null, { status: 200 });
    }
    case 'POST accept': {
      const invited = await findInvitedEmergencyAccess(db, id, user.email);
      if (!invited || invited.grantorId === user.id) return notFound();
      await transitionEmergencyAccess(db, id, [Status.Invited], Status.Accepted, now, { granteeId: user.id, clearEmail: true });
      return new Response(null, { status: 200 });
    }
    case 'POST confirm': {
      const found = await findEmergencyAccess(db, id, user.id, ['grantor']);
      if (!found) return notFound();
      const key = str((await readJson(request)).key);
      if (!key) return errorResponse('Key is required', 400);
      const ok = await transitionEmergencyAccess(db, id, [Status.Accepted], Status.Confirmed, now, { keyEncrypted: key, clearEmail: true });
      if (!ok) return errorResponse(NOT_VALID, 400);
      return jsonResponse(toJson({ ...found.access, status: Status.Confirmed }));
    }
    case 'POST initiate': {
      const found = await findEmergencyAccess(db, id, user.id, ['grantee']);
      if (!found) return notFound();
      if (parseWaitTimeDays(found.access.waitTimeDays) === null) return errorResponse(NOT_VALID, 400);
      const ok = await transitionEmergencyAccess(db, id, [Status.Confirmed], Status.RecoveryInitiated, now, { recoveryInitiatedAt: now });
      if (!ok) return errorResponse(NOT_VALID, 400);
      return jsonResponse(toJson({ ...found.access, status: Status.RecoveryInitiated }));
    }
    case 'POST approve':
    case 'POST reject': {
      const found = await findEmergencyAccess(db, id, user.id, ['grantor']);
      if (!found) return notFound();
      const approve = action.toLowerCase() === 'approve';
      const from = approve ? [Status.RecoveryInitiated] : [Status.RecoveryInitiated, Status.RecoveryApproved];
      const to = approve ? Status.RecoveryApproved : Status.Confirmed;
      if (!(await transitionEmergencyAccess(db, id, from, to, now))) return errorResponse(NOT_VALID, 400);
      return jsonResponse(toJson({ ...found.access, status: to }));
    }
    case 'POST view': {
      const found = await findEmergencyAccess(db, id, user.id, ['grantee']);
      if (!found) return notFound();
      if (!isValidRequest(found.access, Type.View)) return errorResponse(NOT_VALID, 400);
      const storage = new StorageService(db);
      const grantorId = found.access.grantorId;
      const [ciphers, attachments] = await Promise.all([storage.getAllCiphers(grantorId), storage.getAttachmentsByUserId(grantorId)]);
      const responses = ciphers
        .map((c) => cipherToResponse(c, attachments.get(c.id) || []))
        .filter(isCipherResponseSyncCompatible);
      return jsonResponse({ ciphers: responses, keyEncrypted: found.access.keyEncrypted, object: 'emergencyAccessView' });
    }
    case 'POST takeover': {
      const found = await findEmergencyAccess(db, id, user.id, ['grantee']);
      if (!found) return notFound();
      if (!isValidRequest(found.access, Type.Takeover)) return errorResponse(NOT_VALID, 400);
      const grantor = await new StorageService(db).getUserById(found.access.grantorId);
      if (!grantor) return notFound();
      return jsonResponse({
        kdf: grantor.kdfType,
        kdfIterations: grantor.kdfIterations,
        kdfMemory: grantor.kdfMemory ?? null,
        kdfParallelism: grantor.kdfParallelism ?? null,
        keyEncrypted: found.access.keyEncrypted,
        salt: grantor.email.trim().toLowerCase(),
        object: 'emergencyAccessTakeover',
      });
    }
    case 'POST password': {
      const found = await findEmergencyAccess(db, id, user.id, ['grantee']);
      if (!found) return notFound();
      if (!isValidRequest(found.access, Type.Takeover)) return errorResponse(NOT_VALID, 400);
      return takeoverPassword(request, env, user, found.access.grantorId);
    }
    case 'GET policies': {
      const found = await findEmergencyAccess(db, id, user.id, ['grantee']);
      if (!found) return notFound();
      if (!isValidRequest(found.access, Type.Takeover)) return errorResponse(NOT_VALID, 400);
      return jsonResponse({ data: [], object: 'list', continuationToken: null });
    }
  }
  return null;
}

async function invite(request: Request, env: Env, user: User, now: string): Promise<Response> {
  const body = await readJson(request);
  const email = str(body.email).toLowerCase();
  const type = parseType(body.type);
  const wait = parseWaitTimeDays(body.waitTimeDays);
  if (wait === null) return errorResponse('Emergency access wait time is out-of-bounds!', 400);
  if (type === null) return errorResponse('Invalid emergency access type.', 400);
  if (!email) return errorResponse('Email is required', 400);
  if (email === user.email.toLowerCase()) return errorResponse('You can not set yourself as an emergency contact.', 400);

  const grantee = await new StorageService(env.DB).getUser(email);
  if (!grantee) return errorResponse(`Grantee user does not exist: ${email}`, 400);

  const inserted = await insertEmergencyAccess(env.DB, {
    id: generateUUID(),
    grantorId: user.id,
    granteeId: grantee.id,
    email: null,
    keyEncrypted: null,
    type,
    status: Status.Accepted,
    waitTimeDays: wait,
    recoveryInitiatedAt: null,
    createdAt: now,
    updatedAt: now,
  });
  if (!inserted) return errorResponse(`Grantee user already invited: ${grantee.email}`, 400);
  const mail = mailConfig(env);
  if (mail) {
    const grantor = user.name ? `${user.name} (${user.email})` : user.email;
    await sendMail(mail, mailTemplates.emergencyAccessInvite(grantee.email, grantor, new URL(request.url).origin));
  }
  return new Response(null, { status: 200 });
}

// The grantee sets a new master password on the grantor's account. Like Vaultwarden,
// this also disables the grantor's two-factor methods, which would block the login.
async function takeoverPassword(request: Request, env: Env, grantee: User, grantorId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const grantor = await storage.getUserById(grantorId);
  if (!grantor) return notFound();
  const password = readNewMasterPassword(await readJson(request), grantor);
  if (password === null) return errorResponse('Invalid request!', 400);
  if (typeof password === 'string') return errorResponse(password, 400);
  await resetUserCredentials(env, grantor, password, true);
  await safeWriteAuditEvent(env, {
    actorUserId: grantee.id,
    action: 'account.emergency-access.takeover',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: grantor.id,
    metadata: auditRequestMetadata(request),
  });
  return new Response(null, { status: 200 });
}
