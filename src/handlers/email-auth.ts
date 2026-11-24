// Routes that need outbound mail, after Vaultwarden's two_factor/email.rs,
// two_factor/protected_actions.rs, the email routes of core/accounts.rs and the register
// routes of identity.rs. Each handler returns null when mail is not configured, so the
// routers keep answering 501 exactly as before.
// - Registration stays closed: a verification link is only sent while the server has no
//   users, the case where handleRegister needs no invite code. Finish runs handleRegister.
// - Every account counts as verified (the profile reports emailVerified true), so
//   verify-email-token checks and spends the token and changes nothing else.
// - send-email-login takes email and master password hash only, under the password
//   login's lockout key. The auth-request and SSO variants are not served.
import type { Env, User } from '../types';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import { RateLimitService, getClientIdentifier } from '../services/ratelimit';
import { auditRequestMetadata, safeWriteAuditEvent } from '../services/audit-events';
import { type MailConfig, type MailMessage, mailConfig, mailTemplates, sendMail } from '../services/mail';
import {
  EMAIL_CODE_TTL_MS,
  EMAIL_LINK_TTL_MS,
  type EmailCodePurpose,
  consumeEmailCode,
  deleteEmailCode,
  issueEmailCode,
  randomDigits,
  randomLinkToken,
  signRegisterToken,
  verifyRegisterToken,
} from '../services/email-codes';
import { LAST_ORGANIZATION_OWNER_ERROR, isLastActiveAdmin, purgeUser } from '../services/user-deletion';
import { createRecoveryCode } from '../utils/recovery-code';
import { generateUUID } from '../utils/uuid';
import { errorResponse, jsonResponse } from '../utils/response';
import { createTotpUserVerificationToken, handleRegister, verifyTotpUserVerificationToken } from './accounts';
import { loginRateLimitKey } from './identity';

const TWO_FACTOR_PROVIDER_EMAIL = 1;
// The user verification token from get-email is bound to this key, not to an address.
const VERIFICATION_KEY = 'email-2fa';
const ok = () => new Response(null, { status: 200 });

type Body = Record<string, unknown>;

async function readBody(request: Request): Promise<Body | null> {
  try {
    const body = await request.json();
    return body && typeof body === 'object' && !Array.isArray(body) ? (body as Body) : null;
  } catch {
    return null;
  }
}

function str(body: Body, ...names: string[]): string {
  for (const name of names) {
    const value = body[name];
    if (typeof value === 'string') return value.trim();
    if (typeof value === 'number') return String(value);
  }
  return '';
}

const normalizeEmail = (value: string) => value.toLowerCase().trim();
const isEmail = (value: string) => /^[^\s@]+@[^\s@]+$/.test(value) && value.length <= 254;

// Issues a code or link token, then mails it. A failed send spends the row.
async function deliver(
  env: Env,
  mail: MailConfig,
  userId: string,
  purpose: EmailCodePurpose,
  code: string,
  ttlMs: number,
  message: MailMessage
): Promise<Response | null> {
  if (!(await issueEmailCode(env, userId, purpose, message.to, code, ttlMs))) {
    return errorResponse('Too many emails were sent to this address. Try again later.', 429);
  }
  if (!(await sendMail(mail, message))) {
    await deleteEmailCode(env, userId, purpose);
    return errorResponse('The email could not be sent. Try again later.', 502);
  }
  return null;
}

// Master password hash, a protected-action code (otp), or a token from get-email.
async function verifySecret(env: Env, user: User, body: Body): Promise<boolean> {
  const password = str(body, 'masterPasswordHash', 'MasterPasswordHash', 'secret', 'Secret');
  if (password) return new AuthService(env).verifyPassword(password, user.masterPasswordHash, user.email);
  const otp = str(body, 'otp', 'OTP');
  if (otp) return (await consumeEmailCode(env, user.id, 'otp', otp, false)) !== null;
  const token = str(body, 'userVerificationToken', 'UserVerificationToken');
  return !!token && verifyTotpUserVerificationToken(env, user, VERIFICATION_KEY, token);
}

const unverified = () => errorResponse('User verification failed.', 400);

function emailTwoFactorJson(enabled: boolean, email: string | null, userVerificationToken?: string) {
  return {
    Enabled: enabled,
    Email: email,
    ...(userVerificationToken ? { UserVerificationToken: userVerificationToken } : {}),
    Object: 'twoFactorEmail',
  };
}

async function securityAudit(env: Env, request: Request, user: User, action: string): Promise<void> {
  await safeWriteAuditEvent(env, {
    actorUserId: user.id,
    action,
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: user.id,
    metadata: auditRequestMetadata(request),
  });
}

// Signed-in routes: email two-step login setup, email change, verify-email, protected actions.
export async function handleMailAuthenticatedRoute(request: Request, env: Env, cachedUser: User, path: string, method: string): Promise<Response | null> {
  const mail = mailConfig(env);
  if (!mail) return null;
  const route = path.replace(/^\/api\//, '/');
  const origin = new URL(request.url).origin;
  const storage = new StorageService(env.DB);
  // The router's user can be up to 15 seconds old; some handlers below save the whole row.
  const user = await storage.getUserById(cachedUser.id);
  if (!user) return errorResponse('User not found', 404);

  if (route === '/accounts/verify-email-token') return verifyEmailToken(request, env);
  if (route === '/accounts/verify-email') {
    const token = randomLinkToken();
    const link = `${origin}/#/verify-email/?userId=${user.id}&token=${encodeURIComponent(token)}`;
    return (await deliver(env, mail, user.id, 'verify-email', token, EMAIL_LINK_TTL_MS, mailTemplates.verifyEmail(user.email, link, origin))) ?? ok();
  }
  if (route === '/accounts/request-otp') {
    const code = randomDigits();
    return (await deliver(env, mail, user.id, 'otp', code, EMAIL_CODE_TTL_MS, mailTemplates.protectedActionCode(user.email, code, origin))) ?? ok();
  }

  const body = await readBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);

  if (route === '/accounts/verify-otp') {
    return (await consumeEmailCode(env, user.id, 'otp', str(body, 'otp', 'OTP'))) ? ok() : errorResponse('Token is invalid', 400);
  }

  if (route === '/accounts/email-token') {
    if (!(await new AuthService(env).verifyPassword(str(body, 'masterPasswordHash'), user.masterPasswordHash, user.email))) {
      return errorResponse('Invalid password', 400);
    }
    const newEmail = normalizeEmail(str(body, 'newEmail'));
    if (!isEmail(newEmail)) return errorResponse('Invalid email address', 400);
    if (await storage.getUser(newEmail)) return errorResponse('Email already in use', 400);
    const code = randomDigits();
    return (await deliver(env, mail, user.id, 'email-change', code, EMAIL_CODE_TTL_MS, mailTemplates.changeEmailCode(newEmail, code, origin))) ?? ok();
  }

  if (route === '/accounts/email') return changeEmail(request, env, storage, user, body);

  if (route === '/two-factor/get-email') {
    if (!(await verifySecret(env, user, body))) return unverified();
    const token = await createTotpUserVerificationToken(env, user, VERIFICATION_KEY);
    return jsonResponse(emailTwoFactorJson(!!user.emailTwoFactor, user.emailTwoFactor ?? user.email, token));
  }

  if (route === '/two-factor/send-email') {
    if (!(await verifySecret(env, user, body))) return unverified();
    const email = normalizeEmail(str(body, 'email', 'Email'));
    if (!isEmail(email)) return errorResponse('Invalid email address', 400);
    const code = randomDigits();
    return (await deliver(env, mail, user.id, 'setup', code, EMAIL_CODE_TTL_MS, mailTemplates.twoFactorCode(email, code, origin))) ?? ok();
  }

  if (route === '/two-factor/email' && method === 'DELETE') {
    if (!(await verifySecret(env, user, body))) return unverified();
    await storage.setEmailTwoFactor(user.id, null);
    await deleteEmailCode(env, user.id, 'login');
    await storage.deleteRefreshTokensByUserId(user.id);
    AuthService.invalidateUserCache(user.id);
    await securityAudit(env, request, user, 'account.email_2fa.disable');
    return jsonResponse({ Enabled: false, Type: TWO_FACTOR_PROVIDER_EMAIL, Object: 'twoFactorProvider' });
  }

  if (route === '/two-factor/email') {
    if (!(await verifySecret(env, user, body))) return unverified();
    const email = normalizeEmail(str(body, 'email', 'Email'));
    const sentTo = await consumeEmailCode(env, user.id, 'setup', str(body, 'token', 'Token'));
    if (!sentTo || sentTo !== email) return errorResponse('Token is invalid', 400);
    await storage.setEmailTwoFactor(user.id, email);
    if (!user.totpRecoveryCode) {
      user.totpRecoveryCode = createRecoveryCode();
      user.updatedAt = new Date().toISOString();
      await storage.saveUser(user);
    }
    await storage.deleteRefreshTokensByUserId(user.id);
    AuthService.invalidateUserCache(user.id);
    await securityAudit(env, request, user, 'account.email_2fa.enable');
    return jsonResponse(emailTwoFactorJson(true, email));
  }

  return null;
}

// POST /api/accounts/email: the client re-derives its keys with the new address as
// salt, so the request carries a new password hash and a re-wrapped user key.
async function changeEmail(request: Request, env: Env, storage: StorageService, user: User, body: Body): Promise<Response> {
  const auth = new AuthService(env);
  if (!(await auth.verifyPassword(str(body, 'masterPasswordHash'), user.masterPasswordHash, user.email))) {
    return errorResponse('Invalid password', 400);
  }
  const newEmail = normalizeEmail(str(body, 'newEmail'));
  const newHash = str(body, 'newMasterPasswordHash');
  const key = str(body, 'key');
  if (!newHash || !/^\d+\.\S+$/.test(key)) return errorResponse('newMasterPasswordHash and key are required', 400);
  if ((await consumeEmailCode(env, user.id, 'email-change', str(body, 'token'))) !== newEmail) {
    return errorResponse('Token mismatch', 400);
  }
  const previousEmail = user.email;
  user.email = newEmail;
  user.masterPasswordHash = await auth.hashPasswordServer(newHash);
  user.key = key;
  user.securityStamp = generateUUID();
  user.updatedAt = new Date().toISOString();
  try {
    await storage.saveUser(user);
  } catch (error) {
    const message = error instanceof Error ? error.message.toLowerCase() : '';
    if (message.includes('unique') || message.includes('constraint')) return errorResponse('Email already in use', 400);
    throw error;
  }
  await storage.updateRevisionDate(user.id);
  await storage.deleteRefreshTokensByUserId(user.id);
  AuthService.invalidateUserCache(user.id);
  await safeWriteAuditEvent(env, {
    actorUserId: user.id,
    action: 'user.email.change',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: user.id,
    metadata: { previousEmail, email: newEmail, ...auditRequestMetadata(request) },
  });
  return ok();
}

async function verifyEmailToken(request: Request, env: Env): Promise<Response> {
  const body = await readBody(request);
  const userId = body ? str(body, 'userId').toLowerCase() : '';
  const valid = !!userId && (await consumeEmailCode(env, userId, 'verify-email', body ? str(body, 'token') : '')) !== null;
  return valid ? ok() : errorResponse('Invalid claim', 400);
}

// Public routes. The router has applied the sensitive public rate limit already.
export async function handleMailPublicRoute(request: Request, env: Env, path: string): Promise<Response | null> {
  const mail = mailConfig(env);
  if (!mail) return null;
  const route = path.replace(/^\/(?:api|identity)\//, '/');
  const origin = new URL(request.url).origin;
  const storage = new StorageService(env.DB);

  switch (route) {
    case '/two-factor/send-email-login':
      return sendEmailLogin(request, env, mail, storage, origin);
    case '/accounts/verify-email-token':
      return verifyEmailToken(request, env);
    case '/accounts/delete-recover': {
      const body = await readBody(request);
      if (!body) return errorResponse('Invalid JSON', 400);
      const user = await storage.getUser(normalizeEmail(str(body, 'email')));
      // The answer is the same whether or not the account exists.
      if (user && user.status === 'active') {
        const token = randomLinkToken();
        const link = `${origin}/#/verify-recover-delete?userId=${user.id}&token=${encodeURIComponent(token)}&email=${encodeURIComponent(user.email)}`;
        await deliver(env, mail, user.id, 'delete-recover', token, EMAIL_LINK_TTL_MS, mailTemplates.deleteAccount(user.email, link, origin));
      }
      return ok();
    }
    case '/accounts/delete-recover-token':
      return deleteRecoverToken(request, env, storage);
    case '/accounts/register/send-verification-email': {
      const body = await readBody(request);
      if (!body) return errorResponse('Invalid JSON', 400);
      const email = normalizeEmail(str(body, 'email'));
      if (!isEmail(email)) return errorResponse('Invalid email address', 400);
      // Signup is invite-only once an account exists, and official clients cannot send an invite code.
      if ((await storage.getUserCount()) > 0) return errorResponse('Registration not allowed or user already exists', 400);
      const token = await signRegisterToken(env, email, str(body, 'name'));
      const link = `${origin}/#/finish-signup/?email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}&fromEmail=true`;
      if (!(await sendMail(mail, mailTemplates.registerVerify(email, link, origin)))) {
        return errorResponse('The email could not be sent. Try again later.', 502);
      }
      return new Response(null, { status: 204 });
    }
    case '/accounts/register/verification-email-clicked': {
      const body = (await readBody(request)) ?? {};
      const email = normalizeEmail(str(body, 'email'));
      const valid = !!email && (await verifyRegisterToken(env, str(body, 'emailVerificationToken'), email)) && !(await storage.getUser(email));
      return valid ? ok() : errorResponse('Expired link. Please restart registration or try logging in. You may already have an account', 400);
    }
    case '/accounts/register/finish':
      return registerFinish(request, env);
    default:
      return null;
  }
}

async function sendEmailLogin(request: Request, env: Env, mail: MailConfig, storage: StorageService, origin: string): Promise<Response> {
  const body = await readBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);
  const clientIdentifier = getClientIdentifier(request);
  if (!clientIdentifier) return errorResponse('Client IP is required', 403);
  const email = normalizeEmail(str(body, 'email', 'Email'));
  const passwordHash = str(body, 'masterPasswordHash', 'MasterPasswordHash');
  if (!email || !passwordHash) return errorResponse('No password hash has been submitted.', 400);

  // The same lockout as the password grant: this route also checks a password.
  const rateLimit = new RateLimitService(env.DB);
  const loginKey = await loginRateLimitKey(clientIdentifier, 'password', email);
  const check = await rateLimit.checkLoginAttempt(loginKey);
  if (!check.allowed) {
    return errorResponse(`Too many failed login attempts. Try again in ${Math.ceil((check.retryAfterSeconds || 60) / 60)} minutes.`, 429);
  }
  const user = await storage.getUser(email);
  const valid = await new AuthService(env).verifyPassword(passwordHash, user?.masterPasswordHash ?? null, user?.email ?? email);
  if (!valid || !user || user.status !== 'active') {
    await rateLimit.recordFailedLogin(loginKey);
    return errorResponse('Username or password is incorrect. Try again', 400);
  }
  if (!user.emailTwoFactor) return errorResponse('Email two-step login is not enabled for this account', 400);
  const code = randomDigits();
  return (
    (await deliver(env, mail, user.id, 'login', code, EMAIL_CODE_TTL_MS, mailTemplates.twoFactorCode(user.emailTwoFactor, code, origin))) ?? ok()
  );
}

async function deleteRecoverToken(request: Request, env: Env, storage: StorageService): Promise<Response> {
  const body = (await readBody(request)) ?? {};
  const user = await storage.getUserById(str(body, 'userId').toLowerCase());
  if (!user || !(await consumeEmailCode(env, user.id, 'delete-recover', str(body, 'token')))) {
    return errorResponse('Invalid claim', 400);
  }
  if (await isLastActiveAdmin(storage, user)) return errorResponse('The last active admin cannot delete their own account', 400);
  if (!(await purgeUser(env, storage, user))) return errorResponse(LAST_ORGANIZATION_OWNER_ERROR, 400);
  await safeWriteAuditEvent(env, {
    actorUserId: null,
    action: 'account.delete.recover',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: user.id,
    metadata: auditRequestMetadata(request),
  });
  return ok();
}

// Maps Bitwarden's RegisterFinishRequest (old flat and current nested shapes) onto
// handleRegister's body, which keeps every registration rule in one place.
async function registerFinish(request: Request, env: Env): Promise<Response> {
  const body = await readBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);
  const email = normalizeEmail(str(body, 'email'));
  const claims = await verifyRegisterToken(env, str(body, 'emailVerificationToken'), email);
  if (!claims) return errorResponse('Invalid email verification token', 400);
  const authData = (body.masterPasswordAuthentication ?? {}) as Body;
  const unlock = (body.masterPasswordUnlock ?? {}) as Body;
  const kdf = (authData.kdf ?? unlock.kdf ?? {}) as Body;
  const pick = (...values: unknown[]) => values.find((v) => v !== undefined && v !== null);
  const mapped = {
    email,
    name: claims.name || email,
    masterPasswordHash: pick(body.masterPasswordHash, authData.masterPasswordAuthenticationHash, authData.hash),
    key: pick(body.userSymmetricKey, body.key, unlock.masterKeyWrappedUserKey, unlock.key),
    kdf: pick(body.kdf, kdf.kdfType, kdf.kdf),
    kdfIterations: pick(body.kdfIterations, kdf.iterations, kdf.kdfIterations),
    kdfMemory: pick(body.kdfMemory, kdf.memory, kdf.kdfMemory),
    kdfParallelism: pick(body.kdfParallelism, kdf.parallelism, kdf.kdfParallelism),
    keys: pick(body.userAsymmetricKeys, body.keys),
    accountKeys: body.accountKeys,
    userKeyId: unlock.containedKeyId,
    masterPasswordHint: body.masterPasswordHint,
    inviteCode: body.inviteCode,
  };
  const headers = new Headers(request.headers);
  headers.delete('content-length');
  headers.set('content-type', 'application/json');
  return handleRegister(new Request(request.url, { method: 'POST', headers, body: JSON.stringify(mapped) }), env);
}
