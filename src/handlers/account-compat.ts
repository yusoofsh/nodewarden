import type { Env } from '../types';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import { auditRequestMetadata, safeWriteAuditEvent } from '../services/audit-events';
import { jsonResponse, errorResponse } from '../utils/response';
import { isLastActiveAdmin, LAST_ORGANIZATION_OWNER_ERROR, purgeUser } from '../services/user-deletion';
import { generateUUID } from '../utils/uuid';
import { isV2User } from '../utils/account-keys';

const HIBP_USERNAME_PATTERN = /^[^\s/?#]{1,254}$/;

// POST /api/accounts/security-stamp
// Rotates the security stamp so every issued token and refresh token stops working.
export async function handleRotateSecurityStamp(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: { masterPasswordHash?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
  if (!body.masterPasswordHash) return errorResponse('masterPasswordHash is required', 400);

  const valid = await auth.verifyPassword(body.masterPasswordHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse('Invalid password', 400);

  user.securityStamp = generateUUID();
  user.updatedAt = new Date().toISOString();
  await storage.saveUser(user);
  await storage.deleteRefreshTokensByUserId(user.id);
  AuthService.invalidateUserCache(user.id);
  await safeWriteAuditEvent(env, {
    actorUserId: user.id,
    action: 'account.security-stamp.rotate',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: user.id,
    metadata: auditRequestMetadata(request),
  });
  return new Response(null, { status: 200 });
}

// GET /api/users/{id}/public-key, GET /api/users/{id}/keys
// Used by clients to wrap keys for another account (sharing, emergency access). Like Vaultwarden,
// /keys answers with the signed public key and verifying key too, set only for a V2 account.
export async function handleGetUserPublicKey(env: Env, targetUserId: string, withSignature = false): Promise<Response> {
  const storage = new StorageService(env.DB);
  const target = await storage.getUserById(targetUserId);
  if (!target || target.status !== 'active' || !target.publicKey) {
    return errorResponse('User not found', 404);
  }
  if (!withSignature) return jsonResponse({ userId: target.id, publicKey: target.publicKey, object: 'userKey' });
  const keyPair = isV2User(target) ? target.signatureKeyPair : null;
  return jsonResponse({
    publicKey: target.publicKey,
    signedPublicKey: keyPair ? target.signedPublicKey : null,
    verifyingKey: keyPair ? keyPair.verifyingKey : null,
    object: 'publicKeys',
  });
}

// GET /api/tasks
// Security tasks are an organization feature; personal accounts have none.
export function handleGetTasks(): Response {
  return jsonResponse({ data: [], object: 'list', continuationToken: null });
}

// GET /api/hibp/breach?username=...
// Proxies Have I Been Pwned. Requires an HIBP_API_KEY secret, like Vaultwarden.
export async function handleHibpBreach(request: Request, env: Env): Promise<Response> {
  const apiKey = env.HIBP_API_KEY;
  if (!apiKey) return errorResponse('HaveIBeenPwned API key not configured', 400);

  const username = new URL(request.url).searchParams.get('username') || '';
  if (!HIBP_USERNAME_PATTERN.test(username)) return errorResponse('Invalid username', 400);

  const upstream = await fetch(
    `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(username)}?truncateResponse=false`,
    { headers: { 'hibp-api-key': apiKey, 'user-agent': 'NodeWarden' } }
  );
  if (upstream.status === 404) return jsonResponse([]);
  if (!upstream.ok) return errorResponse('HaveIBeenPwned request failed', 502);
  return new Response(upstream.body, { status: 200, headers: { 'Content-Type': 'application/json' } });
}

// POST /api/accounts/delete, POST /api/accounts/delete-account, DELETE /api/accounts
// Permanently deletes the caller's own account and all of its data.
export async function handleDeleteOwnAccount(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: { masterPasswordHash?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
  if (!body.masterPasswordHash) return errorResponse('masterPasswordHash is required', 400);

  const valid = await auth.verifyPassword(body.masterPasswordHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse('Invalid password', 400);

  if (await isLastActiveAdmin(storage, user)) {
    return errorResponse('The last active admin cannot delete their own account', 400);
  }

  if (!(await purgeUser(env, storage, user))) return errorResponse(LAST_ORGANIZATION_OWNER_ERROR, 400);
  await safeWriteAuditEvent(env, {
    actorUserId: null,
    action: 'account.delete',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: user.id,
    metadata: auditRequestMetadata(request),
  });
  return new Response(null, { status: 200 });
}
