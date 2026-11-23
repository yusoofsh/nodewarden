// Organization ciphers: creating one, sharing personal ciphers into an organization, changing a
// cipher's collections and the admin console listing. Follows Vaultwarden's src/api/core/ciphers.rs.
// Every check runs before anything is written.
import { EventType, eventActor, logEvents } from '../services/events';
import type { Cipher, Env } from '../types';
import { StorageService } from '../services/storage';
import {
  type AccessibleCipher,
  FULL_ACCESS,
  getCollectionWriteAccess,
  getOrgCipherForUser,
  insertOrgCipher,
  listCipherCollectionIds,
  listOrgCiphers,
  shareCipher,
  updateCipherCollections,
} from '../services/storage-org-cipher-repo';
import { authorizeOrgRequest, canEditCipherCollections, getConfirmedMembership, hasFullAccess } from '../services/org-access';
import { errorResponse, jsonResponse } from '../utils/response';
import { readActingDeviceIdentifier } from '../utils/device';
import {
  buildFullCipherUpdate,
  cipherResponseFor,
  cipherToResponse,
  clearPerUserCipherState,
  isStaleCipherUpdate,
  readCipherRevisionDate,
  syncIncomingAttachmentMetadata,
} from './ciphers';
import { isRecord, list, readBody, str, touchOrganizationVault } from './organizations';

const STALE = 'The client copy of this cipher is out of date. Resync the client and try again.';

/** The collectionIds of a request body, lowercased and unique, or null when they are not a list. */
export function readCollectionIds(body: Record<string, unknown>): string[] | null {
  const raw = body.collectionIds ?? body.CollectionIds;
  if (raw == null) return [];
  if (!Array.isArray(raw)) return null;
  return [...new Set(raw.map((id) => str(id).toLowerCase()).filter(Boolean))];
}

/** Why the user may not put a cipher in these collections of the organization, or null. */
async function collectionsError(db: D1Database, organizationId: string, userId: string, collectionIds: string[]): Promise<string | null> {
  const writable = await getCollectionWriteAccess(db, organizationId, userId, collectionIds);
  for (const id of collectionIds) {
    if (!writable.has(id)) return 'Invalid collection ID provided';
    if (!writable.get(id)) return 'No rights to modify the collection';
  }
  return null;
}

async function respondWithOrgCipher(request: Request, env: Env, userId: string, fallback: AccessibleCipher): Promise<Response> {
  const storage = new StorageService(env.DB);
  const accessible = (await getOrgCipherForUser(env.DB, fallback.cipher.id, userId)) ?? fallback;
  return jsonResponse(cipherResponseFor(request, accessible, await storage.getAttachmentsByCipher(accessible.cipher.id)));
}

// POST /api/ciphers/create and /api/ciphers/admin with an organizationId, after handleCreateCipher
// built and validated the cipher. Without collections only a member with full access may create it.
export async function createOrgCipher(
  request: Request,
  env: Env,
  userId: string,
  cipher: Cipher,
  collectionIds: string[],
  admin: boolean
): Promise<Response> {
  const organizationId = cipher.organizationId!;
  const member = await getConfirmedMembership(env.DB, organizationId, userId);
  if (!member) return errorResponse("You don't have permission to add item to organization", 400);
  const full = hasFullAccess(member);
  if (admin && !full) return errorResponse('Cipher is not write accessible', 400);
  if (!collectionIds.length && !full) return errorResponse("You don't have permission to add cipher directly to organization", 400);
  const error = await collectionsError(env.DB, organizationId, userId, collectionIds);
  if (error) return errorResponse(error, 400);

  clearPerUserCipherState(cipher);
  await insertOrgCipher(env.DB, cipher, collectionIds);
  await touchOrganizationVault(env, organizationId, readActingDeviceIdentifier(request));
  await logEvents(env, eventActor(request, userId), [{ type: EventType.CipherCreated, organizationId, cipherId: cipher.id }]);
  return respondWithOrgCipher(request, env, userId, { cipher, access: FULL_ACCESS, collectionIds });
}

interface SharePlan {
  cipher: Cipher;
  expectedUpdatedAt: string;
  cipherData: Record<string, unknown>;
}

// The checks of sharing one personal cipher, before anything is written.
async function planShare(
  storage: StorageService,
  userId: string,
  cipherId: string,
  cipherData: Record<string, unknown>
): Promise<SharePlan | Response> {
  const existing = await storage.getCipherForUser(cipherId, userId);
  if (!existing) return errorResponse("Cipher doesn't exist", 404);
  if (isStaleCipherUpdate(existing.updatedAt, readCipherRevisionDate(cipherData))) return errorResponse(STALE, 400);
  const built = buildFullCipherUpdate(existing, cipherData, false);
  if ('error' in built) return errorResponse(built.error, 400);
  return { cipher: built.cipher, expectedUpdatedAt: existing.updatedAt, cipherData };
}

async function applyShare(
  storage: StorageService,
  env: Env,
  plan: SharePlan,
  organizationId: string,
  collectionIds: string[]
): Promise<boolean> {
  plan.cipher.organizationId = organizationId;
  clearPerUserCipherState(plan.cipher);
  if (!(await shareCipher(env.DB, plan.cipher, plan.expectedUpdatedAt, collectionIds))) return false;
  // Clients re-encrypt attachment keys with the organization key and send them along.
  await syncIncomingAttachmentMetadata(storage, plan.cipher.id, plan.cipherData);
  return true;
}

function readShareTarget(cipherData: Record<string, unknown>): string {
  return str(cipherData.organizationId ?? cipherData.OrganizationId).toLowerCase();
}

// PUT/POST /api/ciphers/{id}/share
export async function handleShareCipher(request: Request, env: Env, userId: string, cipherId: string): Promise<Response> {
  const body = await readBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);
  const cipherData = isRecord(body.cipher) ? body.cipher : isRecord(body.Cipher) ? body.Cipher : null;
  if (!cipherData) return errorResponse('cipher is required', 400);
  const organizationId = readShareTarget(cipherData);
  if (!organizationId) return errorResponse('Cipher OrganizationId is required.', 400);
  const collectionIds = readCollectionIds(body);
  if (!collectionIds?.length) return errorResponse('You must select at least one collection.', 400);

  const storage = new StorageService(env.DB);
  const plan = await planShare(storage, userId, cipherId, cipherData);
  if (plan instanceof Response) return plan;
  if (!(await getConfirmedMembership(env.DB, organizationId, userId))) {
    return errorResponse("You don't have permission to add item to organization", 400);
  }
  const error = await collectionsError(env.DB, organizationId, userId, collectionIds);
  if (error) return errorResponse(error, 400);

  if (!(await applyShare(storage, env, plan, organizationId, collectionIds))) return errorResponse(STALE, 400);
  await touchOrganizationVault(env, organizationId, readActingDeviceIdentifier(request));
  await logEvents(env, eventActor(request, userId), [{ type: EventType.CipherShared, organizationId, cipherId: plan.cipher.id }]);
  return respondWithOrgCipher(request, env, userId, { cipher: plan.cipher, access: FULL_ACCESS, collectionIds });
}

// The fields of a cipherMini response, which the bulk share answers with.
const CIPHER_MINI_FIELDS = [
  'id', 'organizationId', 'type', 'data', 'name', 'notes', 'login', 'card', 'identity', 'secureNote', 'sshKey',
  'bankAccount', 'driversLicense', 'passport', 'fields', 'passwordHistory', 'attachments', 'organizationUseTotp',
  'revisionDate', 'creationDate', 'deletedDate', 'reprompt', 'key',
];

// PUT /api/ciphers/share
export async function handleShareCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await readBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);
  const items = Array.isArray(body.ciphers) ? body.ciphers.filter(isRecord) : [];
  if (!items.length) return errorResponse('You must select at least one cipher.', 400);
  if (items.some((c) => !str(c.id) || !readShareTarget(c))) return errorResponse('All Ciphers must have an Id and OrganizationId.', 400);
  const organizationId = readShareTarget(items[0]);
  if (items.some((c) => readShareTarget(c) !== organizationId)) return errorResponse('All ciphers must be for the same organization.', 400);
  const collectionIds = readCollectionIds(body);
  if (!collectionIds?.length) return errorResponse('You must select at least one collection.', 400);

  const storage = new StorageService(env.DB);
  if (!(await getConfirmedMembership(env.DB, organizationId, userId))) {
    return errorResponse("You don't have permission to add item to organization", 400);
  }
  const error = await collectionsError(env.DB, organizationId, userId, collectionIds);
  if (error) return errorResponse(error, 400);
  const plans: SharePlan[] = [];
  for (const item of items) {
    const plan = await planShare(storage, userId, str(item.id), item);
    if (plan instanceof Response) {
      return plan.status === 404 ? errorResponse('Trying to share ciphers that you do not own.', 400) : plan;
    }
    plans.push(plan);
  }

  const shared: Cipher[] = [];
  for (const plan of plans) {
    if (await applyShare(storage, env, plan, organizationId, collectionIds)) shared.push(plan.cipher);
  }
  await touchOrganizationVault(env, organizationId, readActingDeviceIdentifier(request));
  await logEvents(env, eventActor(request, userId), shared.map((c) => ({ type: EventType.CipherShared, organizationId, cipherId: c.id })));

  const attachments = await storage.getAttachmentsByCipherIds(shared.map((c) => c.id));
  return list(
    shared.map((cipher) => {
      const full = cipherToResponse(cipher, attachments.get(cipher.id) || []) as unknown as Record<string, unknown>;
      return { ...Object.fromEntries(CIPHER_MINI_FIELDS.map((field) => [field, full[field] ?? null])), object: 'cipherMini' };
    })
  );
}

// PUT/POST /api/ciphers/{id}/collections, /collections_v2 and /collections-admin (admin = true).
// The admin route lets a member with full access change any collection; the others need write
// access to each collection added or removed.
export async function handleUpdateCipherCollections(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  variant: 'user' | 'v2' | 'admin'
): Promise<Response> {
  const body = await readBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);
  const posted = readCollectionIds(body);
  if (!posted) return errorResponse('collectionIds must be an array', 400);

  const accessible = await getOrgCipherForUser(env.DB, cipherId, userId);
  if (!accessible || !canEditCipherCollections(accessible.access)) return errorResponse('Collection cannot be changed', 400);
  const organizationId = accessible.cipher.organizationId!;
  const member = await getConfirmedMembership(env.DB, organizationId, userId);
  const adminEditAny = variant === 'admin' && !!member && hasFullAccess(member);
  const current = variant === 'admin' ? await listCipherCollectionIds(env.DB, cipherId) : accessible.collectionIds;

  const add = posted.filter((id) => !current.includes(id));
  const remove = current.filter((id) => !posted.includes(id));
  const writable = await getCollectionWriteAccess(env.DB, organizationId, userId, [...new Set([...posted, ...remove])]);
  for (const id of posted) if (!writable.has(id)) return errorResponse('Invalid collection ID provided', 400);
  for (const id of [...add, ...remove]) {
    if (!adminEditAny && !writable.get(id)) return errorResponse('No rights to modify the collection', 400);
  }

  await updateCipherCollections(env.DB, cipherId, organizationId, add, remove);
  await touchOrganizationVault(env, organizationId, readActingDeviceIdentifier(request));
  await logEvents(env, eventActor(request, userId), [{ type: EventType.CipherUpdatedCollections, organizationId, cipherId: accessible.cipher.id }]);
  const storage = new StorageService(env.DB);
  const after = (await getOrgCipherForUser(env.DB, cipherId, userId)) ?? { ...accessible, collectionIds: [] };
  const response = cipherResponseFor(request, after, await storage.getAttachmentsByCipher(cipherId));
  if (variant === 'admin') response.collectionIds = await listCipherCollectionIds(env.DB, cipherId);
  if (variant === 'v2') return jsonResponse({ object: 'optionalCipherDetails', unavailable: false, cipher: response });
  return jsonResponse(response);
}

// GET /api/ciphers/organization-details?organizationId=
// Every cipher of the organization with all its collections, for owners and admins.
export async function handleGetOrganizationCipherDetails(request: Request, env: Env, userId: string): Promise<Response> {
  const organizationId = str(new URL(request.url).searchParams.get('organizationId')).toLowerCase();
  if (!organizationId) return errorResponse('organizationId is required', 400);
  const member = await authorizeOrgRequest(env.DB, organizationId, userId, 'admin');
  if (member instanceof Response) return member;

  const ciphers = await listOrgCiphers(env.DB, organizationId);
  const attachments = await new StorageService(env.DB).getAttachmentsByCipherIds(ciphers.map(({ cipher }) => cipher.id));
  return list(ciphers.map((accessible) => cipherResponseFor(request, accessible, attachments.get(accessible.cipher.id) || [])));
}
