import { Env, Attachment, Cipher } from '../types';
import { notifyUserCipherUpdate, notifyUserVaultSync } from '../durable/notifications-hub';
import { StorageService } from '../services/storage';
import { jsonResponse, errorResponse } from '../utils/response';
import { buildDirectUploadUrl, getMultipartRequestMaxBytes, getSafeJwtSecret, parseDirectUploadPayload } from '../utils/direct-upload';
import { generateUUID } from '../utils/uuid';
import { sanitizeDownloadContentType } from '../utils/content-type';
import {
  createAttachmentUploadToken,
  createFileDownloadToken,
  verifyAttachmentUploadToken,
  verifyFileDownloadToken,
} from '../utils/jwt';
import { applyCipherEmbeddedAttachmentMetadata, cipherToResponse } from './ciphers';
import { LIMITS } from '../config/limits';
import { readActingDeviceIdentifier } from '../utils/device';
import {
  deleteBlobObject,
  getAttachmentObjectKey,
  getBlobObject,
  putBlobObject,
} from '../services/blob-store';
import { auditRequestMetadata, writeAuditEvent } from '../services/audit-events';

// The user's cipher, or the response to send.
async function loadCipher(env: Env, cipherId: string, userId: string): Promise<Cipher | Response> {
  const cipher = await new StorageService(env.DB).getCipherForUser(cipherId, userId);
  if (!cipher) return errorResponse('Cipher not found', 404);
  return cipher;
}

// Callers have checked access to the cipher, so an attachment of it is theirs to use.
async function loadAttachment(storage: StorageService, attachmentId: string, cipherId: string): Promise<Attachment | null> {
  const attachment = await storage.getAttachment(attachmentId);
  return attachment && attachment.cipherId === cipherId ? attachment : null;
}

// Moves the cipher's revision date and tells its owner.
async function publishAttachmentChange(request: Request, env: Env, storage: StorageService, cipher: Cipher): Promise<boolean> {
  const revisionInfo = await storage.updateCipherRevisionDate(cipher.id);
  if (!revisionInfo) return false;
  notifyVaultSyncForRequest(request, env, revisionInfo.userId, revisionInfo.revisionDate);
  notifyCipherUpdateForRequest(request, env, cipher, revisionInfo.revisionDate);
  return true;
}

async function cipherResponseWithAttachments(storage: StorageService, cipherId: string, userId: string) {
  const cipher = await storage.getCipherForUser(cipherId, userId);
  if (!cipher) return null;
  const attachments = await storage.getAttachmentsByCipher(cipherId);
  return cipherToResponse(cipher, attachments);
}

function notifyVaultSyncForRequest(
  request: Request,
  env: Env,
  userId: string,
  revisionDate: string
): void {
  notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
}

function normalizeOptionalId(value: unknown): string | null {
  if (value == null) return null;
  const normalized = String(value).trim();
  return normalized ? normalized : null;
}

function notifyCipherUpdateForRequest(
  request: Request,
  env: Env,
  cipher: Cipher,
  revisionDate: string
): void {
  notifyUserCipherUpdate(env, {
    userId: cipher.userId,
    cipherId: cipher.id,
    revisionDate,
    contextId: readActingDeviceIdentifier(request),
  });
}

function contentDispositionAttachment(fileName: string | null | undefined): string {
  const fallback = 'attachment';
  const value = String(fileName || fallback)
    .replace(/[\r\n"]/g, '_')
    .trim() || fallback;
  return `attachment; filename="${value}"`;
}

async function writeAttachmentAudit(
  storage: StorageService,
  request: Request,
  userId: string,
  action: string,
  metadata: Record<string, unknown>
): Promise<void> {
  await writeAuditEvent(storage, {
    actorUserId: userId,
    action,
    category: 'data',
    level: action.includes('delete') ? 'security' : 'info',
    targetType: 'attachment',
    targetId: typeof metadata.id === 'string' ? metadata.id : null,
    metadata: {
      ...metadata,
      ...auditRequestMetadata(request),
    },
  });
}

// Format file size to human readable
function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} Bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

async function runWithConcurrency<T>(
  items: T[],
  concurrency: number,
  worker: (item: T) => Promise<void>
): Promise<void> {
  if (items.length === 0) return;
  const limit = Math.max(1, concurrency);
  for (let index = 0; index < items.length; index += limit) {
    await Promise.all(items.slice(index, index + limit).map(worker));
  }
}

async function processAttachmentUpload(
  request: Request,
  env: Env,
  cipher: Cipher,
  attachment: Attachment,
  cipherId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const maxFileSize = LIMITS.attachment.maxFileSizeBytes;
  const upload = await parseDirectUploadPayload(request, {
    expectedSize: Number(attachment.size) || 0,
    maxFileSize,
    tooLargeMessage: `File too large. Maximum size is ${Math.floor(maxFileSize / (1024 * 1024))}MB`,
  });
  if (upload instanceof Response) {
    return upload;
  }

  const path = getAttachmentObjectKey(cipherId, attachment.id);
  if (await getBlobObject(env, path)) {
    return errorResponse('Attachment file has already been uploaded', 409);
  }

  try {
    await putBlobObject(env, path, upload.body, {
      size: upload.size,
      contentType: upload.contentType,
      customMetadata: {
        cipherId,
        attachmentId: attachment.id,
      },
    });
  } catch {
    return errorResponse('Attachment storage is not configured', 500);
  }

  if (upload.size !== attachment.size) {
    attachment.size = upload.size;
    attachment.sizeName = formatSize(upload.size);
    await storage.saveAttachment(attachment);
  }

  await publishAttachmentChange(request, env, storage, cipher);

  return new Response(null, { status: 201 });
}

// POST /api/ciphers/{cipherId}/attachment/v2
// Creates attachment metadata and returns upload URL
export async function handleCreateAttachment(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  const cipher = await loadCipher(env, cipherId, userId);
  if (cipher instanceof Response) return cipher;

  let body: {
    fileName?: string;
    key?: string;
    fileSize?: number;
  };

  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.fileName || !body.key) {
    return errorResponse('fileName and key are required', 400);
  }

  const fileSize = body.fileSize || 0;
  const attachmentId = generateUUID();

  // Create attachment metadata
  const attachment: Attachment = {
    id: attachmentId,
    cipherId: cipherId,
    fileName: body.fileName,
    size: fileSize,
    sizeName: formatSize(fileSize),
    key: body.key,
  };

  // Save attachment metadata
  await storage.saveAttachment(attachment);

  // Update cipher revision date
  await publishAttachmentChange(request, env, storage, cipher);

  const cipherResponse = await cipherResponseWithAttachments(storage, cipherId, userId);
  const jwtSecret = getSafeJwtSecret(env);
  if (!jwtSecret) {
    return errorResponse('Server configuration error', 500);
  }
  const uploadToken = await createAttachmentUploadToken(userId, cipherId, attachmentId, jwtSecret);

  return jsonResponse({
    object: 'attachment-fileUpload',
    attachmentId: attachmentId,
    url: buildDirectUploadUrl(request, `/api/ciphers/${cipherId}/attachment/${attachmentId}`, uploadToken),
    fileUploadType: 1,
    cipherResponse,
  });
}

// POST /api/ciphers/{cipherId}/attachment as multipart/form-data.
// The legacy upload: one request carries the attachment key and the file, whose file name is the
// encrypted name. The new file replaces `replaceAttachmentId` once it is stored.
export async function handleLegacyUploadAttachment(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  replaceAttachmentId: string | null = null
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const cipher = await loadCipher(env, cipherId, userId);
  if (cipher instanceof Response) return cipher;
  const replaced = replaceAttachmentId ? await loadAttachment(storage, replaceAttachmentId, cipherId) : null;
  if (replaceAttachmentId && !replaced) return errorResponse('Attachment not found', 404);

  const maxFileSize = LIMITS.attachment.maxFileSizeBytes;
  const tooLarge = `File too large. Maximum size is ${Math.floor(maxFileSize / (1024 * 1024))}MB`;
  if (!(request.headers.get('content-type') || '').includes('multipart/form-data')) {
    return errorResponse('Expected a multipart/form-data upload', 400);
  }
  if (Number(request.headers.get('content-length') || 0) > getMultipartRequestMaxBytes(maxFileSize)) {
    return errorResponse(tooLarge, 413);
  }
  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return errorResponse('Invalid form data', 400);
  }
  const file = form.get('data');
  const key = form.get('key');
  if (!file || typeof file === 'string') return errorResponse('No file uploaded', 400);
  if (!file.name) return errorResponse('No filename provided', 400);
  if (typeof key !== 'string' || !key.trim()) return errorResponse('No attachment key provided', 400);
  if (file.size > maxFileSize) return errorResponse(tooLarge, 413);

  const attachment: Attachment = {
    id: generateUUID(),
    cipherId,
    fileName: file.name,
    size: file.size,
    sizeName: formatSize(file.size),
    key: key.trim(),
  };
  try {
    await putBlobObject(env, getAttachmentObjectKey(cipherId, attachment.id), file.stream(), {
      size: file.size,
      contentType: file.type || 'application/octet-stream',
      customMetadata: { cipherId, attachmentId: attachment.id },
    });
  } catch {
    return errorResponse('Attachment storage is not configured', 500);
  }
  await storage.saveAttachment(attachment);
  if (replaced) {
    await deleteBlobObject(env, getAttachmentObjectKey(cipherId, replaced.id));
    await storage.deleteAttachment(replaced.id);
  }
  await publishAttachmentChange(request, env, storage, cipher);

  return jsonResponse(await cipherResponseWithAttachments(storage, cipherId, userId));
}

// POST /api/ciphers/{cipherId}/attachment/{attachmentId}
// Upload attachment file content
export async function handleUploadAttachment(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  attachmentId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  const cipher = await loadCipher(env, cipherId, userId);
  if (cipher instanceof Response) return cipher;

  // Verify attachment exists
  const attachment = await loadAttachment(storage, attachmentId, cipherId);
  if (!attachment) {
    return errorResponse('Attachment not found', 404);
  }

  return processAttachmentUpload(request, env, cipher, attachment, cipherId);
}

export async function handlePublicUploadAttachment(
  request: Request,
  env: Env,
  cipherId: string,
  attachmentId: string
): Promise<Response> {
  const jwtSecret = getSafeJwtSecret(env);
  if (!jwtSecret) {
    return errorResponse('Server configuration error', 500);
  }

  const token = new URL(request.url).searchParams.get('token');
  if (!token) {
    return errorResponse('Token required', 401);
  }

  const claims = await verifyAttachmentUploadToken(token, jwtSecret);
  if (!claims) {
    return errorResponse('Invalid or expired token', 401);
  }
  if (claims.cipherId !== cipherId || claims.attachmentId !== attachmentId) {
    return errorResponse('Token mismatch', 401);
  }

  const storage = new StorageService(env.DB);
  const cipher = await loadCipher(env, cipherId, claims.userId);
  if (cipher instanceof Response) return cipher;

  const attachment = await loadAttachment(storage, attachmentId, cipherId);
  if (!attachment) {
    return errorResponse('Attachment not found', 404);
  }

  return processAttachmentUpload(request, env, cipher, attachment, cipherId);
}

// GET /api/ciphers/{cipherId}/attachment/{attachmentId}
// Get attachment download info
export async function handleGetAttachment(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  attachmentId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  const cipher = await loadCipher(env, cipherId, userId);
  if (cipher instanceof Response) return cipher;

  // Verify attachment exists
  const attachment = await loadAttachment(storage, attachmentId, cipherId);
  if (!attachment) {
    return errorResponse('Attachment not found', 404);
  }
  const responseAttachment = applyCipherEmbeddedAttachmentMetadata(cipher, [attachment])[0] || attachment;

  // Generate short-lived download token
  const token = await createFileDownloadToken(cipherId, attachmentId, env.JWT_SECRET);
  
  // Generate download URL with token
  const url = new URL(request.url);
  const downloadUrl = `${url.origin}/api/attachments/${cipherId}/${attachmentId}?token=${token}`;

  return jsonResponse({
    object: 'attachment',
    id: responseAttachment.id,
    url: downloadUrl,
    fileName: responseAttachment.fileName,
    key: responseAttachment.key,
    size: String(Number(responseAttachment.size) || 0),
    sizeName: responseAttachment.sizeName,
  });
}

// PUT /api/ciphers/{cipherId}/attachment/{attachmentId}/metadata
// 修正旧附件的加密元数据，供官方客户端按当前 Bitwarden 契约解密。
export async function handleUpdateAttachmentMetadata(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  attachmentId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  const cipher = await loadCipher(env, cipherId, userId);
  if (cipher instanceof Response) return cipher;

  const attachment = await loadAttachment(storage, attachmentId, cipherId);
  if (!attachment) {
    return errorResponse('Attachment not found', 404);
  }

  let body: { fileName?: string | null; key?: string | null };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!Object.prototype.hasOwnProperty.call(body, 'fileName') && !Object.prototype.hasOwnProperty.call(body, 'key')) {
    return errorResponse('No metadata fields supplied', 400);
  }

  if (Object.prototype.hasOwnProperty.call(body, 'fileName')) {
    const fileName = String(body.fileName || '').trim();
    if (!fileName) return errorResponse('fileName is required', 400);
    attachment.fileName = fileName;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'key')) {
    const key = body.key == null ? null : String(body.key || '').trim();
    attachment.key = key || null;
  }

  await storage.saveAttachment(attachment);
  await publishAttachmentChange(request, env, storage, cipher);

  return jsonResponse({
    object: 'attachment',
    id: attachment.id,
    fileName: attachment.fileName,
    key: attachment.key,
    size: String(Number(attachment.size) || 0),
    sizeName: attachment.sizeName,
  });
}

// GET /api/attachments/{cipherId}/{attachmentId}?token=xxx
// Public download endpoint (uses token for auth instead of header)
export async function handlePublicDownloadAttachment(
  request: Request,
  env: Env,
  cipherId: string,
  attachmentId: string
): Promise<Response> {
  const secret = getSafeJwtSecret(env);
  if (!secret) return errorResponse('Server configuration error', 500);

  const url = new URL(request.url);
  const token = url.searchParams.get('token');

  if (!token) {
    return errorResponse('Token required', 401);
  }

  // Verify token
  const claims = await verifyFileDownloadToken(token, secret);
  if (!claims) {
    return errorResponse('Invalid or expired token', 401);
  }

  // Verify token matches request
  if (claims.cipherId !== cipherId || claims.attachmentId !== attachmentId) {
    return errorResponse('Token mismatch', 401);
  }

  const storage = new StorageService(env.DB);

  // Verify attachment exists
  const attachment = await storage.getAttachment(attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse('Attachment not found', 404);
  }

  const path = getAttachmentObjectKey(cipherId, attachmentId);
  const firstUse = await storage.consumeAttachmentDownloadToken(claims.jti, claims.exp);
  if (!firstUse) {
    return errorResponse('Invalid or expired token', 401);
  }

  const object = await getBlobObject(env, path);
  if (!object) {
    return errorResponse('Attachment file not found', 404);
  }

  return new Response(object.body, {
    headers: {
      'Content-Type': sanitizeDownloadContentType(object.contentType),
      'Content-Length': String(object.size),
      'Content-Disposition': contentDispositionAttachment(attachment.fileName),
      'Cache-Control': 'private, no-cache',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

// DELETE /api/ciphers/{cipherId}/attachment/{attachmentId}
// Delete attachment
export async function handleDeleteAttachment(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  attachmentId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);

  const cipher = await loadCipher(env, cipherId, userId);
  if (cipher instanceof Response) return cipher;

  // Verify attachment exists
  const attachment = await loadAttachment(storage, attachmentId, cipherId);
  if (!attachment) {
    return errorResponse('Attachment not found', 404);
  }

  const path = getAttachmentObjectKey(cipherId, attachmentId);
  await deleteBlobObject(env, path);

  // Delete attachment metadata
  await storage.deleteAttachment(attachmentId);

  // Update cipher revision date
  if (await publishAttachmentChange(request, env, storage, cipher)) {
    await writeAttachmentAudit(storage, request, userId, 'attachment.delete', {
      id: attachmentId,
      cipherId,
      size: attachment.size,
    });
  }

  // Get updated cipher for response
  const cipherResponse = await cipherResponseWithAttachments(storage, cipherId, userId);

  return jsonResponse({
    cipher: cipherResponse,
    object: 'deleteAttachment',
  });
}

// Delete all attachments for a cipher (used when deleting cipher)
export async function deleteAllAttachmentsForCipher(
  env: Env,
  cipherId: string
): Promise<void> {
  await deleteAllAttachmentsForCiphers(env, [cipherId]);
}

export async function deleteAllAttachmentsForCiphers(
  env: Env,
  cipherIds: string[]
): Promise<void> {
  const storage = new StorageService(env.DB);
  const attachmentsByCipher = await storage.getAttachmentsByCipherIds(cipherIds);
  const attachments = Array.from(attachmentsByCipher.entries()).flatMap(([ownedCipherId, items]) =>
    items.map((attachment) => ({ attachment, cipherId: ownedCipherId }))
  );
  if (!attachments.length) return;

  await runWithConcurrency(attachments, LIMITS.performance.attachmentDeleteConcurrency, async ({ attachment, cipherId }) => {
    const path = getAttachmentObjectKey(cipherId, attachment.id);
    await deleteBlobObject(env, path);
  });

  await storage.bulkDeleteAttachmentsByIds(attachments.map(({ attachment }) => attachment.id));
}
