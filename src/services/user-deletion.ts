import type { Env, User } from '../types';
import { AuthService } from './auth';
import { StorageService } from './storage';
import { deleteBlobObject, getAttachmentObjectKey, getSendFileObjectKey } from './blob-store';

// Removes a user's stored files first, then the user row. D1 cascades delete the
// remaining rows. Files go first so a failure never leaves orphaned blobs without
// a row that points at them.
export async function purgeUser(env: Env, storage: StorageService, target: User): Promise<void> {
  const attachmentMap = await storage.getAttachmentsByUserId(target.id);
  for (const [cipherId, attachments] of attachmentMap) {
    for (const att of attachments) {
      await deleteBlobObject(env, getAttachmentObjectKey(cipherId, att.id));
    }
  }

  const sends = await storage.getAllSends(target.id);
  for (const send of sends) {
    if (send.type !== 1) continue; // SendType.File
    try {
      const parsed = JSON.parse(send.data) as Record<string, unknown>;
      const fileId = typeof parsed.id === 'string' ? parsed.id : null;
      if (fileId) await deleteBlobObject(env, getSendFileObjectKey(send.id, fileId));
    } catch {
      // Non-file send or malformed data: nothing to delete.
    }
  }

  await storage.deleteRefreshTokensByUserId(target.id);
  await storage.deleteUserById(target.id);
  AuthService.invalidateUserCache(target.id);
}

// True when deleting this user would leave the instance with no active admin.
export async function isLastActiveAdmin(storage: StorageService, user: User): Promise<boolean> {
  if (user.role !== 'admin') return false;
  const users = await storage.getAllUsers();
  return !users.some((u) => u.id !== user.id && u.role === 'admin' && u.status === 'active');
}
