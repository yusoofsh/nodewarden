import type { Env, User } from '../types';
import { AuthService } from './auth';
import { StorageService } from './storage';
import { deleteBlobObject, getAttachmentObjectKey, getSendFileObjectKey } from './blob-store';
import { listOrganizationsSolelyOwnedBy } from './storage-organization-repo';
import { reassignOrgCiphersCreatedBy } from './storage-org-cipher-repo';

export const LAST_ORGANIZATION_OWNER_ERROR = 'The last owner of an organization cannot be deleted';

// Removes a user's stored files first, then the user row. D1 cascades delete the
// remaining rows, organization memberships included. Files go first so a failure never
// leaves orphaned blobs without a row that points at them.
// Organization ciphers the user created belong to their organization, but their user_id would
// cascade them away, so they pass to another owner first.
// Returns false, and deletes nothing, when the user is the last owner of an organization.
export async function purgeUser(env: Env, storage: StorageService, target: User): Promise<boolean> {
  if ((await listOrganizationsSolelyOwnedBy(env.DB, target.id)).length > 0) return false;
  if ((await reassignOrgCiphersCreatedBy(env.DB, target.id)) > 0) return false;

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
  return true;
}

// True when deleting this user would leave the instance with no active admin.
export async function isLastActiveAdmin(storage: StorageService, user: User): Promise<boolean> {
  if (user.role !== 'admin') return false;
  const users = await storage.getAllUsers();
  return !users.some((u) => u.id !== user.id && u.role === 'admin' && u.status === 'active');
}
