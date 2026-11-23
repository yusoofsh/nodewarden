import type { Env, User } from './types';
import { errorResponse, jsonResponse, unsupportedResponse } from './utils/response';
import { handleMailAuthenticatedRoute } from './handlers/email-auth';
import {
  handleGetProfile,
  handleUpdateProfile,
  handlePutAvatar,
  handleGetKeys,
  handleSetKeys,
  handleGetRevisionDate,
  handleSetUserKeyId,
  handleVerifyPassword,
  handleChangePassword,
  handleChangeKdf,
  handleSetVerifyDevices,
  handleGetTotpStatus,
  handleSetTotpStatus,
  handleGetTotpRecoveryCode,
  handleGetTwoFactorProviders,
  handleGetTwoFactorAuthenticator,
  handlePutTwoFactorAuthenticator,
  handleGetTwoFactorYubiKey,
  handlePutTwoFactorYubiKey,
  handlePutTwoFactorYubiKeyConfig,
  handleBootstrapTwoFactorYubiKeyConfig,
  handleGetDeviceVerificationSettings,
  handlePutDeviceVerificationSettings,
  handleDisableTwoFactorProvider,
  handleGetApiKey,
  handleRotateApiKey,
} from './handlers/accounts';
import {
  handleGetCiphers,
  handleGetCipher,
  handleCreateCipher,
  handleUpdateCipher,
  handleDeleteCipher,
  handleDeleteCipherCompat,
  handlePermanentDeleteCipher,
  handleRestoreCipher,
  handleBulkArchiveCiphers,
  handlePartialUpdateCipher,
  handleBulkUnarchiveCiphers,
  handleBulkMoveCiphers,
  handleBulkDeleteCiphers,
  handleBulkPermanentDeleteCiphers,
  handleBulkRestoreCiphers,
  handleArchiveCipher,
  handleUnarchiveCipher,
  handlePurgeVault,
} from './handlers/ciphers';
import {
  handleGetOrganizationCipherDetails,
  handleShareCipher,
  handleShareCiphers,
  handleUpdateCipherCollections,
} from './handlers/org-ciphers';
import {
  handleGetFolders,
  handleGetFolder,
  handleCreateFolder,
  handleUpdateFolder,
  handleDeleteFolder,
  handleBulkDeleteFolders,
} from './handlers/folders';
import {
  handleGetSends,
  handleGetSend,
  handleCreateSend,
  handleCreateFileSendV2,
  handleGetSendFileUpload,
  handleUploadSendFile,
  handleUpdateSend,
  handleDeleteSend,
  handleBulkDeleteSends,
  handleRemoveSendPassword,
  handleRemoveSendAuth,
} from './handlers/sends';
import { handleSync } from './handlers/sync';
import { handleCiphersImport } from './handlers/import';
import {
  handleCreateAttachment,
  handleUploadAttachment,
  handleGetAttachment,
  handleUpdateAttachmentMetadata,
  handleDeleteAttachment,
  handleLegacyUploadAttachment,
} from './handlers/attachments';
import { handleGetKeyRotationData, handleRotateUserAccountKeys } from './handlers/key-rotation';
import { handleEmergencyAccessRoute } from './handlers/emergency-access';
import {
  handleDeleteOwnAccount,
  handleGetTasks,
  handleGetUserPublicKey,
  handleHibpBreach,
  handleRotateSecurityStamp,
} from './handlers/account-compat';
import { handleAuthenticatedDeviceRoute } from './router-devices';
import { handleOrganizationRoute } from './router-organizations';
import { handleCollectEvents, handleGetCipherEvents } from './handlers/events';
import { eventActor } from './services/events';
import { handleAdminRoute } from './router-admin';
import { handleGetDomains, handleUpdateDomains } from './handlers/domains';
import {
  handleCreateAccountPasskeyCredential,
  handleDeleteAccountPasskeyCredential,
  handleDeleteAllTwoFactorWebAuthn,
  handleDeleteTwoFactorWebAuthn,
  handleGetAccountPasskeyAttestationOptions,
  handleGetAccountPasskeyCredentials,
  handleGetAccountPasskeyUpdateAssertionOptions,
  handleGetTwoFactorWebAuthn,
  handleGetTwoFactorWebAuthnChallenge,
  handlePutTwoFactorWebAuthn,
  handleUpdateAccountPasskeyEncryption,
} from './handlers/account-passkeys';
import {
  handleCreateAdminAuthRequest,
  handleGetAuthRequest,
  handleListAuthRequests,
  handleListPendingAuthRequests,
  handleUpdateAuthRequest,
} from './handlers/auth-requests';

export async function handleAuthenticatedRoute(
  request: Request,
  env: Env,
  userId: string,
  currentUser: User,
  path: string,
  method: string
): Promise<Response | null> {
  if (method === 'POST' || method === 'PUT' || method === 'DELETE') {
    const blockedAccountPaths = new Set([
      '/api/accounts/set-password',
      '/api/accounts/delete-vault',
    ]);
    if (blockedAccountPaths.has(path)) {
      return errorResponse('Not implemented', 501);
    }
  }

  if ((path === '/api/accounts/kdf' || path === '/accounts/kdf') && (method === 'POST' || method === 'PUT')) {
    return handleChangeKdf(request, env, userId);
  }

  const mailBackedAccountPaths = new Set([
    '/api/accounts/email-token',
    '/accounts/email-token',
    '/api/accounts/verify-email',
    '/accounts/verify-email',
    '/api/accounts/verify-email-token',
    '/accounts/verify-email-token',
    '/api/accounts/request-otp',
    '/accounts/request-otp',
    '/api/accounts/verify-otp',
    '/accounts/verify-otp',
    // Changing the email needs the token mailed to the new address.
    '/api/accounts/email',
    '/accounts/email',
  ]);
  if (mailBackedAccountPaths.has(path) && (method === 'POST' || method === 'PUT')) {
    const mailResponse = await handleMailAuthenticatedRoute(request, env, currentUser, path, method);
    if (mailResponse) return mailResponse;
    return unsupportedResponse('Email delivery is not supported by this server.');
  }

  const emailTwoFactorPaths = new Set([
    '/api/two-factor/get-email',
    '/two-factor/get-email',
    '/api/two-factor/send-email',
    '/two-factor/send-email',
    '/api/two-factor/send-email-login',
    '/two-factor/send-email-login',
    '/api/two-factor/email',
    '/two-factor/email',
  ]);
  if (emailTwoFactorPaths.has(path) && (method === 'POST' || method === 'PUT' || method === 'DELETE')) {
    const mailResponse = await handleMailAuthenticatedRoute(request, env, currentUser, path, method);
    if (mailResponse) return mailResponse;
    return unsupportedResponse('Email two-step login is not supported by this server.');
  }

  if (path === '/api/accounts/profile') {
    if (method === 'GET') return handleGetProfile(request, env, userId);
    if (method === 'PUT' || method === 'POST') return handleUpdateProfile(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if (path === '/api/accounts/avatar' && method === 'PUT') {
    return handlePutAvatar(request, env, userId);
  }

  if ((path === '/api/accounts/password' || path === '/api/accounts/change-password') && (method === 'POST' || method === 'PUT')) {
    return handleChangePassword(request, env, userId);
  }

  if (path === '/api/accounts/keys') {
    if (method === 'GET') return handleGetKeys(request, env, userId);
    if (method === 'POST') return handleSetKeys(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if (path === '/api/accounts/totp') {
    if (method === 'GET') return handleGetTotpStatus(request, env, userId);
    if (method === 'PUT' || method === 'POST') return handleSetTotpStatus(request, env, userId);
    return null;
  }

  if ((path === '/api/accounts/totp/recovery-code' || path === '/api/two-factor/get-recover') && method === 'POST') {
    return handleGetTotpRecoveryCode(request, env, userId);
  }

  if (path === '/api/two-factor') {
    if (method === 'GET') return handleGetTwoFactorProviders(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if (path === '/api/two-factor/get-authenticator' && method === 'POST') {
    return handleGetTwoFactorAuthenticator(request, env, userId);
  }

  if ((path === '/api/two-factor/get-yubikey' || path === '/api/two-factor/get-yubi-key') && method === 'POST') {
    return handleGetTwoFactorYubiKey(request, env, userId);
  }

  if (path === '/api/two-factor/get-device-verification-settings' && (method === 'GET' || method === 'POST')) {
    return handleGetDeviceVerificationSettings(request, env, userId);
  }

  if (path === '/api/two-factor/device-verification-settings') {
    if (method === 'PUT' || method === 'POST') return handlePutDeviceVerificationSettings(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if (path === '/api/two-factor/get-webauthn' && method === 'POST') {
    return handleGetTwoFactorWebAuthn(request, env, userId, currentUser);
  }

  if (path === '/api/two-factor/get-webauthn-challenge' && method === 'POST') {
    return handleGetTwoFactorWebAuthnChallenge(request, env, userId, currentUser);
  }

  if (path === '/api/two-factor/authenticator') {
    if (method === 'PUT' || method === 'POST') return handlePutTwoFactorAuthenticator(request, env, userId);
    if (method === 'DELETE') return handleDisableTwoFactorProvider(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if ((path === '/api/two-factor/yubikey' || path === '/api/two-factor/yubi-key')) {
    if (method === 'PUT' || method === 'POST') return handlePutTwoFactorYubiKey(request, env, userId);
    if (method === 'DELETE') return handleDisableTwoFactorProvider(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if (path === '/api/two-factor/webauthn') {
    if (method === 'PUT' || method === 'POST') return handlePutTwoFactorWebAuthn(request, env, userId, currentUser);
    if (method === 'DELETE') return handleDeleteTwoFactorWebAuthn(request, env, userId, currentUser);
    return errorResponse('Method not allowed', 405);
  }

  if (path === '/api/two-factor/webauthn/all' && method === 'DELETE') {
    return handleDeleteAllTwoFactorWebAuthn(request, env, userId, currentUser);
  }

  if ((path === '/api/two-factor/yubikey/config' || path === '/api/two-factor/yubi-key/config') && (method === 'PUT' || method === 'POST')) {
    return handlePutTwoFactorYubiKeyConfig(request, env, userId);
  }

  if ((path === '/api/two-factor/yubikey/bootstrap' || path === '/api/two-factor/yubi-key/bootstrap') && method === 'POST') {
    return handleBootstrapTwoFactorYubiKeyConfig(request, env, userId);
  }

  if (path === '/api/two-factor/disable' && (method === 'PUT' || method === 'POST')) {
    return handleDisableTwoFactorProvider(request, env, userId);
  }

  if (
    ((path === '/api/accounts/delete' || path === '/api/accounts/delete-account') && method === 'POST') ||
    (path === '/api/accounts' && method === 'DELETE')
  ) {
    return handleDeleteOwnAccount(request, env, userId);
  }

  if (path === '/api/accounts/key-management/rotate-user-account-keys' && method === 'POST') {
    return handleRotateUserAccountKeys(request, env, userId);
  }

  if (path === '/api/accounts/key-management/key-rotation-data' && method === 'GET') {
    return handleGetKeyRotationData(env, userId);
  }

  // Vaultwarden accepts only V2 account keys (signature key pair and security state) here,
  // and this server stores V1 keys only, so the rotation above is the one it offers.
  if (path === '/api/accounts/key-management/rotate-user-keys' && method === 'POST') {
    return unsupportedResponse('Rotating V2 encryption keys is not supported by this server.');
  }

  if (path === '/api/accounts/security-stamp' && method === 'POST') {
    return handleRotateSecurityStamp(request, env, userId);
  }

  const userPublicKeyMatch = path.match(/^\/api\/users\/([a-f0-9-]+)\/(?:public-key|keys)$/i);
  if (userPublicKeyMatch && method === 'GET') {
    return handleGetUserPublicKey(env, userPublicKeyMatch[1].toLowerCase());
  }

  if (path === '/api/tasks' && method === 'GET') {
    return handleGetTasks();
  }

  if (path === '/api/hibp/breach' && method === 'GET') {
    return handleHibpBreach(request, env);
  }

  if (path === '/api/accounts/revision-date' && method === 'GET') {
    return handleGetRevisionDate(request, env, userId);
  }

  if (path === '/api/accounts/key-management/user-key-id' && method === 'POST') {
    return handleSetUserKeyId(request, env, userId);
  }

  if (path === '/api/accounts/verify-password' && method === 'POST') {
    return handleVerifyPassword(request, env, userId);
  }

  if (path === '/api/accounts/verify-devices' && (method === 'PUT' || method === 'POST')) {
    return handleSetVerifyDevices(request, env, userId);
  }

  if ((path === '/api/accounts/api-key' || path === '/api/accounts/api_key') && method === 'POST') {
    return handleGetApiKey(request, env, userId);
  }

  if ((path === '/api/accounts/rotate-api-key' || path === '/api/accounts/rotate_api_key') && method === 'POST') {
    return handleRotateApiKey(request, env, userId);
  }

  if (path === '/api/webauthn' || path === '/webauthn') {
    if (method === 'GET') return handleGetAccountPasskeyCredentials(request, env, userId);
    if (method === 'POST') return handleCreateAccountPasskeyCredential(request, env, userId);
    if (method === 'PUT') return handleUpdateAccountPasskeyEncryption(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if ((path === '/api/webauthn/attestation-options' || path === '/webauthn/attestation-options') && method === 'POST') {
    return handleGetAccountPasskeyAttestationOptions(request, env, userId, currentUser);
  }

  if ((path === '/api/webauthn/assertion-options' || path === '/webauthn/assertion-options') && method === 'POST') {
    return handleGetAccountPasskeyUpdateAssertionOptions(request, env, userId, currentUser);
  }

  const accountPasskeyDeleteMatch =
    path.match(/^\/api\/webauthn\/([^/]+)\/delete$/i) ||
    path.match(/^\/webauthn\/([^/]+)\/delete$/i);
  if (accountPasskeyDeleteMatch && method === 'POST') {
    return handleDeleteAccountPasskeyCredential(request, env, userId, accountPasskeyDeleteMatch[1], currentUser);
  }

  if (path === '/api/sync' && method === 'GET') {
    return handleSync(request, env, userId);
  }

  if (path.startsWith('/notifications/')) {
    return errorResponse('Not found', 404);
  }

  if (path === '/events/collect' && method === 'POST') {
    return handleCollectEvents(request, env, eventActor(request, userId));
  }

  if (path === '/api/ciphers' || path === '/api/ciphers/create') {
    if (method === 'GET') return handleGetCiphers(request, env, userId);
    if (method === 'POST') return handleCreateCipher(request, env, userId);
    if (path === '/api/ciphers' && method === 'DELETE') return handleBulkPermanentDeleteCiphers(request, env, userId);
    return null;
  }

  // Administrative variants of the bulk routes: access to organization ciphers is checked per
  // cipher, and a member with full access may write them all, so they share the handlers.
  if (path === '/api/ciphers/admin') {
    if (method === 'POST') return handleCreateCipher(request, env, userId, true);
    if (method === 'DELETE') return handleBulkPermanentDeleteCiphers(request, env, userId);
    return null;
  }
  if (path === '/api/ciphers/delete-admin') {
    if (method === 'PUT') return handleBulkDeleteCiphers(request, env, userId);
    if (method === 'POST') return handleBulkPermanentDeleteCiphers(request, env, userId);
    return null;
  }
  if (path === '/api/ciphers/restore-admin' && method === 'PUT') {
    return handleBulkRestoreCiphers(request, env, userId);
  }
  if (path === '/api/ciphers/share' && (method === 'PUT' || method === 'POST')) {
    return handleShareCiphers(request, env, userId);
  }
  if (path === '/api/ciphers/organization-details' && method === 'GET') {
    return handleGetOrganizationCipherDetails(request, env, userId);
  }

  if (path === '/api/ciphers/purge' && method === 'POST') {
    return handlePurgeVault(request, env, userId);
  }

  if (path === '/api/ciphers/import' && method === 'POST') {
    return handleCiphersImport(request, env, userId);
  }

  if (path === '/api/ciphers/delete' && (method === 'PUT' || method === 'POST')) {
    return handleBulkDeleteCiphers(request, env, userId);
  }

  if (path === '/api/ciphers/delete-permanent' && method === 'POST') {
    return handleBulkPermanentDeleteCiphers(request, env, userId);
  }

  if (path === '/api/ciphers/restore' && (method === 'PUT' || method === 'POST')) {
    return handleBulkRestoreCiphers(request, env, userId);
  }

  if (path === '/api/ciphers/archive' && (method === 'PUT' || method === 'POST')) {
    return handleBulkArchiveCiphers(request, env, userId);
  }

  if (path === '/api/ciphers/unarchive' && (method === 'PUT' || method === 'POST')) {
    return handleBulkUnarchiveCiphers(request, env, userId);
  }

  if (path === '/api/ciphers/move' && (method === 'POST' || method === 'PUT')) {
    return handleBulkMoveCiphers(request, env, userId);
  }

  const cipherMatch = path.match(/^\/api\/ciphers\/([a-f0-9-]+)(\/.*)?$/i);
  if (cipherMatch) {
    const cipherId = cipherMatch[1];
    const subPath = cipherMatch[2] || '';

    if (subPath === '' || subPath === '/') {
      if (method === 'GET') return handleGetCipher(request, env, userId, cipherId);
      if (method === 'PUT' || method === 'POST') return handleUpdateCipher(request, env, userId, cipherId);
      if (method === 'DELETE') return handleDeleteCipherCompat(request, env, userId, cipherId);
    }
    if (subPath === '/admin') {
      if (method === 'GET') return handleGetCipher(request, env, userId, cipherId);
      if (method === 'PUT' || method === 'POST') return handleUpdateCipher(request, env, userId, cipherId, true);
      if (method === 'DELETE') return handlePermanentDeleteCipher(request, env, userId, cipherId);
    }
    if (subPath === '/delete-admin' && method === 'PUT') return handleDeleteCipher(request, env, userId, cipherId);
    if (subPath === '/delete-admin' && method === 'POST') return handlePermanentDeleteCipher(request, env, userId, cipherId);
    if (subPath === '/restore-admin' && method === 'PUT') return handleRestoreCipher(request, env, userId, cipherId);
    if ((subPath === '/collections' || subPath === '/collections_v2' || subPath === '/collections-admin') && (method === 'PUT' || method === 'POST')) {
      const variant = subPath === '/collections' ? 'user' : subPath === '/collections_v2' ? 'v2' : 'admin';
      return handleUpdateCipherCollections(request, env, userId, cipherId, variant);
    }

    if (subPath === '/delete' && method === 'PUT') return handleDeleteCipher(request, env, userId, cipherId);
    if (subPath === '/delete' && (method === 'DELETE' || method === 'POST')) return handlePermanentDeleteCipher(request, env, userId, cipherId);
    if (subPath === '/restore' && method === 'PUT') return handleRestoreCipher(request, env, userId, cipherId);
    if (subPath === '/events' && method === 'GET') return handleGetCipherEvents(request, env, userId, cipherId.toLowerCase());
    if (subPath === '/archive' && (method === 'PUT' || method === 'POST')) return handleArchiveCipher(request, env, userId, cipherId);
    if (subPath === '/unarchive' && (method === 'PUT' || method === 'POST')) return handleUnarchiveCipher(request, env, userId, cipherId);
    if (subPath === '/partial' && (method === 'PUT' || method === 'POST')) return handlePartialUpdateCipher(request, env, userId, cipherId);
    if (subPath === '/share' && (method === 'PUT' || method === 'POST')) return handleShareCipher(request, env, userId, cipherId);
    if (subPath === '/details' && method === 'GET') return handleGetCipher(request, env, userId, cipherId);
    if (subPath === '/attachment/v2' && method === 'POST') return handleCreateAttachment(request, env, userId, cipherId);
    if ((subPath === '/attachment' || subPath === '/attachment-admin') && method === 'POST') {
      const multipart = (request.headers.get('content-type') || '').includes('multipart/form-data');
      return multipart
        ? handleLegacyUploadAttachment(request, env, userId, cipherId)
        : handleCreateAttachment(request, env, userId, cipherId);
    }

    const attachmentShareMatch = subPath.match(/^\/attachment\/([a-f0-9-]+)\/share$/i);
    if (attachmentShareMatch && method === 'POST') {
      return handleLegacyUploadAttachment(request, env, userId, cipherId, attachmentShareMatch[1]);
    }

    const attachmentAdminMatch = subPath.match(/^\/attachment\/([a-f0-9-]+)\/(admin|delete-admin)$/i);
    if (attachmentAdminMatch) {
      const attachmentId = attachmentAdminMatch[1];
      if (method === 'GET' && attachmentAdminMatch[2] === 'admin') return handleGetAttachment(request, env, userId, cipherId, attachmentId);
      if (method === 'DELETE' && attachmentAdminMatch[2] === 'admin') return handleDeleteAttachment(request, env, userId, cipherId, attachmentId);
      if (method === 'POST' && attachmentAdminMatch[2] === 'delete-admin') return handleDeleteAttachment(request, env, userId, cipherId, attachmentId);
    }

    const attachmentMatch = subPath.match(/^\/attachment\/([a-f0-9-]+)$/i);
    if (attachmentMatch) {
      const attachmentId = attachmentMatch[1];
      if (method === 'POST' || method === 'PUT') return handleUploadAttachment(request, env, userId, cipherId, attachmentId);
      if (method === 'GET') return handleGetAttachment(request, env, userId, cipherId, attachmentId);
      if (method === 'DELETE') return handleDeleteAttachment(request, env, userId, cipherId, attachmentId);
    }

    const attachmentMetadataMatch = subPath.match(/^\/attachment\/([a-f0-9-]+)\/metadata$/i);
    if (attachmentMetadataMatch && (method === 'POST' || method === 'PUT')) {
      return handleUpdateAttachmentMetadata(request, env, userId, cipherId, attachmentMetadataMatch[1]);
    }

    const attachmentDeleteMatch = subPath.match(/^\/attachment\/([a-f0-9-]+)\/delete$/i);
    if (attachmentDeleteMatch && method === 'POST') {
      return handleDeleteAttachment(request, env, userId, cipherId, attachmentDeleteMatch[1]);
    }
  }

  if (path === '/api/folders') {
    if (method === 'GET') return handleGetFolders(request, env, userId);
    if (method === 'POST') return handleCreateFolder(request, env, userId);
    return null;
  }

  if (path === '/api/folders/delete' && method === 'POST') {
    return handleBulkDeleteFolders(request, env, userId);
  }

  const folderMatch = path.match(/^\/api\/folders\/([a-f0-9-]+)$/i);
  if (folderMatch) {
    const folderId = folderMatch[1];
    if (method === 'GET') return handleGetFolder(request, env, userId, folderId);
    if (method === 'PUT' || method === 'POST') return handleUpdateFolder(request, env, userId, folderId);
    if (method === 'DELETE') return handleDeleteFolder(request, env, userId, folderId);
  }

  const folderDeleteMatch = path.match(/^\/api\/folders\/([a-f0-9-]+)\/delete$/i);
  if (folderDeleteMatch && method === 'POST') {
    return handleDeleteFolder(request, env, userId, folderDeleteMatch[1]);
  }

  if (path === '/api/auth-requests' || path === '/api/auth-requests/' || path === '/auth-requests' || path === '/auth-requests/') {
    if (method === 'GET') return handleListAuthRequests(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if (path === '/api/auth-requests/pending' || path === '/auth-requests/pending') {
    if (method === 'GET') return handleListPendingAuthRequests(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if (path === '/api/auth-requests/admin-request' || path === '/auth-requests/admin-request') {
    if (method === 'POST') return handleCreateAdminAuthRequest(request, env, userId, currentUser.email);
    return errorResponse('Method not allowed', 405);
  }

  const authRequestMatch = path.match(/^\/(?:api\/)?auth-requests\/([a-f0-9-]+)$/i);
  if (authRequestMatch) {
    if (method === 'GET') return handleGetAuthRequest(request, env, userId, authRequestMatch[1]);
    if (method === 'PUT') return handleUpdateAuthRequest(request, env, userId, authRequestMatch[1]);
    return errorResponse('Method not allowed', 405);
  }

  const organizationResponse = await handleOrganizationRoute(request, env, userId, path, method);
  if (organizationResponse) return organizationResponse;

  if (path === '/api/sends') {
    if (method === 'GET') return handleGetSends(request, env, userId);
    if (method === 'POST') return handleCreateSend(request, env, userId);
    return null;
  }

  if (path === '/api/sends/file/v2' && method === 'POST') {
    return handleCreateFileSendV2(request, env, userId);
  }

  if (path === '/api/sends/delete' && method === 'POST') {
    return handleBulkDeleteSends(request, env, userId);
  }

  const sendMatch = path.match(/^\/api\/sends\/([^/]+)(\/.*)?$/i);
  if (sendMatch) {
    const sendId = sendMatch[1];
    const subPath = sendMatch[2] || '';

    if (subPath === '' || subPath === '/') {
      if (method === 'GET') return handleGetSend(request, env, userId, sendId);
      if (method === 'PUT') return handleUpdateSend(request, env, userId, sendId);
      if (method === 'DELETE') return handleDeleteSend(request, env, userId, sendId);
    }

    if (subPath === '/remove-password' && (method === 'PUT' || method === 'POST')) {
      return handleRemoveSendPassword(request, env, userId, sendId);
    }

    if (subPath === '/remove-auth' && (method === 'PUT' || method === 'POST')) {
      return handleRemoveSendAuth(request, env, userId, sendId);
    }

    const sendFileUploadMatch = subPath.match(/^\/file\/([^/]+)\/?$/i);
    if (sendFileUploadMatch) {
      const fileId = sendFileUploadMatch[1];
      if (method === 'GET') return handleGetSendFileUpload(request, env, userId, sendId, fileId);
      if (method === 'POST' || method === 'PUT') return handleUploadSendFile(request, env, userId, sendId, fileId);
    }
  }

  if (path === '/api/policies' || path.startsWith('/api/policies/')) {
    if (method === 'GET') {
      return jsonResponse({ data: [], object: 'list', continuationToken: null });
    }
    return null;
  }

  if (path === '/api/settings/domains' || path === '/settings/domains') {
    if (method === 'GET') return handleGetDomains(env, userId);
    if (method === 'PUT' || method === 'POST') return handleUpdateDomains(request, env, userId);
    return null;
  }

  const emergencyAccessResponse = await handleEmergencyAccessRoute(request, env, currentUser, path, method);
  if (emergencyAccessResponse) return emergencyAccessResponse;

  const authenticatedDeviceResponse = await handleAuthenticatedDeviceRoute(request, env, userId, path, method);
  if (authenticatedDeviceResponse) return authenticatedDeviceResponse;

  const adminResponse = await handleAdminRoute(request, env, currentUser, path, method);
  if (adminResponse) return adminResponse;

  return null;
}
