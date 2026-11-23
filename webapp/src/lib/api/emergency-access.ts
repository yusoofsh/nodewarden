import { t } from '../i18n';
import { parseErrorMessage, parseJson, type AuthedFetch } from './shared';

export const EmergencyType = { View: 0, Takeover: 1 } as const;
export const EmergencyStatus = { Invited: 0, Accepted: 1, Confirmed: 2, RecoveryInitiated: 3, RecoveryApproved: 4 } as const;

export interface EmergencyAccessEntry {
  id: string;
  status: number;
  type: number;
  waitTimeDays: number;
  email: string;
  name: string | null;
  /** Set on trusted entries: the contact who would gain access. */
  granteeId?: string;
  /** Set on granted entries: the account that granted access. */
  grantorId?: string;
}

async function post(authedFetch: AuthedFetch, path: string, body?: unknown): Promise<Response> {
  const resp = await authedFetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, `POST ${path} failed (${resp.status})`));
  return resp;
}

async function list(authedFetch: AuthedFetch, path: string): Promise<EmergencyAccessEntry[]> {
  const resp = await authedFetch(path);
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, `GET ${path} failed (${resp.status})`));
  return (await parseJson<{ data?: EmergencyAccessEntry[] }>(resp))?.data ?? [];
}

const item = (id: string, action: string) => `/api/emergency-access/${encodeURIComponent(id)}/${action}`;

/** Contacts the caller trusts: the caller is the grantor. */
export const listTrusted = (authedFetch: AuthedFetch) => list(authedFetch, '/api/emergency-access/trusted');
/** Accounts that trust the caller: the caller is the grantee. */
export const listGranted = (authedFetch: AuthedFetch) => list(authedFetch, '/api/emergency-access/granted');

export const inviteContact = (authedFetch: AuthedFetch, email: string, type: number, waitTimeDays: number) =>
  post(authedFetch, '/api/emergency-access/invite', { email, type, waitTimeDays });

export const acceptAccess = (authedFetch: AuthedFetch, id: string) => post(authedFetch, item(id, 'accept'));
export const confirmAccess = (authedFetch: AuthedFetch, id: string, key: string) => post(authedFetch, item(id, 'confirm'), { key });
export const initiateRecovery = (authedFetch: AuthedFetch, id: string) => post(authedFetch, item(id, 'initiate'));
export const approveRecovery = (authedFetch: AuthedFetch, id: string) => post(authedFetch, item(id, 'approve'));
export const rejectRecovery = (authedFetch: AuthedFetch, id: string) => post(authedFetch, item(id, 'reject'));
export const deleteAccess = (authedFetch: AuthedFetch, id: string) => post(authedFetch, item(id, 'delete'));

/** The grantor's ciphers and their user key wrapped for the caller, once a view recovery is approved. */
export async function viewGrantorVault(authedFetch: AuthedFetch, id: string): Promise<{ ciphers: Array<{ id: string; type: number; name?: string | null; key?: string | null }>; keyEncrypted: string }> {
  const body = await parseJson<{ ciphers?: Array<{ id: string; type: number; name?: string | null; key?: string | null }>; keyEncrypted?: string }>(
    await post(authedFetch, item(id, 'view'))
  );
  if (!body?.keyEncrypted) throw new Error(t('txt_vault_key_unavailable'));
  return { ciphers: body.ciphers ?? [], keyEncrypted: body.keyEncrypted };
}
