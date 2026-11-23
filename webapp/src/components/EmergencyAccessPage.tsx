import type { ComponentChildren } from 'preact';
import { useState } from 'preact/hooks';
import { useQuery } from '@tanstack/react-query';
import { Check, Eye, Plus, RefreshCw, Trash2, UserCheck, X } from 'lucide-preact';
import LoadingState from '@/components/LoadingState';
import type { AuthedFetch } from '@/lib/api/shared';
import {
  EmergencyStatus,
  EmergencyType,
  acceptAccess,
  approveRecovery,
  confirmAccess,
  deleteAccess,
  initiateRecovery,
  inviteContact,
  listGranted,
  listTrusted,
  rejectRecovery,
  viewGrantorVault,
  type EmergencyAccessEntry,
} from '@/lib/api/emergency-access';
import { getUserPublicKey } from '@/lib/api/organizations';
import { decryptBw } from '@/lib/crypto';
import { t } from '@/lib/i18n';
import { decryptText, importUserPrivateKey, sessionUserKey, unwrapKey, wrapKeyForPublicKey } from '@/lib/org-crypto';
import type { Profile, SessionState } from '@/lib/types';

export interface EmergencyAccessPageProps {
  profile: Profile | null;
  session: SessionState | null;
  authedFetch: AuthedFetch;
  onNotify: (type: 'success' | 'error' | 'warning', text: string) => void;
}

const typeLabel = (type: number) => (type === EmergencyType.Takeover ? t('txt_ea_type_takeover') : t('txt_ea_type_view'));

const STATUS_LABELS: Record<number, string> = {
  [EmergencyStatus.Invited]: 'txt_org_status_invited',
  [EmergencyStatus.Accepted]: 'txt_org_status_accepted',
  [EmergencyStatus.Confirmed]: 'txt_org_status_confirmed',
  [EmergencyStatus.RecoveryInitiated]: 'txt_ea_status_recovery_initiated',
  [EmergencyStatus.RecoveryApproved]: 'txt_ea_status_recovery_approved',
};

const statusLabel = (status: number) => t(STATUS_LABELS[status] ?? 'txt_dash');

export default function EmergencyAccessPage(props: EmergencyAccessPageProps) {
  const { authedFetch, onNotify } = props;
  const [busy, setBusy] = useState(false);
  const [email, setEmail] = useState('');
  const [type, setType] = useState<number>(EmergencyType.View);
  const [waitDays, setWaitDays] = useState(7);
  const [viewed, setViewed] = useState<{ email: string; names: string[] } | null>(null);

  const trustedQuery = useQuery({ queryKey: ['ea-trusted', props.profile?.id], queryFn: () => listTrusted(authedFetch), enabled: !!props.profile?.id });
  const grantedQuery = useQuery({ queryKey: ['ea-granted', props.profile?.id], queryFn: () => listGranted(authedFetch), enabled: !!props.profile?.id });
  const refetch = () => Promise.all([trustedQuery.refetch(), grantedQuery.refetch()]);

  async function run(action: () => Promise<unknown>, success: string): Promise<boolean> {
    setBusy(true);
    try {
      await action();
      await refetch();
      if (success) onNotify('success', success);
      return true;
    } catch (error) {
      onNotify('error', error instanceof Error ? error.message : String(error));
      return false;
    } finally {
      setBusy(false);
    }
  }

  // Confirming gives the contact the user key, wrapped with their public key.
  const confirm = (entry: EmergencyAccessEntry) =>
    run(async () => {
      const publicKey = await getUserPublicKey(authedFetch, entry.granteeId || '');
      await confirmAccess(authedFetch, entry.id, await wrapKeyForPublicKey(sessionUserKey(props.session), publicKey));
    }, t('txt_ea_confirmed'));

  // An approved view recovery returns the grantor's items and their user key wrapped for the caller.
  const view = (entry: EmergencyAccessEntry) =>
    run(async () => {
      if (!props.profile?.privateKey) throw new Error(t('txt_vault_key_unavailable'));
      const privateKey = await importUserPrivateKey(props.profile.privateKey, sessionUserKey(props.session));
      const result = await viewGrantorVault(authedFetch, entry.id);
      const grantorKey = await unwrapKey(result.keyEncrypted, privateKey);
      const names = await Promise.all(
        result.ciphers.map(async (cipher) => {
          let key = grantorKey;
          if (cipher.key) {
            const itemKey = await decryptBw(cipher.key, grantorKey.enc, grantorKey.mac).catch(() => null);
            if (itemKey && itemKey.length >= 64) key = { enc: itemKey.slice(0, 32), mac: itemKey.slice(32, 64) };
          }
          return (await decryptText(cipher.name, key)) || t('txt_org_undecryptable');
        })
      );
      setViewed({ email: entry.email, names });
    }, '');

  const removeButton = (entry: EmergencyAccessEntry) => (
    <button
      type="button"
      className="btn btn-danger"
      disabled={busy}
      onClick={() => {
        if (!window.confirm(t('txt_ea_remove_confirm', { email: entry.email }))) return;
        void run(() => deleteAccess(authedFetch, entry.id), t('txt_ea_removed'));
      }}
    >
      <Trash2 size={14} className="btn-icon" /> {t('txt_remove')}
    </button>
  );

  const table = (entries: EmergencyAccessEntry[] | undefined, loading: boolean, actions: (entry: EmergencyAccessEntry) => ComponentChildren) => (
    <table className="table">
      <thead>
        <tr>
          <th>{t('txt_email')}</th>
          <th>{t('txt_type')}</th>
          <th>{t('txt_status')}</th>
          <th>{t('txt_ea_wait_days')}</th>
          <th>{t('txt_actions')}</th>
        </tr>
      </thead>
      <tbody>
        {(entries ?? []).map((entry) => (
          <tr key={entry.id}>
            <td data-label={t('txt_email')}>{entry.email}</td>
            <td data-label={t('txt_type')}>{typeLabel(entry.type)}</td>
            <td data-label={t('txt_status')}>{statusLabel(entry.status)}</td>
            <td data-label={t('txt_ea_wait_days')}>{entry.waitTimeDays}</td>
            <td data-label={t('txt_actions')}>
              <div className="actions">{actions(entry)}</div>
            </td>
          </tr>
        ))}
        {loading && !entries && (
          <tr>
            <td colSpan={5}>
              <LoadingState lines={2} compact />
            </td>
          </tr>
        )}
        {!loading && !entries?.length && (
          <tr>
            <td colSpan={5}>
              <div className="empty empty-comfortable">{t('txt_org_none')}</div>
            </td>
          </tr>
        )}
      </tbody>
    </table>
  );

  return (
    <div className="stack">
      <section className="card">
        <div className="section-head">
          <h3>{t('txt_ea_trusted')}</h3>
          <button type="button" className="btn btn-secondary small" disabled={busy} onClick={() => void refetch()}>
            <RefreshCw size={14} className="btn-icon" /> {t('txt_refresh')}
          </button>
        </div>
        <p className="muted-inline">{t('txt_ea_trusted_hint')}</p>
        <form
          className="field-grid"
          onSubmit={(event) => {
            event.preventDefault();
            void run(() => inviteContact(authedFetch, email.trim().toLowerCase(), type, waitDays), t('txt_ea_invited')).then((ok) => ok && setEmail(''));
          }}
        >
          <label className="field">
            <span>{t('txt_email')}</span>
            <input className="input" type="email" required value={email} onInput={(event) => setEmail((event.currentTarget as HTMLInputElement).value)} />
          </label>
          <label className="field">
            <span>{t('txt_type')}</span>
            <select className="input" value={type} onInput={(event) => setType(Number((event.currentTarget as HTMLSelectElement).value))}>
              <option value={EmergencyType.View}>{typeLabel(EmergencyType.View)}</option>
              <option value={EmergencyType.Takeover}>{typeLabel(EmergencyType.Takeover)}</option>
            </select>
          </label>
          <label className="field">
            <span>{t('txt_ea_wait_days')}</span>
            <input
              className="input"
              type="number"
              min={1}
              max={90}
              value={waitDays}
              onInput={(event) => setWaitDays(Math.min(90, Math.max(1, Math.round(Number((event.currentTarget as HTMLInputElement).value) || 1))))}
            />
          </label>
          <div className="actions field-span-2">
            <button type="submit" className="btn btn-primary" disabled={busy || !email.trim()}>
              <Plus size={14} className="btn-icon" /> {t('txt_ea_add_contact')}
            </button>
          </div>
        </form>
        {table(trustedQuery.data, trustedQuery.isLoading, (entry) => (
          <>
            {entry.status === EmergencyStatus.Accepted && (
              <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void confirm(entry)}>
                <UserCheck size={14} className="btn-icon" /> {t('txt_confirm')}
              </button>
            )}
            {entry.status === EmergencyStatus.RecoveryInitiated && (
              <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void run(() => approveRecovery(authedFetch, entry.id), t('txt_ea_approved'))}>
                <Check size={14} className="btn-icon" /> {t('txt_approve')}
              </button>
            )}
            {(entry.status === EmergencyStatus.RecoveryInitiated || entry.status === EmergencyStatus.RecoveryApproved) && (
              <button type="button" className="btn btn-secondary" disabled={busy} onClick={() => void run(() => rejectRecovery(authedFetch, entry.id), t('txt_ea_rejected'))}>
                <X size={14} className="btn-icon" /> {t('txt_ea_reject')}
              </button>
            )}
            {removeButton(entry)}
          </>
        ))}
      </section>

      <section className="card">
        <div className="section-head">
          <h3>{t('txt_ea_granted')}</h3>
        </div>
        <p className="muted-inline">{t('txt_ea_granted_hint')}</p>
        {table(grantedQuery.data, grantedQuery.isLoading, (entry) => (
          <>
            {entry.status === EmergencyStatus.Invited && (
              <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void run(() => acceptAccess(authedFetch, entry.id), t('txt_ea_accepted'))}>
                <Check size={14} className="btn-icon" /> {t('txt_org_accept')}
              </button>
            )}
            {entry.status === EmergencyStatus.Confirmed && (
              <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void run(() => initiateRecovery(authedFetch, entry.id), t('txt_ea_initiated'))}>
                {t('txt_ea_request_access')}
              </button>
            )}
            {entry.status === EmergencyStatus.RecoveryApproved && entry.type === EmergencyType.View && (
              <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void view(entry)}>
                <Eye size={14} className="btn-icon" /> {t('txt_view')}
              </button>
            )}
            {removeButton(entry)}
          </>
        ))}
        {viewed && (
          <div className="stack">
            <div className="section-head">
              <h3>{t('txt_ea_viewing', { email: viewed.email })}</h3>
              <button type="button" className="btn btn-secondary small" onClick={() => setViewed(null)}>
                {t('txt_close')}
              </button>
            </div>
            <ul className="ea-view-list">
              {viewed.names.map((name, index) => (
                <li key={index}>{name}</li>
              ))}
              {!viewed.names.length && <li>{t('txt_no_items')}</li>}
            </ul>
          </div>
        )}
        <p className="muted-inline">{t('txt_ea_takeover_hint')}</p>
      </section>
    </div>
  );
}
