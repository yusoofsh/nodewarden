import { useMemo, useState } from 'preact/hooks';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Check, LogOut, Pencil, Plus, RefreshCw, Trash2, UserCheck, UserPlus } from 'lucide-preact';
import LoadingState from '@/components/LoadingState';
import type { AuthedFetch } from '@/lib/api/shared';
import {
  MemberStatus,
  OrgRole,
  acceptInvitation,
  confirmMember,
  createOrganization,
  deleteCollection,
  deleteGroup,
  deleteOrganization,
  getGroupMemberIds,
  getMemberPublicKey,
  getOrganization,
  getUserPublicKey,
  inviteMember,
  leaveOrganization,
  listCollectionDetails,
  listGroups,
  listInvitations,
  listMembers,
  listMyCollections,
  listOrganizationCiphers,
  listPolicies,
  removeMember,
  saveCollection,
  saveGroup,
  setPolicy,
  updateMember,
  updateOrganization,
  type CollectionAccessEntry,
  type OrganizationMember,
  type ProfileOrganization,
} from '@/lib/api/organizations';
import { t } from '@/lib/i18n';
import {
  createOrganizationKeys,
  decryptText,
  encryptText,
  importUserPrivateKey,
  sessionUserKey,
  unwrapKey,
  wrapKeyForPublicKey,
  type SymmetricKey,
} from '@/lib/org-crypto';
import { decryptBw } from '@/lib/crypto';
import type { Profile, SessionState } from '@/lib/types';

export interface OrganizationsPageProps {
  profile: Profile | null;
  session: SessionState | null;
  authedFetch: AuthedFetch;
  onNotify: (type: 'success' | 'error' | 'warning', text: string) => void;
  deriveMasterPasswordHash: (masterPassword: string) => Promise<string>;
}

type Tab = 'members' | 'collections' | 'groups' | 'policies' | 'items' | 'settings';

const roleLabel = (type: number) =>
  type === OrgRole.Owner ? t('txt_org_role_owner') : type === OrgRole.Admin ? t('txt_role_admin') : t('txt_role_user');

const statusLabel = (status: number) =>
  status === MemberStatus.Invited
    ? t('txt_org_status_invited')
    : status === MemberStatus.Accepted
      ? t('txt_org_status_accepted')
      : status === MemberStatus.Confirmed
        ? t('txt_org_status_confirmed')
        : t('txt_org_status_revoked');

// Policies that take no settings. The ones with settings (master password, generator, Send
// options and the like) are left to the official clients.
const POLICY_TYPES: Array<{ type: number; label: string }> = [
  { type: 0, label: 'txt_org_policy_two_step' },
  { type: 3, label: 'txt_org_policy_single_org' },
  { type: 5, label: 'txt_org_policy_personal_ownership' },
  { type: 6, label: 'txt_org_policy_disable_send' },
  { type: 14, label: 'txt_org_policy_remove_pin' },
];

const fullAccess = (id: string): CollectionAccessEntry => ({ id, readOnly: false, hidePasswords: false, manage: false });

function readValue(event: Event): string {
  return (event.currentTarget as HTMLInputElement).value;
}

/** Checkboxes over a list of ids; `selected` is the set of checked ids. */
function CheckList(props: { options: Array<{ id: string; label: string }>; selected: Set<string>; onChange: (next: Set<string>) => void }) {
  if (!props.options.length) return <div className="muted-inline">{t('txt_org_none')}</div>;
  return (
    <div className="org-check-list">
      {props.options.map((option) => (
        <label key={option.id} className="checkbox-inline">
          <input
            type="checkbox"
            checked={props.selected.has(option.id)}
            onInput={(event) => {
              const next = new Set(props.selected);
              if ((event.currentTarget as HTMLInputElement).checked) next.add(option.id);
              else next.delete(option.id);
              props.onChange(next);
            }}
          />
          <span>{option.label}</span>
        </label>
      ))}
    </div>
  );
}

export default function OrganizationsPage(props: OrganizationsPageProps) {
  const { authedFetch, onNotify } = props;
  const queryClient = useQueryClient();
  const organizations = ((props.profile?.organizationsNew as ProfileOrganization[] | undefined) ?? []).slice().sort((a, b) => a.name.localeCompare(b.name));
  const [selectedId, setSelectedId] = useState('');
  const [busy, setBusy] = useState(false);
  const [createName, setCreateName] = useState('');
  const [createEmail, setCreateEmail] = useState('');
  const [createCollection, setCreateCollection] = useState('');

  const privateKey = useMemo(() => {
    if (!props.profile?.privateKey || !props.session?.symEncKey) return null;
    return importUserPrivateKey(props.profile.privateKey, sessionUserKey(props.session));
  }, [props.profile?.privateKey, props.session?.symEncKey, props.session?.symMacKey]);

  const invitationsQuery = useQuery({
    queryKey: ['org-invitations', props.profile?.id],
    queryFn: () => listInvitations(authedFetch),
    enabled: !!props.profile?.id,
  });

  const selected = organizations.find((org) => org.id === selectedId) ?? null;

  async function run(action: () => Promise<unknown>, success: string): Promise<boolean> {
    setBusy(true);
    try {
      await action();
      onNotify('success', success);
      return true;
    } catch (error) {
      onNotify('error', error instanceof Error ? error.message : String(error));
      return false;
    } finally {
      setBusy(false);
    }
  }

  const refreshProfile = () => queryClient.invalidateQueries({ queryKey: ['profile'] });

  async function handleCreate(event: Event) {
    event.preventDefault();
    const profile = props.profile;
    if (!profile) return;
    const ok = await run(async () => {
      const keys = await createOrganizationKeys(await getUserPublicKey(authedFetch, profile.id));
      await createOrganization(authedFetch, {
        name: createName.trim(),
        billingEmail: (createEmail.trim() || profile.email).toLowerCase(),
        collectionName: await encryptText(createCollection.trim() || t('txt_org_default_collection'), keys.orgKey),
        key: keys.wrappedForCreator,
        keys: { publicKey: keys.publicKey, encryptedPrivateKey: keys.encryptedPrivateKey },
      });
      await refreshProfile();
    }, t('txt_org_created'));
    if (ok) {
      setCreateName('');
      setCreateCollection('');
    }
  }

  async function handleAccept(orgId: string, memberId: string) {
    await run(async () => {
      await acceptInvitation(authedFetch, orgId, memberId);
      await Promise.all([refreshProfile(), invitationsQuery.refetch()]);
    }, t('txt_org_invitation_accepted'));
  }

  return (
    <div className="stack">
      <section className="card">
        <div className="section-head">
          <h3>{t('nav_organizations')}</h3>
          <button type="button" className="btn btn-secondary small" disabled={busy} onClick={() =>
              void Promise.all([
                refreshProfile(),
                invitationsQuery.refetch(),
                queryClient.invalidateQueries({ predicate: (query) => ['org-members', 'org-collections', 'org-groups', 'org-policies', 'org-items'].includes(String(query.queryKey[0])) }),
              ])
            }
          >
            <RefreshCw size={14} className="btn-icon" /> {t('txt_refresh')}
          </button>
        </div>
        <table className="table">
          <thead>
            <tr>
              <th>{t('txt_name')}</th>
              <th>{t('txt_role')}</th>
              <th>{t('txt_status')}</th>
              <th>{t('txt_actions')}</th>
            </tr>
          </thead>
          <tbody>
            {organizations.map((org) => (
              <tr key={org.id} className={org.id === selectedId ? 'org-row-selected' : ''}>
                <td data-label={t('txt_name')}>{org.name}</td>
                <td data-label={t('txt_role')}>{roleLabel(org.type)}</td>
                <td data-label={t('txt_status')}>{statusLabel(org.status)}</td>
                <td data-label={t('txt_actions')}>
                  <div className="actions">
                    <button type="button" className="btn btn-secondary" disabled={org.status !== MemberStatus.Confirmed} onClick={() => setSelectedId(org.id)}>
                      {t('txt_org_open')}
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {!organizations.length && (
              <tr>
                <td colSpan={4}>
                  <div className="empty empty-comfortable">{t('txt_org_none_yet')}</div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
        {organizations.some((org) => org.status === MemberStatus.Accepted) && <p className="muted-inline">{t('txt_org_awaiting_confirmation_hint')}</p>}
      </section>

      {!!invitationsQuery.data?.length && (
        <section className="card">
          <div className="section-head">
            <h3>{t('txt_org_pending_invitations')}</h3>
          </div>
          <table className="table">
            <tbody>
              {invitationsQuery.data.map((invite) => (
                <tr key={invite.id}>
                  <td data-label={t('txt_name')}>{invite.organizationName}</td>
                  <td data-label={t('txt_role')}>{roleLabel(invite.type)}</td>
                  <td data-label={t('txt_actions')}>
                    <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void handleAccept(invite.organizationId, invite.id)}>
                      <Check size={14} className="btn-icon" /> {t('txt_org_accept')}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      <section className="card">
        <div className="section-head">
          <h3>{t('txt_org_create')}</h3>
        </div>
        <form className="field-grid" onSubmit={(event) => void handleCreate(event)}>
          <label className="field">
            <span>{t('txt_org_name')}</span>
            <input className="input" required value={createName} onInput={(event) => setCreateName(readValue(event))} />
          </label>
          <label className="field">
            <span>{t('txt_org_billing_email')}</span>
            <input className="input" type="email" placeholder={props.profile?.email} value={createEmail} onInput={(event) => setCreateEmail(readValue(event))} />
          </label>
          <label className="field">
            <span>{t('txt_org_first_collection')}</span>
            <input className="input" placeholder={t('txt_org_default_collection')} value={createCollection} onInput={(event) => setCreateCollection(readValue(event))} />
          </label>
          <div className="actions field-span-2">
            <button type="submit" className="btn btn-primary" disabled={busy || !createName.trim()}>
              <Plus size={14} className="btn-icon" /> {t('txt_create')}
            </button>
          </div>
        </form>
      </section>

      {selected && privateKey && (
        <OrganizationDetail
          key={selected.id}
          org={selected}
          privateKey={privateKey}
          busy={busy}
          run={run}
          onClosed={() => {
            setSelectedId('');
            void refreshProfile();
          }}
          {...props}
        />
      )}
    </div>
  );
}

interface DetailProps extends OrganizationsPageProps {
  org: ProfileOrganization;
  privateKey: Promise<CryptoKey>;
  busy: boolean;
  run: (action: () => Promise<unknown>, success: string) => Promise<boolean>;
  onClosed: () => void;
}

function OrganizationDetail(props: DetailProps) {
  const { authedFetch, org, run, busy } = props;
  const isAdmin = org.type === OrgRole.Owner || org.type === OrgRole.Admin;
  const isOwner = org.type === OrgRole.Owner;
  const [tab, setTab] = useState<Tab>(isAdmin ? 'members' : 'collections');

  const keyQuery = useQuery({
    queryKey: ['org-key', org.id, org.key],
    queryFn: async () => unwrapKey(org.key || '', await props.privateKey),
    enabled: !!org.key,
    staleTime: Infinity,
  });
  const orgKey = keyQuery.data ?? null;

  const membersQuery = useQuery({ queryKey: ['org-members', org.id], queryFn: () => listMembers(authedFetch, org.id), enabled: isAdmin });
  // Admins get every collection with its access; other members only the ones assigned to them.
  const collectionsQuery = useQuery({
    queryKey: ['org-collections', org.id, !!orgKey],
    queryFn: async (): Promise<DecryptedCollection[]> => {
      const rows = isAdmin
        ? await listCollectionDetails(authedFetch, org.id)
        : (await listMyCollections(authedFetch)).filter((c) => c.organizationId === org.id).map((c) => ({ ...c, users: [], groups: [] }));
      return Promise.all(rows.map(async (row) => ({ ...row, decName: orgKey ? await decryptText(row.name, orgKey) : '' })));
    },
    enabled: !!orgKey,
  });
  const groupsQuery = useQuery({ queryKey: ['org-groups', org.id], queryFn: () => listGroups(authedFetch, org.id), enabled: isAdmin });

  const members = membersQuery.data ?? [];
  const collections = collectionsQuery.data ?? [];
  const groups = groupsQuery.data ?? [];
  const refetchAll = () => Promise.all([collectionsQuery.refetch(), ...(isAdmin ? [membersQuery.refetch(), groupsQuery.refetch()] : [])]);

  const tabs: Array<{ id: Tab; label: string }> = isAdmin
    ? [
        { id: 'members', label: t('txt_org_members') },
        { id: 'collections', label: t('txt_org_collections') },
        { id: 'groups', label: t('txt_org_groups') },
        { id: 'policies', label: t('txt_org_policies') },
        { id: 'items', label: t('txt_org_items') },
        { id: 'settings', label: t('txt_settings') },
      ]
    : [
        { id: 'collections', label: t('txt_org_collections') },
        { id: 'settings', label: t('txt_settings') },
      ];

  return (
    <section className="card">
      <div className="section-head">
        <h3>{org.name}</h3>
        <span className="muted-inline">{roleLabel(org.type)}</span>
      </div>
      {keyQuery.isError && <div className="local-error">{t('txt_org_key_unavailable')}</div>}
      <nav className="settings-category-tabs org-tabs" aria-label={org.name}>
        {tabs.map((entry) => (
          <button key={entry.id} type="button" className={`settings-category-tab ${tab === entry.id ? 'active' : ''}`} onClick={() => setTab(entry.id)}>
            {entry.label}
          </button>
        ))}
      </nav>
      {(membersQuery.isLoading || collectionsQuery.isLoading) && isAdmin && <LoadingState lines={3} compact />}
      {tab === 'members' && orgKey && (
        <MembersTab {...props} orgKey={orgKey} isOwner={isOwner} members={members} collections={collections} onChanged={refetchAll} busy={busy} />
      )}
      {tab === 'collections' && orgKey && <CollectionsTab {...props} orgKey={orgKey} isAdmin={isAdmin} collections={collections} onChanged={refetchAll} />}
      {tab === 'groups' && <GroupsTab {...props} groups={groups} members={members} collections={collections} onChanged={refetchAll} />}
      {tab === 'policies' && <PoliciesTab {...props} />}
      {tab === 'items' && orgKey && <ItemsTab {...props} orgKey={orgKey} collections={collections} />}
      {tab === 'settings' && <SettingsTab {...props} isOwner={isOwner} run={run} />}
    </section>
  );
}

type DecryptedCollection = Awaited<ReturnType<typeof listCollectionDetails>>[number] & { decName: string };

function MembersTab(
  props: DetailProps & { orgKey: SymmetricKey; isOwner: boolean; members: OrganizationMember[]; collections: DecryptedCollection[]; onChanged: () => Promise<unknown> }
) {
  const { authedFetch, org, run, busy } = props;
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<number>(OrgRole.User);
  const [inviteCollections, setInviteCollections] = useState<Set<string>>(new Set());
  const [editingId, setEditingId] = useState('');
  const [editRole, setEditRole] = useState<number>(OrgRole.User);
  const [editCollections, setEditCollections] = useState<Set<string>>(new Set());
  const collectionOptions = props.collections.map((c) => ({ id: c.id, label: c.decName || c.id }));
  const roleOptions = [OrgRole.User, OrgRole.Admin, ...(props.isOwner ? [OrgRole.Owner] : [])];

  const roleSelect = (value: number, onChange: (next: number) => void) => (
    <select className="input" value={value} onInput={(event) => onChange(Number(readValue(event)))}>
      {roleOptions.map((option) => (
        <option key={option} value={option}>
          {roleLabel(option)}
        </option>
      ))}
    </select>
  );

  async function handleInvite(event: Event) {
    event.preventDefault();
    const ok = await run(async () => {
      await inviteMember(authedFetch, org.id, email.trim().toLowerCase(), role, role === OrgRole.User ? [...inviteCollections].map(fullAccess) : []);
      await props.onChanged();
    }, t('txt_org_member_invited'));
    if (ok) {
      setEmail('');
      setInviteCollections(new Set());
    }
  }

  async function handleConfirm(member: OrganizationMember) {
    await run(async () => {
      const publicKey = await getMemberPublicKey(authedFetch, org.id, member.id);
      await confirmMember(authedFetch, org.id, member.id, await wrapKeyForPublicKey(props.orgKey, publicKey));
      await props.onChanged();
    }, t('txt_org_member_confirmed'));
  }

  async function handleSaveMember(member: OrganizationMember) {
    const ok = await run(async () => {
      // The update replaces collection access, so the current entries are sent back with the edit.
      const kept = new Map(member.collections.map((c) => [c.id, c]));
      const access = editRole === OrgRole.User ? [...editCollections].map((id) => kept.get(id) ?? fullAccess(id)) : [];
      await updateMember(authedFetch, org.id, member.id, editRole, access);
      await props.onChanged();
    }, t('txt_org_member_updated'));
    if (ok) setEditingId('');
  }

  return (
    <div className="stack">
      <form className="field-grid" onSubmit={(event) => void handleInvite(event)}>
        <label className="field">
          <span>{t('txt_email')}</span>
          <input className="input" type="email" required value={email} onInput={(event) => setEmail(readValue(event))} />
        </label>
        <label className="field">
          <span>{t('txt_role')}</span>
          {roleSelect(role, setRole)}
        </label>
        {role === OrgRole.User && (
          <div className="field field-span-2">
            <span>{t('txt_org_collections')}</span>
            <CheckList options={collectionOptions} selected={inviteCollections} onChange={setInviteCollections} />
          </div>
        )}
        <div className="actions field-span-2">
          <button type="submit" className="btn btn-primary" disabled={busy || !email.trim()}>
            <UserPlus size={14} className="btn-icon" /> {t('txt_org_invite_member')}
          </button>
        </div>
      </form>
      <p className="muted-inline">{t('txt_org_invite_hint')}</p>
      <table className="table">
        <thead>
          <tr>
            <th>{t('txt_email')}</th>
            <th>{t('txt_role')}</th>
            <th>{t('txt_status')}</th>
            <th>{t('txt_actions')}</th>
          </tr>
        </thead>
        <tbody>
          {props.members.map((member) => (
            <tr key={member.id}>
              <td data-label={t('txt_email')}>
                {member.email}
                {member.name ? <div className="muted-inline">{member.name}</div> : null}
              </td>
              <td data-label={t('txt_role')}>
                {editingId === member.id ? (
                  <div className="stack">
                    {roleSelect(editRole, setEditRole)}
                    {editRole === OrgRole.User && <CheckList options={collectionOptions} selected={editCollections} onChange={setEditCollections} />}
                  </div>
                ) : (
                  roleLabel(member.type)
                )}
              </td>
              <td data-label={t('txt_status')}>{statusLabel(member.status)}</td>
              <td data-label={t('txt_actions')}>
                <div className="actions">
                  {member.status === MemberStatus.Accepted && (
                    <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void handleConfirm(member)}>
                      <UserCheck size={14} className="btn-icon" /> {t('txt_confirm')}
                    </button>
                  )}
                  {editingId === member.id ? (
                    <>
                      <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void handleSaveMember(member)}>
                        {t('txt_save')}
                      </button>
                      <button type="button" className="btn btn-secondary" onClick={() => setEditingId('')}>
                        {t('txt_cancel')}
                      </button>
                    </>
                  ) : (
                    <button
                      type="button"
                      className="btn btn-secondary"
                      disabled={member.id === org.organizationUserId}
                      onClick={() => {
                        setEditingId(member.id);
                        setEditRole(member.type);
                        setEditCollections(new Set(member.collections.map((c) => c.id)));
                      }}
                    >
                      <Pencil size={14} className="btn-icon" /> {t('txt_edit')}
                    </button>
                  )}
                  <button
                    type="button"
                    className="btn btn-danger"
                    disabled={busy || member.id === org.organizationUserId}
                    onClick={() => {
                      if (!window.confirm(t('txt_org_remove_member_confirm', { email: member.email }))) return;
                      void run(async () => {
                        await removeMember(authedFetch, org.id, member.id);
                        await props.onChanged();
                      }, t('txt_org_member_removed'));
                    }}
                  >
                    <Trash2 size={14} className="btn-icon" /> {t('txt_remove')}
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CollectionsTab(props: DetailProps & { orgKey: SymmetricKey; isAdmin: boolean; collections: DecryptedCollection[]; onChanged: () => Promise<unknown> }) {
  const { authedFetch, org, run, busy } = props;
  const [newName, setNewName] = useState('');
  const [editingId, setEditingId] = useState('');
  const [editName, setEditName] = useState('');

  async function handleCreate(event: Event) {
    event.preventDefault();
    const ok = await run(async () => {
      await saveCollection(authedFetch, org.id, null, { name: await encryptText(newName.trim(), props.orgKey), users: [], groups: [] });
      await props.onChanged();
    }, t('txt_org_collection_saved'));
    if (ok) setNewName('');
  }

  async function handleRename(collection: DecryptedCollection) {
    const ok = await run(async () => {
      // The update replaces the collection's access, so its current members and groups are sent back.
      await saveCollection(authedFetch, org.id, collection.id, {
        name: await encryptText(editName.trim(), props.orgKey),
        users: collection.users,
        groups: collection.groups,
      });
      await props.onChanged();
    }, t('txt_org_collection_saved'));
    if (ok) setEditingId('');
  }

  return (
    <div className="stack">
      {props.isAdmin && <form className="actions" onSubmit={(event) => void handleCreate(event)}>
        <input className="input" required placeholder={t('txt_org_collection_name')} value={newName} onInput={(event) => setNewName(readValue(event))} />
        <button type="submit" className="btn btn-primary" disabled={busy || !newName.trim()}>
          <Plus size={14} className="btn-icon" /> {t('txt_org_add_collection')}
        </button>
      </form>}
      <table className="table">
        <thead>
          <tr>
            <th>{t('txt_name')}</th>
            {props.isAdmin && <th>{t('txt_org_access')}</th>}
            {props.isAdmin && <th>{t('txt_actions')}</th>}
          </tr>
        </thead>
        <tbody>
          {props.collections.map((collection) => (
            <tr key={collection.id}>
              <td data-label={t('txt_name')}>
                {editingId === collection.id ? (
                  <input className="input" value={editName} onInput={(event) => setEditName(readValue(event))} />
                ) : (
                  collection.decName || t('txt_org_undecryptable')
                )}
              </td>
              {props.isAdmin && <td data-label={t('txt_org_access')}>{t('txt_org_access_summary', { users: collection.users.length, groups: collection.groups.length })}</td>}
              {props.isAdmin && <td data-label={t('txt_actions')}>
                <div className="actions">
                  {editingId === collection.id ? (
                    <>
                      <button type="button" className="btn btn-primary" disabled={busy || !editName.trim()} onClick={() => void handleRename(collection)}>
                        {t('txt_save')}
                      </button>
                      <button type="button" className="btn btn-secondary" onClick={() => setEditingId('')}>
                        {t('txt_cancel')}
                      </button>
                    </>
                  ) : (
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={() => {
                        setEditingId(collection.id);
                        setEditName(collection.decName);
                      }}
                    >
                      <Pencil size={14} className="btn-icon" /> {t('txt_edit')}
                    </button>
                  )}
                  <button
                    type="button"
                    className="btn btn-danger"
                    disabled={busy}
                    onClick={() => {
                      if (!window.confirm(t('txt_org_delete_collection_confirm', { name: collection.decName }))) return;
                      void run(async () => {
                        await deleteCollection(authedFetch, org.id, collection.id);
                        await props.onChanged();
                      }, t('txt_org_collection_deleted'));
                    }}
                  >
                    <Trash2 size={14} className="btn-icon" /> {t('txt_delete')}
                  </button>
                </div>
              </td>}
            </tr>
          ))}
          {!props.collections.length && (
            <tr>
              <td colSpan={3}>
                <div className="empty empty-comfortable">{t('txt_org_none')}</div>
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function GroupsTab(
  props: DetailProps & {
    groups: Awaited<ReturnType<typeof listGroups>>;
    members: OrganizationMember[];
    collections: DecryptedCollection[];
    onChanged: () => Promise<unknown>;
  }
) {
  const { authedFetch, org, run, busy } = props;
  // '' is closed, 'new' is a new group, anything else is the id of the group being edited.
  const [editing, setEditing] = useState('');
  const [name, setName] = useState('');
  const [groupCollections, setGroupCollections] = useState<Set<string>>(new Set());
  const [groupMembers, setGroupMembers] = useState<Set<string>>(new Set());
  const editedGroup = props.groups.find((g) => g.id === editing);

  async function open(groupId: string) {
    const group = props.groups.find((g) => g.id === groupId);
    setName(group?.name ?? '');
    setGroupCollections(new Set(group?.collections.map((c) => c.id) ?? []));
    setGroupMembers(new Set(group ? await getGroupMemberIds(authedFetch, org.id, group.id) : []));
    setEditing(groupId || 'new');
  }

  async function handleSave(event: Event) {
    event.preventDefault();
    const ok = await run(async () => {
      const kept = new Map((editedGroup?.collections ?? []).map((c) => [c.id, c]));
      await saveGroup(authedFetch, org.id, editedGroup?.id ?? null, {
        name: name.trim(),
        collections: [...groupCollections].map((id) => kept.get(id) ?? fullAccess(id)),
        users: [...groupMembers],
      });
      await props.onChanged();
    }, t('txt_org_group_saved'));
    if (ok) setEditing('');
  }

  return (
    <div className="stack">
      {editing ? (
        <form className="field-grid" onSubmit={(event) => void handleSave(event)}>
          <label className="field field-span-2">
            <span>{t('txt_name')}</span>
            <input className="input" required value={name} onInput={(event) => setName(readValue(event))} />
          </label>
          <div className="field">
            <span>{t('txt_org_collections')}</span>
            <CheckList options={props.collections.map((c) => ({ id: c.id, label: c.decName || c.id }))} selected={groupCollections} onChange={setGroupCollections} />
          </div>
          <div className="field">
            <span>{t('txt_org_members')}</span>
            <CheckList options={props.members.map((m) => ({ id: m.id, label: m.email }))} selected={groupMembers} onChange={setGroupMembers} />
          </div>
          <div className="actions field-span-2">
            <button type="submit" className="btn btn-primary" disabled={busy || !name.trim()}>
              {t('txt_save')}
            </button>
            <button type="button" className="btn btn-secondary" onClick={() => setEditing('')}>
              {t('txt_cancel')}
            </button>
          </div>
        </form>
      ) : (
        <div className="actions">
          <button type="button" className="btn btn-primary" onClick={() => void open('')}>
            <Plus size={14} className="btn-icon" /> {t('txt_org_add_group')}
          </button>
        </div>
      )}
      <table className="table">
        <thead>
          <tr>
            <th>{t('txt_name')}</th>
            <th>{t('txt_org_collections')}</th>
            <th>{t('txt_actions')}</th>
          </tr>
        </thead>
        <tbody>
          {props.groups.map((group) => (
            <tr key={group.id}>
              <td data-label={t('txt_name')}>{group.name}</td>
              <td data-label={t('txt_org_collections')}>{group.collections.length}</td>
              <td data-label={t('txt_actions')}>
                <div className="actions">
                  <button type="button" className="btn btn-secondary" onClick={() => void open(group.id)}>
                    <Pencil size={14} className="btn-icon" /> {t('txt_edit')}
                  </button>
                  <button
                    type="button"
                    className="btn btn-danger"
                    disabled={busy}
                    onClick={() => {
                      if (!window.confirm(t('txt_org_delete_group_confirm', { name: group.name }))) return;
                      void run(async () => {
                        await deleteGroup(authedFetch, org.id, group.id);
                        await props.onChanged();
                      }, t('txt_org_group_deleted'));
                    }}
                  >
                    <Trash2 size={14} className="btn-icon" /> {t('txt_delete')}
                  </button>
                </div>
              </td>
            </tr>
          ))}
          {!props.groups.length && (
            <tr>
              <td colSpan={3}>
                <div className="empty empty-comfortable">{t('txt_org_none')}</div>
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function PoliciesTab(props: DetailProps) {
  const { authedFetch, org, run, busy } = props;
  const policiesQuery = useQuery({ queryKey: ['org-policies', org.id], queryFn: () => listPolicies(authedFetch, org.id) });
  const stored = new Map((policiesQuery.data ?? []).map((p) => [p.type, p]));

  return (
    <div className="stack">
      <p className="muted-inline">{t('txt_org_policies_hint')}</p>
      <table className="table">
        <tbody>
          {POLICY_TYPES.map((policy) => {
            const current = stored.get(policy.type);
            const enabled = !!current?.enabled;
            return (
              <tr key={policy.type}>
                <td data-label={t('txt_name')}>{t(policy.label)}</td>
                <td data-label={t('txt_status')}>{enabled ? t('txt_enabled') : t('txt_org_disabled')}</td>
                <td data-label={t('txt_actions')}>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    disabled={busy || policiesQuery.isLoading}
                    onClick={() =>
                      void run(async () => {
                        await setPolicy(authedFetch, org.id, policy.type, !enabled, current?.data ?? null);
                        await policiesQuery.refetch();
                      }, t('txt_org_policy_saved'))
                    }
                  >
                    {enabled ? t('txt_org_disable') : t('txt_org_enable')}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// Organization items are shown here read-only. The vault list keeps to personal items, since its
// edit, repair and export paths all assume the user key.
function ItemsTab(props: DetailProps & { orgKey: SymmetricKey; collections: DecryptedCollection[] }) {
  const { authedFetch, org, orgKey } = props;
  const names = new Map(props.collections.map((c) => [c.id, c.decName]));
  const itemsQuery = useQuery({
    queryKey: ['org-items', org.id],
    queryFn: async () => {
      const ciphers = await listOrganizationCiphers(authedFetch, org.id);
      return Promise.all(
        ciphers.map(async (cipher) => {
          let key = orgKey;
          if (cipher.key) {
            const itemKey = await decryptBw(cipher.key, orgKey.enc, orgKey.mac).catch(() => null);
            if (itemKey && itemKey.length >= 64) key = { enc: itemKey.slice(0, 32), mac: itemKey.slice(32, 64) };
          }
          return { id: cipher.id, name: await decryptText(cipher.name, key), collectionIds: cipher.collectionIds ?? [] };
        })
      );
    },
  });

  return (
    <div className="stack">
      <p className="muted-inline">{t('txt_org_items_hint')}</p>
      {itemsQuery.isLoading && <LoadingState lines={3} compact />}
      <table className="table">
        <thead>
          <tr>
            <th>{t('txt_name')}</th>
            <th>{t('txt_org_collections')}</th>
          </tr>
        </thead>
        <tbody>
          {(itemsQuery.data ?? []).map((item) => (
            <tr key={item.id}>
              <td data-label={t('txt_name')}>
                {item.name || t('txt_org_undecryptable')} <span className="org-badge">{org.name}</span>
              </td>
              <td data-label={t('txt_org_collections')}>{item.collectionIds.map((id) => names.get(id) || id).join(', ')}</td>
            </tr>
          ))}
          {!itemsQuery.isLoading && !itemsQuery.data?.length && (
            <tr>
              <td colSpan={2}>
                <div className="empty empty-comfortable">{t('txt_no_items')}</div>
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function SettingsTab(props: DetailProps & { isOwner: boolean }) {
  const { authedFetch, org, run, busy } = props;
  const [name, setName] = useState(org.name);
  const [masterPassword, setMasterPassword] = useState('');

  return (
    <div className="stack">
      {props.isOwner && (
        <form
          className="actions"
          onSubmit={(event) => {
            event.preventDefault();
            void run(async () => {
              // The update needs the billing email too, which the profile does not carry.
              const current = await getOrganization(authedFetch, org.id);
              await updateOrganization(authedFetch, org.id, name.trim(), current.billingEmail);
              props.onClosed();
            }, t('txt_org_renamed'));
          }}
        >
          <input className="input" required value={name} onInput={(event) => setName(readValue(event))} />
          <button type="submit" className="btn btn-primary" disabled={busy || !name.trim() || name.trim() === org.name}>
            {t('txt_org_rename')}
          </button>
        </form>
      )}
      {props.isOwner ? (
        <form
          className="actions"
          onSubmit={(event) => {
            event.preventDefault();
            if (!window.confirm(t('txt_org_delete_confirm', { name: org.name }))) return;
            void run(async () => {
              await deleteOrganization(authedFetch, org.id, await props.deriveMasterPasswordHash(masterPassword));
              props.onClosed();
            }, t('txt_org_deleted'));
          }}
        >
          <input
            className="input"
            type="password"
            required
            autoComplete="current-password"
            placeholder={t('txt_master_password')}
            value={masterPassword}
            onInput={(event) => setMasterPassword(readValue(event))}
          />
          <button type="submit" className="btn btn-danger" disabled={busy || !masterPassword}>
            <Trash2 size={14} className="btn-icon" /> {t('txt_org_delete')}
          </button>
        </form>
      ) : (
        <div className="actions">
          <button
            type="button"
            className="btn btn-danger"
            disabled={busy}
            onClick={() => {
              if (!window.confirm(t('txt_org_leave_confirm', { name: org.name }))) return;
              void run(async () => {
                await leaveOrganization(authedFetch, org.id);
                props.onClosed();
              }, t('txt_org_left'));
            }}
          >
            <LogOut size={14} className="btn-icon" /> {t('txt_org_leave')}
          </button>
        </div>
      )}
    </div>
  );
}
