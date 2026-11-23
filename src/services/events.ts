// The organization event log, after Vaultwarden's src/api/core/events.rs and Bitwarden's EventType.
// Every event belongs to an organization: Vaultwarden also stores user events without one, which no
// route reads, so they are not kept here. Writing an event never fails the request that caused it.
import type { Env } from '../types';
import { readActingDeviceIdentifier } from '../utils/device';
import { auditRequestMetadata } from './audit-events';
import { generateUUID } from '../utils/uuid';

export const EventType = {
  UserClientExportedVault: 1007,
  CipherCreated: 1100,
  CipherUpdated: 1101,
  CipherDeleted: 1102,
  CipherShared: 1105,
  CipherUpdatedCollections: 1106,
  CipherSoftDeleted: 1115,
  CipherRestored: 1116,
  CollectionCreated: 1300,
  CollectionUpdated: 1301,
  CollectionDeleted: 1302,
  GroupCreated: 1400,
  GroupUpdated: 1401,
  GroupDeleted: 1402,
  OrganizationUserInvited: 1500,
  OrganizationUserConfirmed: 1501,
  OrganizationUserUpdated: 1502,
  OrganizationUserRemoved: 1503,
  OrganizationUserUpdatedGroups: 1504,
  OrganizationUserResetPasswordEnroll: 1506,
  OrganizationUserResetPasswordWithdraw: 1507,
  OrganizationUserAdminResetPassword: 1508,
  OrganizationUserRevoked: 1511,
  OrganizationUserRestored: 1512,
  OrganizationUserLeft: 1516,
  OrganizationUserAdminResetTwoFactor: 1519,
  OrganizationUserNotificationBannerActionClicked: 1522,
  OrganizationUpdated: 1600,
  OrganizationPurgedVault: 1601,
  OrganizationClientExportedVault: 1602,
  PolicyUpdated: 1700,
} as const;

/** Who caused the events of one request. The device type is read from the devices table on insert. */
export interface EventActor {
  userId: string;
  ip: string | null;
  deviceIdentifier: string | null;
}

export interface OrgEvent {
  type: number;
  organizationId: string;
  /** The user the event is about: the exporting user, or the member's user. */
  userId?: string | null;
  cipherId?: string | null;
  collectionId?: string | null;
  groupId?: string | null;
  memberId?: string | null;
  policyId?: string | null;
  /** An ISO date; a client sends its own for the events it collects. */
  date?: string;
}

export interface StoredEvent {
  id: string;
  type: number;
  organization_id: string;
  user_id: string | null;
  cipher_id: string | null;
  collection_id: string | null;
  group_id: string | null;
  member_id: string | null;
  policy_id: string | null;
  acting_user_id: string | null;
  device_type: number | null;
  ip_address: string | null;
  event_date: string;
}

export function eventActor(request: Request, userId: string): EventActor {
  return {
    userId,
    ip: auditRequestMetadata(request).ip as string | null,
    deviceIdentifier: readActingDeviceIdentifier(request),
  };
}

const INSERT_SQL =
  'INSERT INTO events (id, type, organization_id, user_id, cipher_id, collection_id, group_id, member_id, policy_id, ' +
  'acting_user_id, device_type, ip_address, event_date) ' +
  'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, (SELECT type FROM devices WHERE user_id = ? AND device_identifier = ?), ?, ?)';

const DEFAULT_RETAIN_DAYS = 365;
const PRUNE_INTERVAL_MS = 60 * 60 * 1000;
const PRUNE_BATCH = 1000;
let lastPruneAt = 0;

/** EVENTS_DAYS_RETAIN, 365 when unset; 0 keeps events forever. */
function retainDays(env: Env): number {
  const raw = String(env.EVENTS_DAYS_RETAIN ?? '').trim();
  const days = raw === '' ? DEFAULT_RETAIN_DAYS : Math.floor(Number(raw));
  return Number.isFinite(days) && days > 0 ? days : 0;
}

/** Deletes up to PRUNE_BATCH events older than the retention period. Returns how many it deleted. */
export async function pruneEvents(env: Env, now = Date.now()): Promise<number> {
  const days = retainDays(env);
  if (!days) return 0;
  const before = new Date(now - days * 24 * 60 * 60 * 1000).toISOString();
  const result = await env.DB
    .prepare('DELETE FROM events WHERE id IN (SELECT id FROM events WHERE event_date < ? LIMIT ?)')
    .bind(before, PRUNE_BATCH)
    .run();
  return Number(result.meta?.changes ?? 0);
}

/** Records the events, then prunes old ones at most once an hour per isolate. Errors are logged, never thrown. */
export async function logEvents(env: Env, actor: EventActor, events: OrgEvent[]): Promise<void> {
  if (!events.length) return;
  try {
    const now = new Date().toISOString();
    await env.DB.batch(
      events.map((e) =>
        env.DB.prepare(INSERT_SQL).bind(
          generateUUID(), e.type, e.organizationId, e.userId ?? null, e.cipherId ?? null, e.collectionId ?? null,
          e.groupId ?? null, e.memberId ?? null, e.policyId ?? null, actor.userId, actor.userId, actor.deviceIdentifier ?? '',
          actor.ip, e.date ?? now
        )
      )
    );
    if (Date.now() - lastPruneAt >= PRUNE_INTERVAL_MS) {
      lastPruneAt = Date.now();
      await pruneEvents(env);
    }
  } catch (error) {
    console.error('event log write failed', error);
  }
}

/** The event of an organization cipher; a personal cipher has none, as in Vaultwarden. */
export const cipherEvent = (type: number, cipher: { id: string; organizationId?: string | null }): OrgEvent[] =>
  cipher.organizationId ? [{ type, organizationId: cipher.organizationId, cipherId: cipher.id }] : [];

/** The events of the organization ciphers among these ids. Call it before a hard delete removes the rows. */
export async function listCipherEvents(db: D1Database, type: number, ids: string[]): Promise<OrgEvent[]> {
  const out: OrgEvent[] = [];
  try {
    for (let i = 0; i < ids.length; i += 90) {
      const chunk = ids.slice(i, i + 90);
      const { results } = await db
        .prepare(`SELECT id, organization_id FROM ciphers WHERE organization_id IS NOT NULL AND id IN (${chunk.map(() => '?').join(', ')})`)
        .bind(...chunk)
        .all<{ id: string; organization_id: string }>();
      for (const row of results || []) out.push({ type, organizationId: row.organization_id, cipherId: row.id });
    }
  } catch (error) {
    console.error('event log lookup failed', error);
  }
  return out;
}

export const PAGE_SIZE = 30;

export interface EventRange {
  start: string;
  end: string;
  /** The last event of the previous page; this page starts after it. */
  after: { date: string; id: string } | null;
}

/** A page of an organization's events, newest first, optionally narrowed to a cipher or a member's user. */
export async function listEvents(
  db: D1Database,
  organizationId: string,
  range: EventRange,
  filter: { cipherId: string } | { memberId: string; userId: string } | null
): Promise<StoredEvent[]> {
  let sql = 'SELECT * FROM events WHERE organization_id = ? AND event_date >= ?';
  const binds: unknown[] = [organizationId, range.start];
  if (range.after) {
    sql += ' AND (event_date < ? OR (event_date = ? AND id < ?))';
    binds.push(range.after.date, range.after.date, range.after.id);
  } else {
    sql += ' AND event_date <= ?';
    binds.push(range.end);
  }
  if (filter && 'cipherId' in filter) {
    sql += ' AND cipher_id = ?';
    binds.push(filter.cipherId);
  } else if (filter) {
    sql += ' AND (member_id = ? OR user_id = ? OR acting_user_id = ?)';
    binds.push(filter.memberId, filter.userId, filter.userId);
  }
  sql += ` ORDER BY event_date DESC, id DESC LIMIT ${PAGE_SIZE}`;
  return (await db.prepare(sql).bind(...binds).all<StoredEvent>()).results || [];
}
