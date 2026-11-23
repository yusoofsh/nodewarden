// Organization event log routes, after Vaultwarden's src/api/core/events.rs.
// - Events are always on. Vaultwarden records them only with ORG_EVENTS_ENABLED.
// - The continuation token is the last event's date and id, so a page boundary inside a run of
//   events with the same date neither repeats nor skips one. Vaultwarden's token is the date alone.
import type { Env } from '../types';
import { StorageService } from '../services/storage';
import {
  EventType,
  PAGE_SIZE,
  type EventActor,
  type EventRange,
  type OrgEvent,
  type StoredEvent,
  listEvents,
  logEvents,
} from '../services/events';
import { getConfirmedMembership, isAdminOrOwner } from '../services/org-access';
import { MemberStatus, getMemberById } from '../services/storage-organization-repo';
import { errorResponse, jsonResponse } from '../utils/response';

function eventJson(e: StoredEvent) {
  return {
    object: 'event',
    type: e.type,
    userId: e.user_id,
    organizationId: e.organization_id,
    cipherId: e.cipher_id,
    collectionId: e.collection_id,
    groupId: e.group_id,
    organizationUserId: e.member_id,
    actingUserId: e.acting_user_id,
    date: e.event_date,
    deviceType: e.device_type,
    ipAddress: e.ip_address,
    policyId: e.policy_id,
    providerId: null,
    providerUserId: null,
    providerOrganizationId: null,
  };
}

const isoDate = (value: string | null): string | null => {
  if (!value) return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : new Date(ms).toISOString();
};

/** The start, end and continuation token of a request, or the error to send. */
function readRange(request: Request): EventRange | Response {
  const query = new URL(request.url).searchParams;
  const start = isoDate(query.get('start'));
  if (!start) return errorResponse('Invalid start date', 400);
  const end = isoDate(query.get('end'));
  if (!end) return errorResponse('Invalid end date', 400);
  const token = query.get('continuationToken');
  if (!token) return { start, end, after: null };
  const [date, id] = token.split('|');
  const after = isoDate(date);
  if (!after || !id) return errorResponse('Invalid end date', 400);
  return { start, end, after: { date: after, id } };
}

function page(events: StoredEvent[]): Response {
  const last = events.length === PAGE_SIZE ? events[events.length - 1] : null;
  return jsonResponse({
    data: events.map(eventJson),
    object: 'list',
    continuationToken: last ? `${last.event_date}|${last.id}` : null,
  });
}

const emptyPage = () => page([]);

// GET /api/organizations/{id}/events?start=&end=&continuationToken=
export async function handleGetOrganizationEvents(request: Request, env: Env, organizationId: string): Promise<Response> {
  const range = readRange(request);
  if (range instanceof Response) return range;
  return page(await listEvents(env.DB, organizationId, range, null));
}

// GET /api/organizations/{id}/users/{memberId}/events
// The member's own events and the ones they caused; a member of another organization has none.
export async function handleGetMemberEvents(request: Request, env: Env, organizationId: string, memberId: string): Promise<Response> {
  const range = readRange(request);
  if (range instanceof Response) return range;
  const member = await getMemberById(env.DB, organizationId, memberId);
  if (!member) return emptyPage();
  return page(await listEvents(env.DB, organizationId, range, { memberId, userId: member.userId }));
}

// GET /api/ciphers/{id}/events
// Only an owner or admin of the cipher's organization sees its events. Anyone else, and a personal
// cipher, gets an empty list, as in Vaultwarden.
export async function handleGetCipherEvents(request: Request, env: Env, userId: string, cipherId: string): Promise<Response> {
  const range = readRange(request);
  if (range instanceof Response) return range;
  const row = await env.DB.prepare('SELECT organization_id FROM ciphers WHERE id = ?').bind(cipherId).first<{ organization_id: string | null }>();
  if (!row?.organization_id) return emptyPage();
  const member = await getConfirmedMembership(env.DB, row.organization_id, userId);
  if (!member || !isAdminOrOwner(member)) return emptyPage();
  return page(await listEvents(env.DB, row.organization_id, range, { cipherId }));
}

// Client-side cipher events: viewed, toggled, copied, autofilled, HTTP auth released.
const isClientCipherEvent = (type: number) =>
  (type >= 1107 && type <= 1114) || type === 1117 || (type >= 1119 && type <= 1133);

// POST /events/collect
// Accepts only the event types clients report; the rest are written by the server. The organization
// of a cipher event is the cipher's, after checking the caller can reach it; an organization event
// needs the caller's confirmed membership. Anything else is dropped without an error.
export async function handleCollectEvents(request: Request, env: Env, actor: EventActor): Promise<Response> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
  if (!Array.isArray(body)) return errorResponse('Invalid JSON', 400);

  const storage = new StorageService(env.DB);
  const events: OrgEvent[] = [];
  const cipherOrgs = new Map<string, string | null>();
  for (const entry of body) {
    const item = entry && typeof entry === 'object' ? (entry as Record<string, unknown>) : {};
    const type = Number(item.type);
    const date = isoDate(typeof item.date === 'string' ? item.date : null);
    if (!Number.isInteger(type) || !date) return errorResponse('Invalid event date', 400);
    const organizationId = typeof item.organizationId === 'string' ? item.organizationId.toLowerCase() : '';
    const cipherId = typeof item.cipherId === 'string' ? item.cipherId.toLowerCase() : '';

    if (type === EventType.UserClientExportedVault) {
      const { results } = await env.DB
        .prepare('SELECT id, organization_id FROM organization_members WHERE user_id = ? AND status = ?')
        .bind(actor.userId, MemberStatus.Confirmed)
        .all<{ id: string; organization_id: string }>();
      for (const m of results || []) events.push({ type, organizationId: m.organization_id, memberId: m.id, userId: actor.userId, date });
    } else if (type === EventType.OrganizationClientExportedVault || type === EventType.OrganizationUserNotificationBannerActionClicked) {
      const member = organizationId ? await getConfirmedMembership(env.DB, organizationId, actor.userId) : null;
      if (!member) continue;
      const memberId = type === EventType.OrganizationUserNotificationBannerActionClicked ? member.id : null;
      events.push({ type, organizationId, memberId, userId: memberId ? actor.userId : null, date });
    } else if (isClientCipherEvent(type) && cipherId) {
      if (!cipherOrgs.has(cipherId)) {
        const accessible = await storage.getAccessibleCipher(cipherId, actor.userId);
        cipherOrgs.set(cipherId, accessible?.cipher.organizationId ?? null);
      }
      const cipherOrg = cipherOrgs.get(cipherId);
      if (cipherOrg) events.push({ type, organizationId: cipherOrg, cipherId, date });
    }
  }
  await logEvents(env, actor, events);
  return new Response(null, { status: 200 });
}
