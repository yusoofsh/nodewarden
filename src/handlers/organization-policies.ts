// Organization policies, after Vaultwarden's organizations.rs. Policies are stored and served,
// in these routes and in sync, but the server enforces none of them: enabling Two-step login or
// Single organization removes nobody, and no dependency between policies is checked. Clients
// still apply the policies they receive. The Send controls policy is stored like any other, not
// kept in step with Disable Send and Send options as Vaultwarden does.
import type { Env } from '../types';
import { getPolicy, listPolicies, savePolicy, type Policy } from '../services/storage-organization-policy-repo';
import { policyJson } from '../utils/organization-response';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { type EventActor, EventType, logEvents } from '../services/events';
import { isRecord, list, readBody, touchOrganization } from './organizations';

// Vaultwarden's OrgPolicyType: Bitwarden's PolicyType without the types it does not support.
const POLICY_TYPES = new Set([0, 1, 2, 3, 5, 6, 7, 8, 14, 15, 16, 17, 20, 21, 22]);
const MASTER_PASSWORD = 1;
const INVALID_TYPE = 'Invalid or unsupported policy type';

const parseType = (value: string): number | null => (/^\d+$/.test(value) && POLICY_TYPES.has(Number(value)) ? Number(value) : null);

/** The stored policy, or the disabled default every unset type reads as. */
async function readPolicy(db: D1Database, organizationId: string, type: number): Promise<Policy> {
  return (
    (await getPolicy(db, organizationId, type)) ?? {
      id: generateUUID(),
      organizationId,
      type,
      enabled: false,
      data: 'null',
      updatedAt: new Date().toISOString(),
    }
  );
}

// GET /api/organizations/{id}/policies
// GET /api/organizations/{id}/policies/token, GET /api/organizations/{id}/policies/invited-user
export async function handleListPolicies(env: Env, organizationId: string): Promise<Response> {
  return list((await listPolicies(env.DB, organizationId)).map(policyJson));
}

// GET /api/organizations/{id}/policies/{type}
export async function handleGetPolicy(env: Env, organizationId: string, type: string): Promise<Response> {
  const parsed = parseType(type);
  if (parsed === null) return errorResponse(INVALID_TYPE, 400);
  return jsonResponse(policyJson(await readPolicy(env.DB, organizationId, parsed)));
}

// GET /api/organizations/{id}/policies/master-password
export async function handleGetMasterPasswordPolicy(env: Env, organizationId: string): Promise<Response> {
  return jsonResponse(policyJson(await readPolicy(env.DB, organizationId, MASTER_PASSWORD)));
}

// PUT /api/organizations/{id}/policies/{type}
// The body is `{ policy: { enabled, data } }`; a bare `{ enabled, data }` from older clients is read too.
export async function handlePutPolicy(request: Request, env: Env, organizationId: string, type: string, actor: EventActor): Promise<Response> {
  const parsed = parseType(type);
  if (parsed === null) return errorResponse(INVALID_TYPE, 400);
  const body = await readBody(request);
  const policy = isRecord(body?.policy) ? body.policy : body;
  if (!policy || typeof policy.enabled !== 'boolean') return errorResponse('enabled is required', 400);

  const current = await readPolicy(env.DB, organizationId, parsed);
  const saved = await savePolicy(env.DB, {
    ...current,
    enabled: policy.enabled,
    data: JSON.stringify(policy.data ?? null),
    updatedAt: new Date().toISOString(),
  });
  await touchOrganization(env.DB, organizationId);
  await logEvents(env, actor, [{ type: EventType.PolicyUpdated, organizationId, policyId: saved.id }]);
  return jsonResponse(policyJson(saved));
}
