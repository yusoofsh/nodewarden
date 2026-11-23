// Organization policies, one row per organization and policy type. They are stored and served
// to clients; the server does not enforce any of them.

export interface Policy {
  id: string;
  organizationId: string;
  type: number;
  enabled: boolean;
  /** The policy's data as JSON text. */
  data: string;
  updatedAt: string;
}

const POLICY_COLUMNS = 'p.id, p.organization_id, p.type, p.enabled, p.data, p.updated_at';

function mapPolicy(row: any): Policy {
  return {
    id: row.id,
    organizationId: row.organization_id,
    type: Number(row.type),
    enabled: !!row.enabled,
    data: row.data ?? 'null',
    updatedAt: row.updated_at,
  };
}

export async function listPolicies(db: D1Database, organizationId: string): Promise<Policy[]> {
  const { results } = await db
    .prepare(`SELECT ${POLICY_COLUMNS} FROM organization_policies p WHERE p.organization_id = ? ORDER BY p.type ASC`)
    .bind(organizationId)
    .all<any>();
  return (results || []).map(mapPolicy);
}

export async function getPolicy(db: D1Database, organizationId: string, type: number): Promise<Policy | null> {
  const row = await db
    .prepare(`SELECT ${POLICY_COLUMNS} FROM organization_policies p WHERE p.organization_id = ? AND p.type = ?`)
    .bind(organizationId, type)
    .first<any>();
  return row ? mapPolicy(row) : null;
}

/** The policies of every organization in which the user's membership has one of these statuses. */
export async function listPoliciesForUser(db: D1Database, userId: string, statuses: number[]): Promise<Policy[]> {
  const { results } = await db
    .prepare(
      `SELECT ${POLICY_COLUMNS} FROM organization_policies p INNER JOIN organization_members m ON m.organization_id = p.organization_id ` +
      `WHERE m.user_id = ? AND m.status IN (${statuses.map(() => '?').join(', ')}) ORDER BY p.organization_id ASC, p.type ASC`
    )
    .bind(userId, ...statuses)
    .all<any>();
  return (results || []).map(mapPolicy);
}

/** Inserts the policy, or updates the existing row of its organization and type, which keeps its id. */
export async function savePolicy(db: D1Database, policy: Policy): Promise<Policy> {
  await db
    .prepare(
      'INSERT INTO organization_policies(id, organization_id, type, enabled, data, updated_at) VALUES(?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(organization_id, type) DO UPDATE SET enabled = excluded.enabled, data = excluded.data, updated_at = excluded.updated_at'
    )
    .bind(policy.id, policy.organizationId, policy.type, policy.enabled ? 1 : 0, policy.data, policy.updatedAt)
    .run();
  return (await getPolicy(db, policy.organizationId, policy.type)) ?? policy;
}
