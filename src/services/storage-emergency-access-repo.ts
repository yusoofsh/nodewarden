// Emergency access rows (Vaultwarden's emergency_access table). Every lookup is
// scoped to the caller's role, so a row the caller has no part in reads as missing.
export const EmergencyAccessType = { View: 0, Takeover: 1 } as const;
export const EmergencyAccessStatus = {
  Invited: 0,
  Accepted: 1,
  Confirmed: 2,
  RecoveryInitiated: 3,
  RecoveryApproved: 4,
} as const;

export interface EmergencyAccess {
  id: string;
  grantorId: string;
  granteeId: string | null;
  email: string | null;
  keyEncrypted: string | null;
  type: number;
  status: number;
  waitTimeDays: number;
  recoveryInitiatedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export type EmergencyAccessRole = 'grantor' | 'grantee';

const COLUMNS =
  'id, grantor_id, grantee_id, email, key_encrypted, type, status, wait_time_days, recovery_initiated_at, created_at, updated_at';

function mapRow(row: any): EmergencyAccess {
  return {
    id: row.id,
    grantorId: row.grantor_id,
    granteeId: row.grantee_id ?? null,
    email: row.email ?? null,
    keyEncrypted: row.key_encrypted ?? null,
    type: Number(row.type),
    status: Number(row.status),
    waitTimeDays: Number(row.wait_time_days),
    recoveryInitiatedAt: row.recovery_initiated_at ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function findEmergencyAccess(
  db: D1Database,
  id: string,
  userId: string,
  roles: EmergencyAccessRole[]
): Promise<{ access: EmergencyAccess; role: EmergencyAccessRole } | null> {
  const row = await db
    .prepare(`SELECT ${COLUMNS} FROM emergency_access WHERE id = ? AND (grantor_id = ? OR grantee_id = ?)`)
    .bind(id, userId, userId)
    .first<any>();
  if (!row) return null;
  const access = mapRow(row);
  const role: EmergencyAccessRole = access.grantorId === userId ? 'grantor' : 'grantee';
  return roles.includes(role) ? { access, role } : null;
}

// Invited rows have no grantee yet and are found by the invited email.
export async function findInvitedEmergencyAccess(db: D1Database, id: string, email: string): Promise<EmergencyAccess | null> {
  const row = await db
    .prepare(`SELECT ${COLUMNS} FROM emergency_access WHERE id = ? AND email = ? AND status = ?`)
    .bind(id, email, EmergencyAccessStatus.Invited)
    .first<any>();
  return row ? mapRow(row) : null;
}

// The rows a user granted (with grantee details) or was granted (with grantor details).
export async function listEmergencyAccessWithUsers(
  db: D1Database,
  userId: string,
  role: EmergencyAccessRole
): Promise<Array<EmergencyAccess & { otherId: string; otherEmail: string; otherName: string | null }>> {
  const [mine, other] = role === 'grantor' ? ['grantor_id', 'grantee_id'] : ['grantee_id', 'grantor_id'];
  const { results } = await db
    .prepare(
      `SELECT ${COLUMNS.split(', ').map((c) => 'ea.' + c).join(', ')}, u.id AS other_id, u.email AS other_email, u.name AS other_name ` +
      `FROM emergency_access ea JOIN users u ON u.id = ea.${other} WHERE ea.${mine} = ? ORDER BY ea.created_at ASC`
    )
    .bind(userId)
    .all<any>();
  return results.map((row) => ({ ...mapRow(row), otherId: row.other_id, otherEmail: row.other_email, otherName: row.other_name ?? null }));
}

// Fails (returns false) when the pair already exists.
export async function insertEmergencyAccess(db: D1Database, access: EmergencyAccess): Promise<boolean> {
  const result = await db
    .prepare(
      'INSERT INTO emergency_access(id, grantor_id, grantee_id, email, key_encrypted, type, status, wait_time_days, created_at, updated_at) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING'
    )
    .bind(
      access.id, access.grantorId, access.granteeId, access.email, access.keyEncrypted, access.type, access.status,
      access.waitTimeDays, access.createdAt, access.updatedAt
    )
    .run();
  return Number(result.meta.changes) === 1;
}

export async function updateEmergencyAccessSettings(
  db: D1Database,
  id: string,
  type: number,
  waitTimeDays: number,
  keyEncrypted: string | null,
  now: string
): Promise<void> {
  await db
    .prepare('UPDATE emergency_access SET type = ?, wait_time_days = ?, key_encrypted = COALESCE(?, key_encrypted), updated_at = ? WHERE id = ?')
    .bind(type, waitTimeDays, keyEncrypted, now, id)
    .run();
}

// Moves a row to `to` only while its status is one of `from`, so two racing requests
// cannot both apply. Returns false when the row was not in an allowed status.
export async function transitionEmergencyAccess(
  db: D1Database,
  id: string,
  from: number[],
  to: number,
  now: string,
  fields: { granteeId?: string; clearEmail?: boolean; keyEncrypted?: string; recoveryInitiatedAt?: string } = {}
): Promise<boolean> {
  const sets = ['status = ?', 'updated_at = ?'];
  const args: unknown[] = [to, now];
  if (fields.granteeId !== undefined) { sets.push('grantee_id = ?'); args.push(fields.granteeId); }
  if (fields.clearEmail) sets.push('email = NULL');
  if (fields.keyEncrypted !== undefined) { sets.push('key_encrypted = ?'); args.push(fields.keyEncrypted); }
  if (fields.recoveryInitiatedAt !== undefined) {
    sets.push('recovery_initiated_at = ?', 'last_notification_at = ?');
    args.push(fields.recoveryInitiatedAt, fields.recoveryInitiatedAt);
  }
  const result = await db
    .prepare(`UPDATE emergency_access SET ${sets.join(', ')} WHERE id = ? AND status IN (${from.map(() => '?').join(', ')})`)
    .bind(...args, id, ...from)
    .run();
  return Number(result.meta.changes) === 1;
}

export async function deleteEmergencyAccess(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM emergency_access WHERE id = ?').bind(id).run();
}

// Vaultwarden's emergency_request_timeout_job: approve every recovery whose wait time
// has passed. One statement, so it is safe to run from cron and on request alike.
export async function approveTimedOutEmergencyAccess(db: D1Database, now: string): Promise<number> {
  const result = await db
    .prepare(
      'UPDATE emergency_access SET status = ?, updated_at = ? ' +
      'WHERE status = ? AND recovery_initiated_at IS NOT NULL AND julianday(recovery_initiated_at) + wait_time_days <= julianday(?)'
    )
    .bind(EmergencyAccessStatus.RecoveryApproved, now, EmergencyAccessStatus.RecoveryInitiated, now)
    .run();
  return Number(result.meta.changes);
}

// The grantor's rows that hold a copy of the user key; key rotation must re-wrap each.
export async function listKeyedGrantorEmergencyAccess(db: D1Database, grantorId: string): Promise<EmergencyAccess[]> {
  const { results } = await db
    .prepare(`SELECT ${COLUMNS} FROM emergency_access WHERE grantor_id = ? AND status >= ? AND key_encrypted IS NOT NULL`)
    .bind(grantorId, EmergencyAccessStatus.Confirmed)
    .all<any>();
  return results.map(mapRow);
}
