import type { Cipher, User } from '../types';
import { cipherRowValues } from './storage-cipher-repo';

export interface KeyRotationPlan {
  user: User;
  expectedPasswordVerifier: string;
  expectedSecurityStamp: string;
  expectedCounts: { ciphers: number; folders: number; sends: number; emergencyAccess: number };
  newPasswordVerifier: string;
  ciphers: Cipher[];
  attachments: Array<{ cipherId: string; id: string; fileName: string | null; key: string | null }>;
  folders: Array<{ id: string; name: string }>;
  sends: Array<{ id: string; key: string }>;
  // The user key wrapped for each confirmed emergency contact.
  emergencyAccess: Array<{ id: string; keyEncrypted: string }>;
  // Copies of the user key wrapped for a passkey or a trusted device. Rows that are
  // not listed hold the old user key, so their wrapped keys are cleared.
  passkeys: Array<{ id: string; encryptedUserKey: string; encryptedPublicKey: string | null }>;
  devices: Array<{ deviceIdentifier: string; encryptedUserKey: string; encryptedPublicKey: string | null }>;
  now: string;
}

// D1 limits the queries in one invocation, so vault rows go in as JSON through
// json_each, chunked by size, instead of one statement per row.
const MAX_CHUNK_BYTES = 256 * 1024;

function chunkJson<T>(rows: T[]): string[] {
  const chunks: string[] = [];
  let current: T[] = [];
  let size = 0;
  for (const row of rows) {
    const rowSize = JSON.stringify(row).length;
    if (current.length > 0 && size + rowSize > MAX_CHUNK_BYTES) {
      chunks.push(JSON.stringify(current));
      current = [];
      size = 0;
    }
    current.push(row);
    size += rowSize;
  }
  if (current.length > 0) chunks.push(JSON.stringify(current));
  return chunks;
}

// Writes everything a key rotation changes in one D1 batch, which is a single
// transaction. A batch does not stop when a statement changes no rows, so:
// - the first statement only applies while the verifier, security stamp and the
//   number of ciphers, folders, sends and keyed emergency contacts are what the request was checked against,
//   so a concurrent password change or a new item makes it a no-op;
// - every later statement only applies while the user holds the new stamp, a fresh
//   UUID that only the first statement can set.
// If the first statement changed no row this returns false and nothing was written.
export async function applyKeyRotation(db: D1Database, plan: KeyRotationPlan): Promise<boolean> {
  const { user } = plan;
  const guard = ' AND EXISTS (SELECT 1 FROM users WHERE id = ? AND security_stamp = ?)';
  const guardArgs = [user.id, user.securityStamp];

  const statements: D1PreparedStatement[] = [
    db
      .prepare(
        'UPDATE users SET master_password_hash=?, key=?, private_key=?, public_key=?, user_key_id=?, security_stamp=?, updated_at=? ' +
        "WHERE id=? AND master_password_hash=? AND security_stamp=? AND status='active' " +
        'AND (SELECT COUNT(*) FROM ciphers WHERE user_id = ?) = ? ' +
        'AND (SELECT COUNT(*) FROM folders WHERE user_id = ?) = ? ' +
        'AND (SELECT COUNT(*) FROM sends WHERE user_id = ?) = ? ' +
        'AND (SELECT COUNT(*) FROM emergency_access WHERE grantor_id = ? AND status >= 2 AND key_encrypted IS NOT NULL) = ?'
      )
      .bind(
        plan.newPasswordVerifier, user.key, user.privateKey ?? null, user.publicKey ?? null, user.userKeyId ?? null,
        user.securityStamp, plan.now,
        user.id, plan.expectedPasswordVerifier, plan.expectedSecurityStamp,
        user.id, plan.expectedCounts.ciphers, user.id, plan.expectedCounts.folders, user.id, plan.expectedCounts.sends,
        user.id, plan.expectedCounts.emergencyAccess
      ),
  ];

  for (const chunk of chunkJson(plan.folders)) {
    statements.push(
      db
        .prepare(
          'UPDATE folders SET name = j.name, updated_at = ? FROM ' +
          "(SELECT json_extract(value, '$.id') AS id, json_extract(value, '$.name') AS name FROM json_each(?)) AS j " +
          'WHERE folders.id = j.id AND folders.user_id = ?' + guard
        )
        .bind(plan.now, chunk, user.id, ...guardArgs)
    );
  }
  for (const chunk of chunkJson(plan.sends)) {
    statements.push(
      db
        .prepare(
          'UPDATE sends SET key = j.key, updated_at = ? FROM ' +
          "(SELECT json_extract(value, '$.id') AS id, json_extract(value, '$.key') AS key FROM json_each(?)) AS j " +
          'WHERE sends.id = j.id AND sends.user_id = ?' + guard
        )
        .bind(plan.now, chunk, user.id, ...guardArgs)
    );
  }
  for (const chunk of chunkJson(plan.emergencyAccess)) {
    statements.push(
      db
        .prepare(
          'UPDATE emergency_access SET key_encrypted = j.key, updated_at = ? FROM ' +
          "(SELECT json_extract(value, '$.id') AS id, json_extract(value, '$.keyEncrypted') AS key FROM json_each(?)) AS j " +
          'WHERE emergency_access.id = j.id AND emergency_access.grantor_id = ?' + guard
        )
        .bind(plan.now, chunk, user.id, ...guardArgs)
    );
  }
  for (const chunk of chunkJson(plan.ciphers.map(cipherRowValues))) {
    statements.push(
      db
        .prepare(
          'UPDATE ciphers SET type = j.type, folder_id = j.folder_id, name = j.name, notes = j.notes, favorite = j.favorite, ' +
          'data = j.data, reprompt = j.reprompt, key = j.key, updated_at = j.updated_at, archived_at = j.archived_at, deleted_at = j.deleted_at FROM ' +
          "(SELECT json_extract(value, '$.id') AS id, json_extract(value, '$.type') AS type, json_extract(value, '$.folder_id') AS folder_id, " +
          "json_extract(value, '$.name') AS name, json_extract(value, '$.notes') AS notes, json_extract(value, '$.favorite') AS favorite, " +
          "json_extract(value, '$.data') AS data, json_extract(value, '$.reprompt') AS reprompt, json_extract(value, '$.key') AS key, " +
          "json_extract(value, '$.updated_at') AS updated_at, json_extract(value, '$.archived_at') AS archived_at, " +
          "json_extract(value, '$.deleted_at') AS deleted_at FROM json_each(?)) AS j " +
          'WHERE ciphers.id = j.id AND ciphers.user_id = ?' + guard
        )
        .bind(chunk, user.id, ...guardArgs)
    );
  }
  for (const chunk of chunkJson(plan.attachments)) {
    statements.push(
      db
        .prepare(
          'UPDATE attachments SET file_name = COALESCE(j.file_name, attachments.file_name), key = COALESCE(j.key, attachments.key) FROM ' +
          "(SELECT json_extract(value, '$.cipherId') AS cipher_id, json_extract(value, '$.id') AS id, " +
          "json_extract(value, '$.fileName') AS file_name, json_extract(value, '$.key') AS key FROM json_each(?)) AS j " +
          'WHERE attachments.id = j.id AND attachments.cipher_id = j.cipher_id' + guard
        )
        .bind(chunk, ...guardArgs)
    );
  }

  // Wrapped copies of the old user key: clear all, then write back the rotated ones.
  statements.push(
    db
      .prepare(
        'UPDATE webauthn_credentials SET encrypted_user_key = NULL, encrypted_public_key = NULL, encrypted_private_key = NULL ' +
        'WHERE user_id = ? AND encrypted_user_key IS NOT NULL' + guard
      )
      .bind(user.id, ...guardArgs),
    db
      .prepare(
        'UPDATE devices SET encrypted_user_key = NULL, encrypted_public_key = NULL, encrypted_private_key = NULL ' +
        'WHERE user_id = ? AND encrypted_user_key IS NOT NULL' + guard
      )
      .bind(user.id, ...guardArgs),
    db.prepare('DELETE FROM auth_requests WHERE user_id = ?' + guard).bind(user.id, ...guardArgs)
  );
  for (const passkey of plan.passkeys) {
    statements.push(
      db
        .prepare(
          'UPDATE webauthn_credentials SET encrypted_user_key = ?, encrypted_public_key = ?, updated_at = ? WHERE id = ? AND user_id = ?' + guard
        )
        .bind(passkey.encryptedUserKey, passkey.encryptedPublicKey, plan.now, passkey.id, user.id, ...guardArgs)
    );
  }
  for (const device of plan.devices) {
    statements.push(
      db
        .prepare(
          'UPDATE devices SET encrypted_user_key = ?, encrypted_public_key = ?, updated_at = ? WHERE device_identifier = ? AND user_id = ?' + guard
        )
        .bind(device.encryptedUserKey, device.encryptedPublicKey, plan.now, device.deviceIdentifier, user.id, ...guardArgs)
    );
  }

  statements.push(
    db
      .prepare(
        'INSERT INTO user_revisions(user_id, revision_date) VALUES(?, ?) ' +
        'ON CONFLICT(user_id) DO UPDATE SET revision_date = excluded.revision_date ' +
        'WHERE EXISTS (SELECT 1 FROM users WHERE id = ? AND security_stamp = ?)'
      )
      .bind(user.id, plan.now, ...guardArgs),
    db.prepare('DELETE FROM refresh_tokens WHERE user_id = ?' + guard).bind(user.id, ...guardArgs)
  );

  const results = await db.batch(statements);
  return results[0].meta.changes === 1;
}
