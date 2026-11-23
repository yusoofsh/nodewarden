import type { Cipher, User } from '../types';
import { prepareCipherUpdate } from './storage-cipher-repo';

export interface KeyRotationPlan {
  user: User;
  expectedPasswordVerifier: string;
  expectedSecurityStamp: string;
  newPasswordVerifier: string;
  ciphers: Cipher[];
  attachments: Array<{ cipherId: string; id: string; fileName: string | null; key: string | null }>;
  folders: Array<{ id: string; name: string }>;
  sends: Array<{ id: string; key: string }>;
  now: string;
}

// Writes everything a key rotation changes in one D1 batch, which is a single
// transaction. A batch does not stop when a statement changes no rows, so the first
// statement is guarded by the verifier and stamp the request was checked against, and
// every later statement only applies while the user holds the new stamp (a fresh UUID
// that only the first statement can set). If a concurrent change beat us, nothing is
// written and this returns false for the caller to report as a conflict.
export async function applyKeyRotation(db: D1Database, plan: KeyRotationPlan): Promise<boolean> {
  const { user } = plan;
  const guard = ' AND EXISTS (SELECT 1 FROM users WHERE id = ? AND security_stamp = ?)';
  const guardArgs = [user.id, user.securityStamp];
  const statements: D1PreparedStatement[] = [
    db
      .prepare(
        'UPDATE users SET master_password_hash=?, key=?, private_key=?, public_key=?, user_key_id=?, security_stamp=?, updated_at=? ' +
        "WHERE id=? AND master_password_hash=? AND security_stamp=? AND status='active'"
      )
      .bind(
        plan.newPasswordVerifier, user.key, user.privateKey ?? null, user.publicKey ?? null, user.userKeyId ?? null,
        user.securityStamp, plan.now,
        user.id, plan.expectedPasswordVerifier, plan.expectedSecurityStamp
      ),
  ];
  for (const folder of plan.folders) {
    statements.push(
      db.prepare('UPDATE folders SET name=?, updated_at=? WHERE id=? AND user_id=?' + guard).bind(folder.name, plan.now, folder.id, user.id, ...guardArgs)
    );
  }
  for (const send of plan.sends) {
    statements.push(
      db.prepare('UPDATE sends SET key=?, updated_at=? WHERE id=? AND user_id=?' + guard).bind(send.key, plan.now, send.id, user.id, ...guardArgs)
    );
  }
  for (const cipher of plan.ciphers) statements.push(prepareCipherUpdate(db, cipher, { stamp: user.securityStamp }));
  for (const attachment of plan.attachments) {
    statements.push(
      db
        .prepare('UPDATE attachments SET file_name=COALESCE(?, file_name), key=? WHERE id=? AND cipher_id=?' + guard)
        .bind(attachment.fileName, attachment.key, attachment.id, attachment.cipherId, ...guardArgs)
    );
  }
  statements.push(
    db
      .prepare(
        'INSERT INTO user_revisions(user_id, revision_date) VALUES(?, ?) ' +
        'ON CONFLICT(user_id) DO UPDATE SET revision_date = excluded.revision_date ' +
        'WHERE EXISTS (SELECT 1 FROM users WHERE id = ? AND security_stamp = ?)'
      )
      .bind(user.id, plan.now, ...guardArgs)
  );
  statements.push(db.prepare('DELETE FROM refresh_tokens WHERE user_id=?' + guard).bind(user.id, ...guardArgs));

  const results = await db.batch(statements);
  return results[0].meta.changes === 1;
}
