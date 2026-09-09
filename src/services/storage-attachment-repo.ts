import type { Attachment, Cipher } from '../types';

type SafeBind = (stmt: D1PreparedStatement, ...values: any[]) => D1PreparedStatement;
type SqlChunkSize = (fixedBindCount: number) => number;
type GetCipher = (id: string) => Promise<Cipher | null>;
type SaveCipher = (cipher: Cipher) => Promise<void>;
type UpdateRevisionDate = (userId: string) => Promise<string>;

// Attachments are scoped by their own user_id, never by a join into ciphers:
// the planner serves such a join from the ciphers side and reads one index row
// per cipher in the vault, so a vault with no attachments still paid for every
// cipher on every sync. Both statements are exported so the schema test can
// assert that shape holds - the SELECT touches only attachments, and the INSERT
// keeps the denormalised copy in step with the owning cipher.
export const ATTACHMENTS_BY_USER_SQL =
  'SELECT id, cipher_id, file_name, size, size_name, key FROM attachments WHERE user_id = ?';

export const ATTACHMENT_UPSERT_SQL =
  'INSERT INTO attachments(id, cipher_id, user_id, file_name, size, size_name, key) ' +
  'VALUES(?, ?, (SELECT user_id FROM ciphers WHERE id = ?), ?, ?, ?, ?) ' +
  'ON CONFLICT(id) DO UPDATE SET cipher_id=excluded.cipher_id, user_id=excluded.user_id, file_name=excluded.file_name, size=excluded.size, size_name=excluded.size_name, key=excluded.key ' +
  'WHERE EXISTS (' +
  'SELECT 1 FROM ciphers current_cipher INNER JOIN ciphers next_cipher ON next_cipher.id = excluded.cipher_id ' +
  'WHERE current_cipher.id = attachments.cipher_id AND current_cipher.user_id = next_cipher.user_id' +
  ')';

export async function getAttachment(db: D1Database, id: string): Promise<Attachment | null> {
  const row = await db
    .prepare('SELECT id, cipher_id, file_name, size, size_name, key FROM attachments WHERE id = ?')
    .bind(id)
    .first<any>();
  if (!row) return null;
  return {
    id: row.id,
    cipherId: row.cipher_id,
    fileName: row.file_name,
    size: row.size,
    sizeName: row.size_name,
    key: row.key,
  };
}

export async function saveAttachment(db: D1Database, safeBind: SafeBind, attachment: Attachment): Promise<void> {
  // user_id is read off the owning cipher rather than taken from the caller, so
  // the denormalised copy cannot drift from the row it was copied from. The
  // lookup is a primary key seek.
  const stmt = db.prepare(ATTACHMENT_UPSERT_SQL);
  await safeBind(stmt, attachment.id, attachment.cipherId, attachment.cipherId, attachment.fileName, attachment.size, attachment.sizeName, attachment.key).run();
}

export async function deleteAttachment(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM attachments WHERE id = ?').bind(id).run();
}

export async function bulkDeleteAttachmentsByIds(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  attachmentIds: string[]
): Promise<void> {
  const uniqueIds = [...new Set(attachmentIds.map((id) => String(id || '').trim()).filter(Boolean))];
  if (!uniqueIds.length) return;
  const chunkSize = sqlChunkSize(0);

  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db.prepare(`DELETE FROM attachments WHERE id IN (${placeholders})`).bind(...chunk).run();
  }
}

export async function getAttachmentsByCipher(db: D1Database, cipherId: string): Promise<Attachment[]> {
  const res = await db
    .prepare('SELECT id, cipher_id, file_name, size, size_name, key FROM attachments WHERE cipher_id = ?')
    .bind(cipherId)
    .all<any>();
  return (res.results || []).map((r) => ({
    id: r.id,
    cipherId: r.cipher_id,
    fileName: r.file_name,
    size: r.size,
    sizeName: r.size_name,
    key: r.key,
  }));
}

export async function getAttachmentsByCipherIds(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  cipherIds: string[]
): Promise<Map<string, Attachment[]>> {
  const grouped = new Map<string, Attachment[]>();
  if (cipherIds.length === 0) return grouped;

  const uniqueCipherIds = [...new Set(cipherIds)];
  const chunkSize = sqlChunkSize(0);

  for (let i = 0; i < uniqueCipherIds.length; i += chunkSize) {
    const chunk = uniqueCipherIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    const res = await db
      .prepare(`SELECT id, cipher_id, file_name, size, size_name, key FROM attachments WHERE cipher_id IN (${placeholders})`)
      .bind(...chunk)
      .all<any>();

    for (const row of res.results || []) {
      const item: Attachment = {
        id: row.id,
        cipherId: row.cipher_id,
        fileName: row.file_name,
        size: row.size,
        sizeName: row.size_name,
        key: row.key,
      };
      const list = grouped.get(item.cipherId);
      if (list) list.push(item);
      else grouped.set(item.cipherId, [item]);
    }
  }

  return grouped;
}

/**
 * Every attachment a sync has to describe: the user's own, plus any on
 * ciphers reached through an organization's collections.
 *
 * WHY THIS EXISTS, and why the sync path does not simply call
 * getAttachmentsByCipherIds:
 *
 * That function asks `WHERE cipher_id IN (?, ? ...)`, a hundred ids at a
 * time. The planner serves each placeholder with a seek into
 * idx_attachments_cipher, and D1 bills a seek as a row read whether or not it
 * finds anything - so a 1,668-item vault with NO attachments at all paid
 * ~1,700 row reads on every sync. Measured at 180,000 rows a day, which was
 * more than reading the entire ciphers table cost. It is the same defect the
 * note at the top of this file records, arriving by a second route.
 *
 * The user's own attachments are one seek into idx_attachments_user, so they
 * come back in a single query. Org ciphers cannot: `attachments.user_id` is
 * the OWNING user (see ATTACHMENT_UPSERT_SQL, which reads it out of the
 * cipher), and a cipher reached through a collection is commonly owned by
 * somebody else - so those ids are still asked for by cipher, in the same
 * batches as before. An account with no org ciphers therefore makes one
 * query; an account with them pays for those and no longer for its own vault.
 *
 * `orgCipherIds` may safely contain ids the user does own - an org they
 * created themselves. A duplicate costs one extra seek and cannot
 * double-count, because attachments are merged by their own id below.
 */
export async function getAttachmentsForUserAndCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  userId: string,
  orgCipherIds: string[]
): Promise<Map<string, Attachment[]>> {
  const grouped = await getAttachmentsByUserId(db, userId);
  if (orgCipherIds.length === 0) return grouped;

  const seen = new Set<string>();
  for (const list of grouped.values()) {
    for (const attachment of list) seen.add(attachment.id);
  }

  const extra = await getAttachmentsByCipherIds(db, sqlChunkSize, orgCipherIds);
  for (const [cipherId, list] of extra) {
    for (const attachment of list) {
      // Merged by ATTACHMENT id, not by cipher id: an org cipher the user
      // also owns comes back from both queries, and appending blindly would
      // show its file twice on the item.
      if (seen.has(attachment.id)) continue;
      seen.add(attachment.id);
      const existing = grouped.get(cipherId);
      if (existing) existing.push(attachment);
      else grouped.set(cipherId, [attachment]);
    }
  }

  return grouped;
}

export async function getAttachmentsByUserId(db: D1Database, userId: string): Promise<Map<string, Attachment[]>> {
  const grouped = new Map<string, Attachment[]>();
  const res = await db.prepare(ATTACHMENTS_BY_USER_SQL).bind(userId).all<any>();

  for (const row of res.results || []) {
    const item: Attachment = {
      id: row.id,
      cipherId: row.cipher_id,
      fileName: row.file_name,
      size: row.size,
      sizeName: row.size_name,
      key: row.key,
    };
    const list = grouped.get(item.cipherId);
    if (list) list.push(item);
    else grouped.set(item.cipherId, [item]);
  }

  return grouped;
}

export async function addAttachmentToCipher(db: D1Database, cipherId: string, attachmentId: string): Promise<void> {
  await db
    .prepare('UPDATE attachments SET cipher_id = ?, user_id = (SELECT user_id FROM ciphers WHERE id = ?) WHERE id = ?')
    .bind(cipherId, cipherId, attachmentId)
    .run();
}

export async function addAttachmentToCipherForUser(
  db: D1Database,
  cipherId: string,
  attachmentId: string,
  userId: string
): Promise<void> {
  // The first EXISTS already proves the target cipher belongs to userId, so the
  // denormalised user_id can be written straight from the caller's scope.
  await db
    .prepare(
      `UPDATE attachments
       SET cipher_id = ?, user_id = ?
       WHERE id = ?
         AND EXISTS (
           SELECT 1 FROM ciphers target_cipher
           WHERE target_cipher.id = ? AND target_cipher.user_id = ?
         )
         AND EXISTS (
           SELECT 1 FROM ciphers current_cipher
           WHERE current_cipher.id = attachments.cipher_id AND current_cipher.user_id = ?
         )`
    )
    .bind(cipherId, userId, attachmentId, cipherId, userId, userId)
    .run();
}

export async function deleteAllAttachmentsByCipher(db: D1Database, cipherId: string): Promise<void> {
  await db.prepare('DELETE FROM attachments WHERE cipher_id = ?').bind(cipherId).run();
}

export async function updateCipherRevisionDate(
  getCipherById: GetCipher,
  saveCipherRecord: SaveCipher,
  updateRevisionDate: UpdateRevisionDate,
  cipherId: string
): Promise<{ userId: string; revisionDate: string } | null> {
  const cipher = await getCipherById(cipherId);
  if (!cipher) return null;
  cipher.updatedAt = new Date().toISOString();
  await saveCipherRecord(cipher);
  const revisionDate = await updateRevisionDate(cipher.userId);
  return { userId: cipher.userId, revisionDate };
}
