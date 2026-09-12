import { test } from 'node:test';
import assert from 'node:assert/strict';
import { zipSync, strToU8 } from 'fflate';
import { parseBackupArchive, validateBackupPayloadContents } from '../src/services/backup-archive';
import { toSafeAttachmentBlobKey } from '../src/services/backup-import';
import { getAttachmentObjectKey, getSendFileObjectKey } from '../src/services/blob-store';

// Restore writes attachment bytes into the blob store under a key it rebuilds from
// db.json, which is data the uploader controls. The blob store is one flat keyspace:
// attachments live at `<cipherId>/<attachmentId>` and Send files at
// `sends/<sendId>/<fileId>`. A row whose ids smuggle a slash therefore aims the write
// somewhere restore has no business writing. Three layers stop that today and each one
// is asserted here, because the write site used to depend on the other two silently.

const CIPHER_ID = '6f9b1b3e-0d4a-4d4d-8a6f-2b7f9c1d4e55';
const ATTACHMENT_ID = 'b4d7e2a1-88cc-4f10-9d31-0a6e5c2f7b93';
const SEND_ID = 'aa11bb22-cc33-dd44-ee55-ff6677889900';
const SEND_FILE_ID = '0123456789abcdef';

function backupUser() {
  return { id: 'u-1', email: 'owner@example.test' };
}

function backupPayload(attachmentRows: Array<Record<string, string | number | null>>) {
  return {
    manifest: {
      formatVersion: 1 as const,
      exportedAt: '2026-09-11T00:00:00.000Z',
      appVersion: 'test',
      storageKind: 'r2' as const,
      tableCounts: {},
      includes: { attachments: true },
      blobSummary: { attachmentFiles: attachmentRows.length, totalBytes: 0, largestObjectBytes: 0 },
    },
    db: {
      config: [],
      users: [backupUser()],
      domain_settings: [],
      user_revisions: [],
      folders: [],
      ciphers: [{ id: CIPHER_ID, user_id: 'u-1', folder_id: null }],
      attachments: attachmentRows,
    },
  };
}

test('a well formed attachment row keeps its own blob key', () => {
  const key = toSafeAttachmentBlobKey(CIPHER_ID, ATTACHMENT_ID);
  assert.equal(key, getAttachmentObjectKey(CIPHER_ID, ATTACHMENT_ID));
  assert.equal(key, `${CIPHER_ID}/${ATTACHMENT_ID}`);
});

test('an attachment row cannot address a Send file blob', () => {
  // This is the shape that matters: the two halves concatenate into exactly the key
  // getSendFileObjectKey() produces, so an unguarded restore would overwrite the file
  // behind somebody else's Send link with bytes from the uploaded archive.
  const forgedKey = getAttachmentObjectKey('sends', `${SEND_ID}/${SEND_FILE_ID}`);
  assert.equal(forgedKey, getSendFileObjectKey(SEND_ID, SEND_FILE_ID));
  assert.equal(toSafeAttachmentBlobKey('sends', `${SEND_ID}/${SEND_FILE_ID}`), null);
});

test('the blob key guard rejects traversal, empties, and oversized segments', () => {
  for (const [cipherId, attachmentId] of [
    ['..', ATTACHMENT_ID],
    [CIPHER_ID, '..'],
    ['.', '.'],
    ['', ATTACHMENT_ID],
    [CIPHER_ID, ''],
    [`${CIPHER_ID}/x`, ATTACHMENT_ID],
    [CIPHER_ID, `x/${ATTACHMENT_ID}`],
    ['a\\b', ATTACHMENT_ID],
    [CIPHER_ID, 'a b'],
    ['x'.repeat(129), ATTACHMENT_ID],
  ] as Array<[string, string]>) {
    assert.equal(
      toSafeAttachmentBlobKey(cipherId, attachmentId),
      null,
      `expected ${cipherId}/${attachmentId} to be refused`
    );
  }
  assert.equal(toSafeAttachmentBlobKey('x'.repeat(128), 'y'.repeat(128)), `${'x'.repeat(128)}/${'y'.repeat(128)}`);
});

test('the archive reader refuses a zip entry that spells a Send file key', () => {
  const archive = zipSync({
    'manifest.json': strToU8(JSON.stringify(backupPayload([]).manifest)),
    'db.json': strToU8(JSON.stringify(backupPayload([]).db)),
    [`attachments/sends/${SEND_ID}/${SEND_FILE_ID}.bin`]: new Uint8Array([1, 2, 3]),
  });
  assert.throws(() => parseBackupArchive(archive), /unsupported file|unsafe file name/i);
});

test('payload validation refuses an attachment row whose ids carry a slash', () => {
  const payload = backupPayload([{ id: `${SEND_ID}/${SEND_FILE_ID}`, cipher_id: 'sends', size: 3 }]);
  assert.throws(
    () => validateBackupPayloadContents(payload as never, {}),
    /invalid attachment row/i
  );
});

test('payload validation still accepts an ordinary attachment row with its file present', () => {
  const payload = backupPayload([{ id: ATTACHMENT_ID, cipher_id: CIPHER_ID, size: 3 }]);
  const files = { [`attachments/${CIPHER_ID}/${ATTACHMENT_ID}.bin`]: new Uint8Array([1, 2, 3]) };
  validateBackupPayloadContents(payload as never, files);
});
