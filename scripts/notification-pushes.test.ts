import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// Which push each handler sends, read off the handler's own body.
//
// Every Bitwarden client answers a whole-vault push (`SyncVault`) with a full
// `GET /api/sync`, and answers a `SyncCipher*` push by fetching that one
// cipher. The single-cipher handlers used to send both, so a one-item edit made
// every connected client download the whole vault: measured at ~13,600 D1 rows
// read for one delete with eight clients connected. These tests hold the fix.

function bodies(path: string): Map<string, string> {
  const source = readFileSync(new URL(`../${path}`, import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  const found = new Map<string, string>();
  const heads = [...source.matchAll(/^export async function (\w+)\(/gm)];
  heads.forEach((head, i) => {
    const end = i + 1 < heads.length ? heads[i + 1].index : source.length;
    found.set(head[1], source.slice(head.index, end));
  });
  return found;
}

const ciphers = bodies('src/handlers/ciphers.ts');
const attachments = bodies('src/handlers/attachments.ts');

function body(from: Map<string, string>, name: string): string {
  const found = from.get(name);
  assert.ok(found, `no handler named ${name}; the file was reorganised and this test must follow it`);
  return found;
}

const VAULT_SYNC = 'notifyVaultSyncForRequest(';

test('a single-cipher change sends its own push and no whole-vault push', () => {
  const expected: Array<[string, string]> = [
    ['handleCreateCipher', 'notifyCipherCreateForRequest('],
    ['handleUpdateCipher', 'notifyCipherUpdateForRequest('],
    ['handlePartialUpdateCipher', 'notifyCipherUpdateForRequest('],
    ['handleRestoreCipher', 'notifyCipherUpdateForRequest('],
    ['handleArchiveCipher', 'notifyCipherUpdateForRequest('],
    ['handleUnarchiveCipher', 'notifyCipherUpdateForRequest('],
    ['handlePermanentDeleteCipher', 'notifyCipherDeleteForRequest('],
    ['handleDeleteCipherCompat', 'notifyCipherDeleteForRequest('],
  ];
  for (const [name, push] of expected) {
    const text = body(ciphers, name);
    assert.ok(text.includes(push), `${name} does not send ${push.slice(0, -1)}`);
    assert.ok(!text.includes(VAULT_SYNC), `${name} still sends a whole-vault push beside its own`);
  }
});

test('a soft delete is announced as an update, so clients move the item to their trash', () => {
  const text = body(ciphers, 'handleDeleteCipher');
  assert.ok(text.includes('notifyCipherUpdateForRequest('), 'a soft delete is not announced as an update');
  assert.ok(!text.includes('notifyCipherDeleteForRequest('), 'a soft delete is announced as a delete');
  assert.ok(!text.includes(VAULT_SYNC), 'a soft delete still sends a whole-vault push');
});

test('an attachment change sends the cipher update and no whole-vault push', () => {
  for (const name of ['handleCreateAttachment', 'handleUpdateAttachmentMetadata', 'handleDeleteAttachment']) {
    const text = body(attachments, name);
    assert.ok(text.includes('notifyCipherUpdateForRequest('), `${name} does not send the cipher update`);
    assert.ok(!text.includes(VAULT_SYNC), `${name} still sends a whole-vault push`);
  }
  const whole = readFileSync(new URL('../src/handlers/attachments.ts', import.meta.url), 'utf8');
  assert.ok(!whole.includes(VAULT_SYNC), 'attachments.ts still sends a whole-vault push somewhere');
});

test('a bulk change still sends the whole-vault push, because no single cipher describes it', () => {
  // CONTROL: the rule above is not "never send it". A bulk move names no
  // cipher, and without this push no client would learn of it at all.
  for (const name of [
    'handleBulkMoveCiphers',
    'handleBulkArchiveCiphers',
    'handleBulkUnarchiveCiphers',
    'handleBulkDeleteCiphers',
    'handleBulkRestoreCiphers',
    'handleBulkPermanentDeleteCiphers',
  ]) {
    assert.ok(body(ciphers, name).includes(VAULT_SYNC), `${name} no longer announces anything`);
  }
});
