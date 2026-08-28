import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isOrgManager,
  isOrgAdmin,
  isOrgOwner,
  canAccessAllCollections,
} from '../src/services/storage-organization-repo';
import { readOrgCipherFields, setOrgCipherFields, isOrgCipher as isOrgCipherAccess } from '../src/services/storage-org-access';

function member(overrides: Record<string, unknown> = {}) {
  return {
    organizationId: 'org-1',
    userId: 'user-1',
    status: 1,
    role: 'member',
    permissions: {},
    collections: [],
    encryptedOrgKey: null,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

test('org role helpers enforce membership and role rules', () => {
  assert.equal(isOrgManager(member({ role: 'owner' })), true);
  assert.equal(isOrgManager(member({ role: 'admin' })), true);
  assert.equal(isOrgManager(member({ role: 'manager' })), true);
  assert.equal(isOrgManager(member({ role: 'member' })), false);
  assert.equal(isOrgManager(member({ status: 0 })), false);
  assert.equal(isOrgManager(null), false);

  assert.equal(isOrgAdmin(member({ role: 'owner' })), true);
  assert.equal(isOrgAdmin(member({ role: 'admin' })), true);
  assert.equal(isOrgAdmin(member({ role: 'manager' })), false);

  assert.equal(isOrgOwner(member({ role: 'owner' })), true);
  assert.equal(isOrgOwner(member({ role: 'admin' })), false);

  assert.equal(canAccessAllCollections(member({ role: 'manager' })), true);
  assert.equal(canAccessAllCollections(member({ role: 'member' })), false);
});

test('org cipher fields round-trip and detection', () => {
  const cipher: any = {};
  setOrgCipherFields(cipher, 'org-1', ['collection-1']);
  const { organizationId, collectionIds } = readOrgCipherFields(cipher);
  assert.equal(organizationId, 'org-1');
  assert.deepEqual(collectionIds, ['collection-1']);
  assert.equal(isOrgCipherAccess(cipher), true);

  const personal: any = {};
  setOrgCipherFields(personal, null, []);
  assert.equal(isOrgCipherAccess(personal), false);
  assert.equal(readOrgCipherFields(personal).organizationId, null);
});

test('readOrgCipherFields normalizes malformed input', () => {
  assert.deepEqual(readOrgCipherFields({} as any), { organizationId: null, collectionIds: [] });
  assert.deepEqual(
    readOrgCipherFields({ organizationId: '  org-2  ', collectionIds: [' a ', '', 'b'] } as any),
    { organizationId: 'org-2', collectionIds: ['a', 'b'] }
  );
});

test('getCiphersByCollectionIds builds chunked IN queries against D1', async () => {
  const seenSql: string[] = [];
  const mockDb = {
    prepare(sql: string) {
      seenSql.push(sql);
      return this;
    },
    bind() {
      return this;
    },
    async all() {
      return { results: [] };
    },
  } as any;
  const { getCiphersByCollectionIds } = await import('../src/services/storage-cipher-repo');
  const result = await getCiphersByCollectionIds(mockDb, () => 95, ['collection-1', 'collection-2']);
  assert.deepEqual(result, []);
  assert.equal(seenSql.length, 1);
  assert.match(seenSql[0], /JOIN collection_items/);
  assert.match(seenSql[0], /IN \(\?,\?\)/);
});