import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isOrgManager,
  isOrgAdmin,
  isOrgOwner,
  canAccessAllCollections,
  canAssignOrgRole,
  orgRoleRank,
} from '../src/services/storage-organization-repo';
import { isAllowedSsoRedirectUri } from '../src/utils/origins';
import { readOrgCipherFields, setOrgCipherFields, isOrgCipher as isOrgCipherAccess } from '../src/services/storage-org-access';
import { organizationForMember } from '../src/utils/profile-response';

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

test('org role assignment is capped at the actor own rank', () => {
  assert.equal(orgRoleRank('owner') > orgRoleRank('admin'), true);
  assert.equal(orgRoleRank('admin') > orgRoleRank('manager'), true);
  assert.equal(orgRoleRank('manager') > orgRoleRank('member'), true);
  assert.equal(orgRoleRank('nonsense'), 0);

  // A manager cannot mint an admin or an owner.
  assert.equal(canAssignOrgRole(member({ role: 'manager' }), 'owner'), false);
  assert.equal(canAssignOrgRole(member({ role: 'manager' }), 'admin'), false);
  assert.equal(canAssignOrgRole(member({ role: 'manager' }), 'manager'), true);
  assert.equal(canAssignOrgRole(member({ role: 'manager' }), 'member'), true);

  // An admin cannot mint an owner.
  assert.equal(canAssignOrgRole(member({ role: 'admin' }), 'owner'), false);
  assert.equal(canAssignOrgRole(member({ role: 'admin' }), 'admin'), true);

  assert.equal(canAssignOrgRole(member({ role: 'owner' }), 'owner'), true);
  assert.equal(canAssignOrgRole(member({ role: 'member' }), 'member'), true);
  assert.equal(canAssignOrgRole(member({ role: 'member' }), 'manager'), false);

  // Unknown roles and non-members never pass.
  assert.equal(canAssignOrgRole(member({ role: 'owner' }), 'nonsense'), false);
  assert.equal(canAssignOrgRole(member({ role: 'owner', status: 0 }), 'member'), false);
  assert.equal(canAssignOrgRole(null, 'member'), false);
});

test('sso redirect_uri allowlist only accepts the server origin and configured origins', () => {
  const env = { SSO_ALLOWED_REDIRECT_ORIGINS: 'https://vault.example.com' };
  const origin = 'https://nodewarden.example.com';

  assert.equal(isAllowedSsoRedirectUri(env, origin, 'https://nodewarden.example.com/'), true);
  assert.equal(isAllowedSsoRedirectUri(env, origin, 'https://nodewarden.example.com/sso?x=1'), true);
  assert.equal(isAllowedSsoRedirectUri(env, origin, 'https://vault.example.com/callback'), true);

  // Code exfiltration attempts.
  assert.equal(isAllowedSsoRedirectUri(env, origin, 'https://evil.tld/'), false);
  assert.equal(isAllowedSsoRedirectUri(env, origin, 'https://nodewarden.example.com.evil.tld/'), false);
  assert.equal(isAllowedSsoRedirectUri(env, origin, 'https://evil.tld#nodewarden.example.com'), false);
  assert.equal(isAllowedSsoRedirectUri(env, origin, 'https://nodewarden.example.com@evil.tld/'), false);
  assert.equal(isAllowedSsoRedirectUri(env, origin, '//evil.tld'), false);
  assert.equal(isAllowedSsoRedirectUri(env, origin, '/relative'), false);
  assert.equal(isAllowedSsoRedirectUri(env, origin, ''), false);
  assert.equal(isAllowedSsoRedirectUri(env, origin, 'javascript:alert(1)'), false);

  // Fragments break the code append and are not valid OAuth redirect URIs.
  assert.equal(isAllowedSsoRedirectUri(env, origin, 'https://nodewarden.example.com/#/x'), false);

  // Without configuration only the server own origin is allowed.
  assert.equal(isAllowedSsoRedirectUri({}, origin, 'https://vault.example.com/'), false);
  assert.equal(isAllowedSsoRedirectUri({}, origin, 'https://nodewarden.example.com/'), true);
});

test('deleting an account hands its organizations and org ciphers to a survivor', async () => {
  const statements: Array<{ sql: string; args: unknown[] }> = [];
  const orgRow = {
    id: 'org-1', name: 'Acme', enabled: 1, use_totp: 0, owner_id: 'owner-1', billing_email: null,
    public_key: null, private_key: null, identifier: null,
    created_at: '2026-01-01T00:00:00.000Z', updated_at: '2026-01-01T00:00:00.000Z',
  };
  const memberRows = [
    { organization_id: 'org-1', user_id: 'owner-1', status: 1, role: 'owner', permissions: '{}', collections: '[]', encrypted_org_key: null, created_at: '2026-01-01T00:00:00.000Z', updated_at: '2026-01-01T00:00:00.000Z' },
    { organization_id: 'org-1', user_id: 'member-1', status: 1, role: 'member', permissions: '{}', collections: '[]', encrypted_org_key: null, created_at: '2026-01-02T00:00:00.000Z', updated_at: '2026-01-02T00:00:00.000Z' },
    // Ranks above the plain member, so this one inherits the organization.
    { organization_id: 'org-1', user_id: 'admin-1', status: 1, role: 'admin', permissions: '{}', collections: '[]', encrypted_org_key: null, created_at: '2026-01-03T00:00:00.000Z', updated_at: '2026-01-03T00:00:00.000Z' },
  ];

  const mockDb = {
    prepare(sql: string) {
      const statement = { sql, args: [] as unknown[] };
      return {
        bind(...args: unknown[]) {
          statement.args = args;
          statements.push(statement);
          return this;
        },
        async all() {
          if (sql.includes('SELECT id FROM organizations WHERE owner_id')) return { results: [{ id: 'org-1' }] };
          if (sql.includes('FROM organization_members WHERE organization_id = ? ORDER BY created_at')) return { results: memberRows };
          if (sql.includes('SELECT organization_id FROM organization_members WHERE user_id')) return { results: [{ organization_id: 'org-1' }] };
          if (sql.includes('SELECT user_id FROM organization_members WHERE organization_id')) return { results: memberRows.map((row) => ({ user_id: row.user_id })) };
          return { results: [] };
        },
        async first() {
          if (sql.includes('FROM organizations WHERE id = ?')) return { ...orgRow, owner_id: 'admin-1' };
          return null;
        },
        async run() {
          return { meta: { changes: 1 } };
        },
      };
    },
  } as any;

  const { transferOrganizationDataOnUserDelete } = await import('../src/services/storage-organization-repo');
  const affected = await transferOrganizationDataOnUserDelete(mockDb, 'owner-1');

  // The organization is handed over, never deleted.
  assert.equal(statements.some((s) => s.sql.includes('DELETE FROM organizations')), false);
  const transfer = statements.find((s) => s.sql.includes('UPDATE organizations SET owner_id'));
  assert.ok(transfer, 'expected an ownership transfer');
  assert.equal(transfer!.args[0], 'admin-1');

  // The successor is promoted to owner.
  const promotion = statements.find((s) => s.sql.includes('INSERT INTO organization_members'));
  assert.ok(promotion, 'expected the successor to be saved');
  assert.equal(promotion!.args[1], 'admin-1');
  assert.equal(promotion!.args[3], 'owner');

  // Org ciphers authored by the deleted account move to the new owner.
  const cipherMove = statements.find((s) => s.sql.includes('UPDATE ciphers SET user_id'));
  assert.ok(cipherMove, 'expected org ciphers to be reassigned');
  assert.equal(cipherMove!.args[0], 'admin-1');
  assert.equal(cipherMove!.args[2], 'owner-1');
  assert.equal(cipherMove!.args[3], 'org-1');

  // Remaining members are told to resync; the deleted account is not.
  assert.equal(affected.includes('owner-1'), false);
  assert.deepEqual(affected.sort(), ['admin-1', 'member-1']);
});

test('deleting the only member of an organization removes the organization', async () => {
  const statements: string[] = [];
  const mockDb = {
    prepare(sql: string) {
      statements.push(sql);
      return {
        bind() { return this; },
        async all() {
          if (sql.includes('SELECT id FROM organizations WHERE owner_id')) return { results: [{ id: 'org-1' }] };
          return { results: [] };
        },
        async first() { return null; },
        async run() { return { meta: { changes: 1 } }; },
      };
    },
  } as any;

  const { transferOrganizationDataOnUserDelete } = await import('../src/services/storage-organization-repo');
  const affected = await transferOrganizationDataOnUserDelete(mockDb, 'owner-1');

  assert.equal(statements.some((sql) => sql.includes('DELETE FROM organizations')), true);
  assert.equal(statements.some((sql) => sql.includes('UPDATE organizations SET owner_id')), false);
  assert.deepEqual(affected, []);
});

test('deleting a collection strips it from every member access list', async () => {
  const memberRows = [
    { organization_id: 'org-1', user_id: 'user-a', status: 1, role: 'member', permissions: '{}', collections: '["col-1","col-2"]', encrypted_org_key: null, created_at: '2026-01-01T00:00:00.000Z', updated_at: '2026-01-01T00:00:00.000Z' },
    { organization_id: 'org-1', user_id: 'user-b', status: 1, role: 'member', permissions: '{}', collections: '["col-2"]', encrypted_org_key: null, created_at: '2026-01-01T00:00:00.000Z', updated_at: '2026-01-01T00:00:00.000Z' },
  ];
  const saved: unknown[][] = [];
  let deleted = false;

  const mockDb = {
    prepare(sql: string) {
      return {
        bind(...args: unknown[]) {
          if (sql.includes('INSERT INTO organization_members')) saved.push(args);
          if (sql.includes('DELETE FROM collections')) deleted = true;
          return this;
        },
        async all() {
          if (sql.includes('FROM organization_members WHERE organization_id = ? ORDER BY created_at')) return { results: memberRows };
          return { results: [] };
        },
        async first() {
          if (sql.includes('FROM collections WHERE id = ?')) {
            return { id: 'col-1', organization_id: 'org-1', name: 'Shared', external_id: null, created_at: '2026-01-01T00:00:00.000Z', updated_at: '2026-01-01T00:00:00.000Z' };
          }
          return null;
        },
        async run() { return { meta: { changes: 1 } }; },
      };
    },
  } as any;

  const { deleteCollection } = await import('../src/services/storage-organization-repo');
  const affected = await deleteCollection(mockDb, 'col-1');

  assert.equal(deleted, true);
  // Only the member that referenced col-1 is rewritten, and col-1 is gone from it.
  assert.deepEqual(affected, ['user-a']);
  assert.equal(saved.length, 1);
  assert.equal(saved[0][1], 'user-a');
  assert.deepEqual(JSON.parse(String(saved[0][5])), ['col-2']);
});

test('organization ciphers never carry personal folder, favorite, or archive state', () => {
  const orgCipher: any = { id: 'cipher-1', folderId: 'personal-folder-1', favorite: true, archivedAt: '2026-01-01T00:00:00.000Z' };
  setOrgCipherFields(orgCipher, 'org-1', ['col-1']);
  // All three live on the shared row, so one member must not set them for everyone.
  assert.equal(orgCipher.folderId, null);
  assert.equal(orgCipher.favorite, false);
  assert.equal(orgCipher.archivedAt, null);

  // Personal ciphers keep theirs.
  const personal: any = { id: 'cipher-2', folderId: 'personal-folder-1', favorite: true, archivedAt: '2026-01-01T00:00:00.000Z' };
  setOrgCipherFields(personal, null, []);
  assert.equal(personal.folderId, 'personal-folder-1');
  assert.equal(personal.favorite, true);
  assert.equal(personal.archivedAt, '2026-01-01T00:00:00.000Z');
});

test('a profile organization carries the member wrapped key, not the org public key', () => {
  const org = {
    id: 'org-1',
    name: 'Engineering',
    enabled: true,
    useTotp: false,
    ownerId: 'user-1',
    billingEmail: null,
    publicKey: 'ORG-PUBLIC-KEY',
    privateKey: 'ORG-PRIVATE-KEY',
    identifier: null,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
  } as any;

  const seen = organizationForMember(org, member({ encryptedOrgKey: 'WRAPPED-FOR-THIS-MEMBER' }) as any);

  // The defect this test exists for: `key` used to be the organization's
  // public key, which no member can unwrap. A client following the protocol
  // would have failed every field of every shared item.
  assert.equal(seen.key, 'WRAPPED-FOR-THIS-MEMBER');
  assert.notEqual(seen.key, org.publicKey);
  // The organization's public key still has its own field.
  assert.equal(seen.publicKey, 'ORG-PUBLIC-KEY');
  // And the spelling this server has always sent keeps working, with the
  // same value, so nothing already reading it breaks.
  assert.equal(seen.encryptedOrgKey, 'WRAPPED-FOR-THIS-MEMBER');

  // A membership with no wrapped key yields null rather than something
  // unusable: a client that cannot unwrap should be told so, not handed a
  // key that will never work.
  const keyless = organizationForMember(org, member() as any);
  assert.equal(keyless.key, null);
  assert.equal(keyless.encryptedOrgKey, null);

  // Only owners and admins are handed the organization's private key.
  assert.equal(organizationForMember(org, member({ role: 'owner' }) as any).privateKey, 'ORG-PRIVATE-KEY');
  assert.equal(organizationForMember(org, member({ role: 'member' }) as any).privateKey, null);
});
