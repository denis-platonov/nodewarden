import type { Organization, OrganizationMember, Collection, CollectionItem, OrganizationInvitation, Policy } from '../types';
import type { D1Database } from '@cloudflare/workers-types';

function mapOrganizationRow(row: any): Organization {
  return {
    id: row.id,
    name: row.name,
    enabled: Boolean(row.enabled),
    useTotp: Boolean(row.use_totp),
    ownerId: row.owner_id,
    billingEmail: row.billing_email,
    publicKey: row.public_key ?? null,
    privateKey: row.private_key ?? null,
    identifier: row.identifier ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapMemberRow(row: any): OrganizationMember {
  return {
    organizationId: row.organization_id,
    userId: row.user_id,
    status: row.status,
    role: row.role,
    permissions: row.permissions ? JSON.parse(row.permissions) : {},
    collections: row.collections ? JSON.parse(row.collections) : [],
    encryptedOrgKey: row.encrypted_org_key ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapCollectionRow(row: any): Collection {
  return {
    id: row.id,
    organizationId: row.organization_id,
    name: row.name,
    externalId: row.external_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapCollectionItemRow(row: any): CollectionItem {
  return {
    collectionId: row.collection_id,
    cipherId: row.cipher_id,
  };
}

function mapInvitationRow(row: any): OrganizationInvitation {
  return {
    id: row.id,
    organizationId: row.organization_id,
    email: row.email,
    role: row.role,
    permissions: row.permissions ? JSON.parse(row.permissions) : {},
    collections: row.collections ? JSON.parse(row.collections) : [],
    invitedBy: row.invited_by,
    status: row.status,
    token: row.token,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapPolicyRow(row: any): Policy {
  return {
    id: row.id,
    organizationId: row.organization_id,
    type: row.type,
    data: row.data ? JSON.parse(row.data) : {},
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function getOrganization(db: D1Database, id: string): Promise<Organization | null> {
  const row = await db
    .prepare('SELECT id, name, enabled, use_totp, owner_id, billing_email, public_key, private_key, identifier, created_at, updated_at FROM organizations WHERE id = ?')
    .bind(id)
    .first<any>();
  if (!row) return null;
  return mapOrganizationRow(row);
}

export async function getOrganizationsForUser(db: D1Database, userId: string): Promise<Organization[]> {
  const res = await db
    .prepare(
      `SELECT o.id, o.name, o.enabled, o.use_totp, o.owner_id, o.billing_email, o.public_key, o.private_key, o.identifier, o.created_at, o.updated_at
       FROM organizations o
       JOIN organization_members om ON o.id = om.organization_id
       WHERE om.user_id = ? AND om.status = 1
       ORDER BY o.updated_at DESC`
    )
    .bind(userId)
    .all<any>();
  return (res.results || []).map(mapOrganizationRow);
}

export async function getOrganizationByIdentifier(db: D1Database, identifier: string): Promise<Organization | null> {
  const row = await db
    .prepare('SELECT id, name, enabled, use_totp, owner_id, billing_email, public_key, private_key, identifier, created_at, updated_at FROM organizations WHERE identifier = ? COLLATE NOCASE')
    .bind(identifier)
    .first<any>();
  if (!row) return null;
  return mapOrganizationRow(row);
}

export async function saveOrganization(db: D1Database, org: Organization): Promise<void> {
  await db
    .prepare(
      'INSERT INTO organizations(id, name, enabled, use_totp, owner_id, billing_email, public_key, private_key, identifier, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(id) DO UPDATE SET name=excluded.name, enabled=excluded.enabled, use_totp=excluded.use_totp, billing_email=excluded.billing_email, public_key=excluded.public_key, private_key=excluded.private_key, identifier=excluded.identifier, updated_at=excluded.updated_at'
    )
    .bind(org.id, org.name, org.enabled ? 1 : 0, org.useTotp ? 1 : 0, org.ownerId, org.billingEmail, org.publicKey, org.privateKey, org.identifier, org.createdAt, org.updatedAt)
    .run();
}

export async function deleteOrganization(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM organizations WHERE id = ?').bind(id).run();
}

export async function getOrganizationMember(db: D1Database, organizationId: string, userId: string): Promise<OrganizationMember | null> {
  const row = await db
    .prepare('SELECT organization_id, user_id, status, role, permissions, collections, encrypted_org_key, created_at, updated_at FROM organization_members WHERE organization_id = ? AND user_id = ?')
    .bind(organizationId, userId)
    .first<any>();
  if (!row) return null;
  return mapMemberRow(row);
}

export async function getOrganizationMembershipsForUser(db: D1Database, userId: string): Promise<OrganizationMember[]> {
  const res = await db
    .prepare('SELECT organization_id, user_id, status, role, permissions, collections, encrypted_org_key, created_at, updated_at FROM organization_members WHERE user_id = ? AND status = 1')
    .bind(userId)
    .all<any>();
  return (res.results || []).map(mapMemberRow);
}

export async function getOrganizationMemberIds(db: D1Database, organizationId: string): Promise<string[]> {
  const res = await db
    .prepare('SELECT user_id FROM organization_members WHERE organization_id = ?')
    .bind(organizationId)
    .all<{ user_id: string }>();
  return (res.results || []).map((r) => r.user_id);
}

export function isOrgManager(member: OrganizationMember | null | undefined): boolean {
  if (!member || member.status !== 1) return false;
  return member.role === 'owner' || member.role === 'admin' || member.role === 'manager';
}

export function isOrgAdmin(member: OrganizationMember | null | undefined): boolean {
  if (!member || member.status !== 1) return false;
  return member.role === 'owner' || member.role === 'admin';
}

export function isOrgOwner(member: OrganizationMember | null | undefined): boolean {
  if (!member || member.status !== 1) return false;
  return member.role === 'owner';
}

const ORG_ROLE_RANK: Record<string, number> = {
  owner: 4,
  admin: 3,
  manager: 2,
  member: 1,
  custom: 1,
};

export function orgRoleRank(role: unknown): number {
  return ORG_ROLE_RANK[String(role || '').trim().toLowerCase()] ?? 0;
}

// A member may only grant roles at or below their own rank, so a manager cannot
// mint an admin and an admin cannot mint an owner.
export function canAssignOrgRole(actor: OrganizationMember | null | undefined, role: unknown): boolean {
  if (!actor || actor.status !== 1) return false;
  const rank = orgRoleRank(role);
  return rank > 0 && rank <= orgRoleRank(actor.role);
}

export function canAccessAllCollections(member: OrganizationMember | null | undefined): boolean {
  if (!member || member.status !== 1) return false;
  return member.role === 'owner' || member.role === 'admin' || member.role === 'manager';
}

export async function getAccessibleCollectionsForUser(db: D1Database, userId: string): Promise<Collection[]> {
  const memberships = await getOrganizationMembershipsForUser(db, userId);
  if (!memberships.length) return [];

  const orgIds = memberships.map((m) => m.organizationId);
  const orgCollections: Array<{ orgId: string; collection: Collection }> = [];
  for (const orgId of orgIds) {
    const cols = await getCollectionsForOrganization(db, orgId);
    for (const col of cols) orgCollections.push({ orgId, collection: col });
  }

  const accessible = new Set<string>();
  for (const membership of memberships) {
    if (canAccessAllCollections(membership)) {
      for (const entry of orgCollections) {
        if (entry.orgId === membership.organizationId) accessible.add(entry.collection.id);
      }
    } else {
      for (const collectionId of membership.collections || []) accessible.add(collectionId);
    }
  }

  return orgCollections.map((entry) => entry.collection).filter((collection) => accessible.has(collection.id));
}

export async function getOrganizationMembers(db: D1Database, organizationId: string): Promise<OrganizationMember[]> {
  const res = await db
    .prepare('SELECT organization_id, user_id, status, role, permissions, collections, encrypted_org_key, created_at, updated_at FROM organization_members WHERE organization_id = ? ORDER BY created_at ASC')
    .bind(organizationId)
    .all<any>();
  return (res.results || []).map(mapMemberRow);
}

export async function getOrganizationMembersByUserIds(db: D1Database, organizationId: string, userIds: string[]): Promise<OrganizationMember[]> {
  if (!userIds.length) return [];
  const placeholders = userIds.map(() => '?').join(',');
  const res = await db
    .prepare(`SELECT organization_id, user_id, status, role, permissions, collections, encrypted_org_key, created_at, updated_at FROM organization_members WHERE organization_id = ? AND user_id IN (${placeholders})`)
    .bind(organizationId, ...userIds)
    .all<any>();
  return (res.results || []).map(mapMemberRow);
}

export async function saveOrganizationMember(db: D1Database, member: OrganizationMember): Promise<void> {
  await db
    .prepare(
      'INSERT INTO organization_members(organization_id, user_id, status, role, permissions, collections, encrypted_org_key, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(organization_id, user_id) DO UPDATE SET status=excluded.status, role=excluded.role, permissions=excluded.permissions, collections=excluded.collections, encrypted_org_key=excluded.encrypted_org_key, updated_at=excluded.updated_at'
    )
    .bind(
      member.organizationId,
      member.userId,
      member.status,
      member.role,
      JSON.stringify(member.permissions || {}),
      JSON.stringify(member.collections || []),
      member.encryptedOrgKey,
      member.createdAt,
      member.updatedAt
    )
    .run();
}

export async function deleteOrganizationMember(db: D1Database, organizationId: string, userId: string): Promise<void> {
  await db.prepare('DELETE FROM organization_members WHERE organization_id = ? AND user_id = ?').bind(organizationId, userId).run();
}

export async function getCollection(db: D1Database, id: string): Promise<Collection | null> {
  const row = await db
    .prepare('SELECT id, organization_id, name, external_id, created_at, updated_at FROM collections WHERE id = ?')
    .bind(id)
    .first<any>();
  if (!row) return null;
  return mapCollectionRow(row);
}

export async function getCollectionsForOrganization(db: D1Database, organizationId: string): Promise<Collection[]> {
  const res = await db
    .prepare('SELECT id, organization_id, name, external_id, created_at, updated_at FROM collections WHERE organization_id = ? ORDER BY name ASC')
    .bind(organizationId)
    .all<any>();
  return (res.results || []).map(mapCollectionRow);
}

export async function saveCollection(db: D1Database, collection: Collection): Promise<void> {
  await db
    .prepare(
      'INSERT INTO collections(id, organization_id, name, external_id, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(id) DO UPDATE SET name=excluded.name, external_id=excluded.external_id, updated_at=excluded.updated_at'
    )
    .bind(collection.id, collection.organizationId, collection.name, collection.externalId, collection.createdAt, collection.updatedAt)
    .run();
}

// Also strips the collection from every member's access list, so a deleted
// collection cannot linger as a stale id. Returns the members that changed.
export async function deleteCollection(db: D1Database, id: string): Promise<string[]> {
  const collection = await getCollection(db, id);
  await db.prepare('DELETE FROM collections WHERE id = ?').bind(id).run();
  if (!collection) return [];

  const affected: string[] = [];
  for (const member of await getOrganizationMembers(db, collection.organizationId)) {
    const collections = member.collections || [];
    if (!collections.includes(id)) continue;
    member.collections = collections.filter((collectionId) => collectionId !== id);
    member.updatedAt = new Date().toISOString();
    await saveOrganizationMember(db, member);
    affected.push(member.userId);
  }
  return affected;
}

export async function addCollectionItem(db: D1Database, collectionId: string, cipherId: string): Promise<void> {
  await db
    .prepare('INSERT OR IGNORE INTO collection_items(collection_id, cipher_id) VALUES(?, ?)')
    .bind(collectionId, cipherId)
    .run();
}

export async function removeCollectionItem(db: D1Database, collectionId: string, cipherId: string): Promise<void> {
  await db.prepare('DELETE FROM collection_items WHERE collection_id = ? AND cipher_id = ?').bind(collectionId, cipherId).run();
}

export async function getCollectionItems(db: D1Database, collectionId: string): Promise<CollectionItem[]> {
  const res = await db
    .prepare('SELECT collection_id, cipher_id FROM collection_items WHERE collection_id = ?')
    .bind(collectionId)
    .all<any>();
  return (res.results || []).map(mapCollectionItemRow);
}

export async function getCipherCollections(db: D1Database, cipherId: string): Promise<string[]> {
  const res = await db
    .prepare('SELECT collection_id FROM collection_items WHERE cipher_id = ?')
    .bind(cipherId)
    .all<any>();
  return (res.results || []).map((r) => r.collection_id);
}

export async function removeCipherFromAllCollections(db: D1Database, cipherId: string): Promise<void> {
  await db.prepare('DELETE FROM collection_items WHERE cipher_id = ?').bind(cipherId).run();
}

export async function getOrganizationInvitation(db: D1Database, id: string): Promise<OrganizationInvitation | null> {
  const row = await db
    .prepare('SELECT id, organization_id, email, role, permissions, collections, invited_by, status, token, expires_at, created_at, updated_at FROM organization_invitations WHERE id = ?')
    .bind(id)
    .first<any>();
  if (!row) return null;
  return mapInvitationRow(row);
}

export async function getOrganizationInvitationByToken(db: D1Database, token: string): Promise<OrganizationInvitation | null> {
  const row = await db
    .prepare('SELECT id, organization_id, email, role, permissions, collections, invited_by, status, token, expires_at, created_at, updated_at FROM organization_invitations WHERE token = ?')
    .bind(token)
    .first<any>();
  if (!row) return null;
  return mapInvitationRow(row);
}

export async function getOrganizationInvitations(db: D1Database, organizationId: string): Promise<OrganizationInvitation[]> {
  const res = await db
    .prepare('SELECT id, organization_id, email, role, permissions, collections, invited_by, status, token, expires_at, created_at, updated_at FROM organization_invitations WHERE organization_id = ? ORDER BY created_at DESC')
    .bind(organizationId)
    .all<any>();
  return (res.results || []).map(mapInvitationRow);
}

// Invitations addressed to one person, across every organization.
export async function getOrganizationInvitationsForEmail(db: D1Database, email: string): Promise<OrganizationInvitation[]> {
  const res = await db
    .prepare('SELECT id, organization_id, email, role, permissions, collections, invited_by, status, token, expires_at, created_at, updated_at FROM organization_invitations WHERE email = ? COLLATE NOCASE ORDER BY created_at DESC')
    .bind(email.toLowerCase())
    .all<any>();
  return (res.results || []).map(mapInvitationRow);
}

export async function saveOrganizationInvitation(db: D1Database, invitation: OrganizationInvitation): Promise<void> {
  await db
    .prepare(
      'INSERT INTO organization_invitations(id, organization_id, email, role, permissions, collections, invited_by, status, token, expires_at, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(id) DO UPDATE SET email=excluded.email, role=excluded.role, permissions=excluded.permissions, collections=excluded.collections, status=excluded.status, token=excluded.token, expires_at=excluded.expires_at, updated_at=excluded.updated_at'
    )
    .bind(
      invitation.id,
      invitation.organizationId,
      invitation.email,
      invitation.role,
      JSON.stringify(invitation.permissions || {}),
      JSON.stringify(invitation.collections || []),
      invitation.invitedBy,
      invitation.status,
      invitation.token,
      invitation.expiresAt,
      invitation.createdAt,
      invitation.updatedAt
    )
    .run();
}

export async function deleteOrganizationInvitation(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM organization_invitations WHERE id = ?').bind(id).run();
}

export async function getPolicy(db: D1Database, id: string): Promise<Policy | null> {
  const row = await db
    .prepare('SELECT id, organization_id, type, data, created_at, updated_at FROM policies WHERE id = ?')
    .bind(id)
    .first<any>();
  if (!row) return null;
  return mapPolicyRow(row);
}

export async function getPoliciesForOrganization(db: D1Database, organizationId: string): Promise<Policy[]> {
  const res = await db
    .prepare('SELECT id, organization_id, type, data, created_at, updated_at FROM policies WHERE organization_id = ? ORDER BY type ASC')
    .bind(organizationId)
    .all<any>();
  return (res.results || []).map(mapPolicyRow);
}

export async function savePolicy(db: D1Database, policy: Policy): Promise<void> {
  await db
    .prepare(
      'INSERT INTO policies(id, organization_id, type, data, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(id) DO UPDATE SET type=excluded.type, data=excluded.data, updated_at=excluded.updated_at'
    )
    .bind(policy.id, policy.organizationId, policy.type, JSON.stringify(policy.data || {}), policy.createdAt, policy.updatedAt)
    .run();
}

export async function deletePolicy(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM policies WHERE id = ?').bind(id).run();
}

// Both `organizations.owner_id` and `ciphers.user_id` cascade from `users`, so
// deleting an account would otherwise destroy an organization it owns and every
// org cipher it authored. Hand that data to a surviving member first. Returns the
// member ids whose sync state was affected.
export async function transferOrganizationDataOnUserDelete(db: D1Database, userId: string): Promise<string[]> {
  const affected = new Set<string>();
  const now = new Date().toISOString();

  // 1. Organizations owned by the account move to the highest-ranked remaining
  //    member; an organization with no other members is removed outright.
  const owned = await db
    .prepare('SELECT id FROM organizations WHERE owner_id = ?')
    .bind(userId)
    .all<{ id: string }>();
  for (const row of owned.results || []) {
    const members = (await getOrganizationMembers(db, row.id)).filter(
      (member) => member.userId !== userId && member.status === 1
    );
    members.sort((a, b) => orgRoleRank(b.role) - orgRoleRank(a.role) || a.createdAt.localeCompare(b.createdAt));
    const successor = members[0];
    if (!successor) {
      await deleteOrganization(db, row.id);
      continue;
    }
    await db
      .prepare('UPDATE organizations SET owner_id = ?, updated_at = ? WHERE id = ?')
      .bind(successor.userId, now, row.id)
      .run();
    successor.role = 'owner';
    successor.updatedAt = now;
    await saveOrganizationMember(db, successor);
    for (const member of members) affected.add(member.userId);
  }

  // 2. Org ciphers the account authored are reassigned to the (possibly new) owner
  //    so they survive the cascade.
  const memberships = await db
    .prepare('SELECT organization_id FROM organization_members WHERE user_id = ?')
    .bind(userId)
    .all<{ organization_id: string }>();
  for (const row of memberships.results || []) {
    const org = await getOrganization(db, row.organization_id);
    if (!org || org.ownerId === userId) continue;
    // Match both collection-linked org ciphers AND unassigned ones (admins may
    // create org ciphers with no collection) — the latter would otherwise
    // cascade-delete with the account.
    await db
      .prepare(
        `UPDATE ciphers SET user_id = ?, updated_at = ?
         WHERE user_id = ? AND (
           id IN (
             SELECT ci.cipher_id FROM collection_items ci
             JOIN collections c ON c.id = ci.collection_id
             WHERE c.organization_id = ?
           )
           OR (json_valid(data) AND json_extract(data, '$.organizationId') = ?)
         )`
      )
      .bind(org.ownerId, now, userId, org.id, org.id)
      .run();
    for (const member of await getOrganizationMemberIds(db, org.id)) affected.add(member);
  }

  affected.delete(userId);
  return Array.from(affected);
}
