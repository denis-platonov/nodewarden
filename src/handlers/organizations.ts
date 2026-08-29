import type { Env, User, Organization, OrganizationMember, Collection, CollectionItem, OrganizationInvitation, Policy, OrganizationResponse, OrganizationMemberResponse, CollectionResponse, PolicyResponse } from '../types';
import { errorResponse, jsonResponse } from '../utils/response';
import {
  getOrganization,
  getOrganizationsForUser,
  getOrganizationByIdentifier,
  saveOrganization,
  deleteOrganization,
  getOrganizationMember,
  getOrganizationMembers,
  getOrganizationMembershipsForUser,
  saveOrganizationMember,
  deleteOrganizationMember,
  getOrganizationMemberIds,
  isOrgManager,
  isOrgAdmin,
  isOrgOwner,
  canAssignOrgRole,
  orgRoleRank,
  getCollection,
  getCollectionsForOrganization,
  getAccessibleCollectionsForUser,
  saveCollection,
  deleteCollection,
  addCollectionItem,
  removeCollectionItem,
  getCollectionItems,
  getCipherCollections,
  getOrganizationInvitation,
  getOrganizationInvitationByToken,
  getOrganizationInvitations,
  getOrganizationInvitationsForEmail,
  saveOrganizationInvitation,
  deleteOrganizationInvitation,
  getPolicy,
  getPoliciesForOrganization,
  savePolicy,
  deletePolicy,
} from '../services/storage-organization-repo';
import { getCipher } from '../services/storage-cipher-repo';
import { readOrgCipherFields } from '../services/storage-org-access';
import { getUserById, getUser } from '../services/storage-user-repo';
import { generateUUID } from '../utils/uuid';
import { safeWriteAuditEvent } from '../services/audit-events';
import { readActingDeviceIdentifier } from '../utils/device';
import { bumpUserRevisions } from '../utils/revision';
import { getSsoConfig } from '../services/storage-sso-repo';
import { LIMITS } from '../config/limits';

const ORG_ROLES = ['owner', 'admin', 'manager', 'member', 'custom'] as const;

async function writeOrgAudit(
  env: Env,
  actorUserId: string,
  action: string,
  targetType: string,
  targetId: string | null,
  metadata: Record<string, unknown>
): Promise<void> {
  await safeWriteAuditEvent(env, {
    actorUserId,
    action,
    category: 'data',
    level: action.includes('delete') ? 'security' : 'info',
    targetType,
    targetId,
    metadata,
  });
}

async function bumpMembersRevision(env: Env, memberUserIds: string[], contextId?: string | null): Promise<void> {
  await bumpUserRevisions(env, memberUserIds, contextId);
}

async function requireMember(env: Env, orgId: string, userId: string): Promise<OrganizationMember | null> {
  const member = await getOrganizationMember(env.DB, orgId, userId);
  if (!member || member.status !== 1) return null;
  return member;
}

function toOrgResponse(org: Organization, opts: { includeKeys?: boolean } = {}): OrganizationResponse {
  return {
    id: org.id,
    name: org.name,
    enabled: org.enabled,
    useTotp: org.useTotp,
    ownerId: org.ownerId,
    billingEmail: org.billingEmail,
    key: org.publicKey,
    publicKey: org.publicKey,
    privateKey: opts.includeKeys ? org.privateKey : null,
    identifier: org.identifier,
    creationDate: org.createdAt,
    revisionDate: org.updatedAt,
    object: 'organization',
  };
}

function toMemberResponse(member: OrganizationMember, user: User): OrganizationMemberResponse {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    status: member.status,
    role: member.role,
    permissions: member.permissions || {},
    collections: member.collections || [],
    encryptedOrgKey: member.encryptedOrgKey ?? null,
    type: 0,
    hasAvatar: false,
    avatarColor: '',
    object: 'organizationMember',
  };
}

function toCollectionResponse(collection: Collection): CollectionResponse {
  return {
    id: collection.id,
    organizationId: collection.organizationId,
    name: collection.name,
    externalId: collection.externalId,
    creationDate: collection.createdAt,
    revisionDate: collection.updatedAt,
    object: 'collection',
  };
}

function toPolicyResponse(policy: Policy): PolicyResponse {
  return {
    id: policy.id,
    organizationId: policy.organizationId,
    type: policy.type,
    data: policy.data || {},
    creationDate: policy.createdAt,
    revisionDate: policy.updatedAt,
    object: 'policy',
  };
}

function toInvitationResponse(invitation: OrganizationInvitation): Record<string, unknown> {
  return {
    id: invitation.id,
    email: invitation.email,
    role: invitation.role,
    permissions: invitation.permissions || {},
    collections: invitation.collections || [],
    status: invitation.status,
    type: 0,
    object: 'organizationInvitation',
  };
}

function normalizeRole(role: unknown): string {
  const value = String(role || 'member').trim().toLowerCase();
  return (ORG_ROLES as readonly string[]).includes(value) ? value : 'member';
}

// GET /api/organizations
export async function handleGetOrganizations(request: Request, env: Env, userId: string): Promise<Response> {
  const organizations = await getOrganizationsForUser(env.DB, userId);
  const memberships = await getOrganizationMembershipsForUser(env.DB, userId);
  const memberByOrg = new Map(memberships.map((m) => [m.organizationId, m]));
  return jsonResponse({
    data: organizations.map((org) => toOrgResponse(org, { includeKeys: isOrgAdmin(memberByOrg.get(org.id)) })),
    object: 'list',
    continuationToken: null,
  });
}

// POST /api/organizations
export async function handleCreateOrganization(request: Request, env: Env, userId: string): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const name = (body?.name || '').trim();
  if (!name) return errorResponse('Organization name is required', 400);
  if (name.length > 100) return errorResponse('Organization name too long', 400);

  const ownedCount = (await getOrganizationsForUser(env.DB, userId)).filter((org) => org.ownerId === userId).length;
  if (ownedCount >= LIMITS.organizations.maxOwnedPerUser) {
    return errorResponse(`You cannot own more than ${LIMITS.organizations.maxOwnedPerUser} organizations`, 400);
  }

  const identifier = body?.identifier != null ? String(body.identifier).trim() : null;
  if (identifier) {
    const existingByIdentifier = await getOrganizationByIdentifier(env.DB, identifier);
    if (existingByIdentifier) return errorResponse('Organization identifier is already in use', 400);
  }

  const now = new Date().toISOString();
  const orgId = generateUUID();
  const org: Organization = {
    id: orgId,
    name,
    enabled: true,
    useTotp: !!body?.useTotp,
    ownerId: userId,
    billingEmail: body?.billingEmail?.trim() || null,
    publicKey: typeof body?.publicKey === 'string' && body.publicKey ? body.publicKey : null,
    privateKey: typeof body?.privateKey === 'string' && body.privateKey ? body.privateKey : null,
    identifier,
    createdAt: now,
    updatedAt: now,
  };

  await saveOrganization(env.DB, org);

  const ownerMember: OrganizationMember = {
    organizationId: orgId,
    userId,
    status: 1,
    role: 'owner',
    permissions: {},
    collections: [],
    encryptedOrgKey: typeof body?.encryptedOrgKey === 'string' && body.encryptedOrgKey ? body.encryptedOrgKey : null,
    createdAt: now,
    updatedAt: now,
  };
  await saveOrganizationMember(env.DB, ownerMember);

  await bumpMembersRevision(env, [userId], readActingDeviceIdentifier(request));
  await writeOrgAudit(env, userId, 'organization.create', 'organization', orgId, { name, organizationId: orgId });

  return jsonResponse(toOrgResponse(org, { includeKeys: true }));
}

// GET /api/organizations/:id
export async function handleGetOrganization(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env, orgId, userId);
  if (!member) return errorResponse('Not found', 404);

  const org = await getOrganization(env.DB, orgId);
  if (!org) return errorResponse('Not found', 404);

  return jsonResponse(toOrgResponse(org, { includeKeys: isOrgAdmin(member) }));
}

// PUT /api/organizations/:id
export async function handleUpdateOrganization(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env, orgId, userId);
  if (!member || !isOrgAdmin(member)) return errorResponse('Not found', 404);

  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const org = await getOrganization(env.DB, orgId);
  if (!org) return errorResponse('Not found', 404);

  const now = new Date().toISOString();
  if (body.name !== undefined) {
    const name = String(body.name || '').trim();
    if (!name) return errorResponse('Organization name is required', 400);
    if (name.length > 100) return errorResponse('Organization name too long', 400);
    org.name = name;
  }
  if (body.billingEmail !== undefined) {
    org.billingEmail = body.billingEmail ? String(body.billingEmail).trim() : null;
  }
  if (body.enabled !== undefined) {
    org.enabled = !!body.enabled;
  }
  if (body.useTotp !== undefined) {
    org.useTotp = !!body.useTotp;
  }
  if (body.identifier !== undefined) {
    const identifier = body.identifier ? String(body.identifier).trim() : null;
    if (identifier) {
      const existingByIdentifier = await getOrganizationByIdentifier(env.DB, identifier);
      if (existingByIdentifier && existingByIdentifier.id !== orgId) {
        return errorResponse('Organization identifier is already in use', 400);
      }
    }
    org.identifier = identifier;
  }
  if (typeof body.publicKey === 'string') org.publicKey = body.publicKey || null;
  if (typeof body.privateKey === 'string') org.privateKey = body.privateKey || null;
  org.updatedAt = now;

  await saveOrganization(env.DB, org);
  const memberIds = await getOrganizationMemberIds(env.DB, orgId);
  await bumpMembersRevision(env, memberIds, readActingDeviceIdentifier(request));
  await writeOrgAudit(env, userId, 'organization.update', 'organization', orgId, { name: org.name, organizationId: orgId });

  return jsonResponse(toOrgResponse(org, { includeKeys: true }));
}

// DELETE /api/organizations/:id
export async function handleDeleteOrganization(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env, orgId, userId);
  if (!member || !isOrgOwner(member)) return errorResponse('Not found', 404);

  const org = await getOrganization(env.DB, orgId);
  if (!org) return errorResponse('Not found', 404);

  const memberIds = await getOrganizationMemberIds(env.DB, orgId);
  await deleteOrganization(env.DB, orgId);
  await bumpMembersRevision(env, memberIds, readActingDeviceIdentifier(request));
  await writeOrgAudit(env, userId, 'organization.delete', 'organization', orgId, { name: org.name, organizationId: orgId });

  return new Response(null, { status: 204 });
}

// GET /api/organizations/:id/keys
export async function handleGetOrganizationKeys(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env, orgId, userId);
  if (!member) return errorResponse('Not found', 404);

  const org = await getOrganization(env.DB, orgId);
  if (!org) return errorResponse('Not found', 404);

  return jsonResponse({
    key: member.encryptedOrgKey ?? null,
    publicKey: org.publicKey,
    // The org private key is only needed by administrators; members decrypt with
    // the symmetric org key delivered in `key`.
    privateKey: isOrgAdmin(member) ? org.privateKey : null,
    object: 'organizationKeys',
  });
}

// GET /api/organizations/:id/members
export async function handleGetOrganizationMembers(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env, orgId, userId);
  if (!member) return errorResponse('Not found', 404);

  const members = await getOrganizationMembers(env.DB, orgId);
  const users = new Map<string, User>();
  await Promise.all(members.map(async (m) => {
    const user = await getUserById(env.DB, m.userId);
    if (user) users.set(user.id, user);
  }));

  return jsonResponse({
    data: members
      .filter((m) => users.has(m.userId))
      .map((m) => toMemberResponse(m, users.get(m.userId)!)),
    object: 'list',
    continuationToken: null,
  });
}

// GET /api/organizations/:id/members/public-key?email=...
export async function handleGetOrganizationMemberPublicKeyByEmail(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env, orgId, userId);
  if (!member || !isOrgManager(member)) return errorResponse('Not found', 404);

  const url = new URL(request.url);
  const email = String(url.searchParams.get('email') || '').trim().toLowerCase();
  if (!email) return errorResponse('email query parameter is required', 400);

  const { getUser } = await import('../services/storage-user-repo');
  const target = await getUser(env.DB, email);
  if (!target || !target.publicKey) return errorResponse('Member public key not found', 404);

  return jsonResponse({ userId: target.id, publicKey: target.publicKey });
}

// GET /api/organizations/:id/members/:userId/public-key
export async function handleGetOrganizationMemberPublicKey(request: Request, env: Env, userId: string, orgId: string, memberUserId: string): Promise<Response> {
  const member = await requireMember(env, orgId, userId);
  if (!member || !isOrgManager(member)) return errorResponse('Not found', 404);

  const target = await getUserById(env.DB, memberUserId);
  if (!target || !target.publicKey) return errorResponse('Member public key not found', 404);

  return jsonResponse({ publicKey: target.publicKey });
}

// POST /api/organizations/:id/members/invite
export async function handleInviteOrganizationMember(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env, orgId, userId);
  if (!member || !isOrgManager(member)) return errorResponse('Not found', 404);

  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const email = String(body?.email || '').trim().toLowerCase();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return errorResponse('Valid email is required', 400);

  const role = normalizeRole(body?.role);
  const collections = Array.isArray(body?.collections) ? body.collections.map(String).filter(Boolean) : [];
  const permissions = body?.permissions && typeof body.permissions === 'object' ? body.permissions : {};

  if (!canAssignOrgRole(member, role)) {
    return errorResponse('You cannot grant a role above your own', 403);
  }

  const now = new Date().toISOString();
  const targetUser = await getUser(env.DB, email);

  // Membership is keyed by user id, so the duplicate check has to resolve the
  // account first. Only an ACCEPTED membership blocks re-inviting: a status-0
  // row (SCIM-staged or revoked) must stay re-invitable or the user is stuck.
  if (targetUser) {
    const existingMember = await getOrganizationMember(env.DB, orgId, targetUser.id);
    if (existingMember && existingMember.status === 1) {
      return errorResponse('User is already a member', 400);
    }
  }
  const pendingInvitations = await getOrganizationInvitations(env.DB, orgId);
  const alreadyInvited = pendingInvitations.some(
    (invitation) => invitation.status === 0 && invitation.email.toLowerCase() === email && new Date(invitation.expiresAt).getTime() >= Date.now()
  );
  if (alreadyInvited) return errorResponse('User has already been invited', 400);

  if (targetUser) {
    // Direct membership for existing users.
    const newMember: OrganizationMember = {
      organizationId: orgId,
      userId: targetUser.id,
      status: 1,
      role,
      permissions,
      collections,
      encryptedOrgKey: typeof body?.encryptedOrgKey === 'string' && body.encryptedOrgKey ? body.encryptedOrgKey : null,
      createdAt: now,
      updatedAt: now,
    };
    await saveOrganizationMember(env.DB, newMember);
    await bumpMembersRevision(env, [targetUser.id], readActingDeviceIdentifier(request));
    await writeOrgAudit(env, userId, 'organization.invite', 'organization', orgId, {
      email,
      role,
      organizationId: orgId,
      collectionCount: collections.length,
    });
    return jsonResponse(toMemberResponse(newMember, targetUser));
  }

  // No account yet: create a pending invitation (accepted on a later sign-in with the token).
  const invitation: OrganizationInvitation = {
    id: generateUUID(),
    organizationId: orgId,
    email,
    role,
    permissions,
    collections,
    invitedBy: userId,
    status: 0,
    token: generateUUID() + generateUUID(),
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    createdAt: now,
    updatedAt: now,
  };
  await saveOrganizationInvitation(env.DB, invitation);
  await writeOrgAudit(env, userId, 'organization.invite', 'organization', orgId, {
    email,
    role,
    organizationId: orgId,
    collectionCount: collections.length,
  });

  return jsonResponse(toInvitationResponse(invitation));
}

// PUT /api/organizations/:id/members/:userId
export async function handleUpdateOrganizationMember(request: Request, env: Env, userId: string, orgId: string, memberUserId: string): Promise<Response> {
  const member = await requireMember(env, orgId, userId);
  if (!member || !isOrgManager(member)) return errorResponse('Not found', 404);

  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const targetMember = await getOrganizationMember(env.DB, orgId, memberUserId);
  if (!targetMember) return errorResponse('Not found', 404);

  // An actor may only modify members at or below their own rank: a manager must
  // not demote an admin or rewrite their collections/permissions/org key.
  if (orgRoleRank(targetMember.role) > orgRoleRank(member.role)) {
    return errorResponse('You cannot manage a member with a higher role than your own', 403);
  }

  // Only the owner may change another owner's role, and only the owner may demote the owner.
  if (targetMember.role === 'owner' && member.role !== 'owner') return errorResponse('Only the organization owner can manage owners', 403);
  if (targetMember.role === 'owner' && body.role !== undefined && body.role !== 'owner' && member.userId !== memberUserId) {
    return errorResponse('Only the organization owner can change the owner role', 403);
  }

  const now = new Date().toISOString();
  if (body.role !== undefined) {
    const nextRole = normalizeRole(body.role);
    // No self-promotion, and no granting a role above your own.
    if (member.userId === memberUserId && nextRole !== targetMember.role) {
      return errorResponse('You cannot change your own role', 403);
    }
    if (!canAssignOrgRole(member, nextRole)) {
      return errorResponse('You cannot grant a role above your own', 403);
    }
    targetMember.role = nextRole;
  }
  if (body.collections !== undefined) {
    targetMember.collections = Array.isArray(body.collections) ? body.collections.map(String).filter(Boolean) : [];
  }
  if (body.permissions !== undefined && typeof body.permissions === 'object') {
    targetMember.permissions = body.permissions;
  }
  if (typeof body.encryptedOrgKey === 'string' && body.encryptedOrgKey) {
    targetMember.encryptedOrgKey = body.encryptedOrgKey;
  }
  targetMember.updatedAt = now;

  await saveOrganizationMember(env.DB, targetMember);
  await bumpMembersRevision(env, [targetMember.userId], readActingDeviceIdentifier(request));
  const targetUser = await getUserById(env.DB, memberUserId);
  await writeOrgAudit(env, userId, 'organization.member.update', 'organization', orgId, {
    memberId: memberUserId,
    role: targetMember.role,
    organizationId: orgId,
  });

  if (!targetUser) return errorResponse('Not found', 404);
  return jsonResponse(toMemberResponse(targetMember, targetUser));
}

// DELETE /api/organizations/:id/members/:userId
export async function handleRemoveOrganizationMember(request: Request, env: Env, userId: string, orgId: string, memberUserId: string): Promise<Response> {
  const member = await requireMember(env, orgId, userId);
  if (!member || !isOrgManager(member)) return errorResponse('Not found', 404);

  const targetMember = await getOrganizationMember(env.DB, orgId, memberUserId);
  if (!targetMember) return errorResponse('Not found', 404);

  if (targetMember.role === 'owner') return errorResponse('The organization owner cannot be removed', 403);
  if (member.userId === memberUserId) return errorResponse('You cannot remove yourself', 403);
  // Removal is also rank-gated: a manager must not delete an admin.
  if (orgRoleRank(targetMember.role) > orgRoleRank(member.role)) {
    return errorResponse('You cannot remove a member with a higher role than your own', 403);
  }

  // Org ciphers stay with the organization; only the membership row is dropped.
  await deleteOrganizationMember(env.DB, orgId, memberUserId);
  await bumpMembersRevision(env, [memberUserId], readActingDeviceIdentifier(request));
  await writeOrgAudit(env, userId, 'organization.member.remove', 'organization', orgId, {
    memberId: memberUserId,
    organizationId: orgId,
  });

  return new Response(null, { status: 204 });
}

// GET /api/organizations/:id/invitations
export async function handleGetOrganizationInvitations(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env, orgId, userId);
  if (!member || !isOrgManager(member)) return errorResponse('Not found', 404);

  const invitations = await getOrganizationInvitations(env.DB, orgId);
  return jsonResponse({
    data: invitations.map(toInvitationResponse),
    object: 'list',
    continuationToken: null,
  });
}

// DELETE /api/organizations/:id/invitations/:invitationId
export async function handleRevokeOrganizationInvitation(request: Request, env: Env, userId: string, orgId: string, invitationId: string): Promise<Response> {
  const member = await requireMember(env, orgId, userId);
  if (!member || !isOrgManager(member)) return errorResponse('Not found', 404);

  const inv = await getOrganizationInvitation(env.DB, invitationId);
  if (!inv || inv.organizationId !== orgId) return errorResponse('Not found', 404);

  await deleteOrganizationInvitation(env.DB, invitationId);
  await writeOrgAudit(env, userId, 'organization.revokeInvitation', 'organization', orgId, {
    email: inv.email,
    organizationId: orgId,
  });

  return new Response(null, { status: 204 });
}

// GET /api/organizations/:id/collections
export async function handleGetCollections(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env, orgId, userId);
  if (!member) return errorResponse('Not found', 404);

  const collections = await getCollectionsForOrganization(env.DB, orgId);
  return jsonResponse({
    data: collections.map(toCollectionResponse),
    object: 'list',
    continuationToken: null,
  });
}

// GET /api/collections
// Every collection the caller can reach, across all their organizations. Clients
// call this directly as well as reading the collection list out of /api/sync.
export async function handleGetUserCollections(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const collections = await getAccessibleCollectionsForUser(env.DB, userId);
  return jsonResponse({
    data: collections.map(toCollectionResponse),
    object: 'list',
    continuationToken: null,
  });
}

// POST /api/organizations/:id/collections
export async function handleCreateCollection(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env, orgId, userId);
  if (!member || !isOrgManager(member)) return errorResponse('Not found', 404);

  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const name = String(body?.name || '').trim();
  if (!name) return errorResponse('Collection name is required', 400);
  if (name.length > 100) return errorResponse('Collection name too long', 400);

  const now = new Date().toISOString();
  const collection: Collection = {
    id: generateUUID(),
    organizationId: orgId,
    name,
    externalId: body?.externalId ? String(body.externalId).trim() : null,
    createdAt: now,
    updatedAt: now,
  };

  await saveCollection(env.DB, collection);
  const memberIds = await getOrganizationMemberIds(env.DB, orgId);
  await bumpMembersRevision(env, memberIds, readActingDeviceIdentifier(request));
  await writeOrgAudit(env, userId, 'collection.create', 'collection', collection.id, {
    name,
    organizationId: orgId,
    collectionId: collection.id,
  });

  return jsonResponse(toCollectionResponse(collection));
}

// PUT /api/organizations/:id/collections/:collectionId
export async function handleUpdateCollection(request: Request, env: Env, userId: string, orgId: string, collectionId: string): Promise<Response> {
  const member = await requireMember(env, orgId, userId);
  if (!member || !isOrgManager(member)) return errorResponse('Not found', 404);

  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const collection = await getCollection(env.DB, collectionId);
  if (!collection || collection.organizationId !== orgId) return errorResponse('Not found', 404);

  const now = new Date().toISOString();
  if (body.name !== undefined) {
    const name = String(body.name || '').trim();
    if (!name) return errorResponse('Collection name is required', 400);
    if (name.length > 100) return errorResponse('Collection name too long', 400);
    collection.name = name;
  }
  if (body.externalId !== undefined) {
    collection.externalId = body.externalId ? String(body.externalId).trim() : null;
  }
  collection.updatedAt = now;

  await saveCollection(env.DB, collection);
  const memberIds = await getOrganizationMemberIds(env.DB, orgId);
  await bumpMembersRevision(env, memberIds, readActingDeviceIdentifier(request));
  await writeOrgAudit(env, userId, 'collection.update', 'collection', collectionId, {
    name: collection.name,
    organizationId: orgId,
    collectionId,
  });

  return jsonResponse(toCollectionResponse(collection));
}

// DELETE /api/organizations/:id/collections/:collectionId
export async function handleDeleteCollection(request: Request, env: Env, userId: string, orgId: string, collectionId: string): Promise<Response> {
  const member = await requireMember(env, orgId, userId);
  if (!member || !isOrgManager(member)) return errorResponse('Not found', 404);

  const collection = await getCollection(env.DB, collectionId);
  if (!collection || collection.organizationId !== orgId) return errorResponse('Not found', 404);

  const memberIds = await getOrganizationMemberIds(env.DB, orgId);
  await deleteCollection(env.DB, collectionId);
  await bumpMembersRevision(env, memberIds, readActingDeviceIdentifier(request));
  await writeOrgAudit(env, userId, 'collection.delete', 'collection', collectionId, {
    name: collection.name,
    organizationId: orgId,
    collectionId,
  });

  return new Response(null, { status: 204 });
}

// GET /api/organizations/:id/collections/:collectionId/items
export async function handleGetCollectionItems(request: Request, env: Env, userId: string, orgId: string, collectionId: string): Promise<Response> {
  const member = await requireMember(env, orgId, userId);
  if (!member) return errorResponse('Not found', 404);

  const collection = await getCollection(env.DB, collectionId);
  if (!collection || collection.organizationId !== orgId) return errorResponse('Not found', 404);

  const items = await getCollectionItems(env.DB, collectionId);
  return jsonResponse({
    data: items.map((item) => ({
      id: item.cipherId,
      collectionId: item.collectionId,
      object: 'collectionItem',
    })),
    object: 'list',
    continuationToken: null,
  });
}

// POST /api/organizations/:id/collections/:collectionId/items
export async function handleAddCollectionItem(request: Request, env: Env, userId: string, orgId: string, collectionId: string): Promise<Response> {
  const member = await requireMember(env, orgId, userId);
  if (!member || !isOrgManager(member)) return errorResponse('Not found', 404);

  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const cipherId = String(body?.id || body?.cipherId || '').trim();
  if (!cipherId) return errorResponse('Cipher ID is required', 400);

  const collection = await getCollection(env.DB, collectionId);
  if (!collection || collection.organizationId !== orgId) return errorResponse('Not found', 404);

  const cipher = await getCipher(env.DB, cipherId);
  if (!cipher) return errorResponse('Cipher not found', 404);

  // Only this organization's own ciphers may be filed into its collections:
  // collection membership is what grants read access in /api/sync.
  if (readOrgCipherFields(cipher).organizationId !== orgId) {
    return errorResponse('Cipher does not belong to this organization', 400);
  }

  await addCollectionItem(env.DB, collectionId, cipherId);
  // Members' /api/sync responses are cached per revision date, so filing an item
  // into a collection is invisible until their revision moves.
  await bumpMembersRevision(env, await getOrganizationMemberIds(env.DB, orgId), readActingDeviceIdentifier(request));
  await writeOrgAudit(env, userId, 'collection.addItem', 'collection', collectionId, {
    cipherId,
    organizationId: orgId,
    collectionId,
  });

  return jsonResponse({ id: cipherId, collectionId, object: 'collectionItem' });
}

// DELETE /api/organizations/:id/collections/:collectionId/items/:cipherId
export async function handleRemoveCollectionItem(request: Request, env: Env, userId: string, orgId: string, collectionId: string, cipherId: string): Promise<Response> {
  const member = await requireMember(env, orgId, userId);
  if (!member || !isOrgManager(member)) return errorResponse('Not found', 404);

  const collection = await getCollection(env.DB, collectionId);
  if (!collection || collection.organizationId !== orgId) return errorResponse('Not found', 404);

  await removeCollectionItem(env.DB, collectionId, cipherId);
  await bumpMembersRevision(env, await getOrganizationMemberIds(env.DB, orgId), readActingDeviceIdentifier(request));
  await writeOrgAudit(env, userId, 'collection.removeItem', 'collection', collectionId, {
    cipherId,
    organizationId: orgId,
    collectionId,
  });

  return new Response(null, { status: 204 });
}

// GET /api/organizations/:id/policies
export async function handleGetPolicies(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env, orgId, userId);
  if (!member) return errorResponse('Not found', 404);

  const policies = await getPoliciesForOrganization(env.DB, orgId);
  return jsonResponse({
    data: policies.map(toPolicyResponse),
    object: 'list',
    continuationToken: null,
  });
}

// PUT /api/organizations/:id/policies/:policyId
export async function handleUpdatePolicy(request: Request, env: Env, userId: string, orgId: string, policyId: string): Promise<Response> {
  const member = await requireMember(env, orgId, userId);
  if (!member || !isOrgAdmin(member)) return errorResponse('Not found', 404);

  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const policy = await getPolicy(env.DB, policyId);
  if (!policy || policy.organizationId !== orgId) return errorResponse('Not found', 404);

  const now = new Date().toISOString();
  if (body.type !== undefined) policy.type = Number(body.type) || policy.type;
  if (body.data !== undefined) policy.data = body.data && typeof body.data === 'object' ? body.data : {};
  policy.updatedAt = now;

  await savePolicy(env.DB, policy);
  const memberIds = await getOrganizationMemberIds(env.DB, orgId);
  await bumpMembersRevision(env, memberIds, readActingDeviceIdentifier(request));
  await writeOrgAudit(env, userId, 'policy.update', 'policy', policyId, {
    type: policy.type,
    organizationId: orgId,
  });

  return jsonResponse(toPolicyResponse(policy));
}

// DELETE /api/organizations/:id/policies/:policyId
export async function handleDeletePolicy(request: Request, env: Env, userId: string, orgId: string, policyId: string): Promise<Response> {
  const member = await requireMember(env, orgId, userId);
  if (!member || !isOrgOwner(member)) return errorResponse('Not found', 404);

  const policy = await getPolicy(env.DB, policyId);
  if (!policy || policy.organizationId !== orgId) return errorResponse('Not found', 404);

  await deletePolicy(env.DB, policyId);
  const memberIds = await getOrganizationMemberIds(env.DB, orgId);
  await bumpMembersRevision(env, memberIds, readActingDeviceIdentifier(request));
  await writeOrgAudit(env, userId, 'policy.delete', 'policy', policyId, {
    type: policy.type,
    organizationId: orgId,
  });

  return new Response(null, { status: 204 });
}

// POST /api/organizations/invitations/accept
// The token travels in the body, not the path: request URLs land in access logs.
export async function handleAcceptOrganizationInvitation(request: Request, env: Env, userId: string): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const token = String(body?.token || '').trim();
  if (!token) return errorResponse('Invitation token is required', 400);

  const invitation = await getOrganizationInvitationByToken(env.DB, token);
  if (!invitation) return errorResponse('Invitation not found', 404);
  if (invitation.status !== 0) return errorResponse('Invitation is no longer pending', 400);
  if (new Date(invitation.expiresAt).getTime() < Date.now()) return errorResponse('Invitation has expired', 400);

  const user = await getUserById(env.DB, userId);
  if (!user) return errorResponse('Not found', 404);
  if (user.email.toLowerCase() !== invitation.email.toLowerCase()) {
    return errorResponse('Invitation was issued to a different account', 403);
  }

  const now = new Date().toISOString();
  const existingMember = await getOrganizationMember(env.DB, invitation.organizationId, userId);
  if (existingMember) {
    if (existingMember.status === 1) {
      await deleteOrganizationInvitation(env.DB, invitation.id);
      return jsonResponse({ success: true });
    }
    existingMember.status = 1;
    existingMember.role = invitation.role;
    existingMember.collections = invitation.collections || [];
    existingMember.permissions = invitation.permissions || {};
    existingMember.updatedAt = now;
    await saveOrganizationMember(env.DB, existingMember);
  } else {
    const newMember: OrganizationMember = {
      organizationId: invitation.organizationId,
      userId,
      status: 1,
      role: invitation.role,
      permissions: invitation.permissions || {},
      collections: invitation.collections || [],
      encryptedOrgKey: null,
      createdAt: now,
      updatedAt: now,
    };
    await saveOrganizationMember(env.DB, newMember);
  }

  await deleteOrganizationInvitation(env.DB, invitation.id);
  await bumpMembersRevision(env, [userId], readActingDeviceIdentifier(request));

  const ssoEnabled = await getSsoConfig(env.DB, invitation.organizationId);
  return jsonResponse({
    success: true,
    organizationId: invitation.organizationId,
    role: invitation.role,
    ssoEnabled: !!ssoEnabled?.enabled,
  });
}

// GET /api/organizations/invitations/mine
// Invitations waiting for the caller. Without this an invited user has no way to
// discover, let alone accept, an invitation addressed to them.
export async function handleGetMyInvitations(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const user = await getUserById(env.DB, userId);
  if (!user) return errorResponse('Not found', 404);

  const now = Date.now();
  const invitations = (await getOrganizationInvitationsForEmail(env.DB, user.email))
    .filter((invitation) => invitation.status === 0 && new Date(invitation.expiresAt).getTime() >= now);

  const data: Record<string, unknown>[] = [];
  for (const invitation of invitations) {
    const org = await getOrganization(env.DB, invitation.organizationId);
    if (!org || !org.enabled) continue;
    data.push({
      id: invitation.id,
      organizationId: invitation.organizationId,
      organizationName: org.name,
      role: invitation.role,
      // The token belongs to this invitee; they need it to accept.
      token: invitation.token,
      expirationDate: invitation.expiresAt,
      creationDate: invitation.createdAt,
      object: 'organizationInvitation',
    });
  }

  return jsonResponse({ data, object: 'list', continuationToken: null });
}

// POST /api/organizations/invitations/decline
export async function handleDeclineOrganizationInvitation(request: Request, env: Env, userId: string): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const token = String(body?.token || '').trim();
  if (!token) return errorResponse('Invitation token is required', 400);

  const invitation = await getOrganizationInvitationByToken(env.DB, token);
  if (!invitation) return errorResponse('Invitation not found', 404);

  const user = await getUserById(env.DB, userId);
  if (!user) return errorResponse('Not found', 404);
  if (user.email.toLowerCase() !== invitation.email.toLowerCase()) {
    return errorResponse('Invitation was issued to a different account', 403);
  }

  // Drop the pending membership SCIM may have staged alongside the invitation.
  const existingMember = await getOrganizationMember(env.DB, invitation.organizationId, userId);
  if (existingMember && existingMember.status !== 1) {
    await deleteOrganizationMember(env.DB, invitation.organizationId, userId);
  }
  await deleteOrganizationInvitation(env.DB, invitation.id);
  await writeOrgAudit(env, userId, 'organization.declineInvitation', 'organization', invitation.organizationId, {
    organizationId: invitation.organizationId,
  });

  return new Response(null, { status: 204 });
}

// POST /api/organizations/:id/sso/pending-member
export async function handleClaimSsoPendingMember(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const user = await getUserById(env.DB, userId);
  if (!user) return errorResponse('Not found', 404);

  const existingMember = await getOrganizationMember(env.DB, orgId, userId);
  if (existingMember?.status === 1) return jsonResponse({ success: true });

  const invitations = await getOrganizationInvitations(env.DB, orgId);
  const match = invitations.find(
    (inv) => inv.status === 0 && inv.email.toLowerCase() === user.email.toLowerCase() && new Date(inv.expiresAt).getTime() >= Date.now()
  );
  if (!match) return errorResponse('No pending invitation for this account', 404);

  const now = new Date().toISOString();
  const newMember: OrganizationMember = {
    organizationId: orgId,
    userId,
    status: 1,
    role: match.role,
    permissions: match.permissions || {},
    collections: match.collections || [],
    encryptedOrgKey: null,
    createdAt: now,
    updatedAt: now,
  };
  await saveOrganizationMember(env.DB, newMember);
  await deleteOrganizationInvitation(env.DB, match.id);
  await bumpMembersRevision(env, [userId], readActingDeviceIdentifier(request));

  return jsonResponse({ success: true });
}