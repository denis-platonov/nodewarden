import type { Env, OrganizationInvitation, OrganizationMember, ScimConfig, ScimConfigResponse, ScimUser, User } from '../types';
import { errorResponse, jsonResponse } from '../utils/response';
import { getOrganization, getOrganizationMember, getOrganizationMembers, getOrganizationMemberIds } from '../services/storage-organization-repo';
import { saveOrganizationMember } from '../services/storage-organization-repo';
import { getOrganizationInvitations, saveOrganizationInvitation } from '../services/storage-organization-repo';
import { getCollection, getCollectionsForOrganization, saveCollection, deleteCollection } from '../services/storage-organization-repo';
import { isOrgAdmin } from '../services/storage-organization-repo';
import { getScimConfig, saveScimConfig, deleteScimConfig } from '../services/storage-scim-repo';
import { getScimUser, listScimUsers, saveScimUser, deleteScimUser } from '../services/storage-scim-repo';
import { getUser, getUserById, getUsersByIds } from '../services/storage-user-repo';
import { generateUUID } from '../utils/uuid';
import { safeWriteAuditEvent } from '../services/audit-events';
import { bumpUserRevisions } from '../utils/revision';
import { readActingDeviceIdentifier } from '../utils/device';
import { LIMITS } from '../config/limits';

const SCIM_SCHEMA_USER = 'urn:ietf:params:scim:schemas:core:2.0:User';
const SCIM_SCHEMA_GROUP = 'urn:ietf:params:scim:schemas:core:2.0:Group';
const SCIM_SCHEMA_LIST = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
const SCIM_SCHEMA_ERROR = 'urn:ietf:params:scim:api:messages:2.0:Error';

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function toScimConfigResponse(config: ScimConfig | null): ScimConfigResponse {
  return {
    organizationId: config?.organizationId ?? '',
    enabled: config?.enabled ?? false,
    tokenGenerated: !!config?.tokenHash,
    creationDate: config?.createdAt ?? new Date().toISOString(),
    revisionDate: config?.updatedAt ?? new Date().toISOString(),
    object: 'scimConfig',
  };
}

async function writeScimAudit(env: Env, actorUserId: string | null, action: string, metadata: Record<string, unknown>): Promise<void> {
  await safeWriteAuditEvent(env, {
    actorUserId,
    action,
    category: 'security',
    level: action.includes('delete') || action.includes('fail') ? 'security' : 'info',
    targetType: 'scim',
    targetId: typeof metadata.organizationId === 'string' ? metadata.organizationId : null,
    metadata,
  });
}

function scimError(status: number, detail: string): Response {
  return new Response(
    JSON.stringify({
      schemas: [SCIM_SCHEMA_ERROR],
      status: String(status),
      detail,
    }),
    {
      status,
      headers: { 'Content-Type': 'application/scim+json' },
    }
  );
}

function scimJson(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/scim+json' },
  });
}

function userToScim(user: ScimUser, email: string | null, displayName: string | null): Record<string, unknown> {
  return {
    schemas: [SCIM_SCHEMA_USER],
    id: user.externalId,
    externalId: user.externalId,
    userName: email ?? user.externalId,
    name: { formatted: displayName ?? undefined, givenName: undefined, familyName: undefined },
    displayName: displayName ?? undefined,
    emails: email ? [{ value: email, primary: true }] : [],
    active: user.active,
    meta: {
      resourceType: 'User',
      created: user.createdAt,
      lastModified: user.updatedAt,
    },
  };
}

function groupToScim(collection: { id: string; name: string; externalId: string | null; createdAt: string; updatedAt: string }, memberExternalIds: string[]): Record<string, unknown> {
  return {
    schemas: [SCIM_SCHEMA_GROUP],
    id: collection.externalId ?? collection.id,
    externalId: collection.externalId ?? collection.id,
    displayName: collection.name,
    members: memberExternalIds.map((externalId) => ({ value: externalId, $ref: `../Users/${externalId}` })),
    meta: {
      resourceType: 'Group',
      created: collection.createdAt,
      lastModified: collection.updatedAt,
    },
  };
}

// SCIM pagination is 1-indexed and advertised in ServiceProviderConfig.
function readScimPagination(url: URL): { startIndex: number; count: number } {
  const requestedCount = Number(url.searchParams.get('count'));
  const count = Number.isFinite(requestedCount) && requestedCount > 0
    ? Math.min(requestedCount, LIMITS.organizations.scimMaxPageSize)
    : LIMITS.organizations.scimDefaultPageSize;
  const requestedStart = Number(url.searchParams.get('startIndex'));
  const startIndex = Number.isFinite(requestedStart) && requestedStart >= 1 ? Math.floor(requestedStart) : 1;
  return { startIndex, count };
}

// Entra ID sends SCIM boolean values as strings ("True"/"False"); accept both.
function readScimBoolean(value: unknown, fallback: boolean): boolean {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (normalized === 'true') return true;
    if (normalized === 'false') return false;
  }
  return fallback;
}

function readScimEmail(body: Record<string, any>): string | null {
  const emails = body.emails;
  if (Array.isArray(emails) && emails.length) {
    const primary = emails.find((email) => email?.primary) || emails[0];
    const value = String(primary?.value || '').trim().toLowerCase();
    if (value) return value;
  }
  const userName = String(body.userName || '').trim().toLowerCase();
  if (userName && userName.includes('@')) return userName;
  return null;
}

// ============ Org admin configuration endpoints ============

// GET /api/organizations/:id/scim
export async function handleGetScimConfig(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  void request;
  const member = await getOrganizationMember(env.DB, orgId, userId);
  if (!member || member.status !== 1 || !isOrgAdmin(member)) return errorResponse('Not found', 404);

  const config = await getScimConfig(env.DB, orgId);
  return jsonResponse(toScimConfigResponse(config));
}

// PUT /api/organizations/:id/scim
export async function handlePutScimConfig(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await getOrganizationMember(env.DB, orgId, userId);
  if (!member || member.status !== 1 || !isOrgAdmin(member)) return errorResponse('Not found', 404);

  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const existing = await getScimConfig(env.DB, orgId);
  const now = new Date().toISOString();

  let tokenHash = existing?.tokenHash ?? null;
  let generatedToken: string | null = null;
  if (body.generateToken === true) {
    generatedToken = generateUUID() + generateUUID().replace(/-/g, '');
    tokenHash = await sha256Hex(generatedToken);
  }

  const enabled = body.enabled !== undefined ? !!body.enabled : (existing?.enabled ?? false);
  if (!enabled && body.enabled === false) {
    tokenHash = null;
  }

  const config: ScimConfig = {
    organizationId: orgId,
    enabled,
    tokenHash,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  };
  await saveScimConfig(env.DB, config);

  await writeScimAudit(env, userId, 'scim.config.update', {
    organizationId: orgId,
    enabled,
    scimToken: generatedToken ? true : undefined,
  });

  const response: Record<string, unknown> = toScimConfigResponse(config) as unknown as Record<string, unknown>;
  if (generatedToken) response.token = generatedToken;
  return jsonResponse(response);
}

// DELETE /api/organizations/:id/scim
export async function handleDeleteScimConfig(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  void request;
  const member = await getOrganizationMember(env.DB, orgId, userId);
  if (!member || member.status !== 1 || !isOrgAdmin(member)) return errorResponse('Not found', 404);

  await deleteScimConfig(env.DB, orgId);
  await writeScimAudit(env, userId, 'scim.config.delete', { organizationId: orgId });

  return new Response(null, { status: 204 });
}

const SCIM_INVITATION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

// SCIM provisioning must not silently turn an existing account into a full member
// of someone else's organization: create a pending membership plus an invitation
// the account holder claims themselves.
async function provisionScimMember(env: Env, request: Request, orgId: string, account: User): Promise<void> {
  const existingMember = await getOrganizationMember(env.DB, orgId, account.id);
  // An accepted member needs nothing. A status-0 row (fresh stub OR a previously
  // revoked membership being reactivated) falls through so a claimable
  // invitation exists again — otherwise deactivate→reactivate is a one-way door.
  if (existingMember && existingMember.status === 1) return;

  const now = new Date().toISOString();
  if (!existingMember) {
    await saveOrganizationMember(env.DB, {
      organizationId: orgId,
      userId: account.id,
      status: 0,
      role: 'member',
      permissions: {},
      collections: [],
      encryptedOrgKey: null,
      createdAt: now,
      updatedAt: now,
    });
  }

  const email = account.email.toLowerCase();
  const invitations = await getOrganizationInvitations(env.DB, orgId);
  const alreadyInvited = invitations.some(
    (invitation) => invitation.status === 0 && invitation.email.toLowerCase() === email && new Date(invitation.expiresAt).getTime() >= Date.now()
  );
  if (!alreadyInvited) {
    const org = await getOrganization(env.DB, orgId);
    const invitation: OrganizationInvitation = {
      id: generateUUID(),
      organizationId: orgId,
      email,
      role: 'member',
      permissions: {},
      collections: [],
      invitedBy: org?.ownerId ?? account.id,
      status: 0,
      token: generateUUID() + generateUUID(),
      expiresAt: new Date(Date.now() + SCIM_INVITATION_TTL_MS).toISOString(),
      createdAt: now,
      updatedAt: now,
    };
    await saveOrganizationInvitation(env.DB, invitation);
  }

  await bumpUserRevisions(env, [account.id], readActingDeviceIdentifier(request));
}

// Identity providers deprovision by setting active=false (PATCH/PUT), not by
// DELETE, so the membership has to follow the flag. Re-activation deliberately
// does not promote the member back: they re-claim the pending invitation.
async function revokeScimMembership(env: Env, request: Request, orgId: string, userId: string | null): Promise<void> {
  if (!userId) return;
  const member = await getOrganizationMember(env.DB, orgId, userId);
  if (!member || member.status === 0) return;
  // The owner must never be locked out by the IdP: with the owner at status 0
  // every management endpoint 404s and the org becomes unmanageable.
  if (member.role === 'owner') {
    await writeScimAudit(env, null, 'scim.user.revoke.blocked', { organizationId: orgId, userId, reason: 'owner' });
    return;
  }
  member.status = 0;
  member.updatedAt = new Date().toISOString();
  await saveOrganizationMember(env.DB, member);
  await bumpUserRevisions(env, [userId], readActingDeviceIdentifier(request));
}

// ============ SCIM v2 endpoints (token-authenticated) ============

export async function authenticateScimRequest(request: Request, env: Env): Promise<{ orgId: string } | null> {
  const authHeader = request.headers.get('Authorization') || '';
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer' || !parts[1]) return null;

  const tokenHash = await sha256Hex(parts[1].trim());
  const res = await env.DB
    .prepare('SELECT organization_id FROM scim_configs WHERE token_hash = ? AND enabled = 1')
    .bind(tokenHash)
    .first<{ organization_id: string }>();
  return res ? { orgId: res.organization_id } : null;
}

// GET /api/scim/v2/ServiceProviderConfig
export async function handleScimServiceProviderConfig(): Promise<Response> {
  return scimJson({
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
    documentationUri: '',
    authenticationSchemes: [
      { type: 'oauthbearertoken', name: 'OAuth Bearer Token', description: 'Bearer token authentication', specUri: '', documentationUri: '' },
    ],
    patch: { supported: true },
    bulk: { supported: false },
    filter: { supported: true, maxResults: 100 },
    changePassword: { supported: false },
    sort: { supported: false },
    etag: { supported: false },
  });
}

// GET /api/scim/v2/ResourceTypes
export async function handleScimResourceTypes(): Promise<Response> {
  return scimJson({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
    totalResults: 2,
    Resources: [
      { schemas: [SCIM_SCHEMA_USER], id: 'User', name: 'User', endpoint: '/Users', resourceType: 'User' },
      { schemas: [SCIM_SCHEMA_GROUP], id: 'Group', name: 'Group', endpoint: '/Groups', resourceType: 'Group' },
    ],
  });
}

// GET /api/scim/v2/Schemas
export async function handleScimSchemas(): Promise<Response> {
  return scimJson({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
    totalResults: 1,
    Resources: [
      {
        id: SCIM_SCHEMA_USER,
        name: 'User',
        attributes: [
          { name: 'userName', type: 'string', multiValued: false, required: true, caseExact: false, mutability: 'readWrite' },
          { name: 'displayName', type: 'string', multiValued: false, required: false, caseExact: false, mutability: 'readWrite' },
          { name: 'emails', type: 'complex', multiValued: true, required: false, mutability: 'readWrite' },
          { name: 'active', type: 'boolean', multiValued: false, required: false, mutability: 'readWrite' },
          { name: 'externalId', type: 'string', multiValued: false, required: false, caseExact: false, mutability: 'readWrite' },
        ],
      },
    ],
  });
}

// GET /api/scim/v2/Users
export async function handleScimListUsers(request: Request, env: Env, orgId: string): Promise<Response> {
  const url = new URL(request.url);
  const filter = url.searchParams.get('filter') || '';

  let scimUsers = await listScimUsers(env.DB, orgId);

  // One batched lookup instead of a query per row.
  const accounts = await getUsersByIds(env.DB, scimUsers.map((scimUser) => scimUser.userId ?? '').filter(Boolean));

  const emailMatch = filter.match(/userName\s+eq\s+"([^"]+)"/i) || filter.match(/emails\s+eq\s+"([^"]+)"/i);
  if (emailMatch) {
    const email = emailMatch[1].toLowerCase();
    scimUsers = scimUsers.filter((scimUser) => {
      const user = scimUser.userId ? accounts.get(scimUser.userId) : null;
      return !!user && user.email.toLowerCase() === email;
    });
  }

  const externalIdMatch = filter.match(/externalId\s+eq\s+"([^"]+)"/i);
  if (externalIdMatch) {
    const externalId = externalIdMatch[1];
    scimUsers = scimUsers.filter((user) => user.externalId === externalId);
  }

  const totalResults = scimUsers.length;
  const { startIndex, count } = readScimPagination(url);
  const page = scimUsers.slice(startIndex - 1, startIndex - 1 + count);

  const users = page.map((scimUser) => {
    const user = scimUser.userId ? accounts.get(scimUser.userId) : null;
    return userToScim(scimUser, user?.email ?? null, user?.name ?? null);
  });

  return scimJson({
    schemas: [SCIM_SCHEMA_LIST],
    totalResults,
    itemsPerPage: users.length,
    startIndex,
    Resources: users,
  });
}

// POST /api/scim/v2/Users
export async function handleScimCreateUser(request: Request, env: Env, orgId: string): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return scimError(400, 'Invalid JSON body');
  }

  const email = readScimEmail(body || {});
  if (!email) return scimError(400, 'A userName or email is required');
  const externalId = String(body.externalId || body.id || email).trim();
  const active = readScimBoolean(body.active, true);

  const now = new Date().toISOString();
  let scimUser = await getScimUser(env.DB, orgId, externalId);
  const userId = scimUser?.userId ?? null;

  const account = await getUser(env.DB, email);
  if (account) {
    if (active) {
      await provisionScimMember(env, request, orgId, account);
    } else {
      await revokeScimMembership(env, request, orgId, account.id);
    }
    if (!scimUser || scimUser.userId !== account.id) {
      scimUser = {
        organizationId: orgId,
        externalId,
        userId: account.id,
        active,
        createdAt: scimUser?.createdAt ?? now,
        updatedAt: now,
      };
      await saveScimUser(env.DB, scimUser);
    }
  } else {
    if (!scimUser) {
      scimUser = {
        organizationId: orgId,
        externalId,
        userId: null,
        active,
        createdAt: now,
        updatedAt: now,
      };
      await saveScimUser(env.DB, scimUser);
    }
  }

  await writeScimAudit(env, null, 'scim.user.create', { organizationId: orgId, email, externalId, active });

  return scimJson(userToScim(scimUser, email, account?.name ?? null), 201);
}

// GET /api/scim/v2/Users/:id
export async function handleScimGetUser(request: Request, env: Env, orgId: string, id: string): Promise<Response> {
  void request;
  const scimUser = await getScimUser(env.DB, orgId, id);
  if (!scimUser) return scimError(404, 'User not found');

  let email: string | null = null;
  let displayName: string | null = null;
  if (scimUser.userId) {
    const user = await getUserById(env.DB, scimUser.userId);
    email = user?.email ?? null;
    displayName = user?.name ?? null;
  }

  return scimJson(userToScim(scimUser, email, displayName));
}

// PUT /api/scim/v2/Users/:id
export async function handleScimPutUser(request: Request, env: Env, orgId: string, id: string): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return scimError(400, 'Invalid JSON body');
  }

  let scimUser = await getScimUser(env.DB, orgId, id);
  if (!scimUser) {
    scimUser = {
      organizationId: orgId,
      externalId: id,
      userId: null,
      active: readScimBoolean(body.active, true),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
  }

  const email = readScimEmail(body || {});
  const now = new Date().toISOString();
  scimUser.active = readScimBoolean(body.active, true);
  scimUser.updatedAt = now;

  if (email) {
    const account = await getUser(env.DB, email);
    if (account) {
      scimUser.userId = account.id;
      if (scimUser.active) await provisionScimMember(env, request, orgId, account);
    }
  }
  if (!scimUser.active) {
    await revokeScimMembership(env, request, orgId, scimUser.userId);
  }

  await saveScimUser(env.DB, scimUser);
  await writeScimAudit(env, null, 'scim.user.update', { organizationId: orgId, externalId: id, active: scimUser.active });

  const user = scimUser.userId ? await getUserById(env.DB, scimUser.userId) : null;
  return scimJson(userToScim(scimUser, user?.email ?? email, user?.name ?? null));
}

// PATCH /api/scim/v2/Users/:id
export async function handleScimPatchUser(request: Request, env: Env, orgId: string, id: string): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return scimError(400, 'Invalid JSON body');
  }

  const scimUser = await getScimUser(env.DB, orgId, id);
  if (!scimUser) return scimError(404, 'User not found');

  const operations = Array.isArray(body.Operations) ? body.Operations : [];
  for (const operation of operations) {
    const op = String(operation.op || '').toLowerCase();
    const path = String(operation.path || '');
    const value = operation.value;
    if (op !== 'replace') continue;
    if (path.toLowerCase() === 'active') {
      scimUser.active = readScimBoolean(value, scimUser.active);
    } else if (!path && value && typeof value === 'object' && value.active !== undefined) {
      // Pathless replace carries the changed attributes as an object.
      scimUser.active = readScimBoolean(value.active, scimUser.active);
    }
  }
  scimUser.updatedAt = new Date().toISOString();
  if (!scimUser.active) {
    await revokeScimMembership(env, request, orgId, scimUser.userId);
  } else if (scimUser.userId) {
    // Reactivation via PATCH is the default Okta/Entra flow; restore the
    // pending-invitation path just like PUT/POST do.
    const account = await getUserById(env.DB, scimUser.userId);
    if (account) await provisionScimMember(env, request, orgId, account);
  }
  await saveScimUser(env.DB, scimUser);

  await writeScimAudit(env, null, 'scim.user.patch', { organizationId: orgId, externalId: id, active: scimUser.active });

  const user = scimUser.userId ? await getUserById(env.DB, scimUser.userId) : null;
  return scimJson(userToScim(scimUser, user?.email ?? null, user?.name ?? null));
}

// DELETE /api/scim/v2/Users/:id
export async function handleScimDeleteUser(request: Request, env: Env, orgId: string, id: string): Promise<Response> {
  const scimUser = await getScimUser(env.DB, orgId, id);
  if (!scimUser) return scimError(404, 'User not found');

  await revokeScimMembership(env, request, orgId, scimUser.userId);
  await deleteScimUser(env.DB, orgId, id);
  await writeScimAudit(env, null, 'scim.user.delete', { organizationId: orgId, externalId: id });

  return new Response(null, { status: 204 });
}

// Members plus their SCIM mapping, loaded once. Resolving group membership per
// collection with per-member queries costs O(collections x members) round trips
// and blows the Worker subrequest budget on any real directory.
interface ScimOrgSnapshot {
  members: OrganizationMember[];
  externalIdByUserId: Map<string, string>;
}

async function loadScimOrgSnapshot(db: D1Database, orgId: string): Promise<ScimOrgSnapshot> {
  const [members, scimUsers] = await Promise.all([
    getOrganizationMembers(db, orgId),
    listScimUsers(db, orgId),
  ]);
  const externalIdByUserId = new Map<string, string>();
  for (const scimUser of scimUsers) {
    if (scimUser.userId) externalIdByUserId.set(scimUser.userId, scimUser.externalId);
  }
  return { members, externalIdByUserId };
}

function groupMemberExternalIds(snapshot: ScimOrgSnapshot, collectionId: string): string[] {
  const out: string[] = [];
  for (const member of snapshot.members) {
    if (!(member.collections || []).includes(collectionId)) continue;
    const externalId = member.userId ? snapshot.externalIdByUserId.get(member.userId) : undefined;
    if (externalId) out.push(externalId);
  }
  return out;
}

async function getGroupMemberExternalIds(db: D1Database, orgId: string, collectionId: string): Promise<string[]> {
  return groupMemberExternalIds(await loadScimOrgSnapshot(db, orgId), collectionId);
}

async function applyGroupMembers(db: D1Database, env: Env, orgId: string, collectionId: string, memberExternalIds: string[]): Promise<void> {
  const scimUsers: ScimUser[] = [];
  for (const externalId of memberExternalIds) {
    const scimUser = await getScimUser(db, orgId, externalId);
    if (scimUser && scimUser.userId) scimUsers.push(scimUser);
  }

  const members = await getOrganizationMembers(db, orgId);
  for (const member of members) {
    const target = scimUsers.find((scimUser) => scimUser.userId === member.userId);
    let collections = member.collections || [];
    if (target) {
      if (!collections.includes(collectionId)) collections = [...collections, collectionId];
    } else {
      collections = collections.filter((collection) => collection !== collectionId);
    }
    if (collections.length !== (member.collections || []).length) {
      member.collections = collections;
      member.updatedAt = new Date().toISOString();
      await saveOrganizationMember(db, member);
    }
  }
  await bumpUserRevisions(env, scimUsers.map((scimUser) => scimUser.userId!).filter(Boolean));
}

// GET /api/scim/v2/Groups
export async function handleScimListGroups(request: Request, env: Env, orgId: string): Promise<Response> {
  const url = new URL(request.url);
  const collections = (await getCollectionsForOrganization(env.DB, orgId)).filter((collection) => collection.externalId);

  const totalResults = collections.length;
  const { startIndex, count } = readScimPagination(url);
  const page = collections.slice(startIndex - 1, startIndex - 1 + count);

  const snapshot = await loadScimOrgSnapshot(env.DB, orgId);
  const groups = page.map((collection) => groupToScim(collection, groupMemberExternalIds(snapshot, collection.id)));

  return scimJson({
    schemas: [SCIM_SCHEMA_LIST],
    totalResults,
    itemsPerPage: groups.length,
    startIndex,
    Resources: groups,
  });
}

// POST /api/scim/v2/Groups
export async function handleScimCreateGroup(request: Request, env: Env, orgId: string): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return scimError(400, 'Invalid JSON body');
  }

  const displayName = String(body.displayName || '').trim();
  if (!displayName) return scimError(400, 'displayName is required');
  const externalId = String(body.externalId || body.id || '').trim() || generateUUID();
  const now = new Date().toISOString();

  const existingCollection = (await getCollectionsForOrganization(env.DB, orgId)).find((collection) => collection.externalId === externalId);
  const collection = existingCollection ?? {
    id: generateUUID(),
    organizationId: orgId,
    name: displayName,
    externalId,
    createdAt: now,
    updatedAt: now,
  };
  if (!existingCollection) {
    await saveCollection(env.DB, collection);
  }

  const memberExternalIds = Array.isArray(body.members)
    ? body.members.map((member: any) => String(member?.value || '')).filter(Boolean)
    : [];
  if (memberExternalIds.length) {
    await applyGroupMembers(env.DB, env, orgId, collection.id, memberExternalIds);
  }

  await writeScimAudit(env, null, 'scim.group.create', { organizationId: orgId, groupName: displayName, externalId });

  const currentMembers = await getGroupMemberExternalIds(env.DB, orgId, collection.id);
  return scimJson(groupToScim(collection, currentMembers), existingCollection ? 200 : 201);
}

// GET /api/scim/v2/Groups/:id
export async function handleScimGetGroup(request: Request, env: Env, orgId: string, id: string): Promise<Response> {
  void request;
  const collection = (await getCollectionsForOrganization(env.DB, orgId)).find((c) => c.externalId === id || c.id === id);
  if (!collection) return scimError(404, 'Group not found');
  const memberExternalIds = await getGroupMemberExternalIds(env.DB, orgId, collection.id);
  return scimJson(groupToScim(collection, memberExternalIds));
}

// PUT /api/scim/v2/Groups/:id
export async function handleScimPutGroup(request: Request, env: Env, orgId: string, id: string): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return scimError(400, 'Invalid JSON body');
  }

  const collection = (await getCollectionsForOrganization(env.DB, orgId)).find((c) => c.externalId === id || c.id === id);
  if (!collection) return scimError(404, 'Group not found');

  const displayName = String(body.displayName || collection.name).trim();
  collection.name = displayName || collection.name;
  collection.updatedAt = new Date().toISOString();
  await saveCollection(env.DB, collection);

  const memberExternalIds = Array.isArray(body.members)
    ? body.members.map((member: any) => String(member?.value || '')).filter(Boolean)
    : [];
  await applyGroupMembers(env.DB, env, orgId, collection.id, memberExternalIds);

  await writeScimAudit(env, null, 'scim.group.update', { organizationId: orgId, groupName: collection.name });

  const currentMembers = await getGroupMemberExternalIds(env.DB, orgId, collection.id);
  return scimJson(groupToScim(collection, currentMembers));
}

// PATCH /api/scim/v2/Groups/:id
export async function handleScimPatchGroup(request: Request, env: Env, orgId: string, id: string): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return scimError(400, 'Invalid JSON body');
  }

  const collection = (await getCollectionsForOrganization(env.DB, orgId)).find((c) => c.externalId === id || c.id === id);
  if (!collection) return scimError(404, 'Group not found');

  const operations = Array.isArray(body.Operations) ? body.Operations : [];
  for (const operation of operations) {
    const op = String(operation.op || '').toLowerCase();
    if (op === 'replace' && operation.path === 'displayName') {
      const value = String(operation.value || '').trim();
      if (value) collection.name = value;
    }
    if ((op === 'add' || op === 'remove' || op === 'replace') && (!operation.path || operation.path === 'members')) {
      const memberIds = Array.isArray(operation.value)
        ? operation.value.map((member: any) => String(member?.value || '')).filter(Boolean)
        : [];
      const current = await getGroupMemberExternalIds(env.DB, orgId, collection.id);
      let next = current;
      if (op === 'add') {
        next = Array.from(new Set([...current, ...memberIds]));
      } else if (op === 'remove') {
        const removeSet = new Set(memberIds);
        next = current.filter((externalId) => !removeSet.has(externalId));
      } else if (op === 'replace') {
        next = memberIds;
      }
      await applyGroupMembers(env.DB, env, orgId, collection.id, next);
    }
  }
  collection.updatedAt = new Date().toISOString();
  await saveCollection(env.DB, collection);

  await writeScimAudit(env, null, 'scim.group.patch', { organizationId: orgId, groupName: collection.name });

  const currentMembers = await getGroupMemberExternalIds(env.DB, orgId, collection.id);
  return scimJson(groupToScim(collection, currentMembers));
}

// DELETE /api/scim/v2/Groups/:id
export async function handleScimDeleteGroup(request: Request, env: Env, orgId: string, id: string): Promise<Response> {
  const collection = (await getCollectionsForOrganization(env.DB, orgId)).find((c) => c.externalId === id || c.id === id);
  if (!collection) return scimError(404, 'Group not found');

  // Everyone in the org loses a collection from their sync view, not only the
  // members whose access list referenced it.
  const memberIds = await getOrganizationMemberIds(env.DB, orgId);
  await deleteCollection(env.DB, collection.id);
  await bumpUserRevisions(env, memberIds, readActingDeviceIdentifier(request));

  await writeScimAudit(env, null, 'scim.group.delete', { organizationId: orgId, groupName: collection.name });
  return new Response(null, { status: 204 });
}