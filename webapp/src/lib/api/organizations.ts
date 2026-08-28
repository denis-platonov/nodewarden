import type { AuthedFetch } from './shared';
import { parseErrorMessage } from './shared';

export interface OrganizationSummary {
  id: string;
  name: string;
  enabled: boolean;
  useTotp: boolean;
  billingEmail: string | null;
  identifier: string | null;
  creationDate: string;
  revisionDate: string;
  object: 'organization';
  role?: string;
  encryptedOrgKey?: string | null;
}

export interface OrganizationMemberItem {
  id: string;
  email: string;
  name: string | null;
  status: number;
  role: string;
  permissions: Record<string, unknown>;
  collections: string[];
  encryptedOrgKey: string | null;
  type: number;
  object: 'organizationMember';
}

export interface OrganizationInvitationItem {
  id: string;
  email: string;
  role: string;
  status: number;
  object: 'organizationInvitation';
}

export interface CollectionItem {
  id: string;
  organizationId: string;
  name: string;
  externalId: string | null;
  creationDate: string;
  revisionDate: string;
  object: 'collection';
}

export interface SsoConfigItem {
  organizationId: string;
  enabled: boolean;
  identifier: string | null;
  provider: string;
  clientId: string | null;
  issuer: string | null;
  authorizationEndpoint: string | null;
  tokenEndpoint: string | null;
  userinfoEndpoint: string | null;
  jwksUri: string | null;
  scopes: string | null;
  clientSecretSet: boolean;
  object: 'ssoConfig';
}

export interface ScimConfigItem {
  organizationId: string;
  enabled: boolean;
  tokenGenerated: boolean;
  token?: string;
  object: 'scimConfig';
}

export async function listOrganizations(authedFetch: AuthedFetch): Promise<OrganizationSummary[]> {
  const resp = await authedFetch('/api/organizations');
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Organization request failed'));
  const body = await resp.json();
  return body?.data || [];
}

export async function createOrganization(authedFetch: AuthedFetch, body: Record<string, unknown>): Promise<OrganizationSummary> {
  const resp = await authedFetch('/api/organizations', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Organization request failed'));
  return resp.json();
}

export async function getOrganizationKeys(authedFetch: AuthedFetch, orgId: string): Promise<{ key: string | null; publicKey: string | null; privateKey: string | null }> {
  const resp = await authedFetch(`/api/organizations/${orgId}/keys`);
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Organization request failed'));
  return resp.json();
}

export async function listOrganizationMembers(authedFetch: AuthedFetch, orgId: string): Promise<OrganizationMemberItem[]> {
  const resp = await authedFetch(`/api/organizations/${orgId}/members`);
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Organization request failed'));
  const body = await resp.json();
  return body?.data || [];
}

export async function getMemberPublicKeyByEmail(authedFetch: AuthedFetch, orgId: string, email: string): Promise<{ userId: string; publicKey: string }> {
  const resp = await authedFetch(`/api/organizations/${orgId}/members/public-key?email=${encodeURIComponent(email)}`);
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Organization request failed'));
  return resp.json();
}

export async function inviteOrganizationMember(authedFetch: AuthedFetch, orgId: string, body: Record<string, unknown>): Promise<OrganizationMemberItem | OrganizationInvitationItem> {
  const resp = await authedFetch(`/api/organizations/${orgId}/members/invite`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Organization request failed'));
  return resp.json();
}

export async function updateOrganizationMember(authedFetch: AuthedFetch, orgId: string, memberId: string, body: Record<string, unknown>): Promise<OrganizationMemberItem> {
  const resp = await authedFetch(`/api/organizations/${orgId}/members/${memberId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Organization request failed'));
  return resp.json();
}

export async function removeOrganizationMember(authedFetch: AuthedFetch, orgId: string, memberId: string): Promise<void> {
  const resp = await authedFetch(`/api/organizations/${orgId}/members/${memberId}`, { method: 'DELETE' });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Organization request failed'));
}

export async function listOrganizationInvitations(authedFetch: AuthedFetch, orgId: string): Promise<OrganizationInvitationItem[]> {
  const resp = await authedFetch(`/api/organizations/${orgId}/invitations`);
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Organization request failed'));
  const body = await resp.json();
  return body?.data || [];
}

export async function revokeOrganizationInvitation(authedFetch: AuthedFetch, orgId: string, invitationId: string): Promise<void> {
  const resp = await authedFetch(`/api/organizations/${orgId}/invitations/${invitationId}`, { method: 'DELETE' });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Organization request failed'));
}

export async function listCollections(authedFetch: AuthedFetch, orgId: string): Promise<CollectionItem[]> {
  const resp = await authedFetch(`/api/organizations/${orgId}/collections`);
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Organization request failed'));
  const body = await resp.json();
  return body?.data || [];
}

export async function createCollection(authedFetch: AuthedFetch, orgId: string, body: { name: string }): Promise<CollectionItem> {
  const resp = await authedFetch(`/api/organizations/${orgId}/collections`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Organization request failed'));
  return resp.json();
}

export async function updateCollection(authedFetch: AuthedFetch, orgId: string, collectionId: string, body: { name: string }): Promise<CollectionItem> {
  const resp = await authedFetch(`/api/organizations/${orgId}/collections/${collectionId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Organization request failed'));
  return resp.json();
}

export async function deleteCollection(authedFetch: AuthedFetch, orgId: string, collectionId: string): Promise<void> {
  const resp = await authedFetch(`/api/organizations/${orgId}/collections/${collectionId}`, { method: 'DELETE' });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Organization request failed'));
}

export async function getSsoConfig(authedFetch: AuthedFetch, orgId: string): Promise<SsoConfigItem> {
  const resp = await authedFetch(`/api/organizations/${orgId}/sso`);
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Organization request failed'));
  return resp.json();
}

export async function saveSsoConfig(authedFetch: AuthedFetch, orgId: string, body: Record<string, unknown>): Promise<SsoConfigItem> {
  const resp = await authedFetch(`/api/organizations/${orgId}/sso`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Organization request failed'));
  return resp.json();
}

export async function deleteSsoConfig(authedFetch: AuthedFetch, orgId: string): Promise<void> {
  const resp = await authedFetch(`/api/organizations/${orgId}/sso`, { method: 'DELETE' });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Organization request failed'));
}

export async function getScimConfig(authedFetch: AuthedFetch, orgId: string): Promise<ScimConfigItem> {
  const resp = await authedFetch(`/api/organizations/${orgId}/scim`);
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Organization request failed'));
  return resp.json();
}

export async function saveScimConfig(authedFetch: AuthedFetch, orgId: string, body: Record<string, unknown>): Promise<ScimConfigItem> {
  const resp = await authedFetch(`/api/organizations/${orgId}/scim`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Organization request failed'));
  return resp.json();
}

export async function deleteScimConfig(authedFetch: AuthedFetch, orgId: string): Promise<void> {
  const resp = await authedFetch(`/api/organizations/${orgId}/scim`, { method: 'DELETE' });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Organization request failed'));
}