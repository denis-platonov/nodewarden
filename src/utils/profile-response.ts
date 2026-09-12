import type { Env, ProfileResponse, User, OrganizationResponse } from '../types';
import { buildAccountKeys } from './user-decryption';
import { isYubiKeyEnabled } from './yubico-otp';
import { getOrganizationsForUser } from '../services/storage-organization-repo';
import { getOrganizationMembershipsForUser } from '../services/storage-organization-repo';

function toProfileOrganization(org: NonNullable<Awaited<ReturnType<typeof getOrganizationsForUser>>[number]>): OrganizationResponse {
  return {
    id: org.id,
    name: org.name,
    enabled: org.enabled,
    useTotp: org.useTotp,
    ownerId: org.ownerId,
    billingEmail: org.billingEmail,
    // Null here on purpose, and filled in per member below.
    //
    // `key` is the ORGANIZATION'S SYMMETRIC KEY, RSA-wrapped under the
    // reading member's own public key -- it is the thing a client unwraps
    // with its private key to read that organization's ciphers, and it is
    // therefore different for every member. It is not the organization's
    // public key, which is the separate `publicKey` field below.
    //
    // This used to be `org.publicKey`, which is per-organization and could
    // never be unwrapped by anybody. A client following the protocol would
    // fail every field of every shared item, and only once its owner had
    // created their first organization.
    key: null,
    publicKey: org.publicKey,
    privateKey: org.privateKey,
    identifier: org.identifier,
    creationDate: org.createdAt,
    revisionDate: org.updatedAt,
    object: 'organization',
  };
}

/**
 * One organization as the member reading it sees it.
 *
 * Exported and pure so the key invariant below can be tested without a
 * database: it is the one thing here that silently breaks every shared item
 * when it is wrong, and it was wrong.
 */
export function organizationForMember(
  org: NonNullable<Awaited<ReturnType<typeof getOrganizationsForUser>>[number]>,
  membership: { role?: string; permissions?: unknown; encryptedOrgKey?: string | null } | undefined,
): Record<string, unknown> {
  const base = toProfileOrganization(org);
  const role = membership?.role ?? 'member';
  // The member's own RSA-wrapped copy of the organization's symmetric key,
  // in the field every Bitwarden client reads it from. `encryptedOrgKey` is
  // kept beside it rather than instead of it -- that is the spelling this
  // server has always sent, so anything already reading it keeps working.
  const wrapped = membership?.encryptedOrgKey ?? null;
  return {
    ...base,
    // Members decrypt with the symmetric org key; only admins get the org
    // private key.
    privateKey: role === 'owner' || role === 'admin' ? base.privateKey : null,
    role,
    permissions: membership?.permissions ?? {},
    key: wrapped,
    encryptedOrgKey: wrapped,
    users: [],
  };
}

export async function buildProfileResponse(user: User, env: Env): Promise<ProfileResponse> {
  const accountKeys = buildAccountKeys(user);

  let organizations: any[] = [];
  if (env?.DB) {
    try {
      const [orgs, memberships] = await Promise.all([
        getOrganizationsForUser(env.DB, user.id),
        getOrganizationMembershipsForUser(env.DB, user.id),
      ]);
      const memberByOrg = new Map(memberships.map((m) => [m.organizationId, m]));
      organizations = orgs
        .filter((org) => org.enabled)
        .map((org) => organizationForMember(org, memberByOrg.get(org.id)));
    } catch (error) {
      console.error('Failed to load organizations for profile:', error);
      organizations = [];
    }
  }

  return {
    id: user.id,
    name: user.name,
    email: user.email,
    emailVerified: true,
    premium: true,
    premiumFromOrganization: organizations.length > 0,
    usesKeyConnector: false,
    masterPasswordHint: user.masterPasswordHint,
    culture: 'en-US',
    twoFactorEnabled: !!user.totpSecret || isYubiKeyEnabled(user),
    yubikeyEnabled: isYubiKeyEnabled(user),
    key: user.key,
    privateKey: user.privateKey,
    accountKeys,
    securityStamp: user.securityStamp || user.id,
    organizations,
    organizationsNew: organizations,
    providers: [],
    providerOrganizations: [],
    forcePasswordReset: false,
    avatarColor: null,
    creationDate: user.createdAt,
    // New-device verification is not supported without an email delivery channel.
    // Always report disabled so clients do not present a false security posture.
    verifyDevices: false,
    role: user.role,
    status: user.status,
    object: 'profile',
  };
}