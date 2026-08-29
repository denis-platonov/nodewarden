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
    key: org.publicKey,
    publicKey: org.publicKey,
    privateKey: org.privateKey,
    identifier: org.identifier,
    creationDate: org.createdAt,
    revisionDate: org.updatedAt,
    object: 'organization',
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
        .map((org) => {
          const base = toProfileOrganization(org);
          const membership = memberByOrg.get(org.id);
          const role = membership?.role ?? 'member';
          return {
            ...base,
            // Members decrypt with the symmetric org key below; only admins get
            // the org private key.
            privateKey: role === 'owner' || role === 'admin' ? base.privateKey : null,
            role,
            permissions: membership?.permissions ?? {},
            encryptedOrgKey: membership?.encryptedOrgKey ?? null,
            users: [],
          };
        });
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