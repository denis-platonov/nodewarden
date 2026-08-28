import type { Cipher, OrganizationMember } from '../types';
import { getCipher, getCiphersByCollectionIds } from './storage-cipher-repo';
import { getOrganizationMember, canAccessAllCollections, getAccessibleCollectionsForUser } from './storage-organization-repo';

export async function getUserAccessibleCollectionIds(db: D1Database, userId: string): Promise<string[]> {
  const collections = await getAccessibleCollectionsForUser(db, userId);
  return collections.map((collection) => collection.id);
}

export interface CipherAccessResult {
  cipher: Cipher;
  member: OrganizationMember | null;
  organizationId: string | null;
  accessibleCollectionIds: string[];
  canManageCollections: boolean;
}

export async function resolveCipherAccess(db: D1Database, userId: string, cipherId: string): Promise<CipherAccessResult | null> {
  const cipher = await getCipher(db, cipherId);
  if (!cipher) return null;

  const organizationId = String((cipher as any).organizationId || '').trim() || null;

  // Personal cipher: only the owner may access it.
  if (!organizationId) {
    if (cipher.userId !== userId) return null;
    return {
      cipher,
      member: null,
      organizationId: null,
      accessibleCollectionIds: [],
      canManageCollections: false,
    };
  }

  // Organization cipher: the user must be an accepted member with access to at
  // least one collection the cipher belongs to.
  const member = await getOrganizationMember(db, organizationId, userId);
  if (!member || member.status !== 1) return null;

  const cipherCollectionIds: string[] = Array.isArray((cipher as any).collectionIds)
    ? (cipher as any).collectionIds.map((id: unknown) => String(id))
    : [];

  const userCollectionIds = await getUserAccessibleCollectionIds(db, userId);

  if (canAccessAllCollections(member)) {
    return {
      cipher,
      member,
      organizationId,
      accessibleCollectionIds: userCollectionIds,
      canManageCollections: true,
    };
  }

  const hasAccess =
    cipherCollectionIds.length === 0
      ? member.collections.length > 0
      : cipherCollectionIds.some((id) => member.collections.includes(id));
  if (!hasAccess) return null;

  return {
    cipher,
    member,
    organizationId,
    accessibleCollectionIds: userCollectionIds,
    canManageCollections: false,
  };
}

export async function getAccessibleOrgCiphers(db: D1Database, userId: string): Promise<Cipher[]> {
  const collectionIds = await getUserAccessibleCollectionIds(db, userId);
  if (!collectionIds.length) return [];
  return getCiphersByCollectionIds(db, () => 95, collectionIds);
}

export function isOrgCipher(cipher: Cipher): boolean {
  const organizationId = String((cipher as any).organizationId || '').trim();
  const collectionIds = (cipher as any).collectionIds;
  return !!organizationId || (Array.isArray(collectionIds) && collectionIds.length > 0);
}

export function readOrgCipherFields(cipher: Cipher): { organizationId: string | null; collectionIds: string[] } {
  const organizationId = String((cipher as any).organizationId || '').trim() || null;
  const collectionIds = Array.isArray((cipher as any).collectionIds)
    ? (cipher as any).collectionIds.map((id: unknown) => String(id || '').trim()).filter(Boolean)
    : [];
  return { organizationId, collectionIds };
}

export function setOrgCipherFields(cipher: Cipher, organizationId: string | null, collectionIds: string[]): Cipher {
  (cipher as any).organizationId = organizationId;
  (cipher as any).collectionIds = collectionIds;
  return cipher;
}

export async function validateOrgCollectionsForCipher(
  db: D1Database,
  userId: string,
  organizationId: string | null,
  collectionIds: string[] | null | undefined
): Promise<{ ok: boolean; error?: string; member?: OrganizationMember | null }> {
  if (!organizationId) return { ok: true };
  const member = await getOrganizationMember(db, organizationId, userId);
  if (!member || member.status !== 1) {
    return { ok: false, error: 'Organization not found' };
  }
  if (!collectionIds || collectionIds.length === 0) {
    if (canAccessAllCollections(member)) return { ok: true, member };
    return { ok: false, error: 'A collection is required for organization ciphers' };
  }
  const userCollectionIds = await getUserAccessibleCollectionIds(db, userId);
  const allowed = new Set(userCollectionIds);
  for (const collectionId of collectionIds) {
    if (!allowed.has(collectionId)) {
      return { ok: false, error: 'You do not have access to one of the selected collections' };
    }
  }
  return { ok: true, member };
}