import type { Env, Cipher } from '../types';
import { getOrganizationMemberIds } from '../services/storage-organization-repo';
import { getCipherCollections, addCollectionItem, removeCollectionItem } from '../services/storage-organization-repo';
import { validateOrgCollectionsForCipher, readOrgCipherFields, setOrgCipherFields, isOrgCipher } from '../services/storage-org-access';
import { bumpUserRevisions } from '../utils/revision';

export { readOrgCipherFields, setOrgCipherFields, isOrgCipher };

// Validates org membership + collection access, then reconciles the cipher's
// collection_items rows to match the requested collectionIds. Returns an error
// message when the user is not allowed to create/update this organization cipher.
export async function reconcileOrgCipherMembership(
  db: D1Database,
  userId: string,
  cipher: Cipher
): Promise<{ ok: boolean; error?: string }> {
  const { organizationId, collectionIds } = readOrgCipherFields(cipher);

  if (!organizationId) {
    // A cipher without an org must not keep stale collection links.
    const current = await getCipherCollections(db, cipher.id);
    for (const collectionId of current) {
      await removeCollectionItem(db, collectionId, cipher.id);
    }
    setOrgCipherFields(cipher, null, []);
    return { ok: true };
  }

  const validation = await validateOrgCollectionsForCipher(db, userId, organizationId, collectionIds);
  if (!validation.ok) {
    return { ok: false, error: validation.error || 'Organization access denied' };
  }

  const normalized = Array.from(new Set(collectionIds));
  const current = await getCipherCollections(db, cipher.id);
  const currentSet = new Set(current);
  const targetSet = new Set(normalized);

  for (const collectionId of current) {
    if (!targetSet.has(collectionId)) {
      await removeCollectionItem(db, collectionId, cipher.id);
    }
  }
  for (const collectionId of normalized) {
    if (!currentSet.has(collectionId)) {
      await addCollectionItem(db, collectionId, cipher.id);
    }
  }

  setOrgCipherFields(cipher, organizationId, normalized);
  return { ok: true };
}

// After an org cipher is created/updated/deleted, refresh the sync revision for
// every accepted member of the organization so their clients pick up the change.
export async function notifyOrgCipherMembers(env: Env, organizationId: string, contextId?: string | null): Promise<void> {
  const memberIds = await getOrganizationMemberIds(env.DB, organizationId);
  await bumpUserRevisions(env, memberIds, contextId);
}