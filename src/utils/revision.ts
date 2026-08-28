import type { Env } from '../types';
import { notifyUserVaultSync } from '../durable/notifications-hub';
import { updateRevisionDate } from '../services/storage-revision-repo';

export async function bumpUserRevisions(env: Env, userIds: string[], contextId?: string | null): Promise<void> {
  const unique = Array.from(new Set(userIds.filter(Boolean)));
  await Promise.all(unique.map(async (userId) => {
    const revisionDate = await updateRevisionDate(env.DB, userId);
    notifyUserVaultSync(env, userId, revisionDate, contextId ?? undefined);
  }));
}