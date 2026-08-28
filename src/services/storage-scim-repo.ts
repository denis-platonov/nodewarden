import type { ScimConfig, ScimUser } from '../types';

function mapScimConfigRow(row: any): ScimConfig {
  return {
    organizationId: row.organization_id,
    enabled: Boolean(row.enabled),
    tokenHash: row.token_hash ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapScimUserRow(row: any): ScimUser {
  return {
    organizationId: row.organization_id,
    externalId: row.external_id,
    userId: row.user_id ?? null,
    active: Boolean(row.active),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function getScimConfig(db: D1Database, organizationId: string): Promise<ScimConfig | null> {
  const row = await db
    .prepare('SELECT organization_id, enabled, token_hash, created_at, updated_at FROM scim_configs WHERE organization_id = ?')
    .bind(organizationId)
    .first<any>();
  if (!row) return null;
  return mapScimConfigRow(row);
}

export async function saveScimConfig(db: D1Database, config: ScimConfig): Promise<void> {
  await db
    .prepare(
      'INSERT INTO scim_configs(organization_id, enabled, token_hash, created_at, updated_at) VALUES(?, ?, ?, ?, ?) ' +
      'ON CONFLICT(organization_id) DO UPDATE SET enabled=excluded.enabled, token_hash=excluded.token_hash, updated_at=excluded.updated_at'
    )
    .bind(config.organizationId, config.enabled ? 1 : 0, config.tokenHash, config.createdAt, config.updatedAt)
    .run();
}

export async function deleteScimConfig(db: D1Database, organizationId: string): Promise<void> {
  await db.prepare('DELETE FROM scim_configs WHERE organization_id = ?').bind(organizationId).run();
}

export async function getScimUser(db: D1Database, organizationId: string, externalId: string): Promise<ScimUser | null> {
  const row = await db
    .prepare('SELECT organization_id, external_id, user_id, active, created_at, updated_at FROM scim_users WHERE organization_id = ? AND external_id = ?')
    .bind(organizationId, externalId)
    .first<any>();
  if (!row) return null;
  return mapScimUserRow(row);
}

export async function getScimUserByUserId(db: D1Database, organizationId: string, userId: string): Promise<ScimUser | null> {
  const row = await db
    .prepare('SELECT organization_id, external_id, user_id, active, created_at, updated_at FROM scim_users WHERE organization_id = ? AND user_id = ?')
    .bind(organizationId, userId)
    .first<any>();
  if (!row) return null;
  return mapScimUserRow(row);
}

export async function getScimUserByEmail(db: D1Database, organizationId: string, email: string): Promise<ScimUser | null> {
  const row = await db
    .prepare(
      `SELECT su.organization_id, su.external_id, su.user_id, su.active, su.created_at, su.updated_at
       FROM scim_users su
       JOIN users u ON u.id = su.user_id
       WHERE su.organization_id = ? AND u.email = ? COLLATE NOCASE`
    )
    .bind(organizationId, email)
    .first<any>();
  if (!row) return null;
  return mapScimUserRow(row);
}

export async function listScimUsers(db: D1Database, organizationId: string): Promise<ScimUser[]> {
  const res = await db
    .prepare('SELECT organization_id, external_id, user_id, active, created_at, updated_at FROM scim_users WHERE organization_id = ? ORDER BY created_at ASC')
    .bind(organizationId)
    .all<any>();
  return (res.results || []).map(mapScimUserRow);
}

export async function saveScimUser(db: D1Database, user: ScimUser): Promise<void> {
  await db
    .prepare(
      'INSERT INTO scim_users(organization_id, external_id, user_id, active, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(organization_id, external_id) DO UPDATE SET user_id=excluded.user_id, active=excluded.active, updated_at=excluded.updated_at'
    )
    .bind(user.organizationId, user.externalId, user.userId, user.active ? 1 : 0, user.createdAt, user.updatedAt)
    .run();
}

export async function deleteScimUser(db: D1Database, organizationId: string, externalId: string): Promise<void> {
  await db.prepare('DELETE FROM scim_users WHERE organization_id = ? AND external_id = ?').bind(organizationId, externalId).run();
}