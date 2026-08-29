import type { SsoConfig } from '../types';

export interface SsoState {
  state: string;
  organizationId: string;
  redirectUri: string;
  codeChallenge: string | null;
  nonce: string | null;
  expiresAt: number;
  createdAt: number;
}

export interface SsoCode {
  code: string;
  userId: string;
  redirectUri: string;
  codeChallenge: string | null;
  expiresAt: number;
  used: number;
  createdAt: number;
}

function mapSsoConfigRow(row: any): SsoConfig {
  return {
    organizationId: row.organization_id,
    enabled: Boolean(row.enabled),
    identifier: row.identifier ?? null,
    provider: row.provider || 'oidc',
    clientId: row.client_id ?? null,
    clientSecret: row.client_secret ?? null,
    issuer: row.issuer ?? null,
    authorizationEndpoint: row.authorization_endpoint ?? null,
    tokenEndpoint: row.token_endpoint ?? null,
    userinfoEndpoint: row.userinfo_endpoint ?? null,
    jwksUri: row.jwks_uri ?? null,
    scopes: row.scopes ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function getSsoConfig(db: D1Database, organizationId: string): Promise<SsoConfig | null> {
  const row = await db
    .prepare('SELECT organization_id, enabled, identifier, provider, client_id, client_secret, issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri, scopes, created_at, updated_at FROM sso_configs WHERE organization_id = ?')
    .bind(organizationId)
    .first<any>();
  if (!row) return null;
  return mapSsoConfigRow(row);
}

export async function getSsoConfigByIdentifier(db: D1Database, identifier: string): Promise<SsoConfig | null> {
  const row = await db
    .prepare('SELECT organization_id, enabled, identifier, provider, client_id, client_secret, issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri, scopes, created_at, updated_at FROM sso_configs WHERE identifier = ? COLLATE NOCASE')
    .bind(identifier)
    .first<any>();
  if (!row) return null;
  return mapSsoConfigRow(row);
}

export async function saveSsoConfig(db: D1Database, config: SsoConfig): Promise<void> {
  await db
    .prepare(
      'INSERT INTO sso_configs(organization_id, enabled, identifier, provider, client_id, client_secret, issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri, scopes, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(organization_id) DO UPDATE SET enabled=excluded.enabled, identifier=excluded.identifier, provider=excluded.provider, client_id=excluded.client_id, client_secret=excluded.client_secret, issuer=excluded.issuer, authorization_endpoint=excluded.authorization_endpoint, token_endpoint=excluded.token_endpoint, userinfo_endpoint=excluded.userinfo_endpoint, jwks_uri=excluded.jwks_uri, scopes=excluded.scopes, updated_at=excluded.updated_at'
    )
    .bind(
      config.organizationId,
      config.enabled ? 1 : 0,
      config.identifier,
      config.provider || 'oidc',
      config.clientId,
      config.clientSecret,
      config.issuer,
      config.authorizationEndpoint,
      config.tokenEndpoint,
      config.userinfoEndpoint,
      config.jwksUri,
      config.scopes,
      config.createdAt,
      config.updatedAt
    )
    .run();
}

export async function deleteSsoConfig(db: D1Database, organizationId: string): Promise<void> {
  await db.prepare('DELETE FROM sso_configs WHERE organization_id = ?').bind(organizationId).run();
}

export async function saveSsoState(db: D1Database, state: SsoState): Promise<void> {
  await db
    .prepare('INSERT INTO sso_states(state, organization_id, redirect_uri, code_challenge, nonce, expires_at, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)')
    .bind(state.state, state.organizationId, state.redirectUri, state.codeChallenge, state.nonce ?? null, state.expiresAt, state.createdAt)
    .run();
}

export async function getSsoState(db: D1Database, state: string): Promise<SsoState | null> {
  const row = await db
    .prepare('SELECT state, organization_id, redirect_uri, code_challenge, nonce, expires_at, created_at FROM sso_states WHERE state = ?')
    .bind(state)
    .first<any>();
  if (!row) return null;
  return {
    state: row.state,
    organizationId: row.organization_id,
    redirectUri: row.redirect_uri,
    codeChallenge: row.code_challenge ?? null,
    nonce: row.nonce ?? null,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
  };
}

export async function deleteSsoState(db: D1Database, state: string): Promise<void> {
  await db.prepare('DELETE FROM sso_states WHERE state = ?').bind(state).run();
}

export async function saveSsoCode(db: D1Database, code: SsoCode): Promise<void> {
  await db
    .prepare('INSERT INTO sso_codes(code, user_id, redirect_uri, code_challenge, expires_at, used, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)')
    .bind(code.code, code.userId, code.redirectUri, code.codeChallenge, code.expiresAt, code.used, code.createdAt)
    .run();
}

export async function getSsoCode(db: D1Database, code: string): Promise<SsoCode | null> {
  const row = await db
    .prepare('SELECT code, user_id, redirect_uri, code_challenge, expires_at, used, created_at FROM sso_codes WHERE code = ?')
    .bind(code)
    .first<any>();
  if (!row) return null;
  return {
    code: row.code,
    userId: row.user_id,
    redirectUri: row.redirect_uri,
    codeChallenge: row.code_challenge ?? null,
    expiresAt: row.expires_at,
    used: row.used,
    createdAt: row.created_at,
  };
}

// Claims the code atomically: only the caller whose UPDATE actually flipped
// `used` may continue, so concurrent redemptions cannot both succeed.
export async function claimSsoCode(db: D1Database, code: string): Promise<boolean> {
  const result = await db.prepare('UPDATE sso_codes SET used = 1 WHERE code = ? AND used = 0').bind(code).run();
  const changes = (result as any)?.meta?.changes;
  return typeof changes === 'number' ? changes > 0 : true;
}

export async function deleteSsoCode(db: D1Database, code: string): Promise<void> {
  await db.prepare('DELETE FROM sso_codes WHERE code = ?').bind(code).run();
}

export async function pruneSsoStates(db: D1Database, nowMs: number): Promise<void> {
  await db.prepare('DELETE FROM sso_states WHERE expires_at < ?').bind(nowMs).run();
}

export async function pruneSsoCodes(db: D1Database, nowMs: number): Promise<void> {
  await db.prepare('DELETE FROM sso_codes WHERE expires_at < ? OR used = 1').bind(nowMs).run();
}