import type { Env, SsoConfig, SsoConfigResponse, User } from '../types';
import { errorResponse, jsonResponse } from '../utils/response';
import { getOrganization, getOrganizationMember, saveOrganization, getOrganizationInvitations } from '../services/storage-organization-repo';
import { saveOrganizationMember, deleteOrganizationInvitation } from '../services/storage-organization-repo';
import { isOrgAdmin } from '../services/storage-organization-repo';
import { getUser, getUserById } from '../services/storage-user-repo';
import {
  getSsoConfig,
  getSsoConfigByIdentifier,
  saveSsoConfig,
  deleteSsoConfig,
  saveSsoState,
  getSsoState,
  deleteSsoState,
  saveSsoCode,
  getSsoCode,
  markSsoCodeUsed,
  deleteSsoCode,
  pruneSsoStates,
  pruneSsoCodes,
} from '../services/storage-sso-repo';
import { generateUUID } from '../utils/uuid';
import { bytesToBase64Url } from '../utils/passkey';
import { safeWriteAuditEvent } from '../services/audit-events';
import { bumpUserRevisions } from '../utils/revision';

const SSO_STATE_TTL_MS = 10 * 60 * 1000;
const SSO_CODE_TTL_MS = 10 * 60 * 1000;

async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return bytesToBase64Url(new Uint8Array(digest));
}

function toSsoConfigResponse(config: SsoConfig | null): SsoConfigResponse {
  return {
    organizationId: config?.organizationId ?? '',
    enabled: config?.enabled ?? false,
    identifier: config?.identifier ?? null,
    provider: config?.provider ?? 'oidc',
    clientId: config?.clientId ?? null,
    issuer: config?.issuer ?? null,
    authorizationEndpoint: config?.authorizationEndpoint ?? null,
    tokenEndpoint: config?.tokenEndpoint ?? null,
    userinfoEndpoint: config?.userinfoEndpoint ?? null,
    jwksUri: config?.jwksUri ?? null,
    scopes: config?.scopes ?? null,
    clientSecretSet: !!config?.clientSecret,
    creationDate: config?.createdAt ?? new Date().toISOString(),
    revisionDate: config?.updatedAt ?? new Date().toISOString(),
    object: 'ssoConfig',
  };
}

async function writeSsoAudit(env: Env, actorUserId: string, action: string, metadata: Record<string, unknown>): Promise<void> {
  await safeWriteAuditEvent(env, {
    actorUserId,
    action,
    category: 'auth',
    level: action.includes('delete') || action.includes('fail') ? 'security' : 'info',
    targetType: 'ssoConfig',
    targetId: typeof metadata.organizationId === 'string' ? metadata.organizationId : null,
    metadata,
  });
}

interface OidcEndpoints {
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userinfoEndpoint: string;
}

async function resolveOidcEndpoints(config: SsoConfig, request: Request): Promise<OidcEndpoints | null> {
  if (config.authorizationEndpoint && config.tokenEndpoint && config.userinfoEndpoint) {
    return {
      authorizationEndpoint: config.authorizationEndpoint,
      tokenEndpoint: config.tokenEndpoint,
      userinfoEndpoint: config.userinfoEndpoint,
    };
  }
  if (!config.issuer) return null;

  let issuer = config.issuer.trim();
  if (!/^https?:\/\//i.test(issuer)) issuer = `https://${issuer}`;
  const discoveryUrl = `${issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`;
  try {
    const response = await fetch(discoveryUrl, { signal: AbortSignal.timeout(10_000) });
    if (!response.ok) return null;
    const document = await response.json() as Record<string, unknown>;
    return {
      authorizationEndpoint: String(document.authorization_endpoint || ''),
      tokenEndpoint: String(document.token_endpoint || ''),
      userinfoEndpoint: String(document.userinfo_endpoint || ''),
    };
  } catch {
    return null;
  }
}

async function exchangeAuthorizationCode(
  config: SsoConfig,
  endpoints: OidcEndpoints,
  code: string,
  callbackUri: string
): Promise<{ accessToken: string | null; userinfo: Record<string, unknown> | null }> {
  if (!config.clientId) return { accessToken: null, userinfo: null };

  const body = new URLSearchParams();
  body.set('grant_type', 'authorization_code');
  body.set('code', code);
  body.set('redirect_uri', callbackUri);
  body.set('client_id', config.clientId);
  if (config.clientSecret) body.set('client_secret', config.clientSecret);

  try {
    const tokenResponse = await fetch(endpoints.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body,
      signal: AbortSignal.timeout(15_000),
    });
    if (!tokenResponse.ok) return { accessToken: null, userinfo: null };
    const tokenJson = await tokenResponse.json() as Record<string, unknown>;
    const accessToken = String(tokenJson.access_token || '');
    if (!accessToken) return { accessToken: null, userinfo: null };

    const userinfoResponse = await fetch(endpoints.userinfoEndpoint, {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
      signal: AbortSignal.timeout(10_000),
    });
    if (!userinfoResponse.ok) return { accessToken: null, userinfo: null };
    const userinfo = await userinfoResponse.json() as Record<string, unknown>;
    return { accessToken, userinfo };
  } catch {
    return { accessToken: null, userinfo: null };
  }
}

function readUserinfoEmail(userinfo: Record<string, unknown>): string | null {
  for (const key of ['email', 'Email', 'upn', 'preferred_username', 'unique_name']) {
    const value = userinfo[key];
    if (typeof value === 'string' && value.includes('@')) return value.trim().toLowerCase();
  }
  return null;
}

async function acceptPendingInvitations(env: Env, userId: string, organizationId: string, email: string): Promise<boolean> {
  const invitations = await getOrganizationInvitations(env.DB, organizationId);
  let accepted = false;
  for (const invitation of invitations) {
    if (
      invitation.status === 0 &&
      invitation.email.toLowerCase() === email.toLowerCase() &&
      new Date(invitation.expiresAt).getTime() >= Date.now()
    ) {
      const now = new Date().toISOString();
      await saveOrganizationMember(env.DB, {
        organizationId,
        userId,
        status: 1,
        role: invitation.role,
        permissions: invitation.permissions || {},
        collections: invitation.collections || [],
        encryptedOrgKey: null,
        createdAt: now,
        updatedAt: now,
      });
      await deleteOrganizationInvitation(env.DB, invitation.id);
      accepted = true;
    }
  }
  if (accepted) {
    await bumpUserRevisions(env, [userId]);
  }
  return accepted;
}

// ============ Org admin configuration endpoints ============

// GET /api/organizations/:id/sso
export async function handleGetSsoConfig(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  void request;
  const member = await getOrganizationMember(env.DB, orgId, userId);
  if (!member || member.status !== 1 || !isOrgAdmin(member)) return errorResponse('Not found', 404);

  const config = await getSsoConfig(env.DB, orgId);
  return jsonResponse(toSsoConfigResponse(config));
}

// PUT /api/organizations/:id/sso
export async function handlePutSsoConfig(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await getOrganizationMember(env.DB, orgId, userId);
  if (!member || member.status !== 1 || !isOrgAdmin(member)) return errorResponse('Not found', 404);

  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const org = await getOrganization(env.DB, orgId);
  if (!org) return errorResponse('Not found', 404);

  const existing = await getSsoConfig(env.DB, orgId);
  const now = new Date().toISOString();
  const enabled = body.enabled !== undefined ? !!body.enabled : (existing?.enabled ?? false);
  const identifier = body.identifier !== undefined ? (body.identifier ? String(body.identifier).trim() : null) : (existing?.identifier ?? null);
  const provider = body.provider ? String(body.provider).trim() : (existing?.provider || 'oidc');

  if (enabled && identifier) {
    const conflicting = await getSsoConfigByIdentifier(env.DB, identifier);
    if (conflicting && conflicting.organizationId !== orgId) {
      return errorResponse('SSO identifier is already in use by another organization', 400);
    }
  }

  const config: SsoConfig = {
    organizationId: orgId,
    enabled,
    identifier,
    provider,
    clientId: body.clientId !== undefined ? (body.clientId ? String(body.clientId).trim() : null) : (existing?.clientId ?? null),
    clientSecret: body.clientSecret !== undefined ? (body.clientSecret ? String(body.clientSecret).trim() : null) : (existing?.clientSecret ?? null),
    issuer: body.issuer !== undefined ? (body.issuer ? String(body.issuer).trim() : null) : (existing?.issuer ?? null),
    authorizationEndpoint: body.authorizationEndpoint !== undefined ? (body.authorizationEndpoint ? String(body.authorizationEndpoint).trim() : null) : (existing?.authorizationEndpoint ?? null),
    tokenEndpoint: body.tokenEndpoint !== undefined ? (body.tokenEndpoint ? String(body.tokenEndpoint).trim() : null) : (existing?.tokenEndpoint ?? null),
    userinfoEndpoint: body.userinfoEndpoint !== undefined ? (body.userinfoEndpoint ? String(body.userinfoEndpoint).trim() : null) : (existing?.userinfoEndpoint ?? null),
    jwksUri: body.jwksUri !== undefined ? (body.jwksUri ? String(body.jwksUri).trim() : null) : (existing?.jwksUri ?? null),
    scopes: body.scopes !== undefined ? (body.scopes ? String(body.scopes).trim() : null) : (existing?.scopes ?? null),
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  };

  await saveSsoConfig(env.DB, config);

  // Keep the org identifier in sync for prelogin lookups.
  if (org.identifier !== identifier) {
    org.identifier = identifier;
    org.updatedAt = now;
    await saveOrganization(env.DB, org as any);
  }

  await writeSsoAudit(env, userId, 'sso.config.update', {
    organizationId: orgId,
    ssoIdentifier: identifier,
    ssoProvider: provider,
    enabled,
  });

  return jsonResponse(toSsoConfigResponse(config));
}

// DELETE /api/organizations/:id/sso
export async function handleDeleteSsoConfig(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  void request;
  const member = await getOrganizationMember(env.DB, orgId, userId);
  if (!member || member.status !== 1 || !isOrgAdmin(member)) return errorResponse('Not found', 404);

  await deleteSsoConfig(env.DB, orgId);
  await writeSsoAudit(env, userId, 'sso.config.delete', { organizationId: orgId });

  return new Response(null, { status: 204 });
}

// ============ Identity flow endpoints ============

// GET /identity/sso/prelogin?identifier=...
export async function handleSsoPrelogin(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const identifier = String(url.searchParams.get('identifier') || '').trim();
  if (!identifier) {
    return jsonResponse({ ssoAvailable: false, error: 'identifier_required' });
  }

  const config = await getSsoConfigByIdentifier(env.DB, identifier);
  if (!config || !config.enabled) {
    return jsonResponse({ ssoAvailable: false, error: 'sso_not_configured' });
  }
  const org = await getOrganization(env.DB, config.organizationId);
  if (!org || !org.enabled) {
    return jsonResponse({ ssoAvailable: false, error: 'sso_not_configured' });
  }

  return jsonResponse({
    ssoAvailable: true,
    organizationId: org.id,
    organizationName: org.name,
  });
}

// GET /identity/connect/authorize?client_id=...&redirect_uri=...&response_type=code&scope=...&state=...&code_challenge=...&identifier=...
export async function handleSsoAuthorize(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const clientId = String(url.searchParams.get('client_id') || '').trim();
  const redirectUri = String(url.searchParams.get('redirect_uri') || '').trim();
  const responseType = String(url.searchParams.get('response_type') || '').trim();
  const state = String(url.searchParams.get('state') || '').trim();
  const codeChallenge = String(url.searchParams.get('code_challenge') || '').trim();
  const identifier = String(url.searchParams.get('identifier') || url.searchParams.get('orgId') || '').trim();

  const origin = url.origin;
  const callbackUri = `${origin}/identity/sso/callback`;

  const redirectError = (error: string, description: string): Response =>
    Response.redirect(
      `${redirectUri}${redirectUri.includes('?') ? '&' : '?'}error=${encodeURIComponent(error)}&error_description=${encodeURIComponent(description)}${state ? `&state=${encodeURIComponent(state)}` : ''}`,
      302
    );

  if (clientId !== 'web' && clientId !== 'browser') {
    return jsonResponse({ error: 'unsupported_client', error_description: 'SSO is only supported for the web vault' }, 400);
  }
  if (responseType !== 'code') {
    return jsonResponse({ error: 'unsupported_response_type', error_description: 'Only the authorization code flow is supported' }, 400);
  }
  if (!redirectUri || !state || !codeChallenge || !identifier) {
    return jsonResponse({ error: 'invalid_request', error_description: 'redirect_uri, state, code_challenge and identifier are required' }, 400);
  }

  const config = await getSsoConfigByIdentifier(env.DB, identifier);
  if (!config || !config.enabled) {
    return redirectError('sso_not_configured', 'Single sign-on is not enabled for this organization');
  }
  const org = await getOrganization(env.DB, config.organizationId);
  if (!org || !org.enabled) {
    return redirectError('sso_not_configured', 'Single sign-on is not enabled for this organization');
  }

  const endpoints = await resolveOidcEndpoints(config, request);
  if (!endpoints || !endpoints.authorizationEndpoint) {
    return redirectError('server_error', 'Identity provider endpoints could not be resolved');
  }

  const nowMs = Date.now();
  await pruneSsoStates(env.DB, nowMs);
  await saveSsoState(env.DB, {
    state,
    organizationId: org.id,
    redirectUri,
    codeChallenge,
    expiresAt: nowMs + SSO_STATE_TTL_MS,
    createdAt: nowMs,
  });

  const scopes = config.scopes || 'openid email profile';
  const authorizeUrl = new URL(endpoints.authorizationEndpoint);
  authorizeUrl.searchParams.set('client_id', config.clientId || '');
  authorizeUrl.searchParams.set('redirect_uri', callbackUri);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('scope', scopes);
  authorizeUrl.searchParams.set('state', state);
  authorizeUrl.searchParams.set('code_challenge', codeChallenge);
  authorizeUrl.searchParams.set('code_challenge_method', 'S256');

  return Response.redirect(authorizeUrl.toString(), 302);
}

// GET /identity/sso/callback?code=...&state=...
export async function handleSsoCallback(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const code = String(url.searchParams.get('code') || '').trim();
  const state = String(url.searchParams.get('state') || '').trim();
  const origin = url.origin;
  const callbackUri = `${origin}/identity/sso/callback`;

  const failRedirect = (redirectUri: string, originalState: string, error: string, description: string): Response =>
    Response.redirect(
      `${redirectUri}${redirectUri.includes('?') ? '&' : '?'}error=${encodeURIComponent(error)}&error_description=${encodeURIComponent(description)}${originalState ? `&state=${encodeURIComponent(originalState)}` : ''}`,
      302
    );

  if (!code || !state) {
    return jsonResponse({ error: 'invalid_request', error_description: 'code and state are required' }, 400);
  }

  const ssoState = await getSsoState(env.DB, state);
  if (!ssoState || ssoState.expiresAt < Date.now()) {
    await deleteSsoState(env.DB, state);
    return jsonResponse({ error: 'invalid_grant', error_description: 'The SSO request has expired. Try again.' }, 400);
  }

  const config = await getSsoConfig(env.DB, ssoState.organizationId);
  if (!config || !config.enabled) {
    await deleteSsoState(env.DB, state);
    return failRedirect(ssoState.redirectUri, state, 'sso_not_configured', 'Single sign-on is not configured for this organization');
  }

  const endpoints = await resolveOidcEndpoints(config, request);
  if (!endpoints) {
    await deleteSsoState(env.DB, state);
    return failRedirect(ssoState.redirectUri, state, 'server_error', 'Identity provider endpoints could not be resolved');
  }

  const { userinfo } = await exchangeAuthorizationCode(config, endpoints, code, callbackUri);
  if (!userinfo) {
    await deleteSsoState(env.DB, state);
    await writeSsoAudit(env, 'unknown', 'sso.login.failed', {
      organizationId: ssoState.organizationId,
      reason: 'token_exchange_failed',
      ssoProvider: config.provider,
    });
    return failRedirect(ssoState.redirectUri, state, 'access_denied', 'The identity provider rejected the login request');
  }

  const email = readUserinfoEmail(userinfo);
  if (!email) {
    await deleteSsoState(env.DB, state);
    await writeSsoAudit(env, 'unknown', 'sso.login.failed', {
      organizationId: ssoState.organizationId,
      reason: 'no_email_in_userinfo',
      ssoProvider: config.provider,
    });
    return failRedirect(ssoState.redirectUri, state, 'access_denied', 'The identity provider did not return an email address');
  }

  const user = await getUser(env.DB, email);
  if (!user) {
    await deleteSsoState(env.DB, state);
    await writeSsoAudit(env, 'unknown', 'sso.login.failed', {
      organizationId: ssoState.organizationId,
      email,
      reason: 'no_account',
      ssoProvider: config.provider,
    });
    return failRedirect(ssoState.redirectUri, state, 'access_denied', 'No NodeWarden account exists for this email address');
  }
  if (user.status !== 'active') {
    await deleteSsoState(env.DB, state);
    return failRedirect(ssoState.redirectUri, state, 'access_denied', 'This account is disabled');
  }

  await acceptPendingInvitations(env, user.id, ssoState.organizationId, email);
  await deleteSsoState(env.DB, state);

  const nowMs = Date.now();
  await pruneSsoCodes(env.DB, nowMs);
  const ssoCode = generateUUID() + generateUUID();
  await saveSsoCode(env.DB, {
    code: ssoCode,
    userId: user.id,
    redirectUri: ssoState.redirectUri,
    codeChallenge: ssoState.codeChallenge,
    expiresAt: nowMs + SSO_CODE_TTL_MS,
    used: 0,
    createdAt: nowMs,
  });

  await writeSsoAudit(env, user.id, 'sso.login.success', {
    organizationId: ssoState.organizationId,
    email,
    ssoProvider: config.provider,
  });

  const separator = ssoState.redirectUri.includes('?') ? '&' : '?';
  const redirectUrl = `${ssoState.redirectUri}${separator}code=${encodeURIComponent(ssoCode)}&state=${encodeURIComponent(state)}`;
  return Response.redirect(redirectUrl, 302);
}

// Validates a one-time SSO code + PKCE verifier; returns the user when valid.
export async function validateSsoCode(
  env: Env,
  code: string,
  codeVerifier: string | null,
  redirectUri: string | null
): Promise<{ user: User; error?: never } | { user?: never; error: string }> {
  const ssoCode = await getSsoCode(env.DB, code);
  if (!ssoCode) return { error: 'Invalid SSO code' };
  if (ssoCode.used) return { error: 'SSO code has already been used' };
  if (ssoCode.expiresAt < Date.now()) {
    await deleteSsoCode(env.DB, code);
    return { error: 'SSO code has expired' };
  }
  if (redirectUri && ssoCode.redirectUri !== redirectUri) {
    return { error: 'redirect_uri mismatch' };
  }
  if (ssoCode.codeChallenge) {
    if (!codeVerifier) return { error: 'code_verifier is required' };
    const expectedChallenge = await sha256Base64Url(codeVerifier);
    if (expectedChallenge !== ssoCode.codeChallenge) {
      return { error: 'code_verifier mismatch' };
    }
  }

  const user = await getUserById(env.DB, ssoCode.userId);
  if (!user) return { error: 'Account not found' };
  if (user.status !== 'active') return { error: 'Account is disabled' };

  await markSsoCodeUsed(env.DB, code);
  await deleteSsoCode(env.DB, code);
  return { user };
}