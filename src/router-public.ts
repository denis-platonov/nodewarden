import { LIMITS } from './config/limits';
import {
  handleAccessSend,
  handleAccessSendFile,
  handleAccessSendV2,
  handleAccessSendFileV2,
  handleDownloadSendFile,
} from './handlers/sends';
import { handleKnownDevice } from './handlers/devices';
import {
  handleDigitalAssetLinkCheck,
  handleFillAssistForms,
  handleFillAssistManifest,
} from './handlers/fill-assist';
import { handleToken, handlePrelogin, handleRevocation } from './handlers/identity';
import { handleSsoPrelogin, handleSsoAuthorize, handleSsoCallback } from './handlers/sso';
import {
  authenticateScimRequest,
  handleScimServiceProviderConfig,
  handleScimResourceTypes,
  handleScimSchemas,
  handleScimListUsers,
  handleScimCreateUser,
  handleScimGetUser,
  handleScimPutUser,
  handleScimPatchUser,
  handleScimDeleteUser,
  handleScimListGroups,
  handleScimCreateGroup,
  handleScimGetGroup,
  handleScimPutGroup,
  handleScimPatchGroup,
  handleScimDeleteGroup,
} from './handlers/scim';
import { handleGetAccountPasskeyAssertionOptions } from './handlers/account-passkeys';
import {
  handleRegister,
  handleGetPasswordHint,
  handleRecoverTwoFactor,
} from './handlers/accounts';
import {
  handleCreateAuthRequest,
  handleGetAuthRequestResponse,
} from './handlers/auth-requests';
import { handlePublicDownloadAttachment } from './handlers/attachments';
import { handlePublicUploadAttachment } from './handlers/attachments';
import {
  handleAnonymousNotificationsHub,
  handleNotificationsHub,
  handleNotificationsNegotiate,
} from './handlers/notifications';
import { handlePublicUploadSendFile } from './handlers/sends';
import {
  handleWebsiteIcon,
  isWebsiteIconProxyEnabled,
} from './handlers/website-icons';
import { jsonResponse, unsupportedResponse } from './utils/response';
import { StorageService } from './services/storage';
import type { Env } from './types';
import { getConfiguredWebAuthnAllowedOrigins } from './utils/origins';
import { buildConfigResponse } from './config-response';

type PublicRateLimiter = (category?: string, maxRequests?: number) => Promise<Response | null>;
type JwtUnsafeReason = 'missing' | 'too_short' | null;

export interface WebBootstrapResponse {
  defaultKdfIterations: number;
  jwtUnsafeReason: JwtUnsafeReason;
  jwtSecretMinLength: number;
  registrationInviteRequired: boolean;
  webAuthnAllowedOrigins: string[];
  websiteIconsEnabled: boolean;
}

function isSameOriginWriteRequest(request: Request): boolean {
  const targetOrigin = new URL(request.url).origin;
  const origin = request.headers.get('Origin');
  if (origin) {
    return origin === targetOrigin;
  }

  const referer = request.headers.get('Referer');
  if (referer) {
    try {
      return new URL(referer).origin === targetOrigin;
    } catch {
      return false;
    }
  }

  return false;
}

export async function buildWebBootstrapResponse(env: Env): Promise<WebBootstrapResponse> {
  const secret = (env.JWT_SECRET || '').trim();
  const jwtUnsafeReason =
    !secret
      ? 'missing'
      : secret.length < LIMITS.auth.jwtSecretMinLength
          ? 'too_short'
          : null;
  const storage = new StorageService(env.DB);
  const userCount = await storage.getUserCount();

  return {
    defaultKdfIterations: LIMITS.auth.defaultKdfIterations,
    jwtUnsafeReason,
    jwtSecretMinLength: LIMITS.auth.jwtSecretMinLength,
    registrationInviteRequired: userCount > 0,
    webAuthnAllowedOrigins: getConfiguredWebAuthnAllowedOrigins(env),
    websiteIconsEnabled: isWebsiteIconProxyEnabled(env),
  };
}

export async function handlePublicRoute(
  request: Request,
  env: Env,
  path: string,
  method: string,
  enforcePublicRateLimit: PublicRateLimiter
): Promise<Response | null> {
  if (path === '/.well-known/appspecific/com.chrome.devtools.json' && method === 'GET') {
    return new Response('{}', {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
      },
    });
  }

  if ((path === '/api/web-bootstrap' || path === '/web-bootstrap') && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-read', LIMITS.rateLimit.publicReadRequestsPerMinute);
    if (blocked) return blocked;
    return jsonResponse(await buildWebBootstrapResponse(env));
  }

  if (path === '/fill-assist/manifest.json' && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-read', LIMITS.rateLimit.publicReadRequestsPerMinute);
    if (blocked) return blocked;
    return handleFillAssistManifest();
  }

  if ((path === '/v1/assetlinks:check' || path === '/api/v1/assetlinks:check') && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-read', LIMITS.rateLimit.publicReadRequestsPerMinute);
    if (blocked) return blocked;
    return handleDigitalAssetLinkCheck();
  }

  const fillAssistFormsMatch = path.match(/^\/fill-assist\/([^/]+)$/i);
  if (fillAssistFormsMatch && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-read', LIMITS.rateLimit.publicReadRequestsPerMinute);
    if (blocked) return blocked;
    return handleFillAssistForms(fillAssistFormsMatch[1]);
  }

  const iconMatch = path.match(/^\/icons\/([^/]+)\/icon\.png$/i);
  if (iconMatch && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-icon', LIMITS.rateLimit.publicIconRequestsPerMinute);
    if (blocked) return blocked;
    const fallbackMode = new URL(request.url).searchParams.get('fallback') === '404' ? 'not-found' : 'default';
    return handleWebsiteIcon(env, iconMatch[1], fallbackMode);
  }

  const publicAttachmentMatch = path.match(/^\/api\/attachments\/([a-f0-9-]+)\/([a-f0-9-]+)$/i);
  if (publicAttachmentMatch && method === 'GET') {
    return handlePublicDownloadAttachment(request, env, publicAttachmentMatch[1], publicAttachmentMatch[2]);
  }

  const publicAttachmentUploadMatch = path.match(/^\/api\/ciphers\/([a-f0-9-]+)\/attachment\/([a-f0-9-]+)$/i);
  if (publicAttachmentUploadMatch && (method === 'POST' || method === 'PUT') && new URL(request.url).searchParams.has('token')) {
    return handlePublicUploadAttachment(request, env, publicAttachmentUploadMatch[1], publicAttachmentUploadMatch[2]);
  }

  const publicSendUploadMatch = path.match(/^\/api\/sends\/([^/]+)\/file\/([^/]+)\/?$/i);
  if (publicSendUploadMatch && (method === 'POST' || method === 'PUT') && new URL(request.url).searchParams.has('token')) {
    return handlePublicUploadSendFile(request, env, publicSendUploadMatch[1], publicSendUploadMatch[2]);
  }

  const sendAccessMatch = path.match(/^\/api\/sends\/access\/([^/]+)$/i);
  if (sendAccessMatch && method === 'POST') {
    const blocked = await enforcePublicRateLimit();
    if (blocked) return blocked;
    return handleAccessSend(request, env, sendAccessMatch[1]);
  }

  if (path === '/api/sends/access' && method === 'POST') {
    const blocked = await enforcePublicRateLimit();
    if (blocked) return blocked;
    return handleAccessSendV2(request, env);
  }

  const sendAccessFileV2Match = path.match(/^\/api\/sends\/access\/file\/([^/]+)\/?$/i);
  if (sendAccessFileV2Match && method === 'POST') {
    const blocked = await enforcePublicRateLimit();
    if (blocked) return blocked;
    return handleAccessSendFileV2(request, env, sendAccessFileV2Match[1]);
  }

  const sendAccessFileMatch = path.match(/^\/api\/sends\/([^/]+)\/access\/file\/([^/]+)\/?$/i);
  if (sendAccessFileMatch && method === 'POST') {
    const blocked = await enforcePublicRateLimit();
    if (blocked) return blocked;
    return handleAccessSendFile(request, env, sendAccessFileMatch[1], sendAccessFileMatch[2]);
  }

  const sendDownloadMatch = path.match(/^\/api\/sends\/([^/]+)\/([^/]+)\/?$/i);
  if (sendDownloadMatch && method === 'GET') {
    return handleDownloadSendFile(request, env, sendDownloadMatch[1], sendDownloadMatch[2]);
  }

  if ((path === '/api/auth-requests' || path === '/api/auth-requests/' || path === '/auth-requests' || path === '/auth-requests/') && method === 'POST') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handleCreateAuthRequest(request, env);
  }

  const authRequestResponseMatch = path.match(/^\/(?:api\/)?auth-requests\/([a-f0-9-]+)\/response$/i);
  if (authRequestResponseMatch && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handleGetAuthRequestResponse(request, env, authRequestResponseMatch[1]);
  }

  if (path === '/identity/connect/token' && method === 'POST') {
    return handleToken(request, env);
  }

  if (path === '/identity/sso/prelogin' && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handleSsoPrelogin(request, env);
  }

  if (path === '/identity/connect/authorize' && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handleSsoAuthorize(request, env);
  }

  if (path === '/identity/sso/callback' && method === 'GET') {
    return handleSsoCallback(request, env);
  }

  if (path === '/api/devices/knowndevice' && method === 'GET') {
    const blocked = await enforcePublicRateLimit();
    if (blocked) return jsonResponse(false);
    return handleKnownDevice(request, env);
  }

  const clearDeviceTokenMatch = path.match(/^\/api\/devices\/identifier\/([^/]+)\/clear-token$/i);
  if (clearDeviceTokenMatch && (method === 'PUT' || method === 'POST')) {
    return new Response(null, { status: 200 });
  }

  if ((path === '/identity/connect/revocation' || path === '/identity/connect/revoke') && method === 'POST') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handleRevocation(request, env);
  }

  if (path === '/identity/accounts/prelogin' && method === 'POST') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handlePrelogin(request, env);
  }

  if (path === '/identity/accounts/prelogin/password' && method === 'POST') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handlePrelogin(request, env);
  }

  if (path === '/identity/accounts/webauthn/assertion-options' && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handleGetAccountPasskeyAssertionOptions(request, env);
  }

  if ((path === '/identity/accounts/recover-2fa' || path === '/api/accounts/recover-2fa') && method === 'POST') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handleRecoverTwoFactor(request, env);
  }

  const publicMailBackedPaths = new Set([
    '/api/accounts/resend-new-device-otp',
    '/accounts/resend-new-device-otp',
    '/api/accounts/register/send-verification-email',
    '/accounts/register/send-verification-email',
    '/identity/accounts/register/send-verification-email',
    '/api/accounts/register/verification-email-clicked',
    '/accounts/register/verification-email-clicked',
    '/identity/accounts/register/verification-email-clicked',
    '/api/accounts/register/finish',
    '/accounts/register/finish',
    '/identity/accounts/register/finish',
    '/api/accounts/verify-email-token',
    '/accounts/verify-email-token',
    '/api/two-factor/send-email-login',
    '/two-factor/send-email-login',
  ]);
  if (publicMailBackedPaths.has(path) && method === 'POST') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return unsupportedResponse('Email delivery is not supported by this server.');
  }

  if (path === '/api/accounts/password-hint' && method === 'POST') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    if (!isSameOriginWriteRequest(request)) {
      return new Response(JSON.stringify({ error: 'Forbidden origin' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return handleGetPasswordHint(request, env);
  }

  if ((path === '/config' || path === '/api/config') && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-read', LIMITS.rateLimit.publicReadRequestsPerMinute);
    if (blocked) return blocked;
    const origin = new URL(request.url).origin;
    return jsonResponse(buildConfigResponse(origin), 200, { 'Cache-Control': 'no-store' });
  }

  if (path === '/api/version' && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-read', LIMITS.rateLimit.publicReadRequestsPerMinute);
    if (blocked) return blocked;
    return jsonResponse(LIMITS.compatibility.bitwardenServerVersion);
  }

  if (path === '/api/accounts/register' && method === 'POST') {
    const blocked = await enforcePublicRateLimit('register', LIMITS.rateLimit.registerRequestsPerMinute);
    if (blocked) return blocked;
    if (!isSameOriginWriteRequest(request)) {
      return new Response(JSON.stringify({ error: 'Forbidden origin' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return handleRegister(request, env);
  }

  if (path === '/notifications/hub/negotiate' && method === 'POST') {
    return handleNotificationsNegotiate(request, env);
  }

  if (path === '/notifications/hub' && method === 'GET') {
    return handleNotificationsHub(request, env);
  }

  if (path === '/notifications/anonymous-hub' && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handleAnonymousNotificationsHub(request, env);
  }

  // SCIM v2 provisioning endpoints. Authenticated by the organization's SCIM token.
  const scimV2 = path.match(/^\/api\/scim\/v2\/([^/]+)(?:\/([^/]+))?$/i);
  if (scimV2) {
    const blocked = await enforcePublicRateLimit('scim', LIMITS.rateLimit.scimRequestsPerMinute);
    if (blocked) return blocked;
    const scimAuth = await authenticateScimRequest(request, env);
    if (!scimAuth) {
      return new Response(
        JSON.stringify({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], status: '401', detail: 'Unauthorized' }),
        { status: 401, headers: { 'Content-Type': 'application/scim+json' } }
      );
    }
    const orgId = scimAuth.orgId;
    const resource = scimV2[1].toLowerCase();
    const resourceId = scimV2[2];

    if (resource === 'serviceproviderconfig' && method === 'GET') {
      return handleScimServiceProviderConfig();
    }
    if (resource === 'resourcetypes' && method === 'GET') {
      return handleScimResourceTypes();
    }
    if (resource === 'schemas' && method === 'GET') {
      return handleScimSchemas();
    }
    if (resource === 'users') {
      if (method === 'GET' && !resourceId) return handleScimListUsers(request, env, orgId);
      if (method === 'POST' && !resourceId) return handleScimCreateUser(request, env, orgId);
      if (resourceId) {
        if (method === 'GET') return handleScimGetUser(request, env, orgId, resourceId);
        if (method === 'PUT') return handleScimPutUser(request, env, orgId, resourceId);
        if (method === 'PATCH') return handleScimPatchUser(request, env, orgId, resourceId);
        if (method === 'DELETE') return handleScimDeleteUser(request, env, orgId, resourceId);
      }
    }
    if (resource === 'groups') {
      if (method === 'GET' && !resourceId) return handleScimListGroups(request, env, orgId);
      if (method === 'POST' && !resourceId) return handleScimCreateGroup(request, env, orgId);
      if (resourceId) {
        if (method === 'GET') return handleScimGetGroup(request, env, orgId, resourceId);
        if (method === 'PUT') return handleScimPutGroup(request, env, orgId, resourceId);
        if (method === 'PATCH') return handleScimPatchGroup(request, env, orgId, resourceId);
        if (method === 'DELETE') return handleScimDeleteGroup(request, env, orgId, resourceId);
      }
    }

    return new Response(
      JSON.stringify({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], status: '404', detail: 'Not found' }),
      { status: 404, headers: { 'Content-Type': 'application/scim+json' } }
    );
  }

  return null;
}
