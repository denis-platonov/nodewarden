// Minimal OIDC ID token verification for the SSO login flow.
//
// The ID token is the only signed assertion the identity provider gives us; the
// userinfo response is just a bearer-token lookup. When the provider returns an
// ID token we verify it rather than trusting the response body.

interface Jwk {
  kty?: string;
  kid?: string;
  alg?: string;
  use?: string;
  n?: string;
  e?: string;
}

const SUPPORTED_ALGS: Record<string, string> = {
  RS256: 'SHA-256',
  RS384: 'SHA-384',
  RS512: 'SHA-512',
};

// Small clock skew allowance for exp/iat comparisons.
const CLOCK_SKEW_MS = 60_000;

function base64UrlToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function decodeJwtSegment(segment: string): Record<string, unknown> | null {
  try {
    return JSON.parse(new TextDecoder().decode(base64UrlToBytes(segment))) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function audienceMatches(audience: unknown, clientId: string): boolean {
  if (typeof audience === 'string') return audience === clientId;
  if (Array.isArray(audience)) return audience.some((entry) => entry === clientId);
  return false;
}

function normalizeIssuer(value: unknown): string {
  return String(value || '').trim().replace(/\/+$/, '').toLowerCase();
}

export interface IdTokenVerifyOptions {
  jwksUri: string;
  clientId: string;
  issuer?: string | null;
  nonce?: string | null;
}

export interface IdTokenVerifyResult {
  ok: boolean;
  reason?: string;
  claims?: Record<string, unknown>;
}

async function fetchJwks(jwksUri: string): Promise<Jwk[] | null> {
  try {
    const response = await fetch(jwksUri, { signal: AbortSignal.timeout(10_000) });
    if (!response.ok) return null;
    const document = await response.json() as { keys?: Jwk[] };
    return Array.isArray(document?.keys) ? document.keys : null;
  } catch {
    return null;
  }
}

async function verifyWithJwk(jwk: Jwk, hash: string, signed: Uint8Array, signature: Uint8Array): Promise<boolean> {
  if (jwk.kty !== 'RSA' || !jwk.n || !jwk.e) return false;
  try {
    const key = await crypto.subtle.importKey(
      'jwk',
      { kty: 'RSA', n: jwk.n, e: jwk.e, alg: jwk.alg, ext: true },
      { name: 'RSASSA-PKCS1-v1_5', hash },
      false,
      ['verify']
    );
    return await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature as unknown as BufferSource, signed as unknown as BufferSource);
  } catch {
    return false;
  }
}

// Verifies signature, issuer, audience, expiry and nonce. Returns the claims on
// success so the caller can read a trusted email.
export async function verifyIdToken(idToken: string, options: IdTokenVerifyOptions): Promise<IdTokenVerifyResult> {
  const parts = idToken.split('.');
  if (parts.length !== 3) return { ok: false, reason: 'malformed_id_token' };

  const header = decodeJwtSegment(parts[0]);
  const claims = decodeJwtSegment(parts[1]);
  if (!header || !claims) return { ok: false, reason: 'malformed_id_token' };

  const alg = String(header.alg || '');
  const hash = SUPPORTED_ALGS[alg];
  if (!hash) return { ok: false, reason: 'unsupported_id_token_alg' };

  const keys = await fetchJwks(options.jwksUri);
  if (!keys || !keys.length) return { ok: false, reason: 'jwks_unavailable' };

  const kid = typeof header.kid === 'string' ? header.kid : null;
  // Prefer the advertised key, but fall back to trying every signing key: some
  // providers omit `kid` during rotation.
  const candidates = kid ? keys.filter((key) => key.kid === kid) : [];
  const ordered = candidates.length ? candidates : keys.filter((key) => key.use !== 'enc');

  const signed = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  let signature: Uint8Array;
  try {
    signature = base64UrlToBytes(parts[2]);
  } catch {
    // atob throws on invalid base64; a malformed signature is a verification
    // failure, not a 500.
    return { ok: false, reason: 'malformed_id_token' };
  }

  let verified = false;
  for (const jwk of ordered) {
    if (await verifyWithJwk(jwk, hash, signed, signature)) {
      verified = true;
      break;
    }
  }
  if (!verified) return { ok: false, reason: 'bad_id_token_signature' };

  const nowMs = Date.now();
  const exp = Number(claims.exp);
  if (!Number.isFinite(exp) || exp * 1000 + CLOCK_SKEW_MS < nowMs) {
    return { ok: false, reason: 'id_token_expired' };
  }
  const iat = Number(claims.iat);
  if (Number.isFinite(iat) && iat * 1000 - CLOCK_SKEW_MS > nowMs) {
    return { ok: false, reason: 'id_token_not_yet_valid' };
  }
  if (!audienceMatches(claims.aud, options.clientId)) {
    return { ok: false, reason: 'id_token_audience_mismatch' };
  }
  if (options.issuer && normalizeIssuer(claims.iss) !== normalizeIssuer(options.issuer)) {
    return { ok: false, reason: 'id_token_issuer_mismatch' };
  }
  if (options.nonce && String(claims.nonce || '') !== options.nonce) {
    return { ok: false, reason: 'id_token_nonce_mismatch' };
  }

  return { ok: true, claims };
}

export function readIdTokenEmail(claims: Record<string, unknown>): string | null {
  for (const key of ['email', 'upn', 'preferred_username', 'unique_name']) {
    const value = claims[key];
    if (typeof value === 'string' && value.includes('@')) return value.trim().toLowerCase();
  }
  return null;
}
