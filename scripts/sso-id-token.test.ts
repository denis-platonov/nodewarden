import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyIdToken, readIdTokenEmail } from '../src/utils/oidc';

const JWKS_URI = 'https://idp.example.com/jwks';
const CLIENT_ID = 'nodewarden-client';
const ISSUER = 'https://idp.example.com';

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function encodeSegment(value: unknown): string {
  return base64Url(new TextEncoder().encode(JSON.stringify(value)));
}

async function buildIdToken(
  claimOverrides: Record<string, unknown> = {},
  headerOverrides: Record<string, unknown> = {}
): Promise<{ token: string; jwks: { keys: unknown[] } }> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify']
  );
  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

  const nowSeconds = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', kid: 'key-1', typ: 'JWT', ...headerOverrides };
  const claims = {
    iss: ISSUER,
    aud: CLIENT_ID,
    sub: 'idp-user-1',
    email: 'Member@Example.com',
    nonce: 'nonce-1',
    iat: nowSeconds,
    exp: nowSeconds + 300,
    ...claimOverrides,
  };

  const signingInput = `${encodeSegment(header)}.${encodeSegment(claims)}`;
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    keyPair.privateKey,
    new TextEncoder().encode(signingInput)
  );

  return {
    token: `${signingInput}.${base64Url(new Uint8Array(signature))}`,
    jwks: { keys: [{ ...publicJwk, kid: 'key-1', use: 'sig', alg: 'RS256' }] },
  };
}

function withStubbedJwks<T>(jwks: unknown, run: () => Promise<T>): Promise<T> {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: any) => {
    assert.equal(String(input), JWKS_URI);
    return new Response(JSON.stringify(jwks), { headers: { 'Content-Type': 'application/json' } });
  }) as typeof fetch;
  return run().finally(() => {
    globalThis.fetch = originalFetch;
  });
}

const baseOptions = { jwksUri: JWKS_URI, clientId: CLIENT_ID, issuer: ISSUER, nonce: 'nonce-1' };

test('a well-formed id token verifies against the provider jwks', async () => {
  const { token, jwks } = await buildIdToken();
  const result = await withStubbedJwks(jwks, () => verifyIdToken(token, baseOptions));
  assert.equal(result.ok, true);
  assert.equal(readIdTokenEmail(result.claims!), 'member@example.com');
});

test('a tampered payload fails signature verification', async () => {
  const { token, jwks } = await buildIdToken();
  const [header, , signature] = token.split('.');
  const forged = `${header}.${encodeSegment({ iss: ISSUER, aud: CLIENT_ID, email: 'attacker@example.com', exp: Math.floor(Date.now() / 1000) + 300 })}.${signature}`;
  const result = await withStubbedJwks(jwks, () => verifyIdToken(forged, baseOptions));
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'bad_id_token_signature');
});

test('audience, issuer, nonce and expiry are all enforced', async () => {
  const wrongAudience = await buildIdToken({ aud: 'someone-else' });
  assert.equal(
    (await withStubbedJwks(wrongAudience.jwks, () => verifyIdToken(wrongAudience.token, baseOptions))).reason,
    'id_token_audience_mismatch'
  );

  const wrongIssuer = await buildIdToken({ iss: 'https://evil.example.com' });
  assert.equal(
    (await withStubbedJwks(wrongIssuer.jwks, () => verifyIdToken(wrongIssuer.token, baseOptions))).reason,
    'id_token_issuer_mismatch'
  );

  const replayedNonce = await buildIdToken({ nonce: 'nonce-from-another-login' });
  assert.equal(
    (await withStubbedJwks(replayedNonce.jwks, () => verifyIdToken(replayedNonce.token, baseOptions))).reason,
    'id_token_nonce_mismatch'
  );

  const expired = await buildIdToken({ exp: Math.floor(Date.now() / 1000) - 3600 });
  assert.equal(
    (await withStubbedJwks(expired.jwks, () => verifyIdToken(expired.token, baseOptions))).reason,
    'id_token_expired'
  );
});

test('unsigned and unsupported-algorithm tokens are rejected without touching the jwks', async () => {
  const none = await buildIdToken({}, { alg: 'none' });
  assert.equal((await verifyIdToken(none.token, baseOptions)).reason, 'unsupported_id_token_alg');
  assert.equal((await verifyIdToken('not-a-jwt', baseOptions)).reason, 'malformed_id_token');
  assert.equal((await verifyIdToken('a.b.c', baseOptions)).reason, 'malformed_id_token');
});

test('a key set with no usable key fails closed', async () => {
  const { token } = await buildIdToken();
  const result = await withStubbedJwks({ keys: [] }, () => verifyIdToken(token, baseOptions));
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'jwks_unavailable');
});
