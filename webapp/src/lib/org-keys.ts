import { decryptBw, encryptBw, bytesToBase64, base64ToBytes, toBufferSource, requireWebCrypto } from './crypto';
import type { Profile } from './types';

export interface OrgKeyMaterial {
  enc: Uint8Array;
  mac: Uint8Array;
}

export interface ProfileOrganization {
  id: string;
  name: string;
  enabled?: boolean;
  useTotp?: boolean;
  billingEmail?: string | null;
  key?: string | null;
  publicKey?: string | null;
  privateKey?: string | null;
  identifier?: string | null;
  encryptedOrgKey?: string | null;
  role?: string;
  permissions?: Record<string, unknown>;
  users?: unknown[];
  creationDate?: string;
  revisionDate?: string;
}

const RSA_ALGO: RsaHashedImportParams = { name: 'RSA-OAEP', hash: 'SHA-1' };

async function importRsaPublicKey(spkiB64: string): Promise<CryptoKey> {
  const webCrypto = requireWebCrypto();
  return webCrypto.subtle.importKey('spki', toBufferSource(base64ToBytes(spkiB64)), RSA_ALGO, true, ['encrypt']);
}

async function importRsaPrivateKey(pkcs8Bytes: Uint8Array): Promise<CryptoKey> {
  const webCrypto = requireWebCrypto();
  return webCrypto.subtle.importKey('pkcs8', toBufferSource(pkcs8Bytes), RSA_ALGO, false, ['decrypt']);
}

async function rsaEncrypt(publicKeySpkiB64: string, data: Uint8Array): Promise<string> {
  const webCrypto = requireWebCrypto();
  const publicKey = await importRsaPublicKey(publicKeySpkiB64);
  const encrypted = await webCrypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, toBufferSource(data));
  return bytesToBase64(new Uint8Array(encrypted));
}

// Decrypt the user's RSA private key with their symmetric vault key and import it.
export async function importUserPrivateKey(profile: Profile, symEncKeyB64: string, symMacKeyB64: string): Promise<CryptoKey | null> {
  const webCrypto = requireWebCrypto();
  if (!profile.privateKey) return null;
  try {
    const privateKeyBytes = await decryptBw(profile.privateKey, base64ToBytes(symEncKeyB64), base64ToBytes(symMacKeyB64));
    return await importRsaPrivateKey(privateKeyBytes);
  } catch {
    return null;
  }
}

// Derive the org symmetric keys for every organization the user belongs to.
// Returns a map of orgId -> { enc, mac }.
export async function deriveOrgKeys(profile: Profile, symEncKeyB64: string, symMacKeyB64: string): Promise<Map<string, OrgKeyMaterial>> {
  const organizations = ((profile.organizations || []) as unknown) as ProfileOrganization[];
  if (!organizations.length) return new Map();
  const webCrypto = requireWebCrypto();

  const userPrivateKey = await importUserPrivateKey(profile, symEncKeyB64, symMacKeyB64);
  if (!userPrivateKey) return new Map();

  const result = new Map<string, OrgKeyMaterial>();
  for (const org of organizations) {
    if (!org.encryptedOrgKey) continue;
    try {
      const decrypted = await webCrypto.subtle.decrypt({ name: 'RSA-OAEP' }, userPrivateKey, toBufferSource(base64ToBytes(org.encryptedOrgKey)));
      const orgKeyBytes = new Uint8Array(decrypted);
      if (orgKeyBytes.length >= 64) {
        result.set(org.id, { enc: orgKeyBytes.slice(0, 32), mac: orgKeyBytes.slice(32, 64) });
      }
    } catch {
      // Member cannot decrypt this org key (revoked/stale); skip.
    }
  }
  return result;
}

// Create an organization key set: org RSA keypair + symmetric org key, with the
// org key encrypted for the owner's public key and the org private key encrypted
// with the org key.
export async function createOrgKeySet(ownerPublicKeySpkiB64: string): Promise<{
  publicKey: string;
  privateKey: string;
  encryptedOrgKey: string;
  orgKeyBytes: Uint8Array;
}> {
  const webCrypto = requireWebCrypto();
  const keyPair = await webCrypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-1',
    },
    true,
    ['encrypt', 'decrypt']
  );
  const publicKey = new Uint8Array(await webCrypto.subtle.exportKey('spki', keyPair.publicKey));
  const privateKey = new Uint8Array(await webCrypto.subtle.exportKey('pkcs8', keyPair.privateKey));
  const orgKeyBytes = webCrypto.getRandomValues(new Uint8Array(64));
  const privateKeyEnc = await encryptBw(privateKey, orgKeyBytes.slice(0, 32), orgKeyBytes.slice(32, 64));
  const encryptedOrgKey = await rsaEncrypt(ownerPublicKeySpkiB64, orgKeyBytes);

  return {
    publicKey: bytesToBase64(publicKey),
    privateKey: privateKeyEnc,
    encryptedOrgKey,
    orgKeyBytes,
  };
}

// Encrypt the org key for a new member using their RSA public key.
export async function encryptOrgKeyForMember(orgKeyBytes: Uint8Array, memberPublicKeySpkiB64: string): Promise<string> {
  return rsaEncrypt(memberPublicKeySpkiB64, orgKeyBytes);
}

// Decrypt an organization cipher's item key using the org key material.
export async function decryptOrgCipherKey(cipherKey: string, orgKey: OrgKeyMaterial): Promise<Uint8Array | null> {
  try {
    const itemKey = await decryptBw(cipherKey, orgKey.enc, orgKey.mac);
    return itemKey.length >= 64 ? itemKey : null;
  } catch {
    return null;
  }
}

// Decrypt the raw 64-byte org key for an organization (needed to re-encrypt it
// for new members).
export async function deriveOrgKeyBytes(profile: Profile, symEncKeyB64: string, symMacKeyB64: string, organizationId: string): Promise<Uint8Array | null> {
  const organizations = ((profile.organizations || []) as unknown) as ProfileOrganization[];
  const org = organizations.find((candidate) => candidate.id === organizationId);
  if (!org || !org.encryptedOrgKey) return null;
  const webCrypto = requireWebCrypto();
  const userPrivateKey = await importUserPrivateKey(profile, symEncKeyB64, symMacKeyB64);
  if (!userPrivateKey) return null;
  try {
    const decrypted = await webCrypto.subtle.decrypt({ name: 'RSA-OAEP' }, userPrivateKey, toBufferSource(base64ToBytes(org.encryptedOrgKey)));
    const bytes = new Uint8Array(decrypted);
    return bytes.length >= 64 ? bytes : null;
  } catch {
    return null;
  }
}

// Encrypt a fresh item key (64 random bytes) with the org key and return the
// cipher string that becomes the cipher's `key`.
export async function encryptOrgItemKey(orgKey: OrgKeyMaterial): Promise<{ key: string; itemKey: Uint8Array }> {
  const webCrypto = requireWebCrypto();
  const itemKey = webCrypto.getRandomValues(new Uint8Array(64));
  return { key: await encryptBw(itemKey, orgKey.enc, orgKey.mac), itemKey };
}