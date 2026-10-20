import { fromBase64, fromUtf8, randomBytes, toBase64, utf8 } from './encoding';
import { deriveWrappingKey } from './kdf';

/**
 * AES-256-GCM over the vault key and every vault item.
 *
 * Blob layout, base64-encoded as a single string:
 *
 *   [ 12-byte IV ][ ciphertext ][ 16-byte GCM tag ]
 *
 * GCM is authenticated, so a server that flips a bit in stored ciphertext does
 * not get a silently corrupted item — decryption throws. That matters here:
 * the server is explicitly outside the trust boundary, and tamper detection is
 * the difference between "cannot read your data" and "cannot change it either".
 */

const IV_BYTES = 12;
const MIN_BLOB_BYTES = IV_BYTES + 16;

export interface VaultItemData {
  name: string;
  username?: string;
  password?: string;
  url?: string;
  notes?: string;
  totpSecret?: string;
}

export async function generateVaultKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

/** Encrypts the vault key under the master-password-derived wrapping key. */
export async function wrapVaultKey(vaultKey: CryptoKey, masterKey: Uint8Array): Promise<string> {
  const wrappingKey = await deriveWrappingKey(masterKey);
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', vaultKey));

  const blob = await encryptBytes(wrappingKey, raw);
  raw.fill(0);

  return blob;
}

/**
 * Reverses wrapVaultKey. A wrong master password fails here, as a GCM
 * authentication error — which is also how the client knows the password was
 * wrong without the server having to tell it.
 */
export async function unwrapVaultKey(protectedVaultKey: string, masterKey: Uint8Array): Promise<CryptoKey> {
  const wrappingKey = await deriveWrappingKey(masterKey);
  const raw = await decryptBytes(wrappingKey, protectedVaultKey);

  const key = await crypto.subtle.importKey('raw', toArrayBuffer(raw), { name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);

  raw.fill(0);
  return key;
}

export async function encryptItem(vaultKey: CryptoKey, item: VaultItemData): Promise<string> {
  return encryptBytes(vaultKey, utf8(JSON.stringify(item)));
}

export async function decryptItem(vaultKey: CryptoKey, blob: string): Promise<VaultItemData> {
  const plaintext = await decryptBytes(vaultKey, blob);
  const parsed = JSON.parse(fromUtf8(plaintext)) as VaultItemData;

  plaintext.fill(0);
  return parsed;
}

async function encryptBytes(key: CryptoKey, plaintext: Uint8Array): Promise<string> {
  // A fresh random IV per encryption. Reusing an IV with the same key is the
  // one mistake that breaks GCM outright, so it is never derived or counted.
  const iv = randomBytes(IV_BYTES);

  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: toArrayBuffer(iv) }, key, toArrayBuffer(plaintext)),
  );

  const blob = new Uint8Array(iv.length + ciphertext.length);
  blob.set(iv, 0);
  blob.set(ciphertext, iv.length);

  return toBase64(blob);
}

async function decryptBytes(key: CryptoKey, blob: string): Promise<Uint8Array> {
  const bytes = fromBase64(blob);

  if (bytes.length < MIN_BLOB_BYTES) {
    throw new Error('Ciphertext is too short to contain an IV and an authentication tag.');
  }

  const iv = bytes.subarray(0, IV_BYTES);
  const ciphertext = bytes.subarray(IV_BYTES);

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv) },
    key,
    toArrayBuffer(ciphertext),
  );

  return new Uint8Array(plaintext);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}
