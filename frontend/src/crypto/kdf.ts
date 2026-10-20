import { fromBase64, randomBytes, toBase64, utf8 } from './encoding';

/**
 * Key derivation. This module is the whole reason the server can be honest when
 * it says it cannot read your vault.
 *
 * The chain, all of it in the browser:
 *
 *   masterKey   = PBKDF2-SHA256(masterPassword, kdfSalt, 600_000)      32 bytes
 *   authHash    = PBKDF2-SHA256(masterKey, masterPassword, 1)          32 bytes  -> sent to the server
 *   wrappingKey = HKDF-SHA256(masterKey, info="…vault-key-wrap")       32 bytes  -> never leaves the browser
 *
 * The server only ever sees authHash, and it stores Argon2id(authHash) rather
 * than authHash itself. Recovering the master password from authHash means
 * reversing 600_000 PBKDF2 iterations; recovering the wrapping key from it
 * means doing that first. Neither is feasible for a strong master password.
 *
 * Why PBKDF2 and not Argon2id on the client? PBKDF2 is native in WebCrypto, so
 * it runs in compiled code with no extra download. Argon2 in the browser means
 * shipping a WASM bundle, and a slow pure-JS fallback is worse than a fast,
 * correctly-parameterised PBKDF2. The server-side hash is Argon2id, which is
 * where memory-hardness actually buys protection against a database leak.
 */

export const DEFAULT_KDF_ITERATIONS = 600_000;
export const KDF_SALT_BYTES = 16;
const DERIVED_BITS = 256;

/** Domain separator, so the wrapping key can never collide with another use of the master key. */
const WRAP_KEY_INFO = 'securevault:vault-key-wrap:v1';

export interface MasterKeyMaterial {
  /** Raw 32 bytes. Kept only for the moment it takes to derive the two children. */
  readonly masterKey: Uint8Array;
}

export function generateKdfSalt(): string {
  return toBase64(randomBytes(KDF_SALT_BYTES));
}

async function importPbkdf2(keyMaterial: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', toArrayBuffer(keyMaterial), 'PBKDF2', false, ['deriveBits']);
}

/** Step 1: stretch the master password into the master key. */
export async function deriveMasterKey(
  masterPassword: string,
  kdfSaltBase64: string,
  iterations: number,
): Promise<Uint8Array> {
  if (iterations < 100_000) {
    // A client that accepted a low iteration count from the server would let a
    // malicious server weaken every future derivation.
    throw new Error(`Refusing to derive a key with only ${iterations} iterations.`);
  }

  const passwordKey = await importPbkdf2(utf8(masterPassword));

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: toArrayBuffer(fromBase64(kdfSaltBase64)),
      iterations,
      hash: 'SHA-256',
    },
    passwordKey,
    DERIVED_BITS,
  );

  return new Uint8Array(bits);
}

/**
 * Step 2: the value the server is allowed to see.
 *
 * Using the master password as the salt here is deliberate, and it is the
 * trick that makes the scheme work: the result is a deterministic function of
 * the password, so it can be used as a login credential, but it is one
 * irreversible step away from the key that decrypts the vault.
 */
export async function deriveAuthHash(masterKey: Uint8Array, masterPassword: string): Promise<string> {
  const key = await importPbkdf2(masterKey);

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: toArrayBuffer(utf8(masterPassword)),
      iterations: 1,
      hash: 'SHA-256',
    },
    key,
    DERIVED_BITS,
  );

  return toBase64(bits);
}

/** Step 3: the AES-GCM key that wraps and unwraps the vault key. Never transmitted. */
export async function deriveWrappingKey(masterKey: Uint8Array): Promise<CryptoKey> {
  const hkdfKey = await crypto.subtle.importKey('raw', toArrayBuffer(masterKey), 'HKDF', false, ['deriveKey']);

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: toArrayBuffer(utf8(WRAP_KEY_INFO)),
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    // extractable: false. The browser will use this key but will not hand the
    // bytes back to our own code, so a cross-site scripting bug cannot read it
    // out of memory and post it somewhere.
    false,
    ['encrypt', 'decrypt'],
  );
}

/** Narrows a Uint8Array view to a plain ArrayBuffer, which is what WebCrypto expects. */
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}
