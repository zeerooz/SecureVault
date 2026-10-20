import { describe, expect, it } from 'vitest';

import { fromBase64, toBase64 } from './encoding';
import { DEFAULT_KDF_ITERATIONS, deriveAuthHash, deriveMasterKey, generateKdfSalt } from './kdf';
import { decryptItem, encryptItem, generateVaultKey, unwrapVaultKey, wrapVaultKey } from './vault';
import {
  DEFAULT_GENERATOR_OPTIONS,
  buildAlphabet,
  entropyBits,
  estimateTypedEntropy,
  generatePassword,
  strengthFromEntropy,
} from './generator';

// 600k iterations is correct for production and far too slow to run in a test
// loop. The derivation logic is identical at any iteration count.
const TEST_ITERATIONS = 100_000;

describe('key derivation', () => {
  it('is deterministic for the same password and salt', async () => {
    const salt = generateKdfSalt();

    const first = await deriveMasterKey('correct horse battery staple', salt, TEST_ITERATIONS);
    const second = await deriveMasterKey('correct horse battery staple', salt, TEST_ITERATIONS);

    expect(toBase64(first)).toBe(toBase64(second));
  });

  it('produces a different key for a different salt', async () => {
    const password = 'correct horse battery staple';

    const first = await deriveMasterKey(password, generateKdfSalt(), TEST_ITERATIONS);
    const second = await deriveMasterKey(password, generateKdfSalt(), TEST_ITERATIONS);

    expect(toBase64(first)).not.toBe(toBase64(second));
  });

  it('produces a different key for a different password', async () => {
    const salt = generateKdfSalt();

    const first = await deriveMasterKey('password-one', salt, TEST_ITERATIONS);
    const second = await deriveMasterKey('password-two', salt, TEST_ITERATIONS);

    expect(toBase64(first)).not.toBe(toBase64(second));
  });

  it('derives 32 bytes', async () => {
    const key = await deriveMasterKey('whatever', generateKdfSalt(), TEST_ITERATIONS);

    expect(key.length).toBe(32);
  });

  it('refuses a dangerously low iteration count', async () => {
    // A malicious server could otherwise answer prelogin with iterations = 1.
    await expect(deriveMasterKey('whatever', generateKdfSalt(), 10)).rejects.toThrow(/iterations/i);
  });

  it('generates a 16-byte salt', () => {
    expect(fromBase64(generateKdfSalt()).length).toBe(16);
  });

  it('defaults to the OWASP-aligned iteration count', () => {
    expect(DEFAULT_KDF_ITERATIONS).toBeGreaterThanOrEqual(600_000);
  });
});

describe('the auth hash sent to the server', () => {
  it('is not the master key', async () => {
    const salt = generateKdfSalt();
    const masterKey = await deriveMasterKey('hunter2-but-longer', salt, TEST_ITERATIONS);
    const authHash = await deriveAuthHash(masterKey, 'hunter2-but-longer');

    // If these ever matched, handing the auth hash to the server would hand it
    // the key that unwraps the vault.
    expect(authHash).not.toBe(toBase64(masterKey));
  });

  it('is stable for the same credentials', async () => {
    const salt = generateKdfSalt();
    const password = 'hunter2-but-longer';

    const first = await deriveAuthHash(await deriveMasterKey(password, salt, TEST_ITERATIONS), password);
    const second = await deriveAuthHash(await deriveMasterKey(password, salt, TEST_ITERATIONS), password);

    expect(first).toBe(second);
  });

  it('is 32 bytes, which is what the API contract requires', async () => {
    const masterKey = await deriveMasterKey('hunter2-but-longer', generateKdfSalt(), TEST_ITERATIONS);
    const authHash = await deriveAuthHash(masterKey, 'hunter2-but-longer');

    expect(fromBase64(authHash).length).toBe(32);
  });
});

describe('vault key wrapping', () => {
  it('round-trips through the master key', async () => {
    const salt = generateKdfSalt();
    const masterKey = await deriveMasterKey('master-password', salt, TEST_ITERATIONS);

    const vaultKey = await generateVaultKey();
    const wrapped = await wrapVaultKey(vaultKey, masterKey);
    const unwrapped = await unwrapVaultKey(wrapped, masterKey);

    // Prove it is the same key by using it, not by comparing handles.
    const blob = await encryptItem(vaultKey, { name: 'GitHub', password: 'secret' });
    await expect(decryptItem(unwrapped, blob)).resolves.toMatchObject({ name: 'GitHub', password: 'secret' });
  });

  it('fails with the wrong master password', async () => {
    const salt = generateKdfSalt();
    const right = await deriveMasterKey('right-password', salt, TEST_ITERATIONS);
    const wrong = await deriveMasterKey('wrong-password', salt, TEST_ITERATIONS);

    const wrapped = await wrapVaultKey(await generateVaultKey(), right);

    // GCM authentication failure. This, not a server response, is how the
    // client knows the master password was wrong.
    await expect(unwrapVaultKey(wrapped, wrong)).rejects.toThrow();
  });
});

describe('item encryption', () => {
  it('round-trips every field', async () => {
    const vaultKey = await generateVaultKey();
    const item = {
      name: 'Bank',
      username: 'ahmed',
      password: 'p@ssw0rd',
      url: 'https://bank.example',
      notes: 'ملاحظة بالعربية',
    };

    const blob = await encryptItem(vaultKey, item);

    expect(await decryptItem(vaultKey, blob)).toEqual(item);
  });

  it('leaks no plaintext into the blob', async () => {
    const vaultKey = await generateVaultKey();
    const blob = await encryptItem(vaultKey, { name: 'VerySecretName', password: 'VerySecretValue' });

    const decoded = new TextDecoder().decode(fromBase64(blob));

    expect(decoded).not.toContain('VerySecretName');
    expect(decoded).not.toContain('VerySecretValue');
  });

  it('produces a different blob each time, because the IV is random', async () => {
    const vaultKey = await generateVaultKey();
    const item = { name: 'Same', password: 'Same' };

    expect(await encryptItem(vaultKey, item)).not.toBe(await encryptItem(vaultKey, item));
  });

  it('rejects a blob that has been tampered with', async () => {
    const vaultKey = await generateVaultKey();
    const blob = await encryptItem(vaultKey, { name: 'Bank', password: 'secret' });

    const bytes = fromBase64(blob);
    bytes[bytes.length - 1] ^= 0xff; // flip the last byte of the GCM tag

    await expect(decryptItem(vaultKey, toBase64(bytes))).rejects.toThrow();
  });

  it('rejects a blob encrypted under a different key', async () => {
    const blob = await encryptItem(await generateVaultKey(), { name: 'Bank' });

    await expect(decryptItem(await generateVaultKey(), blob)).rejects.toThrow();
  });

  it('rejects a blob too short to hold an IV and a tag', async () => {
    const vaultKey = await generateVaultKey();

    await expect(decryptItem(vaultKey, toBase64(new Uint8Array(8)))).rejects.toThrow(/too short/i);
  });
});

describe('password generator', () => {
  it('honours the requested length', () => {
    const password = generatePassword({ ...DEFAULT_GENERATOR_OPTIONS, length: 32 });

    expect(password).toHaveLength(32);
  });

  it('only uses characters from the selected sets', () => {
    const options = {
      ...DEFAULT_GENERATOR_OPTIONS,
      uppercase: false,
      symbols: false,
      digits: false,
    };

    expect(generatePassword(options)).toMatch(/^[a-z]+$/);
  });

  it('can exclude ambiguous characters', () => {
    const options = { ...DEFAULT_GENERATOR_OPTIONS, excludeAmbiguous: true, length: 128 };

    expect(buildAlphabet(options)).not.toContain('O');
    expect(generatePassword(options)).not.toMatch(/[lI1O0o]/);
  });

  it('throws when every character set is turned off', () => {
    const options = {
      ...DEFAULT_GENERATOR_OPTIONS,
      lowercase: false,
      uppercase: false,
      digits: false,
      symbols: false,
    };

    expect(() => generatePassword(options)).toThrow(/at least one/i);
  });

  it('does not repeat itself across calls', () => {
    const generated = new Set(Array.from({ length: 50 }, () => generatePassword(DEFAULT_GENERATOR_OPTIONS)));

    expect(generated.size).toBe(50);
  });

  it('distributes characters across the alphabet rather than favouring the start', () => {
    // A modulo-biased sampler would skew towards the first characters. With a
    // 26-letter alphabet and 5200 draws, every letter should appear.
    const options = {
      ...DEFAULT_GENERATOR_OPTIONS,
      length: 128,
      uppercase: false,
      digits: false,
      symbols: false,
    };

    const seen = new Set<string>();
    for (let i = 0; i < 50; i++) {
      for (const c of generatePassword(options)) {
        seen.add(c);
      }
    }

    expect(seen.size).toBe(26);
  });

  it('reports entropy that grows with length and alphabet size', () => {
    const short = entropyBits({ ...DEFAULT_GENERATOR_OPTIONS, length: 8 });
    const long = entropyBits({ ...DEFAULT_GENERATOR_OPTIONS, length: 32 });

    expect(long).toBeGreaterThan(short);
    expect(strengthFromEntropy(long)).toBe('excellent');
    expect(strengthFromEntropy(20)).toBe('weak');
  });

  it('rates a typed password below a generated one of the same length', () => {
    expect(estimateTypedEntropy('aaaaaaaaaaaaaaaa')).toBeLessThan(
      entropyBits({ ...DEFAULT_GENERATOR_OPTIONS, length: 16 }),
    );
    expect(estimateTypedEntropy('')).toBe(0);
  });
});
