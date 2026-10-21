#!/usr/bin/env node
/*
 * Seeds a demo account with a handful of vault items.
 *
 * Note what this script is forced to be: a *client*. The server cannot seed a
 * vault, because it has no way to encrypt an item — it never holds a key. So
 * the seeder re-implements the browser's key derivation, encrypts locally, and
 * posts ciphertext over the public API like any other client would.
 *
 * That constraint is the design working as intended, and it is the clearest
 * demonstration of it in the repository.
 *
 * Usage:
 *   node tools/seed-demo.mjs [--api http://localhost:8080] [--email demo@securevault.app] [--password ...]
 */

import { webcrypto as crypto } from 'node:crypto';

const args = parseArgs(process.argv.slice(2));

const API = args.api ?? process.env.SEED_API_URL ?? 'http://localhost:8080';
const EMAIL = args.email ?? process.env.SEED_EMAIL ?? 'demo@securevault.app';
const PASSWORD = args.password ?? process.env.SEED_PASSWORD ?? 'demo-vault-password-2026';

const KDF_ITERATIONS = 600_000;
const WRAP_KEY_INFO = 'securevault:vault-key-wrap:v1';

const DEMO_ITEMS = [
  {
    type: 0,
    data: {
      name: 'Company email',
      username: 'ahmed@example.com',
      password: 'H7v!qRm2xTp9Lc4Zs6Wd',
      url: 'https://mail.example.com',
      notes: 'Shared mailbox for client enquiries.',
    },
  },
  {
    type: 0,
    data: {
      name: 'Staging database',
      username: 'svc_staging',
      password: 'nK3$yFb8Qz1Rt7Vx0Jh5',
      url: 'https://staging.example.com/admin',
      notes: 'Rotate after every contractor offboarding.',
    },
  },
  {
    type: 0,
    data: {
      name: 'Domain registrar',
      username: 'billing@example.com',
      password: 'pW9^tLd4Gn6Xk2Mq8Zy3',
      url: 'https://registrar.example.com',
    },
  },
  {
    type: 1,
    data: {
      name: 'Office alarm code',
      notes: 'Entry code 4471. Disarm within 30 seconds of opening the door.',
    },
  },
  {
    type: 2,
    data: {
      name: 'Company card',
      notes: 'Visa ending 4417, expires 09/29. Finance holds the CVV.',
    },
  },
];

main().catch((error) => {
  console.error(`\nSeeding failed: ${error.message}`);
  process.exit(1);
});

async function main() {
  console.log(`Seeding ${EMAIL} at ${API}`);

  await waitForApi();

  const kdfSalt = toBase64(crypto.getRandomValues(new Uint8Array(16)));
  const masterKey = await deriveMasterKey(PASSWORD, kdfSalt, KDF_ITERATIONS);
  const authHash = await deriveAuthHash(masterKey, PASSWORD);

  const vaultKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);

  const protectedVaultKey = await wrapVaultKey(vaultKey, masterKey);

  let session = await post('/api/auth/register', {
    email: EMAIL,
    authHash,
    kdfSalt,
    kdfIterations: KDF_ITERATIONS,
    protectedVaultKey,
  });

  if (session.status === 409) {
    console.log('Account already exists — signing in instead.');

    const prelogin = await post('/api/auth/prelogin', { email: EMAIL }, true);
    const existingKey = await deriveMasterKey(PASSWORD, prelogin.kdfSalt, prelogin.kdfIterations);

    session = await post(
      '/api/auth/login',
      { email: EMAIL, authHash: await deriveAuthHash(existingKey, PASSWORD) },
      true,
    );

    if (session.requiresTwoFactor) {
      throw new Error('The demo account has two-factor enabled. Reset the database to reseed it.');
    }

    // Reuse the existing vault key so previously stored items stay readable.
    const unwrapped = await unwrapVaultKey(session.protectedVaultKey, existingKey);
    await seedItems(session.accessToken, unwrapped);
    return;
  }

  if (session.status) {
    throw new Error(`Registration failed (HTTP ${session.status}): ${session.detail ?? 'unknown error'}`);
  }

  await seedItems(session.accessToken, vaultKey);
}

async function seedItems(accessToken, vaultKey) {
  const existing = await get('/api/vault/items', accessToken);

  if (existing.length > 0) {
    console.log(`Vault already holds ${existing.length} item(s). Nothing to add.`);
    printSummary();
    return;
  }

  for (const item of DEMO_ITEMS) {
    const encryptedData = await encryptItem(vaultKey, item.data);
    await post('/api/vault/items', { type: item.type, encryptedData }, true, accessToken);
    console.log(`  + ${item.data.name}`);
  }

  printSummary();
}

function printSummary() {
  console.log('\nDemo account ready.');
  console.log(`  Email:    ${EMAIL}`);
  console.log(`  Password: ${PASSWORD}`);
  console.log('\nThe server stored only ciphertext. Nothing above was ever sent in plaintext.');
}

// --- the browser's crypto, re-implemented ----------------------------------

async function deriveMasterKey(password, saltBase64, iterations) {
  const key = await crypto.subtle.importKey('raw', encode(password), 'PBKDF2', false, ['deriveBits']);

  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: fromBase64(saltBase64), iterations, hash: 'SHA-256' },
    key,
    256,
  );

  return new Uint8Array(bits);
}

async function deriveAuthHash(masterKey, password) {
  const key = await crypto.subtle.importKey('raw', masterKey, 'PBKDF2', false, ['deriveBits']);

  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: encode(password), iterations: 1, hash: 'SHA-256' },
    key,
    256,
  );

  return toBase64(new Uint8Array(bits));
}

async function deriveWrappingKey(masterKey) {
  const hkdfKey = await crypto.subtle.importKey('raw', masterKey, 'HKDF', false, ['deriveKey']);

  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: encode(WRAP_KEY_INFO) },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function wrapVaultKey(vaultKey, masterKey) {
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', vaultKey));
  return encryptBytes(await deriveWrappingKey(masterKey), raw);
}

async function unwrapVaultKey(blob, masterKey) {
  const raw = await decryptBytes(await deriveWrappingKey(masterKey), blob);
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

async function encryptItem(vaultKey, data) {
  return encryptBytes(vaultKey, encode(JSON.stringify(data)));
}

async function encryptBytes(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext));

  const blob = new Uint8Array(iv.length + ciphertext.length);
  blob.set(iv, 0);
  blob.set(ciphertext, iv.length);

  return toBase64(blob);
}

async function decryptBytes(key, blob) {
  const bytes = fromBase64(blob);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bytes.subarray(0, 12) },
    key,
    bytes.subarray(12),
  );

  return new Uint8Array(plaintext);
}

// --- plumbing ---------------------------------------------------------------

async function waitForApi() {
  for (let attempt = 0; attempt < 30; attempt++) {
    try {
      const response = await fetch(`${API}/health`);

      if (response.ok) {
        return;
      }
    } catch {
      // Not up yet.
    }

    await new Promise((resolve) => setTimeout(resolve, 1000));
  }

  throw new Error(`${API} did not become healthy in 30 seconds.`);
}

async function post(path, body, throwOnError = false, token) {
  const response = await fetch(`${API}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const problem = await response.json().catch(() => ({}));

    if (throwOnError) {
      throw new Error(`${path} returned HTTP ${response.status}: ${problem.detail ?? 'unknown error'}`);
    }

    return { status: response.status, detail: problem.detail };
  }

  return response.status === 204 ? {} : response.json();
}

async function get(path, token) {
  const response = await fetch(`${API}${path}`, { headers: { Authorization: `Bearer ${token}` } });

  if (!response.ok) {
    throw new Error(`${path} returned HTTP ${response.status}`);
  }

  return response.json();
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i]?.replace(/^--/, '');

    if (key) {
      parsed[key] = argv[i + 1];
    }
  }

  return parsed;
}

const encode = (value) => new TextEncoder().encode(value);
const toBase64 = (bytes) => Buffer.from(bytes).toString('base64');
const fromBase64 = (value) => new Uint8Array(Buffer.from(value, 'base64'));
