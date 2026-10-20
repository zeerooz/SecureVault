/**
 * Password generation.
 *
 * Two rules that are easy to get wrong and are the whole value of this file:
 *
 * 1. Randomness comes from crypto.getRandomValues, never Math.random.
 * 2. Selection is rejection-sampled rather than taken modulo the alphabet
 *    length. `random % 62` quietly makes the first few characters of the
 *    alphabet more likely, which shaves entropy off every password generated.
 */

const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const SYMBOLS = '!@#$%^&*()-_=+[]{};:,.?';

/** Characters a human will misread when copying by hand. */
const AMBIGUOUS = new Set(['l', 'I', '1', 'O', '0', 'o']);

export interface GeneratorOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
}

export const DEFAULT_GENERATOR_OPTIONS: GeneratorOptions = {
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  excludeAmbiguous: false,
};

export function buildAlphabet(options: GeneratorOptions): string {
  let alphabet = '';

  if (options.lowercase) alphabet += LOWERCASE;
  if (options.uppercase) alphabet += UPPERCASE;
  if (options.digits) alphabet += DIGITS;
  if (options.symbols) alphabet += SYMBOLS;

  if (options.excludeAmbiguous) {
    alphabet = [...alphabet].filter((c) => !AMBIGUOUS.has(c)).join('');
  }

  return alphabet;
}

export function generatePassword(options: GeneratorOptions): string {
  const alphabet = buildAlphabet(options);

  if (alphabet.length === 0) {
    throw new Error('Select at least one character set.');
  }

  const length = Math.max(8, Math.min(128, Math.floor(options.length)));
  let password = '';

  for (let i = 0; i < length; i++) {
    password += alphabet[randomIndex(alphabet.length)];
  }

  return password;
}

/**
 * Uniform random integer in [0, max) by rejection sampling: draw a byte, throw
 * it away if it falls in the uneven tail, and draw again.
 */
function randomIndex(max: number): number {
  if (max > 256) {
    throw new Error('This sampler only supports alphabets of up to 256 characters.');
  }

  const limit = Math.floor(256 / max) * max;
  const buffer = new Uint8Array(1);

  for (;;) {
    crypto.getRandomValues(buffer);

    if (buffer[0] < limit) {
      return buffer[0] % max;
    }
  }
}

/**
 * Shannon entropy for a password drawn uniformly from this alphabet:
 * length * log2(alphabet size). This is an upper bound on strength and says
 * nothing about a password a human chose — it is only honest for generated ones.
 */
export function entropyBits(options: GeneratorOptions): number {
  const alphabet = buildAlphabet(options);

  if (alphabet.length <= 1) {
    return 0;
  }

  return Math.round(options.length * Math.log2(alphabet.length));
}

export type StrengthLabel = 'weak' | 'fair' | 'strong' | 'excellent';

export function strengthFromEntropy(bits: number): StrengthLabel {
  if (bits < 50) return 'weak';
  if (bits < 75) return 'fair';
  if (bits < 110) return 'strong';
  return 'excellent';
}

/**
 * A rough entropy estimate for a password someone typed. Deliberately
 * pessimistic: it assumes only the character classes actually present, and
 * penalises obvious repetition. Never present this as a guarantee.
 */
export function estimateTypedEntropy(password: string): number {
  if (!password) {
    return 0;
  }

  let poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/[0-9]/.test(password)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) poolSize += 23;

  const uniqueRatio = new Set(password).size / password.length;

  return Math.round(password.length * Math.log2(Math.max(poolSize, 2)) * uniqueRatio);
}
