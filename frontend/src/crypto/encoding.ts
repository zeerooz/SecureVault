export function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export function fromUtf8(bytes: ArrayBuffer | Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function toBase64(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';

  // Chunked to avoid blowing the argument limit on large blobs.
  const chunkSize = 0x8000;
  for (let i = 0; i < view.length; i += chunkSize) {
    binary += String.fromCharCode(...view.subarray(i, i + chunkSize));
  }

  return btoa(binary);
}

export function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

export function toHex(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);

  return Array.from(view)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Overwrites a buffer in place. JavaScript gives no real guarantee that the
 * original bytes are gone — the engine may have copied them during a GC — but
 * clearing what we can hold shortens the window in which a heap snapshot is
 * useful to an attacker.
 */
export function wipe(bytes: Uint8Array): void {
  bytes.fill(0);
}
