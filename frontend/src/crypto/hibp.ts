import { toHex, utf8 } from './encoding';

/**
 * Breach checking against Have I Been Pwned, using their k-anonymity range API.
 *
 * The password never leaves the browser, and neither does its full hash. We
 * SHA-1 the password, send the first five hex characters of the digest, and
 * HIBP returns every suffix it holds under that prefix — typically several
 * hundred. The comparison happens here. HIBP learns that somebody asked about
 * one of ~800 possible hashes, which tells them nothing useful.
 *
 * SHA-1 is not a choice: it is the hash HIBP's corpus is indexed by. It is used
 * here purely as a lookup key against a public dataset, never to protect
 * anything, so its collision weakness is irrelevant.
 *
 * The request goes straight from the browser to HIBP rather than through our
 * API. Proxying it would hand our own server a stream of password prefixes,
 * which is exactly the kind of thing this project exists to avoid.
 */

const RANGE_ENDPOINT = 'https://api.pwnedpasswords.com/range/';

export interface BreachResult {
  breached: boolean;
  /** How many times this password appears across known breaches. */
  count: number;
}

export async function checkPasswordBreach(password: string, signal?: AbortSignal): Promise<BreachResult> {
  if (!password) {
    return { breached: false, count: 0 };
  }

  const digest = await crypto.subtle.digest('SHA-1', toArrayBuffer(utf8(password)));
  const hash = toHex(digest).toUpperCase();

  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const response = await fetch(`${RANGE_ENDPOINT}${prefix}`, {
    signal,
    headers: {
      // Asks HIBP to pad the response with random entries, so an observer
      // cannot infer anything from its size.
      'Add-Padding': 'true',
    },
  });

  if (!response.ok) {
    throw new Error(`Breach check failed (HTTP ${response.status}).`);
  }

  const body = await response.text();

  for (const line of body.split('\n')) {
    const [candidate, countText] = line.trim().split(':');

    if (candidate === suffix) {
      const count = Number.parseInt(countText ?? '0', 10);

      // Padding entries are returned with a count of zero.
      if (count > 0) {
        return { breached: true, count };
      }
    }
  }

  return { breached: false, count: 0 };
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}
