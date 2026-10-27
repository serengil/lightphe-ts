/** Shared helpers for the test suite. */

import {
  EllipticCurvePoint,
  FP2,
  deserializeKeys,
  serializeKeys,
} from '../src';
import type { CiphertextValue, Keys } from '../src';

/**
 * Structural equality for ciphertext payloads.
 *
 * Payload shapes vary by cryptosystem — an integer, a pair, a bit vector, a
 * curve point — so the tests need one comparison that handles all of them.
 */
export function valuesEqual(a: CiphertextValue, b: CiphertextValue): boolean {
  if (Array.isArray(a) && Array.isArray(b)) {
    return (
      a.length === b.length && a.every((item, i) => valuesEqual(item, b[i]))
    );
  }
  if (a instanceof EllipticCurvePoint && b instanceof EllipticCurvePoint) {
    return a.equals(b);
  }
  if (a instanceof FP2 && b instanceof FP2) {
    return a.equals(b);
  }
  return a === b;
}

/** Absolute difference between two numbers. */
export function absDiff(a: number, b: number): number {
  return Math.abs(a - b);
}

/** Deep-clones a plain key structure, the way `copy.deepcopy` does in Python. */
export function deepClone<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((item: unknown) => deepClone(item)) as unknown as T;
  }
  if (typeof value === 'object' && value !== null) {
    const result: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      result[key] = deepClone(entry);
    }
    return result as T;
  }
  return value;
}

/** The bit length of a big integer, mirroring Python's `int.bit_length()`. */
export function bitLength(value: bigint): number {
  const magnitude = value < 0n ? -value : value;
  return magnitude === 0n ? 0 : magnitude.toString(2).length;
}

/** A uniform random integer in the inclusive range `[lo, hi]`, like Python's `random.randint`. */
export function randomInt(lo: number, hi: number): number {
  return lo + Math.floor(Math.random() * (hi - lo + 1));
}

/** A uniform random bigint in `[0, bound)`, like Python's `random.randrange`. */
export function randomBigInt(bound: bigint): bigint {
  const digits = bound.toString(16).length + 8;
  let hex = '';
  for (let i = 0; i < digits; i++) {
    hex += Math.floor(Math.random() * 16).toString(16);
  }
  return BigInt(`0x${hex}`) % bound;
}

/** Python-style modulo for bigints, always in `[0, m)`. */
export function pmod(a: bigint, m: bigint): bigint {
  return ((a % m) + m) % m;
}

/**
 * Sends a value through json and back, the way keys, proofs and partial
 * decryptions travel over the wire. Bigints are written as decimal strings and
 * restored as bigints, like Python's `json.loads(json.dumps(...))` keeps ints.
 */
export function jsonRoundTrip<T>(value: T): T {
  return deserializeKeys(serializeKeys({ value } as unknown as Keys))
    .value as T;
}

/** Adds 1 to the first entry of a proof, like a forger would. */
export function tamper<T>(proof: T): T {
  const tampered = deepClone(proof) as Record<string, unknown>;
  const key = Object.keys(tampered)[0];
  const value = tampered[key];
  if (Array.isArray(value)) {
    value[0] = (value[0] as bigint) + 1n;
  } else {
    tampered[key] = (value as bigint) + 1n;
  }
  return tampered as T;
}
