/** Shared helpers for the test suite. */

import { EllipticCurvePoint, FP2 } from '../src';
import type { CiphertextValue } from '../src';

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
