/**
 * JSON serialisation of key material.
 *
 * Keys are bags of arbitrarily large integers, which JSON has no type for, so
 * every `bigint` is written as a decimal string and read back as a `bigint`.
 * Non-numeric strings — the `form` and `curve` markers — pass through untouched.
 */

import type { Keys } from '../models/types.js';

const INTEGER_STRING = /^-?\d+$/;

function encode(value: unknown): unknown {
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value.map(encode);
  }
  if (typeof value === 'object' && value !== null) {
    const result: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      result[key] = encode(entry);
    }
    return result;
  }
  return value;
}

function decode(value: unknown): unknown {
  if (typeof value === 'string' && INTEGER_STRING.test(value)) {
    return BigInt(value);
  }
  if (typeof value === 'number' && Number.isInteger(value)) {
    return BigInt(value);
  }
  if (Array.isArray(value)) {
    return value.map(decode);
  }
  if (typeof value === 'object' && value !== null) {
    const result: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      result[key] = key === 'form' || key === 'curve' ? entry : decode(entry);
    }
    return result;
  }
  return value;
}

/** Renders a key pair as JSON text. */
export function serializeKeys(keys: Keys): string {
  return JSON.stringify(encode(keys));
}

/** Parses key JSON text back into a key pair, restoring every `bigint`. */
export function deserializeKeys(text: string): Keys {
  const parsed: unknown = JSON.parse(text);
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('The content does not represent a valid dictionary.');
  }
  return decode(parsed) as Keys;
}
