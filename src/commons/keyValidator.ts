/** Validation of user-supplied key material. */

import { REQUIRED_KEYS_BY_ALGORITHM } from '../cryptosystems/index.js';
import type { Keys } from '../models/types.js';

function typeName(value: unknown): string {
  if (value === null) {
    return 'null';
  }
  if (Array.isArray(value)) {
    return 'Array';
  }
  return typeof value;
}

/** Renders field names the way Python prints a list of strings. */
function formatFields(fields: readonly string[]): string {
  return `[${fields.map((field) => `'${field}'`).join(', ')}]`;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Checks that user-supplied keys carry the sub-fields the cryptosystem needs.
 *
 * `public_key` is always required — every cryptosystem needs it to encrypt.
 * `private_key` is optional, since encryption-only setups omit it; whichever
 * part is present must be complete.
 *
 * The spec comes from the cryptosystem's own `REQUIRED_KEYS` declaration. An
 * optional `alternative_private_key` entry lists another set of fields that is
 * accepted instead of the required `private_key` fields.
 *
 * @throws when a required field is missing or the structure is wrong.
 */
export function validateKeys(
  algorithmName: string,
  keys: unknown
): asserts keys is Keys {
  const spec = REQUIRED_KEYS_BY_ALGORITHM[algorithmName];
  if (spec === undefined) {
    return;
  }

  if (!isPlainObject(keys)) {
    throw new Error(
      `${algorithmName} keys must be a dict, got ${typeName(keys)}`
    );
  }

  if (!('public_key' in keys)) {
    throw new Error(`${algorithmName} keys must contain 'public_key'`);
  }

  for (const kind of ['public_key', 'private_key'] as const) {
    if (!(kind in keys)) {
      continue;
    }
    const part = keys[kind];
    if (!isPlainObject(part)) {
      throw new Error(
        `${algorithmName} '${kind}' must be a dict, got ${typeName(part)}`
      );
    }
    const missing = spec[kind].filter((field) => !(field in part));
    const alternative =
      kind === 'private_key' ? spec.alternative_private_key : undefined;
    if (missing.length > 0 && alternative !== undefined) {
      if (alternative.every((field) => field in part)) {
        continue;
      }
      throw new Error(
        `${algorithmName} '${kind}' is missing required fields: ${formatFields(
          missing
        )} (or alternatively ${formatFields(alternative)})`
      );
    }
    if (missing.length > 0) {
      throw new Error(
        `${algorithmName} '${kind}' is missing required fields: ${formatFields(
          missing
        )}`
      );
    }
  }

  const nested = spec.nested ?? {};
  const publicKey = keys.public_key as Record<string, unknown>;
  for (const [parent, required] of Object.entries(nested)) {
    if (!(parent in publicKey)) {
      continue;
    }
    const sub = publicKey[parent];
    if (!isPlainObject(sub)) {
      throw new Error(
        `${algorithmName} 'public_key.${parent}' must be a dict, got ${typeName(sub)}`
      );
    }
    const missing = required.filter((field) => !(field in sub));
    if (missing.length > 0) {
      throw new Error(
        `${algorithmName} 'public_key.${parent}' is missing required fields: ${formatFields(
          missing
        )}`
      );
    }
  }
}
