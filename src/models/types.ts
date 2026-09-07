/** Shared value and key shapes. */

import type { FP2 } from '../ecc/fp2.js';
import type { EllipticCurvePoint } from '../ecc/point.js';

/**
 * A ciphertext payload.
 *
 * The concrete shape depends on the cryptosystem: a single integer for RSA and
 * Paillier, a `[c1, c2]` pair for ElGamal, a bit vector for Goldwasser-Micali,
 * a curve point or an `F_{p^2}` element for Boneh-Goh-Nissim, and so on. The
 * cryptosystem that produced a value is the one that knows how to read it.
 */
export type CiphertextValue =
  bigint | EllipticCurvePoint | FP2 | readonly CiphertextValue[];

/** One half of a key pair: a bag of named big integers (or nested structures). */
export type KeyPart = Record<string, unknown>;

/** A private/public key pair as the cryptosystems store it. */
export interface Keys {
  public_key?: KeyPart;
  private_key?: KeyPart;
  /** Set for Elliptic Curve ElGamal so a restored key remembers its curve. */
  curve?: string;
  /** Set for Elliptic Curve ElGamal so a restored key remembers its form. */
  form?: string;
  [key: string]: unknown;
}

/**
 * The required-field spec a cryptosystem publishes so user-supplied keys can be
 * validated before use.
 */
export interface RequiredKeys {
  /** Sub-fields that must be present in `keys.public_key`. */
  public_key: readonly string[];
  /** Sub-fields that must be present in `keys.private_key`, when it is given. */
  private_key: readonly string[];
  /**
   * Sub-fields required inside a `public_key` entry that is itself a dictionary,
   * keyed by that entry's name.
   */
  nested?: Readonly<Record<string, readonly string[]>>;
}
