/** An encrypted message together with the public cryptosystem that evaluates on it. */

import { normalizeInput } from '../commons/pheUtils.js';
import { buildCryptosystem } from '../cryptosystems/index.js';
import { BV_FLOAT_NOT_SUPPORTED_MSG } from '../cryptosystems/BrakerskiVaikuntanathan.js';
import { FBGN_FLOAT_NOT_SUPPORTED_MSG } from '../cryptosystems/FreemanBonehGohNissim.js';
import { GHV_FLOAT_NOT_SUPPORTED_MSG } from '../cryptosystems/GentryHaleviVaikuntanathan.js';
import { FLOAT_NOT_SUPPORTED_MSG } from '../cryptosystems/JoyeLibert.js';
import { REGEV_FLOAT_NOT_SUPPORTED_MSG } from '../cryptosystems/Regev.js';
import type { CurveForm } from '../ecc/index.js';
import { Algorithm, type AlgorithmName } from './Algorithm.js';
import { Homomorphic } from './Homomorphic.js';
import type { CiphertextValue, Keys } from './types.js';

/** Algorithms rejecting floats, as their plaintext spaces cannot hold scaled values. */
export const FLOAT_NOT_SUPPORTED_MESSAGES: Readonly<Record<string, string>> = {
  [Algorithm.JoyeLibert]: FLOAT_NOT_SUPPORTED_MSG,
  [Algorithm.Regev]: REGEV_FLOAT_NOT_SUPPORTED_MSG,
  [Algorithm.BrakerskiVaikuntanathan]: BV_FLOAT_NOT_SUPPORTED_MSG,
  [Algorithm.FreemanBonehGohNissim]: FBGN_FLOAT_NOT_SUPPORTED_MSG,
  [Algorithm.GentryHaleviVaikuntanathan]: GHV_FLOAT_NOT_SUPPORTED_MSG,
};

export class Ciphertext {
  readonly algorithmName: AlgorithmName | string;
  readonly keys: Keys;
  readonly value: CiphertextValue;
  readonly cs: Homomorphic;
  private readonly form?: CurveForm | string | null;
  private readonly curve?: string | null;

  constructor(options: {
    algorithmName: AlgorithmName | string;
    keys: Keys;
    value: CiphertextValue;
    form?: CurveForm | string | null;
    curve?: string | null;
  }) {
    this.algorithmName = options.algorithmName;
    this.keys = options.keys;
    this.value = options.value;
    this.form = options.form;
    this.curve = options.curve;

    this.cs = buildCryptosystem(options.algorithmName, {
      keys: options.keys,
      form: options.form,
      curve: options.curve,
    });
  }

  toString(): string {
    return `Ciphertext(${describe(this.value)})`;
  }

  /** Wraps a freshly computed payload, carrying this ciphertext's settings along. */
  private wrap(value: CiphertextValue): Ciphertext {
    return new Ciphertext({
      algorithmName: this.algorithmName,
      keys: this.keys,
      value,
      form: this.form,
      curve: this.curve,
    });
  }

  /** Homomorphic addition: the result decrypts to `m1 + m2`. */
  add(other: Ciphertext): Ciphertext {
    if (this.cs.keys.public_key == null) {
      throw new Error(
        'You must have public key to perform homomorphic addition'
      );
    }
    return this.wrap(this.cs.add(this.value, other.value));
  }

  /**
   * Homomorphic multiplication with another ciphertext, or scalar
   * multiplication by a known constant.
   */
  multiply(other: Ciphertext | number | bigint): Ciphertext {
    if (this.cs.keys.public_key == null) {
      throw new Error(
        'You must have public key to perform homomorphic multiplication'
      );
    }

    if (other instanceof Ciphertext) {
      return this.wrap(this.cs.multiply(this.value, other.value));
    }
    if (typeof other === 'bigint' || Number.isInteger(other)) {
      return this.wrap(
        this.cs.multiplyByConstant(this.value, BigInt(other as number | bigint))
      );
    }
    if (typeof other === 'number') {
      const floatNotSupported =
        FLOAT_NOT_SUPPORTED_MESSAGES[this.algorithmName];
      if (floatNotSupported !== undefined) {
        throw new Error(floatNotSupported);
      }
      const constant = normalizeInput(other, this.cs.plaintextModulo);
      return this.wrap(this.cs.multiplyByConstant(this.value, constant));
    }
    throw new Error(
      'A ciphertext can be multiplied by either ciphertext itself or a scalar' +
        ` but it is ${typeof other}`
    );
  }

  /** Scalar multiplication by a known constant. */
  multiplyByConstant(constant: number | bigint): Ciphertext {
    return this.multiply(constant);
  }

  /** Homomorphic exclusive or: the result decrypts to `m1 ^ m2`. */
  xor(other: Ciphertext): Ciphertext {
    if (this.cs.keys.public_key == null) {
      throw new Error('You must have public key to perform homomorphic xor');
    }
    return this.wrap(this.cs.xor(this.value, other.value));
  }

  /** Homomorphic bitwise and: the result decrypts to `m1 & m2`. */
  and(other: Ciphertext): Ciphertext {
    if (this.cs.keys.public_key == null) {
      throw new Error('You must have public key to perform homomorphic and');
    }
    return this.wrap(this.cs.homomorphicAnd(this.value, other.value));
  }
}

/** Renders a ciphertext payload for logging. */
function describe(value: CiphertextValue): string {
  if (Array.isArray(value)) {
    return `[${value.map(describe).join(', ')}]`;
  }
  return String(value);
}
