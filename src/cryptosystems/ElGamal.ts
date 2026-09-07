import { Logger } from '../commons/logger.js';
import {
  isqrt,
  modPow,
  pow2,
  randPrime,
  randomRange,
  ZERO,
  ONE,
  TWO,
} from '../commons/mathUtils.js';
import { Algorithm } from '../models/Algorithm.js';
import { Homomorphic } from '../models/Homomorphic.js';
import type { CiphertextValue, Keys, RequiredKeys } from '../models/types.js';

const logger = new Logger('lightphe-ts/cryptosystems/ElGamal.ts');

/**
 * ElGamal is either multiplicatively or additively homomorphic.
 *
 * Regular ElGamal is homomorphic with respect to multiplication; the
 * exponential variant is homomorphic with respect to addition, at the cost of
 * having to solve a discrete logarithm during decryption.
 *
 * Ref: https://sefiks.com/2023/03/27/a-step-by-step-partially-homomorphic-encryption-example-with-elgamal-in-python/
 */
export class ElGamal extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['p', 'g', 'y'],
    private_key: ['x'],
  };

  readonly exponential: boolean;

  constructor(options?: {
    keys?: Keys | null;
    exponential?: boolean;
    keySize?: number | null;
  }) {
    super();
    this.exponential = options?.exponential ?? false;
    this.keys = options?.keys ?? this.generateKeys(options?.keySize ?? 1024);
    const p = this.keys.public_key!.p as bigint;
    this.plaintextModulo = p;
    this.ciphertextModulo = p;
  }

  get requiredKeys(): RequiredKeys {
    return ElGamal.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return this.exponential ? Algorithm.ExponentialElGamal : Algorithm.ElGamal;
  }

  generateKeys(keySize: number): Keys {
    // picking a prime modulus p
    const p = randPrime(100n, pow2(Math.floor(keySize / 2)) - ONE);

    // picking a generator g
    const g = randomRange(TWO, isqrt(p));

    // picking a private key x
    const x = randomRange(ONE, p - TWO);

    // public key
    const y = modPow(g, x, p);

    return {
      public_key: { p, g, y },
      private_key: { x },
    };
  }

  /** ElGamal draws a fresh one-time random key per encryption. */
  generateRandomKey(): bigint {
    const p = this.keys.public_key!.p as bigint;
    return randomRange(ONE, p - ONE);
  }

  encrypt(plaintext: bigint, randomKey?: bigint | bigint[]): CiphertextValue {
    const p = this.keys.public_key!.p as bigint;
    const g = this.keys.public_key!.g as bigint;
    const y = this.keys.public_key!.y as bigint;
    const r =
      typeof randomKey === 'bigint' && randomKey !== ZERO
        ? randomKey
        : this.generateRandomKey();

    let message = plaintext;
    if (message > p) {
      message = message % p;
      logger.debug(
        `ElGamal can encrypt messages [1, ${p}]. ` +
          `Seems you exceeded this limit. New plaintext is ${message}`
      );
    }

    const c1 = modPow(g, r, p);
    const c2 = this.exponential
      ? (modPow(g, message, p) * modPow(y, r, p)) % p
      : (message * modPow(y, r, p)) % p;

    return [c1, c2];
  }

  decrypt(ciphertext: CiphertextValue): bigint {
    const [c1, c2] = ciphertext as [bigint, bigint];

    const x = this.keys.private_key!.x as bigint;
    const p = this.keys.public_key!.p as bigint;
    const g = this.keys.public_key!.g as bigint;

    const mPrime = (c2 * modPow(c1, -x, p)) % p;

    if (!this.exponential) {
      return mPrime;
    }

    // m_prime = g^m. Recover m for known m_prime and g, which is a DLP.
    let m = ZERO;
    for (;;) {
      if (modPow(g, m, p) === mPrime) {
        return m;
      }
      m += ONE;
      if (m > p) {
        throw new Error(`Cannot restore the message in [0, ${p}]`);
      }
    }
  }

  /** Homomorphic multiplication: the result decrypts to `m1 * m2`. */
  override multiply(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): CiphertextValue {
    if (this.exponential) {
      throw new Error(
        'Exponential ElGamal is not homomorphic with respect to the addition'
      );
    }
    const p = this.keys.public_key!.p as bigint;
    const a = ciphertext1 as [bigint, bigint];
    const b = ciphertext2 as [bigint, bigint];
    return [(a[0] * b[0]) % p, (a[1] * b[1]) % p];
  }

  /** Homomorphic addition: the result decrypts to `m1 + m2`. */
  override add(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): CiphertextValue {
    if (!this.exponential) {
      throw new Error(
        'Regular ElGamal is not homomorphic with respect to the addition'
      );
    }
    const p = this.keys.public_key!.p as bigint;
    const a = ciphertext1 as [bigint, bigint];
    const b = ciphertext2 as [bigint, bigint];
    return [(a[0] * b[0]) % p, (a[1] * b[1]) % p];
  }

  override multiplyByConstant(
    ciphertext: CiphertextValue,
    constant: bigint
  ): CiphertextValue {
    if (!this.exponential) {
      throw new Error(
        'ElGamal is not supporting multiplying ciphertext by a known constant'
      );
    }
    const p = this.keys.public_key!.p as bigint;
    let k = constant;
    if (k > p) {
      k = k % p;
      logger.debug(
        `ElGamal can encrypt messages [1, ${p}]. ` +
          `Seems constant exceeded this limit. New constant is ${k}`
      );
    }
    const c = ciphertext as [bigint, bigint];
    return [modPow(c[0], k, p), modPow(c[1], k, p)];
  }

  override reencrypt(ciphertext: CiphertextValue): CiphertextValue {
    // Additively homomorphic schemes re-randomise by adding an encrypted zero;
    // multiplicative ones by multiplying with an encrypted one.
    const neutralElement = this.exponential ? ZERO : ONE;
    const neutralEncrypted = this.encrypt(neutralElement);

    return this.exponential
      ? this.add(ciphertext, neutralEncrypted)
      : this.multiply(ciphertext, neutralEncrypted);
  }
}
