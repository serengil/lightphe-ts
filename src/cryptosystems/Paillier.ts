import { Logger } from '../commons/logger.js';
import {
  gcd,
  modInverse,
  modPow,
  pow2,
  randPrime,
  randomRange,
  ZERO,
  ONE,
} from '../commons/mathUtils.js';
import { Algorithm } from '../models/Algorithm.js';
import { Homomorphic } from '../models/Homomorphic.js';
import type { CiphertextValue, Keys, RequiredKeys } from '../models/types.js';

const logger = new Logger('lightphe-ts/cryptosystems/Paillier.ts');

/**
 * Paillier is homomorphic with respect to addition, and also supports raising a
 * ciphertext to a plaintext exponent.
 *
 * Ref: https://sefiks.com/2023/04/03/a-step-by-step-partially-homomorphic-encryption-example-with-paillier-in-python/
 */
export class Paillier extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['g', 'n'],
    private_key: ['phi'],
  };

  constructor(options?: { keys?: Keys | null; keySize?: number | null }) {
    super();
    this.keys = options?.keys ?? this.generateKeys(options?.keySize ?? 1024);
    const n = this.keys.public_key!.n as bigint;
    this.plaintextModulo = n;
    this.ciphertextModulo = n * n;
  }

  get requiredKeys(): RequiredKeys {
    return Paillier.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.Paillier;
  }

  generateKeys(keySize: number): Keys {
    const hi = pow2(Math.floor(keySize / 2)) - ONE;

    // picking prime moduli p and q
    const p = randPrime(200n, hi);
    const q = randPrime(200n, hi);

    const n = p * q;
    const phi = (p - ONE) * (q - ONE);
    const g = ONE + n;

    return {
      public_key: { g, n },
      private_key: { phi },
    };
  }

  /** Paillier draws a fresh random key coprime to `n` per encryption. */
  generateRandomKey(): bigint {
    const n = this.keys.public_key!.n as bigint;
    for (;;) {
      const r = randomRange(ZERO, n);
      if (gcd(r, n) === ONE) {
        return r;
      }
    }
  }

  encrypt(plaintext: bigint, randomKey?: bigint | bigint[]): CiphertextValue {
    const g = this.keys.public_key!.g as bigint;
    const n = this.keys.public_key!.n as bigint;
    const r =
      typeof randomKey === 'bigint' && randomKey !== ZERO
        ? randomKey
        : this.generateRandomKey();

    if (gcd(r, n) !== ONE) {
      throw new Error('random key must be coprime to n');
    }
    const nSquared = n * n;
    return (modPow(g, plaintext, nSquared) * modPow(r, n, nSquared)) % nSquared;
  }

  decrypt(ciphertext: CiphertextValue): bigint {
    const phi = this.keys.private_key!.phi as bigint;
    const n = this.keys.public_key!.n as bigint;
    const mu = modInverse(phi, n);

    return (this.lx(modPow(ciphertext as bigint, phi, n * n)) * mu) % n;
  }

  /**
   * Homomorphic addition, computed modulo `n^2`: the result decrypts to
   * `m1 + m2`.
   */
  override add(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): CiphertextValue {
    const n = this.keys.public_key!.n as bigint;
    return ((ciphertext1 as bigint) * (ciphertext2 as bigint)) % (n * n);
  }

  /**
   * Multiplies a ciphertext by a known plain constant: the result decrypts to
   * `m * constant`.
   */
  override multiplyByConstant(
    ciphertext: CiphertextValue,
    constant: bigint
  ): CiphertextValue {
    const n = this.keys.public_key!.n as bigint;

    let k = constant;
    if (k > this.plaintextModulo) {
      k = k % this.plaintextModulo;
      logger.debug(
        `Paillier can encrypt messages [1, ${n}]. ` +
          `Seems constant exceeded this limit. New constant is ${k}`
      );
    }
    return modPow(ciphertext as bigint, k, n * n);
  }

  override reencrypt(ciphertext: CiphertextValue): CiphertextValue {
    const neutralEncrypted = this.encrypt(ZERO);
    return this.add(ciphertext, neutralEncrypted);
  }

  /** The `L` function over the cyclic group: `(x - 1) / n`. */
  lx(x: bigint): bigint {
    const n = this.keys.public_key!.n as bigint;
    const y = x - ONE;
    if (y % n !== ZERO) {
      throw new Error(`(${x} - 1) must be divisible by ${n}`);
    }
    return y / n;
  }
}
