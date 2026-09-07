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
  TWO,
} from '../commons/mathUtils.js';
import { Algorithm } from '../models/Algorithm.js';
import { Homomorphic } from '../models/Homomorphic.js';
import type { CiphertextValue, Keys, RequiredKeys } from '../models/types.js';

const logger = new Logger('lightphe-ts/cryptosystems/OkamotoUchiyama.ts');

/**
 * Okamoto-Uchiyama is homomorphic with respect to addition.
 *
 * Ref: https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-okamoto-uchiyama-in-python/
 */
export class OkamotoUchiyama extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['n', 'g', 'h'],
    private_key: ['p', 'q'],
  };

  constructor(options?: { keys?: Keys | null; keySize?: number | null }) {
    super();
    this.keys = options?.keys ?? this.generateKeys(options?.keySize ?? 1024);
    const n = this.keys.public_key!.n as bigint;
    this.plaintextModulo = n;
    this.ciphertextModulo = n;
  }

  get requiredKeys(): RequiredKeys {
    return OkamotoUchiyama.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.OkamotoUchiyama;
  }

  generateKeys(keySize: number): Keys {
    const hi = pow2(Math.floor(keySize / 2)) - ONE;

    // picking prime moduli p and q
    const p = randPrime(200n, hi);
    const q = randPrime(200n, hi);

    // modulo
    const n = p * p * q;

    // generator
    const g = randomRange(TWO, n);

    if (modPow(g, p - ONE, p * p) === ONE) {
      throw new Error("Fermat's Little Theorem must be satisfied");
    }

    const h = modPow(g, n, n);

    return {
      public_key: { n, g, h },
      private_key: { p, q },
    };
  }

  /** Okamoto-Uchiyama draws a fresh one-time random key per encryption. */
  generateRandomKey(): bigint {
    const n = this.keys.public_key!.n as bigint;
    return randomRange(ONE, n - ONE);
  }

  encrypt(plaintext: bigint, randomKey?: bigint | bigint[]): CiphertextValue {
    const g = this.keys.public_key!.g as bigint;
    const n = this.keys.public_key!.n as bigint;
    const h = this.keys.public_key!.h as bigint;
    const r =
      typeof randomKey === 'bigint' && randomKey !== ZERO
        ? randomKey
        : this.generateRandomKey();

    let message = plaintext;
    // Holding the private key is not required to encrypt, but when it is
    // available the plaintext bound can be enforced.
    if (this.keys.private_key != null) {
      const p = this.keys.private_key.p as bigint;
      if (message > p) {
        message = message % p;
        logger.debug(
          `plaintext must be in scale [0, p=${p}] but this is exceeded.` +
            `New plaintext is ${message}`
        );
      }
    }
    return (modPow(g, message, n) * modPow(h, r, n)) % n;
  }

  decrypt(ciphertext: CiphertextValue): bigint {
    const p = this.keys.private_key!.p as bigint;
    const g = this.keys.public_key!.g as bigint;

    const a = this.lx(modPow(ciphertext as bigint, p - ONE, p * p));
    const b = this.lx(modPow(g, p - ONE, p * p));
    return (a * modInverse(b, p)) % p;
  }

  /** Homomorphic addition, computed modulo `n`: the result decrypts to `m1 + m2`. */
  override add(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): CiphertextValue {
    const n = this.keys.public_key!.n as bigint;
    return ((ciphertext1 as bigint) * (ciphertext2 as bigint)) % n;
  }

  /** Multiplies a ciphertext by a known plain constant. */
  override multiplyByConstant(
    ciphertext: CiphertextValue,
    constant: bigint
  ): CiphertextValue {
    const n = this.keys.public_key!.n as bigint;
    let k = constant;
    if (k > this.plaintextModulo) {
      k = k % this.plaintextModulo;
      logger.debug(
        `Okamoto-Uchiyama can encrypt messages [1, ${n}]. ` +
          `Seems constant exceeded this limit. New constant is ${k}`
      );
    }
    return modPow(ciphertext as bigint, k, n);
  }

  override reencrypt(ciphertext: CiphertextValue): CiphertextValue {
    const neutralEncrypted = this.encrypt(ZERO);
    return this.add(ciphertext, neutralEncrypted);
  }

  /** The `L` function over the cyclic group: `(x - 1) / p`. */
  lx(x: bigint): bigint {
    const p = this.keys.private_key!.p as bigint;
    if (x % p !== ONE) {
      throw new Error(
        `Input passed to lx (${x}) must be identical to 1 in modulo ${p}`
      );
    }
    if (gcd(x, p * p) !== ONE) {
      throw new Error(`gcd(${x}, ${p}^2) must be equal to 1`);
    }
    const y = x - ONE;
    if (y % p !== ZERO) {
      throw new Error(`(${x} - 1) must be divisible by ${p}`);
    }
    return y / p;
  }
}
