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

const logger = new Logger('lightphe-ts/cryptosystems/DamgardJurik.ts');

/**
 * Damgard-Jurik generalises Paillier and is homomorphic with respect to
 * addition. Its modulus is `n^(s+1)`; with `s = 1` it is Paillier.
 *
 * Ref: https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-damgard-jurik-in-python/
 */
export class DamgardJurik extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['g', 'n', 's'],
    private_key: ['phi'],
  };

  constructor(options?: {
    s?: number;
    keys?: Keys | null;
    keySize?: number | null;
  }) {
    super();
    const s = options?.s ?? 2;
    this.keys =
      options?.keys ?? this.generateKeys(options?.keySize ?? 1024, { s });
    const n = this.keys.public_key!.n as bigint;
    this.plaintextModulo = n;
    this.ciphertextModulo = n ** (BigInt(s) + ONE);
  }

  get requiredKeys(): RequiredKeys {
    return DamgardJurik.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.DamgardJurik;
  }

  generateKeys(keySize: number, options?: { s?: number }): Keys {
    const s = options?.s ?? 2;
    const hi = pow2(Math.floor(keySize / 2)) - ONE;

    // picking prime moduli p and q
    const p = randPrime(200n, hi);
    const q = randPrime(200n, hi);

    const n = p * q;
    const phi = (p - ONE) * (q - ONE);
    const g = ONE + n;

    return {
      public_key: { g, n, s: BigInt(s) },
      private_key: { phi },
    };
  }

  /** Damgard-Jurik draws a fresh random key coprime to `n` per encryption. */
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
    const s = this.keys.public_key!.s as bigint;
    const r =
      typeof randomKey === 'bigint' && randomKey !== ZERO
        ? randomKey
        : this.generateRandomKey();
    const modulo = n ** (s + ONE);

    const c = (modPow(g, plaintext, modulo) * modPow(r, n, modulo)) % modulo;
    if (gcd(c, modulo) !== ONE) {
      logger.info(`WARNING! gcd(c=${c}, modulo=${modulo}) != 1`);
    }
    return c;
  }

  decrypt(ciphertext: CiphertextValue): bigint {
    const phi = this.keys.private_key!.phi as bigint;
    const n = this.keys.public_key!.n as bigint;
    const s = this.keys.public_key!.s as bigint;
    const mu = modInverse(phi, n);
    const modulo = n ** (s + ONE);
    return (this.lx(modPow(ciphertext as bigint, phi, modulo)) * mu) % n;
  }

  /** Homomorphic addition: the result decrypts to `m1 + m2`. */
  override add(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): CiphertextValue {
    const n = this.keys.public_key!.n as bigint;
    const s = this.keys.public_key!.s as bigint;
    const modulo = n ** (s + ONE);
    return ((ciphertext1 as bigint) * (ciphertext2 as bigint)) % modulo;
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
        `Damgard-Jurik can encrypt messages [1, ${n}]. ` +
          `Seems constant exceeded this limit. New constant is ${k}`
      );
    }
    return modPow(ciphertext as bigint, k, this.ciphertextModulo);
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
