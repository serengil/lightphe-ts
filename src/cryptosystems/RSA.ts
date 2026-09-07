import { Logger } from '../commons/logger.js';
import {
  gcd,
  modInverse,
  modPow,
  pow2,
  randPrime,
  randomRange,
  ONE,
  TWO,
} from '../commons/mathUtils.js';
import { Algorithm } from '../models/Algorithm.js';
import { Homomorphic } from '../models/Homomorphic.js';
import type { CiphertextValue, Keys, RequiredKeys } from '../models/types.js';

const logger = new Logger('lightphe-ts/cryptosystems/RSA.ts');

/**
 * RSA is partially homomorphic with respect to multiplication.
 *
 * Ref: https://sefiks.com/2023/03/06/a-step-by-step-partially-homomorphic-encryption-example-with-rsa-in-python/
 */
export class RSA extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['n', 'e'],
    private_key: ['d'],
  };

  /**
   * RSA has two keys: private (`d`) and public (`e`). Encrypting with someone's
   * public key means only they can decrypt (secure message); encrypting with
   * your private key means anyone can decrypt with your public one (digital
   * signature). Set this to true to encrypt with `e` and decrypt with `d`.
   */
  readonly encryptWithPublic: boolean;

  constructor(options?: {
    keys?: Keys | null;
    keySize?: number | null;
    encryptWithPublic?: boolean;
    maxTries?: number;
  }) {
    super();
    const maxTries = options?.maxTries ?? 10000;
    this.keys =
      options?.keys ??
      this.generateKeys(options?.keySize ?? 1024, { maxTries });
    const n = this.keys.public_key!.n as bigint;
    this.plaintextModulo = n;
    this.ciphertextModulo = n;
    this.encryptWithPublic = options?.encryptWithPublic ?? true;
  }

  get requiredKeys(): RequiredKeys {
    return RSA.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.RSA;
  }

  generateKeys(keySize: number, options?: { maxTries?: number }): Keys {
    const maxTries = options?.maxTries ?? 10000;
    const half = Math.floor(keySize / 2);
    const lo = pow2(half - 300);
    const hi = pow2(half) - ONE;

    for (let attempt = 0; attempt < maxTries; attempt++) {
      // picking a prime modulus p and q
      const p = randPrime(lo, hi);
      const q = randPrime(lo, hi);
      if (p === q) {
        continue;
      }

      const n = p * q;
      const phi = (p - ONE) * (q - ONE);

      // select public exponent e
      for (let i = 0; i < 1000; i++) {
        const e = randomRange(TWO, phi - ONE);
        if (gcd(e, phi) === ONE) {
          const d = modInverse(e, phi);
          return {
            public_key: { n, e },
            private_key: { d },
          };
        }
      }
    }
    throw new Error(`Failed to generate RSA keys after ${maxTries} tries`);
  }

  /** RSA needs no random key for encryption; one is returned anyway. */
  generateRandomKey(): bigint {
    const n = this.keys.public_key!.n as bigint;
    return randomRange(ONE, n - ONE);
  }

  encrypt(plaintext: bigint): CiphertextValue {
    const n = this.keys.public_key!.n as bigint;

    let message = plaintext;
    if (message > n) {
      message = message % n;
      logger.debug(
        `RSA can encrypt messages [1, ${n}]. ` +
          `Seems you exceeded this limit. New plaintext is ${message}`
      );
    }

    if (this.encryptWithPublic) {
      const e = this.keys.public_key!.e as bigint;
      return modPow(message, e, n);
    }
    const d = this.keys.private_key!.d as bigint;
    return modPow(message, d, n);
  }

  decrypt(ciphertext: CiphertextValue): bigint {
    const n = this.keys.public_key!.n as bigint;
    if (this.encryptWithPublic) {
      const d = this.keys.private_key!.d as bigint;
      return modPow(ciphertext as bigint, d, n);
    }
    const e = this.keys.public_key!.e as bigint;
    return modPow(ciphertext as bigint, e, n);
  }

  /** Homomorphic multiplication: the result decrypts to `m1 * m2`. */
  override multiply(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): CiphertextValue {
    const n = this.keys.public_key!.n as bigint;
    return ((ciphertext1 as bigint) * (ciphertext2 as bigint)) % n;
  }
}
