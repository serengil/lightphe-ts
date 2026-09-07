import { Logger } from '../commons/logger.js';
import {
  bitLength,
  gcd,
  jacobiSymbol,
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

const logger = new Logger('lightphe-ts/cryptosystems/GoldwasserMicali.ts');

/**
 * Goldwasser-Micali is homomorphic with respect to exclusive or.
 *
 * Ref: https://sefiks.com/2023/10/27/a-step-by-step-partially-homomorphic-encryption-example-with-goldwasser-micali-in-python/
 */
export class GoldwasserMicali extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['n', 'x'],
    private_key: ['p', 'q'],
  };

  constructor(options?: {
    keys?: Keys | null;
    keySize?: number | null;
    maxTries?: number;
  }) {
    super();
    this.keys =
      options?.keys ??
      this.generateKeys(options?.keySize ?? 1024, {
        maxTries: options?.maxTries ?? 10000,
      });
    this.ciphertextModulo = this.keys.public_key!.n as bigint;

    // Plaintexts of any size work because they are encrypted bit by bit.
    // Internally each bit uses modulo 2, but LightPHE deals in integers, and
    // the original integer is fully restored on decryption even when it exceeds
    // n.
    this.plaintextModulo = this.keys.public_key!.n as bigint;
  }

  get requiredKeys(): RequiredKeys {
    return GoldwasserMicali.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.GoldwasserMicali;
  }

  generateKeys(keySize: number, options?: { maxTries?: number }): Keys {
    const maxTries = options?.maxTries ?? 10000;
    const half = Math.floor(keySize / 2);
    const lo = pow2(half - 100);
    const hi = pow2(half) - ONE;

    for (let attempt = 0; attempt < maxTries; attempt++) {
      // pick large random primes p and q
      const p = randPrime(lo, hi);
      const q = randPrime(lo, hi);

      // To resist factorisation attacks n should be several hundred bits.
      const n = p * q;

      // find a quadratic non-residue x
      let x: bigint | undefined;
      for (let i = 0; i < 1000; i++) {
        const candidate = randomRange(TWO, n - ONE);
        if (gcd(candidate, n) !== ONE) {
          continue;
        }
        if (
          jacobiSymbol(candidate, p) === -1 &&
          jacobiSymbol(candidate, q) === -1
        ) {
          x = candidate;
          break;
        }
      }
      if (x === undefined) {
        // No suitable x found: discard this p-q pair and retry.
        continue;
      }

      logger.debug(
        `Goldwasser-Micali keys generated after ${attempt + 1} attempts, n bits: ${bitLength(n)}`
      );
      return {
        public_key: { n, x },
        private_key: { p, q },
      };
    }

    throw new Error(
      `Failed to generate Goldwasser-Micali keys after ${maxTries} attempts.` +
        'Please try to rerun.'
    );
  }

  /** Goldwasser-Micali draws a fresh random key coprime to `n` per bit. */
  generateRandomKey(): bigint {
    const n = this.keys.public_key!.n as bigint;
    for (;;) {
      const r = randomRange(ONE, n);
      if (gcd(r, n) === ONE) {
        return r;
      }
    }
  }

  encrypt(plaintext: bigint, randomKey?: bigint | bigint[]): bigint[] {
    const n = this.keys.public_key!.n as bigint;
    const x = this.keys.public_key!.x as bigint;

    const mBinary = plaintext.toString(2);
    const k = mBinary.length;

    const keyStream = Array.isArray(randomKey) ? randomKey : undefined;
    if (keyStream !== undefined && keyStream.length !== k) {
      throw new Error(`Random key must be length of ${k}`);
    }

    const c: bigint[] = [];
    for (let i = 0; i < k; i++) {
      const mi = BigInt(mBinary[i]);
      const ri =
        keyStream !== undefined ? keyStream[i] : this.generateRandomKey();
      c.push((modPow(ri, TWO, n) * modPow(x, mi, n)) % n);
    }
    return c;
  }

  decrypt(ciphertext: CiphertextValue): bigint {
    const p = this.keys.private_key!.p as bigint;
    const q = this.keys.private_key!.q as bigint;

    const mBinaries: string[] = [];
    for (const ci of ciphertext as bigint[]) {
      const xp = ci % p;
      const xq = ci % q;

      if (
        modPow(xp, (p - ONE) / TWO, p) === ONE &&
        modPow(xq, (q - ONE) / TWO, q) === ONE
      ) {
        mBinaries.push('0');
      } else {
        mBinaries.push('1');
      }
    }

    return BigInt(`0b${mBinaries.join('')}`);
  }

  /**
   * Homomorphic exclusive or: the result decrypts to `m1 ^ m2`. The shorter
   * ciphertext is left-padded with encrypted zero bits first.
   */
  override xor(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): bigint[] {
    let c1 = [...(ciphertext1 as bigint[])];
    let c2 = [...(ciphertext2 as bigint[])];

    if (c1.length > c2.length) {
      const pad = Array.from(
        { length: c1.length - c2.length },
        () => this.encrypt(ZERO)[0]
      );
      c2 = [...pad, ...c2];
    } else if (c2.length > c1.length) {
      const pad = Array.from(
        { length: c2.length - c1.length },
        () => this.encrypt(ZERO)[0]
      );
      c1 = [...pad, ...c1];
    }

    return c1.map((value, i) => (value * c2[i]) % this.ciphertextModulo);
  }

  override reencrypt(ciphertext: CiphertextValue): bigint[] {
    const n = this.keys.public_key!.n as bigint;
    return (ciphertext as bigint[]).map((ci) => {
      const ri = this.generateRandomKey();
      return (modPow(ri, TWO, n) * ci) % n;
    });
  }
}
