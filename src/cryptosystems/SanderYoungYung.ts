import { Logger } from '../commons/logger.js';
import {
  gcd,
  jacobiSymbol,
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

const logger = new Logger('lightphe-ts/cryptosystems/SanderYoungYung.ts');

/**
 * Sander-Young-Yung is homomorphic with respect to bitwise AND.
 *
 * Each plaintext bit becomes a vector in `Z_2^l` lifted into the quadratic
 * residues modulo `n`: a one bit is the zero vector, a zero bit any non-zero
 * vector. Multiplying two encodings component-wise ORs the vectors, which ANDs
 * the underlying bits.
 *
 * Ref: https://sefiks.com/2026/04/02/a-step-by-step-partially-homomorphic-sander-young-yung-example-in-python/
 */
export class SanderYoungYung extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['n', 'x', 'l'],
    private_key: ['p', 'q'],
  };

  constructor(options?: {
    keys?: Keys | null;
    keySize?: number | null;
    plaintextLimit?: number | bigint | null;
  }) {
    super();
    this.keys =
      options?.keys ??
      this.generateKeys(options?.keySize ?? 1024, {
        plaintextLimit: options?.plaintextLimit,
      });
    this.ciphertextModulo = this.keys.public_key!.n as bigint;
    this.plaintextModulo = this.keys.public_key!.l as bigint;
  }

  get requiredKeys(): RequiredKeys {
    return SanderYoungYung.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.SanderYoungYung;
  }

  generateKeys(
    keySize: number,
    options?: { maxTries?: number; plaintextLimit?: number | bigint | null }
  ): Keys {
    const maxTries = options?.maxTries ?? 10000;
    const plaintextLimit =
      options?.plaintextLimit === undefined || options.plaintextLimit === null
        ? null
        : BigInt(options.plaintextLimit);

    const half = Math.floor(keySize / 2);
    const lo = pow2(half - 100);
    const hi = pow2(half) - ONE;

    for (let attempt = 0; attempt < maxTries; attempt++) {
      // pick primes p and q
      const p = randPrime(lo, hi);
      const q = randPrime(lo, hi);

      // pick positive integer l
      const l =
        plaintextLimit === null
          ? randomRange(100n, 200n)
          : randomRange(plaintextLimit, plaintextLimit + 100n);

      const n = p * q;

      for (let i = 0; i < Math.floor(maxTries / 10); i++) {
        const x = randomRange(ONE, n - ONE);
        if (gcd(x, n) !== ONE) {
          continue;
        }
        if (jacobiSymbol(x, p) !== -1 || jacobiSymbol(x, q) !== -1) {
          continue;
        }

        return {
          public_key: { n, x, l },
          private_key: { p, q },
        };
      }

      // No suitable x within maxTries/10 attempts: try a different p and q.
    }

    throw new Error(`Failed to find suitable key in ${maxTries} tries`);
  }

  /** Sander-Young-Yung draws a fresh random key coprime to `n` per component. */
  generateRandomKey(): bigint {
    const n = this.keys.public_key!.n as bigint;
    for (;;) {
      const r = randomRange(ZERO, n);
      if (gcd(r, n) === ONE) {
        return r;
      }
    }
  }

  encrypt(plaintext: bigint): bigint[][] {
    const n = this.keys.public_key!.n as bigint;
    const l = Number(this.keys.public_key!.l as bigint);
    const x = this.keys.public_key!.x as bigint;

    const mBinary = plaintext.toString(2);
    const k = mBinary.length;
    logger.debug(`plaintext: ${plaintext}, binary: ${mBinary} (${k} bits)`);

    const ciphertexts: bigint[][] = [];
    for (let bit = 0; bit < k; bit++) {
      const mi = Number(mBinary[bit]);
      logger.debug(`Encrypting bit ${bit} of plaintext: ${mi}`);

      const ciphertext: bigint[] = [];
      if (mi === 1) {
        // 1 is encoded as the zero vector in Z_2^l
        for (let i = 0; i < l; i++) {
          const yi = this.generateRandomKey();
          ciphertext.push((yi * yi) % n);
        }
      } else {
        // 0 is encoded as a non-zero vector in Z_2^l
        let vs: number[] = [];
        for (;;) {
          vs = [];
          let total = 0;
          for (let i = 0; i < l; i++) {
            const vi = Number(randomRange(ZERO, ONE));
            vs.push(vi);
            total += vi;
          }
          if (total > 0) {
            break;
          }
        }

        for (let i = 0; i < l; i++) {
          const yi = this.generateRandomKey();
          ciphertext.push((yi * yi * modPow(x, BigInt(vs[i]), n)) % n);
        }
      }

      ciphertexts.push(ciphertext);
    }

    return ciphertexts;
  }

  decrypt(ciphertext: CiphertextValue): bigint {
    const p = this.keys.private_key!.p as bigint;
    const q = this.keys.private_key!.q as bigint;
    const l = Number(this.keys.public_key!.l as bigint);

    const plaintexts: string[] = [];
    for (const ci of ciphertext as bigint[][]) {
      let total = 0;
      for (let i = 0; i < l; i++) {
        const isResidue =
          jacobiSymbol(ci[i], p) === 1 && jacobiSymbol(ci[i], q) === 1;
        total += isResidue ? 0 : 1;
      }
      plaintexts.push(total === 0 ? '1' : '0');
    }

    return BigInt(`0b${plaintexts.join('')}`);
  }

  /** Homomorphic bitwise AND: the result decrypts to `m1 & m2`. */
  override homomorphicAnd(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): bigint[][] {
    let c1 = [...(ciphertext1 as bigint[][])];
    let c2 = [...(ciphertext2 as bigint[][])];

    // The shorter ciphertext is left-padded with encrypted zero bits. Capture
    // the gap up front: the arrays grow as they are padded.
    if (c1.length > c2.length) {
      const gap = c1.length - c2.length;
      const pad = this.encrypt(ZERO);
      for (let i = 0; i < gap; i++) {
        c2 = [...pad, ...c2];
      }
    } else if (c2.length > c1.length) {
      const gap = c2.length - c1.length;
      const pad = this.encrypt(ZERO);
      for (let i = 0; i < gap; i++) {
        c1 = [...pad, ...c1];
      }
    }

    const n = this.keys.public_key!.n as bigint;
    const l = Number(this.keys.public_key!.l as bigint);

    if (c1.length !== c2.length) {
      throw new Error(
        `Ciphertexts must have the same length but got ${c1.length} and ${c2.length}`
      );
    }

    const result: bigint[][] = [];
    for (let i = 0; i < c1.length; i++) {
      const a = c1[i];
      const b = c2[i];
      if (a.length !== b.length) {
        throw new Error(
          `Ciphertexts must have the same length but got ${a.length} and ${b.length}`
        );
      }
      const combined: bigint[] = [];
      for (let j = 0; j < l; j++) {
        combined.push((a[j] * b[j]) % n);
      }
      result.push(combined);
    }
    return result;
  }

  override reencrypt(ciphertext: CiphertextValue): bigint[][] {
    const l = Number(this.keys.public_key!.l as bigint);
    return (ciphertext as bigint[][]).map((ci) => {
      const reencrypted: bigint[] = [];
      for (let i = 0; i < l; i++) {
        const r = this.generateRandomKey();
        reencrypted.push((ci[i] * r * r) % this.ciphertextModulo);
      }
      return reencrypted;
    });
  }
}
