import { shake128, toBytesBigEndian } from '../commons/hashing.js';
import { Logger } from '../commons/logger.js';
import { randomBits, ONE, ZERO } from '../commons/mathUtils.js';
import { Algorithm } from '../models/Algorithm.js';
import { Homomorphic } from '../models/Homomorphic.js';
import type {
  CiphertextValue,
  Keys,
  RandomKey,
  RequiredKeys,
} from '../models/types.js';
import { sampleSmall } from './Regev.js';

const logger = new Logger('lightphe-ts/cryptosystems/MLKEM.ts');

/** Floats are scaled by powers of 10, and xor of their encodings is meaningless. */
export const MLKEM_FLOAT_NOT_SUPPORTED_MSG =
  'ML-KEM does not support float values or tensors, because it is homomorphic with' +
  ' respect to the exclusive or of 256-bit messages. Use integers instead.';

/** Parameters of FIPS 203: ring `Z_q[x] / (x^N + 1)` with q = 3329 and N = 256. */
export const MLKEM_Q = 3329;
export const MLKEM_N = 256;

/**
 * Parameter sets of FIPS 203: module rank k, and parameters of centered
 * binomial distributions for secret and error vectors (eta1) and errors of
 * encryption (eta2).
 */
export const MLKEM_PARAMETER_SETS: Readonly<
  Record<number, { k: number; eta1: number; eta2: number }>
> = {
  512: { k: 2, eta1: 3, eta2: 2 },
  768: { k: 3, eta1: 2, eta2: 2 },
  1024: { k: 4, eta1: 2, eta2: 2 },
};

/** Bits of a message are encoded as 0 or round(q / 2). */
export const MLKEM_HALF_Q = (MLKEM_Q + 1) / 2;

const Q = MLKEM_Q;
const N = MLKEM_N;

/**
 * ML-KEM is homomorphic with respect to the exclusive or of 256-bit messages,
 * like Goldwasser-Micali, but it is quantum resistant. It uses the parameter
 * sets standardized by NIST in FIPS 203: ML-KEM-512, ML-KEM-768 and
 * ML-KEM-1024. Its security relies on the module learning with errors
 * (Module-LWE) problem.
 *
 * ML-KEM is a key encapsulation mechanism built on a public key encryption
 * scheme K-PKE. This is K-PKE, which works in modules of rank k over the ring
 * `R_q = Z_q[x] / (x^256 + 1)`.
 *   - private key: vector s of k polynomials with small coefficients
 *   - public key: k x k matrix A of polynomials and `t = A s + e`, where e is
 *     small
 *   - encryption of 256 message bits m_i: `u = A^T r + e1`, and
 *     `v = t^T r + e2 + m q / 2` where `m q / 2` is the polynomial whose i-th
 *     coefficient is `m_i * round(q / 2)`
 *   - decryption: `v - s^T u = m q / 2 + noise`, so m_i is 1 if the i-th
 *     coefficient is closer to q / 2 than to 0
 *   - exclusive or: adding ciphertexts adds the bits modulo 2
 * A is expanded from a public seed with SHAKE-128, so the public key is the
 * seed and t.
 *
 * Notice that this is not a FIPS 203 compliant implementation of ML-KEM:
 *   - It is the CPA secure K-PKE, without the Fujisaki-Okamoto transform of
 *     ML-KEM that makes it CCA secure, because a CCA secure scheme cannot be
 *     homomorphic.
 *   - Ciphertexts are not compressed, because compression adds rounding noise
 *     that leaves no room for homomorphic operations. Security of K-PKE does
 *     not depend on compression, which only drops information from
 *     ciphertexts.
 *   - Byte encodings, the sampling of A and the NTT representation are not the
 *     ones in FIPS 203, so its keys and ciphertexts are not interoperable with
 *     other libraries.
 *   - It is not validated by NIST under FIPS 140-3.
 * It uses the standardized parameters q, n, k, eta1 and eta2 only.
 *
 * keySize is the parameter set: 512, 768 or 1024. Default is 768, i.e.
 * ML-KEM-768, which NIST categorizes as at least as hard to break as AES-192.
 *
 * Every ciphertext has noise, and exclusive or adds the noises of
 * ciphertexts. Decryption returns a wrong result without any error when the
 * noise exceeds q / 4. Fresh ciphertexts practically never fail, but q is
 * small, so only a few ciphertexts can be combined. Failure probability of
 * decrypting the exclusive or of c ciphertexts of ML-KEM-768 is about 2^-77
 * for c = 4, 2^-50 for c = 6, and 2^-36 for c = 8. Regenerating a ciphertext
 * counts as combining it with one more ciphertext. Ciphertexts have k + 1
 * polynomials of 256 coefficients of 12 bits, about 1.5 KB for ML-KEM-768.
 * Floats and tensors are not supported.
 *
 * Ref: National Institute of Standards and Technology (2024). Module-Lattice-
 * Based Key-Encapsulation Mechanism Standard. FIPS 203.
 *
 * Ref: Bos, J. et al. (2018). CRYSTALS - Kyber: a CCA-secure
 * module-lattice-based KEM. IEEE EuroS&P 2018.
 */
export class MLKEM extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['parameter_set', 'seed', 't'],
    private_key: ['s'],
  };

  // A expanded from the seed when needed
  private a?: number[][][];

  /** @param options.keySize - parameter set, 512, 768 or 1024. Default is 768. */
  constructor(options?: { keys?: Keys | null; keySize?: number | null }) {
    super();
    this.keys = options?.keys ?? this.generateKeys(options?.keySize ?? 768);
    this.plaintextModulo = ONE << BigInt(N);
    this.ciphertextModulo = BigInt(Q);
  }

  get requiredKeys(): RequiredKeys {
    return MLKEM.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.MLKEM;
  }

  generateKeys(keySize: number): Keys {
    const parameters = MLKEM_PARAMETER_SETS[keySize];
    if (parameters === undefined) {
      throw new Error(
        `Key size ${keySize} must be one of the parameter sets of ML-KEM:` +
          ` [${Object.keys(MLKEM_PARAMETER_SETS).join(', ')}]`
      );
    }
    const { k, eta1 } = parameters;

    const seed = randomBits(256);
    const a = expand(seed, k);
    const s = Array.from({ length: k }, () => sampleSmall(N, eta1));
    const e = Array.from({ length: k }, () => sampleSmall(N, eta1));

    // t = A s + e
    const t: number[][] = [];
    for (let i = 0; i < k; i++) {
      const row = e[i].slice();
      for (let j = 0; j < k; j++) {
        addInto(row, polyMul(a[i][j], s[j]));
      }
      t.push(row.map(reduce));
    }

    return {
      public_key: {
        parameter_set: BigInt(keySize),
        seed,
        t: t.map(toBigInts),
      },
      private_key: { s: s.map(toBigInts) },
    };
  }

  /** ML-KEM draws a one-time small random vector of k polynomials r per encryption. */
  generateRandomKey(): bigint[][] {
    const { k, eta1 } = this.parameters();
    return Array.from({ length: k }, () => toBigInts(sampleSmall(N, eta1)));
  }

  /**
   * Encrypts a plaintext in `[0, 2^256)`.
   *
   * @returns k polynomials of `u = A^T r + e1`, and `v = t^T r + e2 + m q / 2`.
   */
  encrypt(plaintext: bigint, randomKey?: RandomKey): bigint[][] {
    const { k, eta2 } = this.parameters();
    const t = (this.keys.public_key!.t as bigint[][]).map(toNumbers);
    const r = (
      Array.isArray(randomKey) && randomKey.length > 0
        ? (randomKey as readonly (readonly bigint[])[])
        : this.generateRandomKey()
    ).map(toNumbers);

    let m = plaintext;
    if (m >= this.plaintextModulo) {
      m = m % this.plaintextModulo;
      logger.debug(
        `ML-KEM can encrypt messages [0, 2^${N}). ` +
          `Seems plaintext exceeded this limit. New plaintext is ${m}`
      );
    }

    if (this.a === undefined) {
      this.a = expand(this.keys.public_key!.seed as bigint, k);
    }

    // u = A^T r + e1
    const u: number[][] = [];
    for (let i = 0; i < k; i++) {
      const row = sampleSmall(N, eta2);
      for (let j = 0; j < k; j++) {
        addInto(row, polyMul(this.a[j][i], r[j]));
      }
      u.push(row.map(reduce));
    }

    // v = t^T r + e2 + m q / 2
    const v = sampleSmall(N, eta2);
    for (let j = 0; j < k; j++) {
      addInto(v, polyMul(t[j], r[j]));
    }
    for (let x = 0; x < N; x++) {
      if ((m >> BigInt(x)) & ONE) {
        v[x] += MLKEM_HALF_Q;
      }
    }
    return [...u, v.map(reduce)].map(toBigInts);
  }

  /** Decrypts k polynomials of u and v. */
  decrypt(ciphertext: CiphertextValue): bigint {
    const s = (this.keys.private_key!.s as bigint[][]).map(toNumbers);
    const polynomials = (ciphertext as readonly (readonly bigint[])[]).map(
      toNumbers
    );
    const u = polynomials.slice(0, -1);
    const v = polynomials[polynomials.length - 1];

    // v - s^T u = m q / 2 + noise
    const products = new Array<number>(N).fill(0);
    u.forEach((poly, j) => addInto(products, polyMul(poly, s[j])));
    let plaintext = ZERO;
    for (let x = 0; x < N; x++) {
      const w = reduce(v[x] - products[x]);
      // bit is 1 if w is closer to q / 2 than to 0
      if (Math.floor(Q / 4) < w && w < Q - Math.floor(Q / 4)) {
        plaintext |= ONE << BigInt(x);
      }
    }
    return plaintext;
  }

  /**
   * Homomorphic exclusive or: the result decrypts to `m1 ^ m2`. Noise of the
   * result is the sum of noises of the ciphertexts.
   */
  override xor(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): bigint[][] {
    // bits are added modulo 2, as 2 * round(q / 2) = q + 1 is close to 0 modulo q
    const q = BigInt(Q);
    const second = ciphertext2 as readonly (readonly bigint[])[];
    return (ciphertext1 as readonly (readonly bigint[])[]).map((poly, i) =>
      poly.map((x, j) => (x + second[i][j]) % q)
    );
  }

  override reencrypt(ciphertext: CiphertextValue): bigint[][] {
    return this.xor(ciphertext, this.encrypt(ZERO));
  }

  private parameters(): { k: number; eta1: number; eta2: number } {
    return MLKEM_PARAMETER_SETS[
      Number(this.keys.public_key!.parameter_set as bigint)
    ];
  }
}

/** Reduces an integer into `[0, q)`. */
function reduce(x: number): number {
  const r = x % Q;
  return r < 0 ? r + Q : r;
}

/** Adds the coefficients of a polynomial into another one in place. */
function addInto(target: number[], poly: readonly number[]): void {
  for (let i = 0; i < N; i++) {
    target[i] += poly[i];
  }
}

function toBigInts(poly: readonly number[]): bigint[] {
  return poly.map(BigInt);
}

function toNumbers(poly: readonly bigint[]): number[] {
  return poly.map(Number);
}

/**
 * Multiplies two polynomials in `Z_q[x] / (x^256 + 1)`. Small coefficients may
 * be negative, so they are reduced modulo q first. Each coefficient of the
 * product is a sum of 256 products less than q^2, which fits into a double.
 *
 * @returns 256 coefficients in `[0, q)`.
 */
export function polyMul(
  poly1: readonly number[],
  poly2: readonly number[]
): number[] {
  const a = poly1.map(reduce);
  const b = poly2.map(reduce);
  const product = new Array<number>(2 * N).fill(0);
  for (let i = 0; i < N; i++) {
    const ai = a[i];
    if (ai === 0) {
      continue;
    }
    for (let j = 0; j < N; j++) {
      product[i + j] += ai * b[j];
    }
  }
  // x^256 = -1
  const result: number[] = [];
  for (let i = 0; i < N; i++) {
    result.push(reduce((product[i] % Q) - (product[i + N] % Q)));
  }
  return result;
}

/**
 * Expands the public matrix A from its seed with SHAKE-128. Every 3 bytes give
 * two 12-bit values, which are accepted if they are less than q, so
 * coefficients are uniform in `[0, q)`. Each entry of A has its own stream.
 *
 * @returns k x k polynomials.
 */
export function expand(seed: bigint, k: number): number[][][] {
  const seedBytes = toBytesBigEndian(seed, 32);
  const a: number[][][] = [];
  for (let i = 0; i < k; i++) {
    const row: number[][] = [];
    for (let j = 0; j < k; j++) {
      const input = new Uint8Array(34);
      input.set(seedBytes);
      input[32] = j;
      input[33] = i;
      let coefficients: number[] = [];
      let length = 3 * N;
      while (coefficients.length < N) {
        const stream = shake128(input, length);
        coefficients = [];
        for (let x = 0; x < length - 2; x += 3) {
          const d1 = stream[x] | ((stream[x + 1] & 0x0f) << 8);
          const d2 = (stream[x + 1] >> 4) | (stream[x + 2] << 4);
          for (const d of [d1, d2]) {
            if (d < Q && coefficients.length < N) {
              coefficients.push(d);
            }
          }
        }
        length *= 2;
      }
      row.push(coefficients);
    }
    a.push(row);
  }
  return a;
}
