import {
  fromBytesLittleEndian,
  shake128,
  toBytesBigEndian,
} from '../commons/hashing.js';
import { Logger } from '../commons/logger.js';
import { bitLength, mod, randomBits, ONE, ZERO } from '../commons/mathUtils.js';
import { Algorithm } from '../models/Algorithm.js';
import { Homomorphic } from '../models/Homomorphic.js';
import type {
  CiphertextValue,
  Keys,
  RandomKey,
  RequiredKeys,
} from '../models/types.js';
import { sampleSmall } from './Regev.js';

const logger = new Logger(
  'lightphe-ts/cryptosystems/LyubashevskyPeikertRegev.ts'
);

/**
 * Floats are scaled by powers of 10, which exceeds the small plaintext space,
 * and multiplies the noise in ciphertexts by the same factor.
 */
export const LPR_FLOAT_NOT_SUPPORTED_MSG =
  'Lyubashevsky-Peikert-Regev does not support float values or tensors, because they are' +
  ' scaled by powers of 10, which exceed its small plaintext space and noise budget.' +
  ' Use integers instead.';

/** Ciphertext modulus `q = 2^LOG_Q`. */
export const LPR_LOG_Q = 50;
const Q = ONE << BigInt(LPR_LOG_Q);

/** Default plaintext modulus `t = 2^DEFAULT_LOG_T`. */
const DEFAULT_LOG_T = 24;

/**
 * Secret and errors are sampled from centered binomial distribution with this
 * parameter. Its standard deviation is `sqrt(ETA / 2) = 3.24`, and its values
 * are in `[-ETA, ETA]`.
 */
export const LPR_ETA = 21;

/** Fresh noise must stay below this many standard deviations for correct decryption. */
const NOISE_TAIL = 12;

/**
 * Lyubashevsky-Peikert-Regev is homomorphic with respect to the addition.
 * Also, it supports multiplying a ciphertext with a plain constant. It is
 * Regev's cryptosystem over a polynomial ring, and it is quantum resistant.
 * Its security relies on the ring learning with errors (Ring-LWE) problem like
 * Brakerski-Vaikuntanathan.
 *
 * It works in the polynomial ring `R_q = Z_q[x] / (x^d + 1)`.
 *   - private key: polynomial s with small coefficients
 *   - public key: a and `b = a s + e`, where e is a small error polynomial
 *   - encryption: `c1 = a u + e1`, and
 *     `c2 = constant term of (b u) + e2 + m * q / t`
 *   - decryption: `c2 - constant term of (c1 s) = m * q / t + noise`, so m is
 *     restored by rounding
 * a is expanded from a public seed with SHAKE-128, so the public key is the
 * seed and b.
 *
 * Regev uses a random n x n matrix A, whereas this uses the negacyclic matrix
 * of a single polynomial a, so the public structure is n times smaller, and
 * `c1 = a u` is a single polynomial multiplication instead of a matrix-vector
 * product. Message is encoded into the constant term only, which is the only
 * coefficient decryption reads, so other coefficients of c2 are dropped. Thus,
 * a ciphertext has d + 1 coefficients like Regev, instead of 2d of the
 * original scheme. Dropping parts of a ciphertext does not help an attacker,
 * so the security is the same.
 *
 * keySize is the ring degree d, a power of 2. Default is 2048. With q = 2^50,
 * degree 2048 gives about 128-bit security against quantum attacks according
 * to the tables of Homomorphic Encryption Standard (log q must be at most 51
 * for d = 2048). Smaller degrees are not secure, and are for testing only.
 *
 * Notice that its plaintext space is small, 2^24 by default, and every
 * ciphertext has noise. Noise grows with homomorphic operations: addition adds
 * the noise of ciphertexts, and multiplying with a constant k multiplies the
 * noise by |k|. Decryption returns a wrong result without any error when the
 * noise exceeds q / 2t. Fresh noise is about 2^13 for d = 2048, and the limit
 * is 2^25 by default, so there is room for thousands of additions or
 * multiplication with constants up to a few thousands. A greater plaintext
 * space can be set with plaintextLimit in exchange of a smaller room for
 * noise. Floats and tensors are not supported, as they are scaled by powers of
 * 10. Ciphertexts have d + 1 entries of 50 bits each, about 12.8 KB for
 * d = 2048.
 *
 * Ref: Lyubashevsky, V., Peikert, C., Regev, O. (2010). On Ideal Lattices and
 * Learning with Errors over Rings. EUROCRYPT 2010.
 *
 * Ref: Albrecht, M. et al. (2018). Homomorphic Encryption Security Standard.
 * HomomorphicEncryption.org.
 */
export class LyubashevskyPeikertRegev extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['d', 'q', 't', 'seed', 'b'],
    private_key: ['s'],
  };

  // a expanded from the seed when needed
  private a?: bigint[];

  /**
   * @param options.keySize - ring degree, a power of 2. Default is 2048.
   * @param options.plaintextLimit - upper bound for plaintext values. It is
   *   rounded up to a power of 2. Default is 2^24. Greater values leave less
   *   room for noise.
   */
  constructor(options?: {
    keys?: Keys | null;
    keySize?: number | null;
    plaintextLimit?: number | bigint | null;
  }) {
    super();
    this.keys =
      options?.keys ??
      this.generateKeys(options?.keySize ?? 2048, {
        plaintextLimit: options?.plaintextLimit,
      });
    this.plaintextModulo = this.keys.public_key!.t as bigint;
    this.ciphertextModulo = this.keys.public_key!.q as bigint;
  }

  get requiredKeys(): RequiredKeys {
    return LyubashevskyPeikertRegev.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.LyubashevskyPeikertRegev;
  }

  generateKeys(
    keySize: number,
    options?: { plaintextLimit?: number | bigint | null }
  ): Keys {
    const d = keySize;
    if (!Number.isInteger(d) || d < 8 || (d & (d - 1)) !== 0) {
      throw new Error(
        `Key size ${d} must be a power of 2 and at least 8 for` +
          ' Lyubashevsky-Peikert-Regev'
      );
    }

    const q = Q;
    let t = ONE << BigInt(DEFAULT_LOG_T);
    const plaintextLimit = options?.plaintextLimit;
    if (plaintextLimit != null) {
      const limit = BigInt(plaintextLimit);
      if (limit < 2n) {
        throw new Error('Plaintext limit must be at least 2');
      }
      t = ONE << BigInt(bitLength(limit - ONE));
    }

    // fresh ciphertexts must be decrypted correctly
    const noiseBound = noiseBoundOf(d);
    if (q / t / 2n <= noiseBound) {
      throw new Error(
        `Plaintext limit ${String(plaintextLimit)} is too large for Lyubashevsky-Peikert-Regev.` +
          ` It must be less than ${q / (2n * noiseBound)} for degree ${d}.`
      );
    }
    logger.debug(
      `noise of fresh ciphertexts can grow ${(
        Number(q / t / 2n) / Number(noiseBound)
      ).toFixed(0)} times`
    );

    const seed = randomBits(256);
    const a = expand(seed, d);
    const s = sampleSmall(d, LPR_ETA).map(BigInt);
    const e = sampleSmall(d, LPR_ETA).map(BigInt);

    // b = a s + e
    const aS = polyMul(
      a,
      s.map((x) => mod(x, q)),
      d
    );
    const b = aS.map((x, i) => mod(x + e[i], q));

    return {
      public_key: { d: BigInt(d), q, t, seed, b },
      private_key: { s },
    };
  }

  /**
   * Lyubashevsky-Peikert-Regev draws a one-time small random polynomial u per
   * encryption.
   */
  generateRandomKey(): bigint[] {
    return sampleSmall(this.degree(), LPR_ETA).map(BigInt);
  }

  /**
   * Encrypts a plaintext in `[0, t)`.
   *
   * @returns d coefficients of `c1 = a u + e1`, and
   *   `c2 = constant term of (b u) + e2 + m q / t`.
   */
  encrypt(plaintext: bigint, randomKey?: RandomKey): bigint[] {
    const d = this.degree();
    const q = this.keys.public_key!.q as bigint;
    const t = this.keys.public_key!.t as bigint;
    const b = this.keys.public_key!.b as bigint[];
    const u =
      Array.isArray(randomKey) && randomKey.length > 0
        ? (randomKey as readonly bigint[])
        : this.generateRandomKey();

    let m = plaintext;
    if (m >= t) {
      m = m % t;
      logger.debug(
        `Lyubashevsky-Peikert-Regev can encrypt messages [0, ${t}). ` +
          `Seems plaintext exceeded this limit. New plaintext is ${m}`
      );
    }

    if (this.a === undefined) {
      this.a = expand(this.keys.public_key!.seed as bigint, d);
    }

    const e1 = sampleSmall(d, LPR_ETA);
    const e2 = sampleSmall(1, LPR_ETA)[0];

    const c1 = polyMul(
      this.a,
      u.map((x) => mod(x, q)),
      d
    ).map((x, i) => mod(x + BigInt(e1[i]), q));
    const c2 = mod(constantTerm(b, u) + BigInt(e2) + m * (q / t), q);
    return [...c1, c2];
  }

  /** Decrypts a ciphertext of d + 1 coefficients. */
  decrypt(ciphertext: CiphertextValue): bigint {
    const q = this.keys.public_key!.q as bigint;
    const t = this.keys.public_key!.t as bigint;
    const s = this.keys.private_key!.s as bigint[];
    const delta = q / t;

    const coefficients = ciphertext as readonly bigint[];
    const c1 = coefficients.slice(0, -1);
    const c2 = coefficients[coefficients.length - 1];
    // m * q / t + noise
    const noisyMessage = mod(c2 - constantTerm(c1, s), q);
    return mod((noisyMessage + delta / 2n) / delta, t);
  }

  /**
   * Homomorphic addition: the result decrypts to `m1 + m2`. Noise of the
   * result is the sum of noises of the ciphertexts.
   */
  override add(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): bigint[] {
    const q = this.keys.public_key!.q as bigint;
    const second = ciphertext2 as readonly bigint[];
    return (ciphertext1 as readonly bigint[]).map(
      (x, i) => (x + second[i]) % q
    );
  }

  /**
   * Multiplies a ciphertext by a known plain constant. Noise of the result is
   * the noise of the ciphertext times |constant|.
   */
  override multiplyByConstant(
    ciphertext: CiphertextValue,
    constant: bigint
  ): bigint[] {
    const q = this.keys.public_key!.q as bigint;
    const t = this.keys.public_key!.t as bigint;

    // centered representative keeps the noise small for negative constants,
    // e.g. t - 1 is multiplied as -1. as t divides q, this does not change the result.
    let k = mod(constant, t);
    if (k > t / 2n) {
      k -= t;
    }

    return (ciphertext as readonly bigint[]).map((x) => mod(x * k, q));
  }

  override reencrypt(ciphertext: CiphertextValue): bigint[] {
    return this.add(ciphertext, this.encrypt(ZERO));
  }

  private degree(): number {
    return Number(this.keys.public_key!.d as bigint);
  }
}

/** Packs non-negative coefficients into a big integer of `width` bytes each, lowest first. */
export function pack(poly: readonly bigint[], width: number): bigint {
  const digits = 2 * width;
  const parts: string[] = [];
  for (let i = poly.length - 1; i >= 0; i--) {
    parts.push(poly[i].toString(16).padStart(digits, '0'));
  }
  return BigInt(`0x${parts.join('')}`);
}

/**
 * Unpacks the product of two packed polynomials, and reduces it modulo
 * `x^d + 1`. Coefficients are not reduced modulo q.
 */
export function unpack(packed: bigint, d: number, width: number): bigint[] {
  const digits = 2 * width;
  const product = packed.toString(16).padStart(2 * d * digits, '0');

  // coefficient i is at digits [(2d - 1 - i) * digits, (2d - i) * digits)
  const coefficient = (i: number): bigint => {
    const end = product.length - i * digits;
    return BigInt(`0x${product.slice(end - digits, end)}`);
  };

  // x^d = -1
  const result: bigint[] = [];
  for (let i = 0; i < d; i++) {
    result.push(coefficient(i) - coefficient(i + d));
  }
  return result;
}

/**
 * Multiplies two polynomials in `Z_q[x] / (x^d + 1)` for `q = 2^50` with
 * Kronecker substitution. Coefficients are packed into big integers, so that a
 * single big integer multiplication computes all coefficients of the product.
 *
 * @param poly1 - d coefficients in `[0, q)`.
 * @param poly2 - d coefficients in `[0, q)`.
 * @returns d coefficients in `[0, q)`.
 */
export function polyMul(
  poly1: readonly bigint[],
  poly2: readonly bigint[],
  d: number
): bigint[] {
  // each coefficient of the product is a sum of d products less than q^2
  const width = Math.ceil((2 * LPR_LOG_Q + bitLength(BigInt(d))) / 8);
  return unpack(pack(poly1, width) * pack(poly2, width), d, width).map((x) =>
    mod(x, Q)
  );
}

/**
 * Constant term of the product of two polynomials in `Z[x] / (x^d + 1)`, i.e.
 * `p1_0 p2_0 - sum of p1_i p2_(d-i) for i in [1, d)`.
 */
export function constantTerm(
  poly1: readonly bigint[],
  poly2: readonly bigint[]
): bigint {
  const d = poly1.length;
  let result = poly1[0] * poly2[0];
  for (let i = 1; i < d; i++) {
    result -= poly1[i] * poly2[d - i];
  }
  return result;
}

/**
 * Expands the public polynomial a from its seed with SHAKE-128. q is a power
 * of 2, so each coefficient is uniform in `[0, q)` when its bits are masked.
 */
export function expand(seed: bigint, d: number): bigint[] {
  const width = Math.ceil(LPR_LOG_Q / 8);
  const mask = Q - ONE;
  const stream = shake128(toBytesBigEndian(seed, 32), d * width);
  const result: bigint[] = [];
  for (let i = 0; i < d; i++) {
    result.push(
      fromBytesLittleEndian(stream.subarray(i * width, (i + 1) * width)) & mask
    );
  }
  return result;
}

/**
 * Bound of the noise `constant term of (e u) + e2 - constant term of (e1 s)`
 * in fresh ciphertexts. It sums 2d products of small coefficients like Regev.
 */
function noiseBoundOf(d: number): bigint {
  const variance = LPR_ETA / 2;
  return BigInt(Math.ceil(NOISE_TAIL * variance * Math.sqrt(2 * d)) + LPR_ETA);
}
