import { shake128, toBytesBigEndian } from '../commons/hashing.js';
import { Logger } from '../commons/logger.js';
import { bitLength, mod, randomBits, ONE } from '../commons/mathUtils.js';
import { Algorithm } from '../models/Algorithm.js';
import { Homomorphic } from '../models/Homomorphic.js';
import type {
  CiphertextValue,
  Keys,
  RandomKey,
  RequiredKeys,
} from '../models/types.js';

const logger = new Logger('lightphe-ts/cryptosystems/Regev.ts');

/**
 * Floats are scaled by powers of 10, which exceeds the small plaintext space of
 * Regev, and multiplies the noise in ciphertexts by the same factor.
 */
export const REGEV_FLOAT_NOT_SUPPORTED_MSG =
  'Regev does not support float values or tensors, because they are scaled by powers' +
  ' of 10, which exceed its small plaintext space and noise budget. Use integers instead.';

/** Ciphertext modulus `q = 2^LOG_Q`. */
export const REGEV_LOG_Q = 50;

/** Default plaintext modulus `t = 2^DEFAULT_LOG_T`. */
const DEFAULT_LOG_T = 24;

/**
 * Secret and errors are sampled from centered binomial distribution with this
 * parameter. Its standard deviation is `sqrt(ETA / 2) = 3.24`, and its values
 * are in `[-ETA, ETA]`.
 */
export const REGEV_ETA = 21;

/** Fresh noise must stay below this many standard deviations for correct decryption. */
const NOISE_TAIL = 12;

// entries of A are split into two 25-bit halves, so that sums of their
// products with small numbers stay exact in doubles
const HALF_BITS = 25;
const HALF = 2 ** HALF_BITS;
const HALF_MASK = HALF - 1;
const Q_NUMBER = 2 ** REGEV_LOG_Q;

/** The public matrix A expanded from its seed, row-major, in 25-bit halves. */
interface ExpandedMatrix {
  lo: Uint32Array;
  hi: Uint32Array;
}

/**
 * Regev is homomorphic with respect to addition, and supports multiplying a
 * ciphertext by a known plain constant. It is the first quantum resistant
 * algorithm in LightPHE. Its security relies on the learning with errors (LWE)
 * problem, which is believed to be hard for quantum computers, unlike factoring
 * and discrete logarithm problems that other algorithms rely on.
 *
 * This is the Lindner-Peikert form of Regev's cryptosystem, which is the one
 * used in practice, e.g. by FrodoKEM. Original form requires a public key
 * matrix with about n log q rows, whereas this needs an n x n matrix A.
 *   - private key: secret vector s with small entries
 *   - public key: A and `b = A s + e mod q`, where e is a small error vector
 *   - encryption: `c1 = A^T r + e1` and `c2 = <b, r> + e2 + m * q / t mod q`
 *   - decryption: `c2 - <c1, s> = m * q / t + noise`, so m is restored by
 *     rounding
 * A is expanded from a public seed with SHAKE-128, so the public key is the
 * seed and b.
 *
 * keySize is the lattice dimension n. Default is 2048. With q = 2^50,
 * dimension 2048 or more gives about 128-bit security against quantum attacks
 * according to the tables of Homomorphic Encryption Standard (log q must be at
 * most 51 for n = 2048). Smaller dimensions are not secure, and are for testing
 * only.
 *
 * Notice that its plaintext space is small, 2^24 by default, and every
 * ciphertext has noise. Noise grows with homomorphic operations: addition adds
 * the noise of ciphertexts, and multiplying with a constant k multiplies the
 * noise by |k|. Decryption returns a wrong result without any error when the
 * noise exceeds q / 2t. Fresh noise is about 2^13 for n = 2048, and the limit is
 * 2^25 by default, so there is room for thousands of additions or
 * multiplication with constants up to a few thousands. A greater plaintext
 * space can be set with plaintextLimit in exchange of a smaller room for noise.
 * Floats and tensors are not supported, as they are scaled by powers of 10.
 * Ciphertexts have n + 1 entries of 50 bits each, about 12.8 KB for n = 2048.
 *
 * Ref: Regev, O. (2005). On Lattices, Learning with Errors, Random Linear
 * Codes, and Cryptography. STOC 2005.
 *
 * Ref: Lindner, R., Peikert, C. (2011). Better Key Sizes (and Attacks) for
 * LWE-Based Encryption. CT-RSA 2011.
 *
 * Ref: Albrecht, M. et al. (2018). Homomorphic Encryption Security Standard.
 * HomomorphicEncryption.org.
 */
export class Regev extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['n', 'q', 't', 'seed', 'b'],
    private_key: ['s'],
  };

  // A expanded from the seed when needed
  private matrix?: ExpandedMatrix;

  /**
   * @param options.keySize - lattice dimension. Default is 2048.
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
    return Regev.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.Regev;
  }

  generateKeys(
    keySize: number,
    options?: { plaintextLimit?: number | bigint | null }
  ): Keys {
    const n = keySize;
    if (n < 8) {
      throw new Error(`Key size ${n} is too small for Regev`);
    }

    const q = ONE << BigInt(REGEV_LOG_Q);
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
    const noiseBound = BigInt(noiseBoundOf(n));
    if (q / t / 2n <= noiseBound) {
      throw new Error(
        `Plaintext limit ${String(plaintextLimit)} is too large for Regev. ` +
          `It must be less than ${q / (2n * noiseBound)} for dimension ${n}.`
      );
    }
    logger.debug(
      `noise of fresh ciphertexts can grow ${(
        Number(q / t / 2n) / Number(noiseBound)
      ).toFixed(0)} times`
    );

    const seed = randomBits(256);
    const s = sampleSmall(n);
    const e = sampleSmall(n);

    // b = A s + e mod q
    const matrix = expand(seed, n);
    const as = multiplyMatrix(matrix, s, n, false);
    const b = as.map((x, i) => BigInt(mod53(x + e[i])));

    return {
      public_key: {
        n: BigInt(n),
        q,
        t,
        seed,
        b,
      },
      private_key: { s: s.map(BigInt) },
    };
  }

  /** Regev draws a one-time small random vector r per encryption. */
  generateRandomKey(): bigint[] {
    return sampleSmall(this.dimension()).map(BigInt);
  }

  /**
   * Encrypts a plaintext in `[0, t)`.
   *
   * @returns n entries of `c1 = A^T r + e1`, and `c2 = <b, r> + e2 + m q / t`.
   */
  encrypt(plaintext: bigint, randomKey?: RandomKey): bigint[] {
    const n = this.dimension();
    const q = this.keys.public_key!.q as bigint;
    const t = this.keys.public_key!.t as bigint;
    const b = this.keys.public_key!.b as readonly bigint[];
    const r =
      Array.isArray(randomKey) && randomKey.length > 0
        ? (randomKey as readonly bigint[]).map(Number)
        : sampleSmall(n);

    let m = plaintext;
    if (m >= t) {
      m = m % t;
      logger.debug(
        `Regev can encrypt messages [0, ${t}). ` +
          `Seems plaintext exceeded this limit. New plaintext is ${m}`
      );
    }

    if (this.matrix === undefined) {
      this.matrix = expand(this.keys.public_key!.seed as bigint, n);
    }

    const e1 = sampleSmall(n);
    const e2 = sampleSmall(1)[0];

    const c1 = multiplyMatrix(this.matrix, r, n, true).map((x, i) =>
      BigInt(mod53(x + e1[i]))
    );
    let inner = BigInt(e2) + m * (q / t);
    for (let i = 0; i < n; i++) {
      inner += b[i] * BigInt(r[i]);
    }
    c1.push(mod(inner, q));
    return c1;
  }

  decrypt(ciphertext: CiphertextValue): bigint {
    const q = this.keys.public_key!.q as bigint;
    const t = this.keys.public_key!.t as bigint;
    const s = this.keys.private_key!.s as readonly bigint[];
    const delta = q / t;

    const values = ciphertext as readonly bigint[];
    const c2 = values[values.length - 1];
    // m * q / t + noise
    let inner = c2;
    for (let i = 0; i < values.length - 1; i++) {
      inner -= values[i] * s[i];
    }
    const noisyMessage = mod(inner, q);
    return ((noisyMessage + delta / 2n) / delta) % t;
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
    const c1 = ciphertext1 as readonly bigint[];
    const c2 = ciphertext2 as readonly bigint[];
    return c1.map((x, i) => (x + c2[i]) % q);
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
    // e.g. t - 1 is multiplied as -1. as t divides q, this does not change the
    // result.
    let k = mod(constant, t);
    if (k > t / 2n) {
      k -= t;
    }

    return (ciphertext as readonly bigint[]).map((x) => mod(x * k, q));
  }

  override reencrypt(ciphertext: CiphertextValue): bigint[] {
    return this.add(ciphertext, this.encrypt(0n));
  }

  private dimension(): number {
    return Number(this.keys.public_key!.n as bigint);
  }
}

/** Reduces an exact integer held in a double modulo `q = 2^50`. */
function mod53(x: number): number {
  const r = x % Q_NUMBER;
  return r < 0 ? r + Q_NUMBER : r;
}

/**
 * Samples from centered binomial distribution with cryptographically secure
 * randomness.
 *
 * @returns integers in `[-ETA, ETA]`.
 */
export function sampleSmall(size: number, eta = REGEV_ETA): number[] {
  const samples: number[] = [];
  const mask = (ONE << BigInt(eta)) - ONE;
  for (let i = 0; i < size; i++) {
    const bits = randomBits(2 * eta);
    samples.push(popCount(bits & mask) - popCount(bits >> BigInt(eta)));
  }
  return samples;
}

function popCount(value: bigint): number {
  let count = 0;
  for (const digit of value.toString(2)) {
    if (digit === '1') {
      count += 1;
    }
  }
  return count;
}

/** Bound of the noise `<e, r> + e2 - <s, e1>` in fresh ciphertexts. */
function noiseBoundOf(n: number): number {
  const variance = REGEV_ETA / 2;
  return Math.ceil(NOISE_TAIL * variance * Math.sqrt(2 * n)) + REGEV_ETA;
}

/**
 * Bytes per entry of A in the SHAKE-128 stream. Python packs entries into
 * slots that must hold a sum of n products of an entry and a small number, and
 * the stream layout follows those slots.
 */
function slotBytes(n: number): number {
  return Math.ceil((REGEV_LOG_Q + bitLength(BigInt(REGEV_ETA * n))) / 8);
}

/**
 * Expands the public matrix A from its seed with SHAKE-128. Entry (i, j) is
 * the low 50 bits of the little-endian slot `i * n + j` of the stream.
 */
function expand(seed: bigint, n: number): ExpandedMatrix {
  const width = slotBytes(n);
  const stream = shake128(toBytesBigEndian(seed, 32), n * n * width);
  const lo = new Uint32Array(n * n);
  const hi = new Uint32Array(n * n);
  for (let index = 0; index < n * n; index++) {
    const at = index * width;
    const low32 =
      (stream[at] |
        (stream[at + 1] << 8) |
        (stream[at + 2] << 16) |
        (stream[at + 3] << 24)) >>>
      0;
    lo[index] = low32 & HALF_MASK;
    hi[index] =
      (low32 >>> HALF_BITS) |
      (stream[at + 4] << 7) |
      (stream[at + 5] << 15) |
      ((stream[at + 6] & 0x03) << 23);
  }
  return { lo, hi };
}

/**
 * Multiplies A (or A^T) with a vector of small integers. Results are exact
 * integers reduced modulo q.
 */
function multiplyMatrix(
  matrix: ExpandedMatrix,
  weights: readonly number[],
  n: number,
  transposed: boolean
): number[] {
  const loSums = new Float64Array(n);
  const hiSums = new Float64Array(n);
  if (transposed) {
    // (A^T r)_j = sum_i A[i][j] r_i
    for (let i = 0; i < n; i++) {
      const weight = weights[i];
      if (weight === 0) {
        continue;
      }
      const row = i * n;
      for (let j = 0; j < n; j++) {
        loSums[j] += matrix.lo[row + j] * weight;
        hiSums[j] += matrix.hi[row + j] * weight;
      }
    }
  } else {
    // (A s)_i = sum_j A[i][j] s_j
    for (let i = 0; i < n; i++) {
      const row = i * n;
      let loSum = 0;
      let hiSum = 0;
      for (let j = 0; j < n; j++) {
        loSum += matrix.lo[row + j] * weights[j];
        hiSum += matrix.hi[row + j] * weights[j];
      }
      loSums[i] = loSum;
      hiSums[i] = hiSum;
    }
  }

  // hi * 2^25 + lo mod 2^50, keeping intermediate values below 2^53
  const result: number[] = [];
  for (let i = 0; i < n; i++) {
    let h = hiSums[i] % HALF;
    if (h < 0) {
      h += HALF;
    }
    result.push(mod53(h * HALF + loSums[i]));
  }
  return result;
}
