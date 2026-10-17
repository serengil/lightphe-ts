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
  'lightphe-ts/cryptosystems/BrakerskiVaikuntanathan.ts'
);

/**
 * Floats are scaled by powers of 10, which exceeds the small plaintext space,
 * and multiplies the noise in ciphertexts by the same factor.
 */
export const BV_FLOAT_NOT_SUPPORTED_MSG =
  'Brakerski-Vaikuntanathan does not support float values or tensors, because they are' +
  ' scaled by powers of 10, which exceed its small plaintext space and noise budget.' +
  ' Use integers instead.';

/**
 * Ciphertext modulus q is the greatest prime less than `2^LOG_Q`. It must be
 * co-prime to t, otherwise public key reveals the secret modulo t.
 */
export const BV_LOG_Q = 100;
const Q = 1267650600228229401496703205361n;

/** Default plaintext modulus `t = 2^DEFAULT_LOG_T`. */
const DEFAULT_LOG_T = 24;

/**
 * Secret and errors are sampled from centered binomial distribution with this
 * parameter. Its standard deviation is `sqrt(ETA / 2) = 3.24`, and its values
 * are in `[-ETA, ETA]`.
 */
export const BV_ETA = 21;

/** Noise must stay below this many standard deviations for correct decryption. */
const NOISE_TAIL = 12;

/** A ciphertext is a pair of polynomials, and a multiplied ciphertext is a triple. */
const FRESH_SIZE = 2;
const MULTIPLIED_SIZE = 3;

/**
 * Brakerski-Vaikuntanathan is homomorphic with respect to addition, and
 * supports one multiplication of ciphertexts like Boneh-Goh-Nissim. Unlike
 * Boneh-Goh-Nissim, it does not need pairings, and it is quantum resistant.
 * Its security relies on the ring learning with errors (Ring-LWE) problem,
 * which is believed to be hard for quantum computers.
 *
 * It works in the polynomial ring `R_q = Z_q[x] / (x^d + 1)`.
 *   - private key: polynomial s with small coefficients
 *   - public key: a and `b = -(a s + t e)`, where e is a small error polynomial
 *   - encryption: `c0 = b u + t g + m`, `c1 = a u + t f` where u, f, g are
 *     small
 *   - decryption: `c0 + c1 s = m + t (g + f s - e u) mod q`, so m is its
 *     constant term mod t
 *   - multiplication: `(c0, c1) x (c0', c1') = (c0 c0', c0 c1' + c1 c0', c1 c1')`,
 *     which is decrypted with `(1, s, s^2)` as
 *     `(c0 + c1 s)(c0' + c1' s) = m m' + t (...)`
 * Multiplied ciphertexts are triples of polynomials. They can be added with
 * each other and with fresh ciphertexts, and multiplied with constants, but
 * cannot be multiplied with ciphertexts again. a is expanded from a public seed
 * with SHAKE-128.
 *
 * keySize is the ring degree d, a power of 2. Default is 4096. With q around
 * 2^100, degree 4096 gives about 128-bit security against quantum attacks
 * according to the tables of Homomorphic Encryption Standard (log q must be at
 * most 101 for d = 4096). Smaller degrees are not secure, and are for testing
 * only.
 *
 * Notice that its plaintext space is small, 2^24 by default, and every
 * ciphertext has noise growing with homomorphic operations: addition adds the
 * noises, multiplying with a constant k multiplies the noise by |k|, and
 * multiplication of ciphertexts multiplies their noises. Decryption returns a
 * wrong result without any error when the noise exceeds q / 2. With default
 * settings, a multiplied ciphertext still has room for millions of times more
 * noise, i.e. for many additions and multiplications with constants. A greater
 * plaintext space can be set with plaintextLimit in exchange of a smaller room.
 * Floats and tensors are not supported, as they are scaled by powers of 10.
 * Ciphertexts have 2 polynomials of d coefficients of 100 bits, about 100 KB
 * for d = 4096.
 *
 * Ref: Brakerski, Z., Vaikuntanathan, V. (2011). Fully Homomorphic Encryption
 * from Ring-LWE and Security for Key Dependent Messages. CRYPTO 2011.
 *
 * Ref: Albrecht, M. et al. (2018). Homomorphic Encryption Security Standard.
 * HomomorphicEncryption.org.
 */
export class BrakerskiVaikuntanathan extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['d', 'q', 't', 'seed', 'b'],
    private_key: ['s'],
  };

  // a expanded from the seed, and s^2 for decryption of multiplied ciphertexts
  private a?: bigint[];
  private sSquare?: bigint[];

  /**
   * @param options.keySize - ring degree, a power of 2. Default is 4096.
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
      this.generateKeys(options?.keySize ?? 4096, {
        plaintextLimit: options?.plaintextLimit,
      });
    this.plaintextModulo = this.keys.public_key!.t as bigint;
    this.ciphertextModulo = this.keys.public_key!.q as bigint;
  }

  get requiredKeys(): RequiredKeys {
    return BrakerskiVaikuntanathan.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.BrakerskiVaikuntanathan;
  }

  generateKeys(
    keySize: number,
    options?: { plaintextLimit?: number | bigint | null }
  ): Keys {
    const d = keySize;
    if (!Number.isInteger(d) || d < 8 || (d & (d - 1)) !== 0) {
      throw new Error(
        `Key size ${d} must be a power of 2 and at least 8 for Brakerski-Vaikuntanathan`
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

    // product of two fresh ciphertexts must be decrypted correctly
    const multipliedNoise = multipliedNoiseBound(d, t);
    if (multipliedNoise >= q / 2n) {
      throw new Error(
        `Plaintext limit ${String(plaintextLimit)} is too large for Brakerski-Vaikuntanathan,` +
          ' because product of two ciphertexts cannot be decrypted correctly.'
      );
    }
    logger.debug(
      `noise of multiplied ciphertexts can grow ${(
        Number(q / 2n) / Number(multipliedNoise)
      ).toFixed(0)} times`
    );

    const seed = randomBits(256);
    const a = expand(seed, d);
    const s = sampleSmall(d, BV_ETA).map(BigInt);
    const e = sampleSmall(d, BV_ETA).map(BigInt);

    // b = -(a s + t e)
    const aS = polyMul(
      a,
      s.map((x) => mod(x, q)),
      d
    );
    const b = aS.map((x, i) => mod(-(x + t * e[i]), q));

    return {
      public_key: { d: BigInt(d), q, t, seed, b },
      private_key: { s },
    };
  }

  /**
   * Brakerski-Vaikuntanathan draws a one-time small random polynomial u per
   * encryption.
   */
  generateRandomKey(): bigint[] {
    return sampleSmall(this.degree(), BV_ETA).map(BigInt);
  }

  /**
   * Encrypts a plaintext in `[0, t)`.
   *
   * @returns pair of polynomials `c0 = b u + t g + m` and `c1 = a u + t f`.
   */
  encrypt(plaintext: bigint, randomKey?: RandomKey): bigint[][] {
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
        `Brakerski-Vaikuntanathan can encrypt messages [0, ${t}). ` +
          `Seems plaintext exceeded this limit. New plaintext is ${m}`
      );
    }

    if (this.a === undefined) {
      this.a = expand(this.keys.public_key!.seed as bigint, d);
    }

    const uModQ = u.map((x) => mod(x, q));
    const f = sampleSmall(d, BV_ETA);
    const g = sampleSmall(d, BV_ETA);

    const c0 = polyMul(b, uModQ, d).map((x, i) => mod(x + t * BigInt(g[i]), q));
    c0[0] = (c0[0] + m) % q;
    const c1 = polyMul(this.a, uModQ, d).map((x, i) =>
      mod(x + t * BigInt(f[i]), q)
    );
    return [c0, c1];
  }

  /** Decrypts a pair or triple of polynomials. */
  decrypt(ciphertext: CiphertextValue): bigint {
    const q = this.keys.public_key!.q as bigint;
    const t = this.keys.public_key!.t as bigint;
    const s = this.keys.private_key!.s as bigint[];

    const polynomials = ciphertext as readonly (readonly bigint[])[];
    if (
      polynomials.length !== FRESH_SIZE &&
      polynomials.length !== MULTIPLIED_SIZE
    ) {
      throw new Error('Ciphertext must be a pair or triple of polynomials');
    }

    // only the constant term carries the message: c0 + c1 s (+ c2 s^2)
    let result = polynomials[0][0] + constantTerm(polynomials[1], s);
    if (polynomials.length === MULTIPLIED_SIZE) {
      if (this.sSquare === undefined) {
        const sModQ = s.map((x) => mod(x, q));
        this.sSquare = polyMul(sModQ, sModQ, this.degree());
      }
      result += constantTerm(polynomials[2], this.sSquare);
    }

    // centered representative is m + t * noise
    result = mod(result, q);
    if (result > q / 2n) {
      result -= q;
    }
    return mod(result, t);
  }

  /**
   * Homomorphic addition: the result decrypts to `m1 + m2`. Fresh and
   * multiplied ciphertexts can be added.
   */
  override add(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): bigint[][] {
    const q = this.keys.public_key!.q as bigint;
    const first = ciphertext1 as readonly (readonly bigint[])[];
    const second = ciphertext2 as readonly (readonly bigint[])[];
    const size = Math.max(first.length, second.length);
    const result: bigint[][] = [];
    for (let i = 0; i < size; i++) {
      const poly1 = first[i];
      const poly2 = second[i];
      if (poly1 === undefined) {
        result.push([...poly2]);
      } else if (poly2 === undefined) {
        result.push([...poly1]);
      } else {
        result.push(poly1.map((x, j) => (x + poly2[j]) % q));
      }
    }
    return result;
  }

  /**
   * Homomorphic multiplication: the result decrypts to `m1 * m2`. Only fresh
   * ciphertexts (or sums of them) can be multiplied.
   *
   * @returns triple of polynomials.
   */
  override multiply(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): bigint[][] {
    const first = ciphertext1 as readonly (readonly bigint[])[];
    const second = ciphertext2 as readonly (readonly bigint[])[];
    if (first.length !== FRESH_SIZE || second.length !== FRESH_SIZE) {
      throw new Error(
        'Brakerski-Vaikuntanathan supports only one multiplication. ' +
          'Multiplied ciphertexts cannot be multiplied with ciphertexts again.'
      );
    }
    const q = this.keys.public_key!.q as bigint;
    const d = this.degree();
    const [c0, c1] = first;
    const [c0Prime, c1Prime] = second;

    // Karatsuba: c0 c1' + c1 c0' = (c0 + c1)(c0' + c1') - c0 c0' - c1 c1'
    const low = polyMul(c0, c0Prime, d);
    const high = polyMul(c1, c1Prime, d);
    const cross = polyMul(
      c0.map((x, i) => (x + c1[i]) % q),
      c0Prime.map((x, i) => (x + c1Prime[i]) % q),
      d
    );
    const middle = cross.map((x, i) => mod(x - low[i] - high[i], q));
    return [low, middle, high];
  }

  /**
   * Multiplies a ciphertext by a known plain constant. Noise of the result is
   * the noise of the ciphertext times |constant|.
   */
  override multiplyByConstant(
    ciphertext: CiphertextValue,
    constant: bigint
  ): bigint[][] {
    const q = this.keys.public_key!.q as bigint;
    const t = this.keys.public_key!.t as bigint;

    // centered representative keeps the noise small for negative constants.
    // it is congruent to the constant mod t, so the result does not change.
    let k = mod(constant, t);
    if (k > t / 2n) {
      k -= t;
    }

    return (ciphertext as readonly (readonly bigint[])[]).map((poly) =>
      poly.map((x) => mod(x * k, q))
    );
  }

  override reencrypt(ciphertext: CiphertextValue): bigint[][] {
    return this.add(ciphertext, this.encrypt(ZERO));
  }

  private degree(): number {
    return Number(this.keys.public_key!.d as bigint);
  }
}

/**
 * Multiplies two polynomials in `Z_q[x] / (x^d + 1)` with Kronecker
 * substitution. Coefficients are packed into big integers, so that a single
 * big integer multiplication computes all coefficients of the product.
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
  const width = Math.ceil((2 * BV_LOG_Q + bitLength(BigInt(d))) / 8);
  const digits = 2 * width;
  const product = (pack(poly1, digits) * pack(poly2, digits))
    .toString(16)
    .padStart(2 * d * digits, '0');

  // coefficient i is at digits [(2d - 1 - i) * digits, (2d - i) * digits)
  const coefficient = (i: number): bigint => {
    const end = product.length - i * digits;
    return BigInt(`0x${product.slice(end - digits, end)}`);
  };

  // x^d = -1
  const result: bigint[] = [];
  for (let i = 0; i < d; i++) {
    result.push(mod(coefficient(i) - coefficient(i + d), Q));
  }
  return result;
}

/** Packs coefficients into a big integer, lowest coefficient in lowest digits. */
function pack(poly: readonly bigint[], digits: number): bigint {
  const parts: string[] = [];
  for (let i = poly.length - 1; i >= 0; i--) {
    parts.push(poly[i].toString(16).padStart(digits, '0'));
  }
  return BigInt(`0x${parts.join('')}`);
}

/**
 * Constant term of the product of two polynomials in `Z[x] / (x^d + 1)`, i.e.
 * `p1_0 p2_0 - sum of p1_i p2_(d-i) for i in [1, d)`.
 */
function constantTerm(
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
 * Expands the public polynomial a from its seed with SHAKE-128. Each
 * coefficient is reduced from 64 more bits than q, so it is statistically
 * uniform in `[0, q)`.
 */
export function expand(seed: bigint, d: number): bigint[] {
  const width = Math.ceil((BV_LOG_Q + 64) / 8);
  const stream = shake128(toBytesBigEndian(seed, 32), d * width);
  const result: bigint[] = [];
  for (let i = 0; i < d; i++) {
    result.push(
      fromBytesLittleEndian(stream.subarray(i * width, (i + 1) * width)) % Q
    );
  }
  return result;
}

/**
 * Bound of the noise in the product of two fresh ciphertexts. A fresh
 * ciphertext decrypts to `m + t v` where `v = g + f s - e u`, whose
 * coefficients have standard deviation about `sigma^2 sqrt(2d)`. The product
 * multiplies two such polynomials, whose constant term sums d products of
 * coefficients.
 */
function multipliedNoiseBound(d: number, t: bigint): bigint {
  const variance = BV_ETA / 2;
  const freshDeviation = Number(t) * (variance * Math.sqrt(2 * d) + 1);
  const bound = Math.ceil(NOISE_TAIL * Math.sqrt(d) * freshDeviation ** 2);
  return BigInt(bound);
}
