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
import {
  constantTerm,
  expand,
  pack,
  polyMul,
  unpack,
} from './LyubashevskyPeikertRegev.js';
import { sampleSmall } from './Regev.js';

const logger = new Logger('lightphe-ts/cryptosystems/GentrySahaiWaters.ts');

/** Floats, tensors and integers other than bits cannot be encrypted. */
export const GSW_FLOAT_NOT_SUPPORTED_MSG =
  'Gentry-Sahai-Waters encrypts bits, i.e. 0 or 1, and it does not support float values,' +
  ' tensors or other integers. Encrypt integers bit by bit instead.';

/** Ciphertext modulus `q = 2^LOG_Q`. */
export const GSW_LOG_Q = 50;

/**
 * Gadget decomposition in base `B = 2^LOG_B` with ELL digits. Gadget is
 * approximate: its entries are `2^OFFSET, 2^OFFSET * B, ...,
 * 2^OFFSET * B^(ELL - 1) = q / 2`, so the lowest OFFSET bits are dropped by
 * rounding, and decryption reads the parity of the message.
 */
export const GSW_LOG_B = 10;
export const GSW_ELL = 5;
export const GSW_OFFSET = GSW_LOG_Q - 1 - GSW_LOG_B * (GSW_ELL - 1);

/**
 * Secret and errors are sampled from centered binomial distribution with this
 * parameter. Its standard deviation is `sqrt(ETA / 2) = 3.24`, and its values
 * are in `[-ETA, ETA]`.
 */
export const GSW_ETA = 21;

const ELL = GSW_ELL;
const LOG_B = GSW_LOG_B;
const OFFSET = GSW_OFFSET;

/** A ciphertext is `2 * ELL` rows of polynomial pairs. */
type GSWCiphertext = bigint[][][];

/**
 * Gentry-Sahai-Waters encrypts bits, and it is homomorphic with respect to
 * both the exclusive or and the and. Unlike Boneh-Goh-Nissim or
 * Brakerski-Vaikuntanathan, it supports more than one multiplication, so
 * boolean circuits of a small depth can be evaluated on encrypted bits. It is
 * quantum resistant, and its security relies on the ring learning with errors
 * (Ring-LWE) problem.
 *
 * This is the ring variant of GSW. It works in the polynomial ring
 * `R_q = Z_q[x] / (x^d + 1)`.
 *   - private key: polynomial s with small coefficients
 *   - public key: a and `b = -(a s) + e`, where e is a small error polynomial
 *   - an encryption of zero is `(b u + e1, a u + e2)`, whose phase
 *     `c0 + c1 s` is small
 *   - encryption of a bit m: `2 * ELL` encryptions of zero Z, and
 *     `C = Z + m G`, where G is the gadget matrix having powers of B in its
 *     first and second columns
 *   - decryption: phase of the last row is `m q / 2 + noise`, so m is restored
 *     by rounding
 *   - and: `C1 x G^-1(C2)` where `G^-1` decomposes entries of C2 into small
 *     digits, so the noise of C2 is multiplied by small digits only
 *   - exclusive or: `C1 + C2` encrypts `m1 + m2`, whose parity is restored by
 *     decryption
 * a is expanded from a public seed with SHAKE-128, so the public key is the
 * seed and b.
 *
 * keySize is the ring degree d, a power of 2. Default is 2048. With q = 2^50,
 * degree 2048 gives about 128-bit security against quantum attacks according
 * to the tables of Homomorphic Encryption Standard (log q must be at most 51
 * for d = 2048). Smaller degrees are not secure, and are for testing only.
 *
 * Every ciphertext has noise. Exclusive or adds the noises of ciphertexts, so
 * it is almost free. Noise of `C1 & C2` is the noise of C2 times small digits
 * plus the noise of C1, so it depends on the order of operands:
 *   - chains: `acc = acc & c` where c is a fresh ciphertext adds a fixed noise
 *     of about 2^17 each time, so long chains of ands, e.g. carries of a
 *     ripple carry adder, work.
 *   - products of products: noise is multiplied by about 2^15 in each level,
 *     so circuits of multiplicative depth 2 work, e.g. `(a & b) & (c & d)`,
 *     but depth 3 does not. Decryption returns a wrong result without any
 *     error when the noise exceeds q / 4 = 2^48. Fresh noise is about 2^10.
 * Ciphertexts have `2 * ELL x 2` polynomials of d coefficients of 50 bits,
 * about 256 KB for d = 2048. Floats, tensors and integers other than bits are
 * not supported.
 *
 * Ref: Gentry, C., Sahai, A., Waters, B. (2013). Homomorphic Encryption from
 * Learning with Errors: Conceptually-Simpler, Asymptotically-Faster,
 * Attribute-Based. CRYPTO 2013.
 *
 * Ref: Ducas, L., Micciancio, D. (2015). FHEW: Bootstrapping Homomorphic
 * Encryption in less than a second. EUROCRYPT 2015.
 *
 * Ref: Albrecht, M. et al. (2018). Homomorphic Encryption Security Standard.
 * HomomorphicEncryption.org.
 */
export class GentrySahaiWaters extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['d', 'q', 'seed', 'b'],
    private_key: ['s'],
  };

  // a expanded from the seed when needed
  private a?: bigint[];

  /** @param options.keySize - ring degree, a power of 2. Default is 2048. */
  constructor(options?: { keys?: Keys | null; keySize?: number | null }) {
    super();
    this.keys = options?.keys ?? this.generateKeys(options?.keySize ?? 2048);
    this.plaintextModulo = 2n;
    this.ciphertextModulo = this.keys.public_key!.q as bigint;
  }

  get requiredKeys(): RequiredKeys {
    return GentrySahaiWaters.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.GentrySahaiWaters;
  }

  generateKeys(keySize: number): Keys {
    const d = keySize;
    if (!Number.isInteger(d) || d < 8 || (d & (d - 1)) !== 0) {
      throw new Error(
        `Key size ${d} must be a power of 2 and at least 8 for Gentry-Sahai-Waters`
      );
    }

    const q = ONE << BigInt(GSW_LOG_Q);
    const seed = randomBits(256);
    const a = expand(seed, d);
    const s = sampleSmall(d, GSW_ETA).map(BigInt);
    const e = sampleSmall(d, GSW_ETA).map(BigInt);

    // b = -(a s) + e
    const aS = polyMul(
      a,
      s.map((x) => mod(x, q)),
      d
    );
    const b = aS.map((x, i) => mod(-x + e[i], q));

    return {
      public_key: { d: BigInt(d), q, seed, b },
      private_key: { s },
    };
  }

  /**
   * Gentry-Sahai-Waters draws a one-time small random polynomial for each
   * row, i.e. `2 * ELL` polynomials u.
   */
  generateRandomKey(): bigint[][] {
    const d = this.degree();
    return Array.from({ length: 2 * ELL }, () =>
      sampleSmall(d, GSW_ETA).map(BigInt)
    );
  }

  /**
   * Encrypts a bit, 0 or 1.
   *
   * @returns `2 * ELL` rows of polynomial pairs `Z + m G`.
   */
  encrypt(plaintext: bigint, randomKey?: RandomKey): GSWCiphertext {
    const d = this.degree();
    const q = this.keys.public_key!.q as bigint;
    const b = this.keys.public_key!.b as bigint[];
    const us =
      Array.isArray(randomKey) && randomKey.length > 0
        ? (randomKey as readonly (readonly bigint[])[])
        : this.generateRandomKey();

    let m = plaintext;
    if (m !== ZERO && m !== ONE) {
      m = mod(m, 2n);
      logger.debug(
        'Gentry-Sahai-Waters can encrypt bits only. ' +
          `Seems plaintext exceeded this limit. New plaintext is ${m}`
      );
    }

    if (this.a === undefined) {
      this.a = expand(this.keys.public_key!.seed as bigint, d);
    }

    return us.map((u, i) => {
      const uModQ = u.map((x) => mod(x, q));
      const e1 = sampleSmall(d, GSW_ETA);
      const e2 = sampleSmall(d, GSW_ETA);
      const c0 = polyMul(b, uModQ, d).map((x, j) => mod(x + BigInt(e1[j]), q));
      const c1 = polyMul(this.a!, uModQ, d).map((x, j) =>
        mod(x + BigInt(e2[j]), q)
      );

      // first ELL rows carry m g_i in c0, and last ELL rows carry it in c1
      if (i < ELL) {
        c0[0] = (c0[0] + m * gadget(i)) % q;
      } else {
        c1[0] = (c1[0] + m * gadget(i - ELL)) % q;
      }
      return [c0, c1];
    });
  }

  /** Decrypts `2 * ELL` rows of polynomial pairs into a bit. */
  decrypt(ciphertext: CiphertextValue): bigint {
    const q = this.keys.public_key!.q as bigint;
    const s = this.keys.private_key!.s as bigint[];

    // phase of the last row of the first half is m q / 2 + noise
    const [c0, c1] = (ciphertext as GSWCiphertext)[ELL - 1];
    const phase = mod(c0[0] + constantTerm(c1, s), q);
    return q / 4n <= phase && phase < q - q / 4n ? ONE : ZERO;
  }

  /**
   * Homomorphic and on encrypted bits: the result decrypts to `m1 & m2`.
   * Noise of the result is the noise of ciphertext2 times small digits plus
   * the noise of ciphertext1, so keep ciphertext2 fresh in long chains, e.g.
   * `acc = acc & fresh`.
   */
  override homomorphicAnd(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): GSWCiphertext {
    return this.product(ciphertext1, ciphertext2);
  }

  /**
   * Homomorphic multiplication on encrypted bits, which is the and of them:
   * the result decrypts to `m1 * m2`.
   */
  override multiply(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): GSWCiphertext {
    return this.product(ciphertext1, ciphertext2);
  }

  /**
   * Homomorphic exclusive or on encrypted bits: the result decrypts to
   * `m1 ^ m2`. Sum of ciphertexts encrypts `m1 + m2`, and decryption restores
   * its parity. Noise of the result is the sum of noises of the ciphertexts.
   */
  override xor(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): GSWCiphertext {
    const q = this.keys.public_key!.q as bigint;
    const second = ciphertext2 as GSWCiphertext;
    return (ciphertext1 as GSWCiphertext).map((row, i) =>
      row.map((poly, j) => poly.map((x, k) => (x + second[i][j][k]) % q))
    );
  }

  override reencrypt(ciphertext: CiphertextValue): GSWCiphertext {
    return this.xor(ciphertext, this.encrypt(ZERO));
  }

  /**
   * Computes `G^-1(C1) x C2`, i.e. each row of C1 is decomposed into
   * `2 * ELL` small digit polynomials, and the row of the result is their
   * weighted sum of rows of C2. Its phase is
   * `G^-1(C1) x noise of C2 + m2 * phase of C1`, so it encrypts `m1 m2`.
   * Digits are shifted by B / 2 to be non-negative for packing, and the shift
   * is subtracted afterwards.
   */
  private product(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): GSWCiphertext {
    const d = this.degree();
    const q = this.keys.public_key!.q as bigint;
    const halfB = ONE << BigInt(LOG_B - 1);
    const first = ciphertext1 as GSWCiphertext;
    const second = ciphertext2 as GSWCiphertext;

    // each coefficient sums 2 * ELL * d products of a digit less than B and an entry of C2
    const width = Math.ceil(
      (GSW_LOG_Q + LOG_B + bitLength(BigInt(2 * ELL * d)) + 1) / 8
    );
    const packed2 = second.map((row) => row.map((poly) => pack(poly, width)));

    // shift adds (B / 2) J to digits where J is the all ones polynomial, so
    // (B / 2) J times the sum of rows of C2 is subtracted from every row of the result.
    // (J c)_i = sum of c_j for j <= i minus sum of c_j for j > i
    const corrections = [0, 1].map((column) => {
      const total: bigint[] = [];
      for (let i = 0; i < d; i++) {
        total.push(second.reduce((sum, row) => sum + row[column][i], ZERO));
      }
      const whole = total.reduce((sum, x) => sum + x, ZERO);
      let prefix = ZERO;
      return total.map((x) => {
        prefix += x;
        return halfB * (2n * prefix - whole);
      });
    });

    return first.map((row) => {
      const digits = [...decompose(row[0]), ...decompose(row[1])];
      const accumulators = [ZERO, ZERO];
      digits.forEach((digit, i) => {
        const packedDigit = pack(
          digit.map((x) => x + halfB),
          width
        );
        accumulators[0] += packedDigit * packed2[i][0];
        accumulators[1] += packedDigit * packed2[i][1];
      });
      return accumulators.map((accumulator, column) =>
        unpack(accumulator, d, width).map((x, i) =>
          mod(x - corrections[column][i], q)
        )
      );
    });
  }

  private degree(): number {
    return Number(this.keys.public_key!.d as bigint);
  }
}

/** Entry of the approximate gadget, `2^OFFSET * B^index`. */
export function gadget(index: number): bigint {
  return ONE << BigInt(OFFSET + LOG_B * index);
}

/**
 * Decomposes a polynomial into ELL polynomials of signed digits in
 * `[-B / 2, B / 2)`, so that sum of `digits_i * gadget_i` is the polynomial up
 * to a rounding error less than `2^OFFSET` in each coefficient.
 *
 * @param poly - d coefficients in `[0, q)`.
 * @returns ELL polynomials.
 */
export function decompose(poly: readonly bigint[]): bigint[][] {
  const q = ONE << BigInt(GSW_LOG_Q);
  const base = ONE << BigInt(LOG_B);
  const halfB = base >> ONE;
  const offset = BigInt(OFFSET);
  const logB = BigInt(LOG_B);
  const digits: bigint[][] = Array.from({ length: ELL }, () => []);
  for (const coefficient of poly) {
    // centered representative, rounded to a multiple of 2^OFFSET
    let x = coefficient >= q >> ONE ? coefficient - q : coefficient;
    x = (x + (ONE << (offset - ONE))) >> offset;
    for (let j = 0; j < ELL; j++) {
      let digit = mod(x, base);
      if (digit >= halfB) {
        digit -= base;
      }
      digits[j].push(digit);
      x = (x - digit) >> logB;
    }
  }
  return digits;
}
