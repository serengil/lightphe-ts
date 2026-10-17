import { Logger } from '../commons/logger.js';
import {
  mod,
  modInverse,
  nextPrime,
  randomBelow,
  ONE,
  ZERO,
} from '../commons/mathUtils.js';
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
  'lightphe-ts/cryptosystems/GentryHaleviVaikuntanathan.ts'
);

/** Floats are scaled by powers of 10, which exceeds the small plaintext space. */
export const GHV_FLOAT_NOT_SUPPORTED_MSG =
  'Gentry-Halevi-Vaikuntanathan does not support float values or tensors, because they are' +
  ' scaled by powers of 10, which exceed its small plaintext space. Use integers instead.';

/** Shown whenever the cryptosystem is built. */
export const GHV_INSECURE_WARNING_MSG =
  'Gentry-Halevi-Vaikuntanathan is for learning purposes only. Its ciphertexts are huge' +
  ' matrices for secure parameters, so it supports tiny key sizes that are not secure.' +
  ' Use Brakerski-Vaikuntanathan for a practical alternative.';

/** Lattice dimension is limited, as ciphertexts are m x m matrices where m grows with n log q. */
const MIN_KEY_SIZE = 2;
const MAX_KEY_SIZE = 8;
const DEFAULT_KEY_SIZE = 4;

/** Default plaintext modulus p. */
const DEFAULT_PLAINTEXT_MODULO = 101n;

/** Room for noise growth after a multiplication in bits, i.e. for additions and constants. */
const NOISE_MARGIN_BITS = 12;

/** Errors are sampled from centered binomial distribution with this parameter. */
const ETA = 2;

const FRESH = 1n;
const MULTIPLIED = 2n;

type Matrix = bigint[][];

/**
 * Gentry-Halevi-Vaikuntanathan is homomorphic with respect to addition, and
 * supports one multiplication of ciphertexts like Boneh-Goh-Nissim, without
 * pairings. Its security relies on learning with errors (LWE) problem.
 *
 * THIS IS FOR LEARNING PURPOSES ONLY, AND IT IS NOT SECURE. Ciphertexts are
 * m x m matrices where m grows with n log q, so secure parameters would need
 * ciphertexts of terabytes. Here, the lattice dimension n is between 2 and 8,
 * which offers no security at all. Use Brakerski-Vaikuntanathan for a
 * practical and quantum resistant alternative.
 *
 * Matrices are over `Z_q` where q is a power of 2, and plaintexts are in `Z_p`
 * for an odd prime p.
 *   - private key: short m x m matrix T, which is full rank and satisfies
 *     `T A = 0 mod q`. It is generated with the gadget trapdoor of
 *     Micciancio-Peikert: `A^T = [A_bar | G - A_bar R]` where G is the gadget
 *     matrix of powers of 2.
 *   - public key: m x n matrix A
 *   - encryption of m: `C = A S + p X + m I mod q` for uniformly random S and
 *     small X
 *   - decryption: `T C T^T mod q = T (p X + m I) T^T`, as `T A = 0`. When its
 *     entries are small enough, it equals `T (p X + m I) T^T` over integers,
 *     so reducing it modulo p and multiplying with `T^-1` and `T^-T` modulo p
 *     restores `m I`.
 *   - multiplication: `C1 C2^T`, which is decrypted in the same way to
 *     `m1 m2 I`, as `T (A S1 + Z1)(A S2 + Z2)^T T^T = T Z1 Z2^T T^T`
 * The original scheme encrypts m x m matrices of plaintexts. Here, a single
 * plaintext is encrypted as the scalar matrix `m I`.
 *
 * Noise grows with homomorphic operations, and decryption returns a wrong
 * result without any error when it exceeds q / 2. q is chosen to leave room for
 * multiplying a product with constants up to a few thousands, or for adding
 * thousands of products.
 *
 * Ref: Gentry, C., Halevi, S., Vaikuntanathan, V. (2010). A Simple BGN-Type
 * Cryptosystem from LWE. EUROCRYPT 2010.
 *
 * Ref: Micciancio, D., Peikert, C. (2012). Trapdoors for Lattices: Simpler,
 * Tighter, Faster, Smaller. EUROCRYPT 2012.
 */
export class GentryHaleviVaikuntanathan extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['A', 'q', 'p'],
    private_key: ['T'],
  };

  /**
   * @param options.keySize - lattice dimension n in [2, 8]. Default is 4.
   * @param options.plaintextLimit - upper bound for plaintext values.
   *   Plaintext modulus p is the smallest prime greater than or equal to it.
   *   Default is 101.
   */
  constructor(options?: {
    keys?: Keys | null;
    keySize?: number | null;
    plaintextLimit?: number | bigint | null;
  }) {
    super();
    logger.warn(GHV_INSECURE_WARNING_MSG);
    this.keys =
      options?.keys ??
      this.generateKeys(options?.keySize ?? DEFAULT_KEY_SIZE, {
        plaintextLimit: options?.plaintextLimit,
      });
    this.plaintextModulo = this.keys.public_key!.p as bigint;
    this.ciphertextModulo = this.keys.public_key!.q as bigint;
  }

  get requiredKeys(): RequiredKeys {
    return GentryHaleviVaikuntanathan.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.GentryHaleviVaikuntanathan;
  }

  generateKeys(
    keySize: number,
    options?: { plaintextLimit?: number | bigint | null }
  ): Keys {
    const n = keySize;
    if (!Number.isInteger(n) || n < MIN_KEY_SIZE || n > MAX_KEY_SIZE) {
      throw new Error(
        `Key size ${n} is not supported. Gentry-Halevi-Vaikuntanathan is for learning` +
          ` purposes only, and its key size must be in [${MIN_KEY_SIZE}, ${MAX_KEY_SIZE}].`
      );
    }

    // T must be invertible modulo p, and det(T) is a power of 2
    let p = DEFAULT_PLAINTEXT_MODULO;
    if (options?.plaintextLimit != null) {
      const limit = BigInt(options.plaintextLimit);
      p = nextPrime((limit > 3n ? limit : 3n) - ONE);
    }

    const mBar = 2 * n;
    const k = modulusBits(n, mBar, Number(p));
    const q = ONE << BigInt(k);
    const nk = n * k;
    logger.debug(`n = ${n}, log q = ${k}, m = ${mBar + nk}, p = ${p}`);

    // A^T = [A_bar | G - A_bar R], where G = I_n (x) (1, 2, ..., 2^(k-1))
    const aBar: Matrix = Array.from({ length: n }, () =>
      Array.from({ length: mBar }, () => randomBelow(q))
    );
    const r: Matrix = Array.from({ length: mBar }, () =>
      Array.from({ length: nk }, () => randomBelow(3n) - ONE)
    );
    const aBarR = matmul(aBar, r);
    const aTransposed: Matrix = aBar.map((row, i) => [
      ...row,
      ...Array.from({ length: nk }, (_, c) =>
        mod(
          (Math.floor(c / k) === i ? ONE << BigInt(c % k) : ZERO) - aBarR[i][c],
          q
        )
      ),
    ]);

    // W is the bit decomposition of -A_bar, so that G W = -A_bar mod q
    const w: Matrix = Array.from({ length: nk }, () =>
      new Array<bigint>(mBar).fill(ZERO)
    );
    for (let j = 0; j < mBar; j++) {
      for (let i = 0; i < n; i++) {
        const value = mod(-aBar[i][j], q);
        for (let bit = 0; bit < k; bit++) {
          w[i * k + bit][j] = (value >> BigInt(bit)) & ONE;
        }
      }
    }

    // S_G = I_n (x) S_k, whose columns 2 e_i - e_(i+1) and 2 e_k are
    // orthogonal to the gadget
    const sG: Matrix = Array.from({ length: nk }, () =>
      new Array<bigint>(nk).fill(ZERO)
    );
    for (let block = 0; block < n; block++) {
      for (let i = 0; i < k; i++) {
        sG[block * k + i][block * k + i] = 2n;
        if (i + 1 < k) {
          sG[block * k + i + 1][block * k + i] = -ONE;
        }
      }
    }

    // S = [[I + R W, R S_G], [W, S_G]] is a short basis with A^T S = 0 mod q
    const rW = matmul(r, w);
    const rSG = matmul(r, sG);
    const s: Matrix = [];
    for (let i = 0; i < mBar; i++) {
      s.push([...rW[i].map((x, j) => (i === j ? ONE : ZERO) + x), ...rSG[i]]);
    }
    for (let i = 0; i < nk; i++) {
      s.push([...w[i], ...sG[i]]);
    }

    const t = transpose(s);
    const a = transpose(aTransposed);

    return {
      public_key: { A: a, q, p },
      // first row of T^-1 mod p is enough to restore scalar matrices m I
      private_key: { T: t, u: firstRowOfInverse(t, p) },
    };
  }

  /**
   * Gentry-Halevi-Vaikuntanathan draws a uniformly random n x m matrix S per
   * encryption.
   */
  generateRandomKey(): Matrix {
    const a = this.keys.public_key!.A as Matrix;
    const q = this.keys.public_key!.q as bigint;
    return Array.from({ length: a[0].length }, () =>
      Array.from({ length: a.length }, () => randomBelow(q))
    );
  }

  /**
   * Encrypts a plaintext in `[0, p)`.
   *
   * @returns level and m x m matrix `C = A S + p X + m I mod q`.
   */
  encrypt(plaintext: bigint, randomKey?: RandomKey): CiphertextValue {
    const a = this.keys.public_key!.A as Matrix;
    const q = this.keys.public_key!.q as bigint;
    const p = this.keys.public_key!.p as bigint;
    const s =
      Array.isArray(randomKey) && randomKey.length > 0
        ? (randomKey as Matrix)
        : this.generateRandomKey();
    const m = a.length;

    let message = plaintext;
    if (message >= p) {
      message = message % p;
      logger.debug(
        `Gentry-Halevi-Vaikuntanathan can encrypt messages [0, ${p}). ` +
          `Seems plaintext exceeded this limit. New plaintext is ${message}`
      );
    }

    const aS = matmul(a, s);
    const noise = sampleSmall(m * m, ETA);
    const matrix: Matrix = aS.map((row, i) =>
      row.map((x, j) =>
        mod(x + p * BigInt(noise[i * m + j]) + (i === j ? message : ZERO), q)
      )
    );
    return [FRESH, matrix];
  }

  decrypt(ciphertext: CiphertextValue): bigint {
    const q = this.keys.public_key!.q as bigint;
    const p = this.keys.public_key!.p as bigint;
    const privateKey = this.keys.private_key!;
    const t = privateKey.T as Matrix;
    if (privateKey.u === undefined) {
      privateKey.u = firstRowOfInverse(t, p);
    }
    const u = privateKey.u as bigint[];

    const matrix = (ciphertext as readonly CiphertextValue[])[1] as Matrix;

    // E = T C T^T mod q, centered, equals T (p X + B) T^T over integers
    const tC = matmul(t, matrix).map((row) => row.map((x) => mod(x, q)));
    const half = q / 2n;
    const e = matmulTransposed(tC, t).map((row) =>
      row.map((value) => {
        const x = mod(value, q);
        return x > half ? x - q : x;
      })
    );

    // B = T^-1 E T^-T mod p, and its first diagonal entry is the message
    const size = e.length;
    let result = ZERO;
    for (let j = 0; j < size; j++) {
      let uE = ZERO;
      for (let i = 0; i < size; i++) {
        uE += u[i] * e[i][j];
      }
      result += uE * u[j];
    }
    return mod(result, p);
  }

  /**
   * Homomorphic addition: the result decrypts to `m1 + m2`. Fresh and
   * multiplied ciphertexts can be added, as they are decrypted in the same way.
   */
  override add(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): CiphertextValue {
    const q = this.keys.public_key!.q as bigint;
    const [level1, matrix1] = ciphertext1 as readonly [bigint, Matrix];
    const [level2, matrix2] = ciphertext2 as readonly [bigint, Matrix];
    const matrix = matrix1.map((row, i) =>
      row.map((x, j) => (x + matrix2[i][j]) % q)
    );
    return [level1 > level2 ? level1 : level2, matrix];
  }

  /**
   * Homomorphic multiplication: the result decrypts to `m1 * m2`. It is the
   * matrix product `C1 C2^T`.
   */
  override multiply(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): CiphertextValue {
    const q = this.keys.public_key!.q as bigint;
    const [level1, matrix1] = ciphertext1 as readonly [bigint, Matrix];
    const [level2, matrix2] = ciphertext2 as readonly [bigint, Matrix];
    if (level1 !== FRESH || level2 !== FRESH) {
      throw new Error(
        'Gentry-Halevi-Vaikuntanathan supports only one multiplication. ' +
          'Multiplied ciphertexts cannot be multiplied with ciphertexts again.'
      );
    }
    const product = matmulTransposed(matrix1, matrix2);
    return [MULTIPLIED, product.map((row) => row.map((x) => x % q))];
  }

  /**
   * Multiplies a ciphertext by a known plain constant. Noise of the result is
   * the noise of the ciphertext times |constant|.
   */
  override multiplyByConstant(
    ciphertext: CiphertextValue,
    constant: bigint
  ): CiphertextValue {
    const q = this.keys.public_key!.q as bigint;
    const p = this.keys.public_key!.p as bigint;

    // centered representative keeps the noise small for negative constants
    let k = mod(constant, p);
    if (k > p / 2n) {
      k -= p;
    }

    const [level, matrix] = ciphertext as readonly [bigint, Matrix];
    return [level, matrix.map((row) => row.map((x) => mod(x * k, q)))];
  }

  override reencrypt(ciphertext: CiphertextValue): CiphertextValue {
    return this.add(ciphertext, this.encrypt(ZERO));
  }
}

/**
 * Bits of q, so that the noise of a product stays below q / 2 with a margin.
 * Noise of a product is about `p^2 m^2` times a small factor, and
 * `m = m_bar + n log q`, so it is found iteratively.
 */
function modulusBits(n: number, mBar: number, p: number): number {
  let k = 32;
  for (;;) {
    const m = mBar + n * k;
    const required = Math.ceil(
      2 * Math.log2(p) + 2 * Math.log2(m) + 2 + NOISE_MARGIN_BITS
    );
    if (required <= k) {
      return k;
    }
    k = required;
  }
}

function transpose(matrix: Matrix): Matrix {
  return matrix[0].map((_, j) => matrix.map((row) => row[j]));
}

/** Matrix product `left x right`. */
function matmul(left: Matrix, right: Matrix): Matrix {
  return matmulTransposed(left, transpose(right));
}

/** Matrix product `left x right^T`. */
function matmulTransposed(left: Matrix, right: Matrix): Matrix {
  return left.map((row) =>
    right.map((other) => {
      let sum = ZERO;
      for (let i = 0; i < row.length; i++) {
        if (row[i] !== ZERO && other[i] !== ZERO) {
          sum += row[i] * other[i];
        }
      }
      return sum;
    })
  );
}

/**
 * First row of the inverse of a matrix modulo prime p with Gauss-Jordan
 * elimination.
 */
function firstRowOfInverse(matrix: Matrix, p: bigint): bigint[] {
  const size = matrix.length;
  const augmented: Matrix = matrix.map((row, i) => [
    ...row.map((x) => mod(x, p)),
    ...Array.from({ length: size }, (_, j) => (i === j ? ONE : ZERO)),
  ]);
  for (let column = 0; column < size; column++) {
    let pivot = column;
    while (augmented[pivot][column] === ZERO) {
      pivot += 1;
    }
    [augmented[column], augmented[pivot]] = [
      augmented[pivot],
      augmented[column],
    ];
    const inverse = modInverse(augmented[column][column], p);
    augmented[column] = augmented[column].map((x) => (x * inverse) % p);
    for (let row = 0; row < size; row++) {
      const factor = augmented[row][column];
      if (row !== column && factor !== ZERO) {
        augmented[row] = augmented[row].map((x, j) =>
          mod(x - factor * augmented[column][j], p)
        );
      }
    }
  }
  return augmented[0].slice(size);
}
