import { Logger } from '../commons/logger.js';
import {
  bitLength,
  gcd,
  isPrime,
  mod,
  modInverse,
  randomBelow,
  randomBits,
  randomRange,
  ONE,
  TWO,
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

const logger = new Logger('lightphe-ts/cryptosystems/EllipticCurvePaillier.ts');

/** Extra bits of the random key, so that it is statistically uniform modulo the order of g. */
const RANDOM_KEY_EXTRA_BITS = 128;

const THREE = 3n;

/** A point `(X : Y : Z)` in projective coordinates. */
type ProjectivePoint = readonly [bigint, bigint, bigint];

/** The point at infinity `(0 : 1 : 0)`. */
const INFINITY: ProjectivePoint = [ZERO, ONE, ZERO];

/**
 * Elliptic Curve Paillier is homomorphic with respect to addition, and supports
 * multiplying a ciphertext by a known plain constant. It is the elliptic curve
 * analogue of Paillier. Paillier works in the multiplicative group
 * `Z_{n^2}*`, whereas this works in the group of points on an elliptic curve
 * `y^2 = x^3 + b` over the ring `Z_{n^2}` where `n = pq`.
 *
 * Points reducing to the point at infinity modulo n form a subgroup of order
 * n, in which discrete logarithm is easy, similar to `1 + n` in Paillier. A
 * ciphertext is `m * (n : 1 : 0) + r * g`, where g is a point whose order is a
 * secret factor of the group order. Multiplying a ciphertext by that order
 * clears `r * g` and leaves m.
 *
 * p and q are 2 mod 3, so the curve has p + 1 points modulo p and q + 1 points
 * modulo q as in KMOV cryptosystem, and the group order is known by the
 * private key owner only. Points are in projective coordinates as division is
 * not always possible in `Z_{n^2}`. Additions use complete formulas, which work
 * for all points including doubling and the point at infinity, as the order of
 * g is odd and so it has no point of order 2. Ciphertexts are 3 times larger
 * than Paillier's, and operations are slower.
 *
 * Note: point arithmetic is implemented here instead of the bundled elliptic
 * curve module. It works with affine (x, y) points and divides in its addition
 * formulas, which suits curves over prime fields as in Boneh-Goh-Nissim.
 * `Z_{n^2}` is not a field, and messages live in points reducing to the point
 * at infinity modulo n, such as `(mn : 1 : 0)`. Those points cannot be written
 * as affine points, and reaching them requires dividing by multiples of n.
 * Projective coordinates with complete formulas never divide and keep those
 * points distinct.
 *
 * Ref: Galbraith, S. D. (2002). Elliptic Curve Paillier Schemes. Journal of
 * Cryptology, 15(2), 129-138.
 *
 * Ref: Renes, J., Costello, C., Batina, L. (2016). Complete Addition Formulas
 * for Prime Order Elliptic Curves. EUROCRYPT 2016.
 */
export class EllipticCurvePaillier extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['n', 'b', 'g'],
    private_key: ['order'],
  };

  // 2^i * g for i = 0, 1, ..., built when needed
  private gPowers?: ProjectivePoint[];

  constructor(options?: { keys?: Keys | null; keySize?: number | null }) {
    super();
    this.keys = options?.keys ?? this.generateKeys(options?.keySize ?? 1024);
    const n = this.keys.public_key!.n as bigint;
    this.plaintextModulo = n;
    this.ciphertextModulo = n * n;
  }

  get requiredKeys(): RequiredKeys {
    return EllipticCurvePaillier.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.EllipticCurvePaillier;
  }

  generateKeys(keySize: number): Keys {
    if (keySize < 16) {
      throw new Error(
        `Key size ${keySize} is too small for Elliptic Curve Paillier`
      );
    }

    const half = Math.floor(keySize / 2);
    for (;;) {
      const p = findPrime(half);
      const q = findPrime(half);
      if (p === q) {
        continue;
      }
      const n = p * q;
      const nSquare = n * n;

      // exponent of the group modulo n, and its odd part
      const exponent = ((p + ONE) * (q + ONE)) / gcd(p + ONE, q + ONE);
      let order = exponent;
      while (order % TWO === ZERO) {
        order /= TWO;
      }
      if (gcd(order, n) !== ONE) {
        continue;
      }

      // random point P, and the curve passing through it
      const x = randomBelow(nSquare);
      const y = randomBelow(nSquare);
      const b = mod(y * y - x ** THREE, nSquare);
      if (gcd(b, n) !== ONE) {
        continue;
      }

      // g has odd order dividing the secret order
      const projective = multiplyPoint(
        [x, y, ONE],
        n * (exponent / order),
        b,
        nSquare
      );
      if (gcd(projective[2], n) !== ONE) {
        continue;
      }
      const zInv = modInverse(projective[2], nSquare);
      const g = [
        (projective[0] * zInv) % nSquare,
        (projective[1] * zInv) % nSquare,
      ];

      return {
        public_key: { n, b, g },
        private_key: { order, p, q },
      };
    }
  }

  /** Elliptic Curve Paillier draws a fresh random key per encryption. */
  generateRandomKey(): bigint {
    const n = this.keys.public_key!.n as bigint;
    return randomRange(ONE, n << BigInt(RANDOM_KEY_EXTRA_BITS));
  }

  /** Encrypts a plaintext as the projective point `m * (n : 1 : 0) + r * g`. */
  encrypt(plaintext: bigint, randomKey?: RandomKey): bigint[] {
    const n = this.keys.public_key!.n as bigint;
    const b = this.keys.public_key!.b as bigint;
    const r =
      typeof randomKey === 'bigint' && randomKey !== ZERO
        ? randomKey
        : this.generateRandomKey();

    let m = plaintext;
    if (m >= n) {
      m = m % n;
      logger.debug(
        `Elliptic Curve Paillier can encrypt messages [0, ${n}). ` +
          `Seems plaintext exceeded this limit. New plaintext is ${m}`
      );
    }

    // m * (n : 1 : 0) = (mn : 1 : 0), similar to (1 + n)^m = 1 + mn in Paillier
    const messagePoint: ProjectivePoint = [(m * n) % (n * n), ONE, ZERO];
    return [...addPoints(messagePoint, this.multiplyG(r), b, n * n)];
  }

  decrypt(ciphertext: CiphertextValue): bigint {
    const n = this.keys.public_key!.n as bigint;
    const b = this.keys.public_key!.b as bigint;
    const order = this.keys.private_key!.order as bigint;
    const nSquare = n * n;

    // order * C = (order * m) * (n : 1 : 0) as order * r * g is the point at
    // infinity
    const [x, y, z] = multiplyPoint(toPoint(ciphertext), order, b, nSquare);
    if (x % n !== ZERO || z % n !== ZERO || gcd(y, n) !== ONE) {
      throw new Error('Ciphertext is invalid');
    }

    // (kn : 1 : 0) -> k
    const scaledMessage = ((x * modInverse(y, nSquare)) % nSquare) / n;
    return (scaledMessage * modInverse(order, n)) % n;
  }

  /** Homomorphic addition: the result decrypts to `m1 + m2`. */
  override add(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): bigint[] {
    const n = this.keys.public_key!.n as bigint;
    const b = this.keys.public_key!.b as bigint;
    return [...addPoints(toPoint(ciphertext1), toPoint(ciphertext2), b, n * n)];
  }

  /** Multiplies a ciphertext by a known plain constant. */
  override multiplyByConstant(
    ciphertext: CiphertextValue,
    constant: bigint
  ): bigint[] {
    const n = this.keys.public_key!.n as bigint;
    const b = this.keys.public_key!.b as bigint;

    let k = constant;
    if (k >= this.plaintextModulo) {
      k = k % this.plaintextModulo;
      logger.debug(
        `Elliptic Curve Paillier can encrypt messages [0, ${n}). ` +
          `Seems constant exceeded this limit. New constant is ${k}`
      );
    }

    return [...multiplyPoint(toPoint(ciphertext), k, b, n * n)];
  }

  override reencrypt(ciphertext: CiphertextValue): bigint[] {
    return this.add(ciphertext, this.encrypt(ZERO));
  }

  /**
   * Multiplies g with a scalar using precomputed `2^i * g` points, which
   * avoids doublings.
   */
  private multiplyG(scalar: bigint): ProjectivePoint {
    const n = this.keys.public_key!.n as bigint;
    const b = this.keys.public_key!.b as bigint;
    const nSquare = n * n;

    const bits = Math.max(
      bitLength(scalar),
      bitLength(n << BigInt(RANDOM_KEY_EXTRA_BITS))
    );
    if (this.gPowers === undefined || this.gPowers.length < bits) {
      const [x, y] = this.keys.public_key!.g as readonly bigint[];
      const powers: ProjectivePoint[] = [[x, y, ONE]];
      for (let i = 1; i < bits; i++) {
        const last = powers[powers.length - 1];
        powers.push(addPoints(last, last, b, nSquare));
      }
      this.gPowers = powers;
    }

    let result = INFINITY;
    for (let i = 0; i < bitLength(scalar); i++) {
      if ((scalar >> BigInt(i)) & ONE) {
        result = addPoints(result, this.gPowers[i], b, nSquare);
      }
    }
    return result;
  }
}

/** Reads a ciphertext as a projective point. */
function toPoint(ciphertext: CiphertextValue): ProjectivePoint {
  const [x, y, z] = ciphertext as readonly bigint[];
  return [x, y, z];
}

/**
 * Adds two projective points on `y^2 = x^3 + b` over `Z_{n^2}` with complete
 * formulas (Algorithm 7 of Renes-Costello-Batina for a = 0).
 */
function addPoints(
  point1: ProjectivePoint,
  point2: ProjectivePoint,
  b: bigint,
  modulus: bigint
): ProjectivePoint {
  const b3 = THREE * b;
  const [x1, y1, z1] = point1;
  const [x2, y2, z2] = point2;

  let t0 = (x1 * x2) % modulus;
  let t1 = (y1 * y2) % modulus;
  let t2 = (z1 * z2) % modulus;
  const t3 = mod((x1 + y1) * (x2 + y2) - t0 - t1, modulus);
  const t4 = mod((y1 + z1) * (y2 + z2) - t1 - t2, modulus);
  let y3 = mod((x1 + z1) * (x2 + z2) - t0 - t2, modulus);
  t0 = (THREE * t0) % modulus;
  t2 = (b3 * t2) % modulus;
  let z3 = (t1 + t2) % modulus;
  t1 = mod(t1 - t2, modulus);
  y3 = (b3 * y3) % modulus;
  const x3 = mod(t3 * t1 - t4 * y3, modulus);
  y3 = (t1 * z3 + y3 * t0) % modulus;
  z3 = (z3 * t4 + t0 * t3) % modulus;
  return [x3, y3, z3];
}

/** Multiplies a projective point with a non-negative scalar by double and add. */
function multiplyPoint(
  point: ProjectivePoint,
  scalar: bigint,
  b: bigint,
  modulus: bigint
): ProjectivePoint {
  let result = INFINITY;
  for (let i = bitLength(scalar) - 1; i >= 0; i--) {
    result = addPoints(result, result, b, modulus);
    if ((scalar >> BigInt(i)) & ONE) {
      result = addPoints(result, point, b, modulus);
    }
  }
  return result;
}

/** Finds a prime p = 2 mod 3, so that `y^2 = x^3 + b` has p + 1 points modulo p. */
function findPrime(bits: number): bigint {
  for (;;) {
    const candidate = randomBits(bits) | (ONE << BigInt(bits - 1)) | ONE;
    if (candidate % THREE === TWO && isPrime(candidate)) {
      return candidate;
    }
  }
}
