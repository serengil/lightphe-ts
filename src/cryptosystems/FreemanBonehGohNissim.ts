import {
  abs,
  isPrime,
  isqrt,
  mod,
  modInverse,
  modPow,
  pow2,
  randPrime,
  randomBelow,
  sqrtModAll,
  ONE,
  ZERO,
} from '../commons/mathUtils.js';
import { EllipticCurvePoint, FP2, LightECC } from '../ecc/index.js';
import { Algorithm } from '../models/Algorithm.js';
import { Homomorphic } from '../models/Homomorphic.js';
import type {
  CiphertextValue,
  Keys,
  RandomKey,
  RequiredKeys,
} from '../models/types.js';

/** Floats are scaled by powers of 10, which exceeds the range of discrete logarithm. */
export const FBGN_FLOAT_NOT_SUPPORTED_MSG =
  'Freeman-Boneh-Goh-Nissim does not support float values or tensors, because they are' +
  ' scaled by powers of 10, which exceed the range that decryption can restore.' +
  ' Use integers instead.';

/**
 * Decrypted values must be in `[-limit, limit]` by default, as decryption
 * solves discrete logarithm with baby-step giant-step.
 */
const DEFAULT_PLAINTEXT_LIMIT = 2n ** 20n;

/** Bit length of the prime group order r. */
const MAX_ORDER_BITS = 256;

/** A ciphertext is a vector of DIMENSION points, and a multiplied one is DIMENSION^2 elements. */
const DIMENSION = 3;

/** Coordinates of a point as stored in keys, or null for the point at infinity. */
type StoredPoint = readonly [bigint, bigint] | null;

/** Baby-step giant-step table: base, step size, baby steps and the giant step. */
interface DiscreteLogTable<T> {
  base: T;
  size: bigint;
  babySteps: Map<string, bigint>;
  giantStep: T;
}

/**
 * Freeman-Boneh-Goh-Nissim is the prime-order version of Boneh-Goh-Nissim. It
 * is homomorphic with respect to addition, and supports one multiplication of
 * ciphertexts. Boneh-Goh-Nissim works in a group of composite order
 * `n = q1 q2`, and its security relies on hardness of factoring n, which
 * requires a large group. This works in a group of prime order r, and its
 * security relies on decision linear assumption.
 *
 * Groups are vectors of 3 points on the supersingular curve `y^2 = x^3 + x`
 * over `F_p`, whose points of order r have a symmetric pairing into `F_{p^2}`.
 *   - private key: secret vector v in `Z_r^3`
 *   - public key: h1 and h2 spanning the subgroup H of vectors orthogonal to
 *     v, and g out of H. Vectors are multiplied with the generator point P.
 *   - encryption: `C = m g + a1 h1 + a2 h2` for random a1 and a2
 *   - decryption: projection `pi(C) = v1 C1 + v2 C2 + v3 C3 = m pi(g)` as
 *     `pi(H) = 0`, then discrete logarithm of it with base `pi(g)`
 *   - multiplication: 3 x 3 pairings `e(C_i, C'_j)`. Its projection, product
 *     of `e(C_i, C'_j)^(v_i v_j)`, is
 *     `e(pi(C), pi(C')) = e(pi(g), pi(g))^(m m')`.
 * Freeman's symmetric instantiation needs vectors of 3 points, because
 * decisional Diffie-Hellman is easy in groups having a symmetric pairing.
 *
 * Notice that decryption solves discrete logarithm as in Boneh-Goh-Nissim, so
 * decrypted values must be small: in `[-limit, limit]` where limit is 2^20 by
 * default, and can be set with plaintextLimit. Floats and tensors are not
 * supported. Ciphertexts are 3 points, and multiplied ciphertexts are 9
 * elements of `F_{p^2}`. Multiplied ciphertexts can be added with each other
 * and multiplied with constants. Adding a fresh ciphertext to a multiplied one
 * pairs it with g first, which costs 9 pairings.
 *
 * keySize is the bit length of the field size p. Default is 1024. The group
 * order r is 256 bits, and security is bounded by discrete logarithm in
 * `F_{p^2}`: about 112 bits for p of 1024 bits, and 128 bits for p of 1536
 * bits. Boneh-Goh-Nissim of the same key size has about 80-bit security, as
 * factoring its 1024-bit n is easier, and it needs a 2048-bit n to reach a
 * similar level. A multiplication costs 9 pairings instead of 1, but each
 * pairing is cheaper, as the group order is 256 bits instead of the size of n.
 * It is not quantum resistant.
 *
 * Ref: Freeman, D. M. (2010). Converting Pairing-Based Cryptosystems from
 * Composite-Order Groups to Prime-Order Groups. EUROCRYPT 2010.
 *
 * Ref: Boneh, D., Goh, E.-J., Nissim, K. (2005). Evaluating 2-DNF Formulas on
 * Ciphertexts. TCC 2005.
 */
export class FreemanBonehGohNissim extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['p', 'r', 'P', 'g', 'h1', 'h2', 'limit'],
    private_key: ['v'],
  };

  readonly ec: LightECC;

  // baby-step giant-step tables, built when needed
  private curveTable?: DiscreteLogTable<EllipticCurvePoint>;
  private gtTable?: DiscreteLogTable<FP2>;

  /**
   * @param options.keySize - bit length of the field size p. Default is 1024.
   * @param options.plaintextLimit - decrypted values must be in
   *   `[-limit, limit]`. Default is 2^20. Decryption takes about sqrt(limit)
   *   steps.
   */
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
    const publicKey = this.keys.public_key!;
    this.ec = buildCurve(
      publicKey.p as bigint,
      publicKey.r as bigint,
      publicKey.P as readonly [bigint, bigint]
    );
    this.plaintextModulo = publicKey.r as bigint;
    this.ciphertextModulo = publicKey.p as bigint;
  }

  get requiredKeys(): RequiredKeys {
    return FreemanBonehGohNissim.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.FreemanBonehGohNissim;
  }

  generateKeys(
    keySize: number,
    options?: { plaintextLimit?: number | bigint | null }
  ): Keys {
    if (keySize < 32) {
      throw new Error(
        `Key size ${keySize} is too small for Freeman-Boneh-Goh-Nissim`
      );
    }

    const limit =
      options?.plaintextLimit != null
        ? BigInt(options.plaintextLimit)
        : DEFAULT_PLAINTEXT_LIMIT;
    const rBits = Math.min(MAX_ORDER_BITS, Math.floor(keySize / 2));
    const r = randPrime(pow2(rBits - 1), pow2(rBits));
    if (2n * limit + ONE >= r) {
      throw new Error(
        `Plaintext limit ${limit} is too large for the group order of key size ${keySize}`
      );
    }

    // p = r l - 1 with 4 | l, so that p = 3 mod 4 and y^2 = x^3 + x has
    // p + 1 = r l points
    let l = (pow2(keySize - rBits) / 4n) * 4n;
    if (l < 4n) {
      l = 4n;
    }
    while (!isPrime(r * l - ONE)) {
      l += 4n;
    }
    const p = r * l - ONE;

    // generator P of the subgroup of order r
    let generator: EllipticCurvePoint;
    for (;;) {
      const x = randomBelow(p);
      const roots = sqrtModAll(mod(modPow(x, 3n, p) + x, p), p);
      if (roots.length === 0) {
        continue;
      }
      // order of the curve is not set, so that the cofactor l is not reduced
      const ec = new LightECC({
        formName: 'weierstrass',
        curveName: 'custom',
        config: { a: ONE, b: ZERO, p, G: [x, roots[0]], n: ZERO },
      });
      generator = ec.G.multiply(l);
      if (!generator.isIdentity()) {
        break;
      }
    }
    const ec = buildCurve(p, r, generator.getPoint());

    // secret projection v, and H = vectors orthogonal to v
    const v = Array.from(
      { length: DIMENSION },
      () => randomBelow(r - ONE) + ONE
    );
    let h1: bigint[];
    let h2: bigint[];
    for (;;) {
      h1 = randomOrthogonal(v, r);
      h2 = randomOrthogonal(v, r);
      // h1 and h2 must be linearly independent
      let independent = false;
      for (let i = 0; i < DIMENSION; i++) {
        for (let j = i + 1; j < DIMENSION; j++) {
          if (mod(h1[i] * h2[j] - h1[j] * h2[i], r) !== ZERO) {
            independent = true;
          }
        }
      }
      if (independent) {
        break;
      }
    }
    let g: bigint[];
    for (;;) {
      g = Array.from({ length: DIMENSION }, () => randomBelow(r));
      if (mod(dot(v, g), r) !== ZERO) {
        break;
      }
    }

    const toStored = (scalars: readonly bigint[]): StoredPoint[] =>
      scalars.map((x) => storePoint(scale(ec, ec.G, x, r)));

    return {
      public_key: {
        p,
        r,
        P: ec.G.getPoint(),
        g: toStored(g),
        h1: toStored(h1),
        h2: toStored(h2),
        limit,
      },
      private_key: { v },
    };
  }

  /** Freeman-Boneh-Goh-Nissim draws a pair of random scalars per encryption. */
  generateRandomKey(): bigint[] {
    const r = this.order();
    return [randomBelow(r), randomBelow(r)];
  }

  /**
   * Encrypts a plaintext.
   *
   * @returns 3 points of `m g + a1 h1 + a2 h2`.
   */
  encrypt(plaintext: bigint, randomKey?: RandomKey): EllipticCurvePoint[] {
    const r = this.order();
    const [a1, a2] =
      Array.isArray(randomKey) && randomKey.length > 0
        ? (randomKey as readonly bigint[])
        : this.generateRandomKey();
    const m = mod(plaintext, r);

    const g = this.publicPoints('g');
    const h1 = this.publicPoints('h1');
    const h2 = this.publicPoints('h2');
    return g.map((gi, i) =>
      this.scale(gi, m).add(this.scale(h1[i], a1)).add(this.scale(h2[i], a2))
    );
  }

  /** Decrypts 3 points, or 9 elements of `F_{p^2}` if multiplied. */
  decrypt(ciphertext: CiphertextValue): bigint {
    const r = this.order();
    const p = this.ec.modulo;
    const v = this.keys.private_key!.v as readonly bigint[];
    const values = ciphertext as readonly CiphertextValue[];

    if (isMultiplied(values)) {
      // product of e(C_i, C'_j)^(v_i v_j) = e(pi(C), pi(C'))
      let projected = FP2.one();
      values.forEach((element, index) => {
        const i = Math.floor(index / DIMENSION);
        const j = index % DIMENSION;
        projected = projected.mul(
          (element as FP2).exp(mod(v[i] * v[j], r), p),
          p
        );
      });
      return mod(this.discreteLogGT(projected), r);
    }

    const projected = this.project(values as readonly EllipticCurvePoint[]);
    return mod(this.discreteLogCurve(projected), r);
  }

  /**
   * Homomorphic addition: the result decrypts to `m1 + m2`. A fresh
   * ciphertext is paired with g before it is added to a multiplied one.
   */
  override add(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): EllipticCurvePoint[] | FP2[] {
    const p = this.ec.modulo;
    let first = ciphertext1 as readonly CiphertextValue[];
    let second = ciphertext2 as readonly CiphertextValue[];
    const multiplied1 = isMultiplied(first);
    const multiplied2 = isMultiplied(second);

    if (!multiplied1 && !multiplied2) {
      return (first as readonly EllipticCurvePoint[]).map((x, i) =>
        x.add(second[i] as EllipticCurvePoint)
      );
    }

    // E(m g + h, g) is an encryption of m as a multiplied ciphertext
    const g = this.publicPoints('g');
    if (!multiplied1) {
      first = this.pair(first as readonly EllipticCurvePoint[], g);
    }
    if (!multiplied2) {
      second = this.pair(second as readonly EllipticCurvePoint[], g);
    }
    return (first as readonly FP2[]).map((x, i) => x.mul(second[i] as FP2, p));
  }

  /**
   * Homomorphic multiplication: the result decrypts to `m1 * m2`. It costs 9
   * pairings.
   *
   * @returns 9 elements of `F_{p^2}`.
   */
  override multiply(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): FP2[] {
    const first = ciphertext1 as readonly CiphertextValue[];
    const second = ciphertext2 as readonly CiphertextValue[];
    if (isMultiplied(first) || isMultiplied(second)) {
      throw new Error(
        'Freeman-Boneh-Goh-Nissim supports only one multiplication. ' +
          'Multiplied ciphertexts cannot be multiplied with ciphertexts again.'
      );
    }
    return this.pair(
      first as readonly EllipticCurvePoint[],
      second as readonly EllipticCurvePoint[]
    );
  }

  /** Multiplies a ciphertext by a known plain constant. */
  override multiplyByConstant(
    ciphertext: CiphertextValue,
    constant: bigint
  ): EllipticCurvePoint[] | FP2[] {
    const r = this.order();
    const p = this.ec.modulo;
    const k = mod(constant, r);
    const values = ciphertext as readonly CiphertextValue[];

    if (isMultiplied(values)) {
      return (values as readonly FP2[]).map((element) => element.exp(k, p));
    }
    return (values as readonly EllipticCurvePoint[]).map((point) =>
      this.scale(point, k)
    );
  }

  override reencrypt(ciphertext: CiphertextValue): EllipticCurvePoint[] {
    if (isMultiplied(ciphertext as readonly CiphertextValue[])) {
      throw new Error(
        'Freeman-Boneh-Goh-Nissim can re-encrypt non-multiplied ciphertexts only'
      );
    }
    return this.add(ciphertext, this.encrypt(ZERO)) as EllipticCurvePoint[];
  }

  /**
   * Secret projection `pi(C) = v1 C1 + v2 C2 + v3 C3`, which vanishes on H.
   * Requires the private key.
   */
  project(points: readonly EllipticCurvePoint[]): EllipticCurvePoint {
    const v = this.keys.private_key!.v as readonly bigint[];
    let result = this.ec.O;
    points.forEach((point, i) => {
      result = result.add(this.scale(point, v[i]));
    });
    return result;
  }

  /** Points of g, h1 or h2 in the public key. */
  publicPoints(name: 'g' | 'h1' | 'h2'): EllipticCurvePoint[] {
    return (this.keys.public_key![name] as readonly StoredPoint[]).map(
      (point) =>
        point === null
          ? this.ec.O
          : new EllipticCurvePoint(point[0], point[1], this.ec.curve)
    );
  }

  /** Tensor product of two vectors of points with the pairing: `e(C_i, C'_j)` for all i, j. */
  private pair(
    points1: readonly EllipticCurvePoint[],
    points2: readonly EllipticCurvePoint[]
  ): FP2[] {
    const result: FP2[] = [];
    for (const x of points1) {
      for (const y of points2) {
        result.push(
          x.isIdentity() || y.isIdentity()
            ? FP2.one()
            : this.ec.pairingFP2(x, y)
        );
      }
    }
    return result;
  }

  private scale(point: EllipticCurvePoint, scalar: bigint): EllipticCurvePoint {
    return scale(this.ec, point, scalar, this.order());
  }

  private order(): bigint {
    return this.keys.public_key!.r as bigint;
  }

  private limit(): bigint {
    return BigInt(this.keys.public_key!.limit as bigint);
  }

  /**
   * Finds m in `[-limit, limit]` such that `target = m pi(g)` with baby-step
   * giant-step.
   */
  private discreteLogCurve(target: EllipticCurvePoint): bigint {
    const limit = this.limit();
    if (this.curveTable === undefined) {
      const base = this.project(this.publicPoints('g'));
      const size = isqrt(2n * limit) + ONE;
      const babySteps = new Map<string, bigint>();
      let current = this.ec.O;
      for (let j = ZERO; j < size; j++) {
        const key = pointKey(current);
        if (!babySteps.has(key)) {
          babySteps.set(key, j);
        }
        current = current.add(base);
      }
      // giant step is -size * base, and the search starts from
      // target + limit * base
      this.curveTable = {
        base,
        size,
        babySteps,
        giantStep: this.scale(base, -size),
      };
    }

    const { base, size, babySteps, giantStep } = this.curveTable;
    let current = target.add(this.scale(base, limit));
    for (let i = ZERO; i <= size; i++) {
      const j = babySteps.get(pointKey(current));
      if (j !== undefined && abs(i * size + j - limit) <= limit) {
        return i * size + j - limit;
      }
      current = current.add(giantStep);
    }
    throw outOfLimit(limit);
  }

  /**
   * Finds m in `[-limit, limit]` such that `target = e(pi(g), pi(g))^m` with
   * baby-step giant-step.
   */
  private discreteLogGT(target: FP2): bigint {
    const p = this.ec.modulo;
    const limit = this.limit();
    if (this.gtTable === undefined) {
      const projectedG = this.project(this.publicPoints('g'));
      const base = this.ec.pairingFP2(projectedG, projectedG);
      const size = isqrt(2n * limit) + ONE;
      const babySteps = new Map<string, bigint>();
      let current = FP2.one();
      for (let j = ZERO; j < size; j++) {
        const key = current.toString();
        if (!babySteps.has(key)) {
          babySteps.set(key, j);
        }
        current = current.mul(base, p);
      }
      this.gtTable = {
        base,
        size,
        babySteps,
        giantStep: base.exp(size, p).inverse(p),
      };
    }

    const { base, size, babySteps, giantStep } = this.gtTable;
    let current = target.mul(base.exp(limit, p), p);
    for (let i = ZERO; i <= size; i++) {
      const j = babySteps.get(current.toString());
      if (j !== undefined && abs(i * size + j - limit) <= limit) {
        return i * size + j - limit;
      }
      current = current.mul(giantStep, p);
    }
    throw outOfLimit(limit);
  }
}

function outOfLimit(limit: bigint): Error {
  return new Error(
    `Decryption failed, because result is out of [-${limit}, ${limit}]. ` +
      'Set a greater plaintextLimit while building the cryptosystem.'
  );
}

/**
 * Scalar multiplication handling the point at infinity. It runs in Jacobian
 * coordinates, which need a single modular inversion instead of one per step.
 */
function scale(
  ec: LightECC,
  point: EllipticCurvePoint,
  scalar: bigint,
  r: bigint
): EllipticCurvePoint {
  const k = mod(scalar, r);
  if (k === ZERO || point.isIdentity()) {
    return ec.O;
  }

  const p = ec.modulo;
  const a = ec.curve.a;
  const { x, y } = point;

  // (X : Y : Z) represents (X / Z^2, Y / Z^3), and Z = 0 is the point at infinity
  let [rx, ry, rz] = [x, y, ONE];
  for (let i = k.toString(2).length - 2; i >= 0; i--) {
    [rx, ry, rz] = doubleJacobian(rx, ry, rz, a, p);
    if ((k >> BigInt(i)) & ONE) {
      [rx, ry, rz] = addAffine(rx, ry, rz, x, y, a, p);
    }
  }

  if (rz === ZERO) {
    return ec.O;
  }
  const zInv = modInverse(rz, p);
  const zInv2 = (zInv * zInv) % p;
  return new EllipticCurvePoint(
    (rx * zInv2) % p,
    (ry * zInv2 * zInv) % p,
    ec.curve
  );
}

type JacobianPoint = [bigint, bigint, bigint];

function doubleJacobian(
  x: bigint,
  y: bigint,
  z: bigint,
  a: bigint,
  p: bigint
): JacobianPoint {
  if (z === ZERO || y === ZERO) {
    return [ONE, ONE, ZERO];
  }
  const y2 = (y * y) % p;
  const s = (4n * x * y2) % p;
  const z2 = (z * z) % p;
  const m = (3n * x * x + a * z2 * z2) % p;
  const x3 = mod(m * m - 2n * s, p);
  const y3 = mod(m * (s - x3) - 8n * y2 * y2, p);
  const z3 = (2n * y * z) % p;
  return [x3, y3, z3];
}

/** Adds an affine point `(x2, y2)` to a Jacobian point. */
function addAffine(
  x1: bigint,
  y1: bigint,
  z1: bigint,
  x2: bigint,
  y2: bigint,
  a: bigint,
  p: bigint
): JacobianPoint {
  if (z1 === ZERO) {
    return [x2, y2, ONE];
  }
  const z1Squared = (z1 * z1) % p;
  const u2 = (x2 * z1Squared) % p;
  const s2 = (y2 * z1Squared * z1) % p;
  const h = mod(u2 - x1, p);
  const r = mod(s2 - y1, p);
  if (h === ZERO) {
    return r === ZERO ? doubleJacobian(x1, y1, z1, a, p) : [ONE, ONE, ZERO];
  }
  const h2 = (h * h) % p;
  const h3 = (h2 * h) % p;
  const x1h2 = (x1 * h2) % p;
  const x3 = mod(r * r - h3 - 2n * x1h2, p);
  const y3 = mod(r * (x1h2 - x3) - y1 * h3, p);
  const z3 = (z1 * h) % p;
  return [x3, y3, z3];
}

function storePoint(point: EllipticCurvePoint): StoredPoint {
  return point.isIdentity() ? null : point.getPoint();
}

function pointKey(point: EllipticCurvePoint): string {
  return point.toString();
}

function isMultiplied(ciphertext: readonly CiphertextValue[]): boolean {
  return ciphertext.length === DIMENSION * DIMENSION;
}

function dot(x: readonly bigint[], y: readonly bigint[]): bigint {
  return x.reduce((acc, value, i) => acc + value * y[i], ZERO);
}

/** Random vector x in `Z_r^3` such that `v . x = 0 mod r`. */
function randomOrthogonal(v: readonly bigint[], r: bigint): bigint[] {
  const x1 = randomBelow(r);
  const x2 = randomBelow(r);
  const x3 = mod(-(v[0] * x1 + v[1] * x2) * modInverse(v[2], r), r);
  return [x1, x2, x3];
}

/** Supersingular curve `y^2 = x^3 + x` over `F_p` whose generator has prime order r. */
function buildCurve(
  p: bigint,
  r: bigint,
  point: readonly [bigint, bigint]
): LightECC {
  return new LightECC({
    formName: 'weierstrass',
    curveName: 'custom',
    config: { a: ONE, b: ZERO, p, G: [point[0], point[1]], n: r },
  });
}
