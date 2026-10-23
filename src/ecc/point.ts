/**
 * Affine points and the curve interface they live on.
 *
 * Points are immutable: every operation allocates its result, so a curve can be
 * shared freely.
 */

import { bitLength, mod, ZERO, ONE } from '../commons/mathUtils.js';
import type { CurveForm } from './curves/index.js';

/** The arithmetic backend for a single elliptic curve. */
export interface Curve {
  /** The curve identifier, for example `secp256k1`. */
  readonly name: string;

  /** Which equation shape the curve uses. */
  readonly form: CurveForm;

  /**
   * The field modulus: the prime `p` for prime fields, or the reduction
   * polynomial packed into an integer for binary fields.
   */
  readonly modulo: bigint;

  /** The order `n` of the base point. */
  readonly n: bigint;

  /** The first equation coefficient. */
  readonly a: bigint;

  /** The second Weierstrass or Koblitz coefficient. */
  readonly b: bigint;

  /** The twisted Edwards coefficient. */
  readonly d: bigint;

  /**
   * The neutral element: the point at infinity for Weierstrass and Koblitz
   * curves, `(0, 1)` for Edwards curves.
   */
  identity(): EllipticCurvePoint;

  /** The generator `G`. */
  base(): EllipticCurvePoint;

  /** Reports whether `p` satisfies the curve equation. */
  isOnCurve(p: EllipticCurvePoint): boolean;

  /** Returns `p + q`. */
  add(p: EllipticCurvePoint, q: EllipticCurvePoint): EllipticCurvePoint;

  /** Returns `2p`. */
  double(p: EllipticCurvePoint): EllipticCurvePoint;

  /** Returns `-p`. */
  negate(p: EllipticCurvePoint): EllipticCurvePoint;
}

/** An affine point on an elliptic curve. */
export class EllipticCurvePoint {
  readonly x: bigint;
  readonly y: bigint;
  readonly infinity: boolean;
  readonly curve: Curve;

  constructor(
    x: bigint,
    y: bigint,
    curve: Curve,
    infinity = false,
    validate = false
  ) {
    this.x = x;
    this.y = y;
    this.curve = curve;
    this.infinity = infinity;
    if (validate && !curve.isOnCurve(this)) {
      throw new Error(`(${x}, ${y}) is not on curve ${curve.name}`);
    }
  }

  /** Builds a point after checking that it satisfies the curve equation. */
  static create(x: bigint, y: bigint, curve: Curve): EllipticCurvePoint {
    return new EllipticCurvePoint(x, y, curve, false, true);
  }

  /**
   * Rebuilds a point from the coordinates `getPoint()` returned. The point at
   * infinity of Weierstrass and Koblitz curves comes back as `(0, 0)`, which is
   * never an affine point on them, so it is restored to the identity.
   */
  static restore(x: bigint, y: bigint, curve: Curve): EllipticCurvePoint {
    const identity = curve.identity();
    if (identity.infinity && x === identity.x && y === identity.y) {
      return identity;
    }
    return new EllipticCurvePoint(x, y, curve);
  }

  /** Reports whether this is the neutral element of its curve. */
  isIdentity(): boolean {
    return this.equals(this.curve.identity());
  }

  /**
   * Reports whether two points have the same coordinates. Points on different
   * curves are never equal.
   */
  equals(other: EllipticCurvePoint): boolean {
    if (!sameCurve(this.curve, other.curve)) {
      return false;
    }
    if (this.infinity || other.infinity) {
      return this.infinity === other.infinity;
    }
    return this.x === other.x && this.y === other.y;
  }

  /** Returns `this + other`. */
  add(other: EllipticCurvePoint): EllipticCurvePoint {
    if (!sameCurve(this.curve, other.curve)) {
      throw new Error('points are not on the same curve');
    }
    return this.curve.add(this, other);
  }

  /** Returns `this - other`. */
  sub(other: EllipticCurvePoint): EllipticCurvePoint {
    return this.add(other.negate());
  }

  /** Returns `-this`. */
  negate(): EllipticCurvePoint {
    return this.curve.negate(this);
  }

  /** Returns `2 * this`. */
  double(): EllipticCurvePoint {
    return this.curve.double(this);
  }

  /**
   * Returns `k * this` by left-to-right double-and-add.
   *
   * The scalar is first reduced modulo the curve order; a negative scalar
   * negates the result.
   */
  multiply(k: bigint): EllipticCurvePoint {
    const curve = this.curve;
    let scalar = k;

    if (curve.n > ZERO) {
      const magnitude = scalar < ZERO ? -scalar : scalar;
      if (magnitude >= curve.n) {
        scalar = mod(scalar, curve.n);
      }
    }
    if (scalar === ZERO) {
      return curve.identity();
    }
    if (scalar < ZERO) {
      return this.multiply(-scalar).negate();
    }

    let acc: EllipticCurvePoint = this;
    for (let i = bitLength(scalar) - 2; i >= 0; i--) {
      acc = curve.double(acc);
      if ((scalar >> BigInt(i)) & ONE) {
        acc = curve.add(acc, this);
      }
    }
    return acc;
  }

  /**
   * Recovers `k` from `this = k * base` by exhaustive search — the discrete
   * logarithm the security of every elliptic curve scheme rests on. It is only
   * tractable here because homomorphic schemes keep their plaintexts small.
   */
  divide(base: EllipticCurvePoint, limit?: bigint): bigint {
    if (this.isIdentity()) {
      return ZERO;
    }
    if (this.equals(base)) {
      return ONE;
    }

    let acc = base;
    let k = ONE;
    for (;;) {
      k += ONE;
      if (limit !== undefined && k > limit) {
        throw new Error(
          `could not recover the scalar behind ${this.toString()} within ${limit} steps`
        );
      }
      acc = acc.add(base);
      if (acc.equals(this)) {
        return k;
      }
      if (acc.isIdentity()) {
        throw new Error(
          `could not recover the scalar behind ${this.toString()}: the subgroup was exhausted`
        );
      }
    }
  }

  /** Returns the affine coordinates as a `[x, y]` pair. */
  getPoint(): [bigint, bigint] {
    return [this.x, this.y];
  }

  toString(): string {
    return this.infinity ? 'O' : `(${this.x}, ${this.y})`;
  }
}

/**
 * Compares two curves by their defining parameters rather than by identity, so
 * a point keeps working after its curve has been rebuilt from the same config.
 */
export function sameCurve(a: Curve, b: Curve): boolean {
  if (a === b) {
    return true;
  }
  return (
    a.form === b.form &&
    a.modulo === b.modulo &&
    a.n === b.n &&
    a.a === b.a &&
    a.b === b.b &&
    a.d === b.d
  );
}
