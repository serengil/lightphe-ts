/**
 * Koblitz curves: `y^2 + x*y = x^3 + a*x^2 + b` over the binary field
 * `F_{2^m}`.
 *
 * Field elements are polynomials packed into `bigint`s and reduced modulo the
 * irreducible polynomial derived from the curve's coefficient list.
 */

import { ZERO, ONE } from '../commons/mathUtils.js';
import {
  binAdd,
  binDivide,
  binExp,
  binMod,
  binMul,
  binSquare,
} from './binary.js';
import { defaultCurve, lookupKoblitz } from './curves/index.js';
import type { CurveForm } from './curves/index.js';
import { Curve, EllipticCurvePoint } from './point.js';

export class KoblitzCurve implements Curve {
  readonly name: string;
  readonly form: CurveForm = 'koblitz';
  readonly a: bigint;
  readonly b: bigint;
  readonly d: bigint = ZERO;
  readonly modulo: bigint;
  readonly n: bigint;
  readonly m: number;
  readonly coefficients: readonly number[];
  private readonly gx: bigint;
  private readonly gy: bigint;

  constructor(params: {
    name: string;
    m: number;
    coefficients: readonly number[];
    a: bigint;
    b: bigint;
    gx: bigint;
    gy: bigint;
    n: bigint;
  }) {
    this.name = params.name;
    this.m = params.m;
    this.coefficients = params.coefficients;
    this.a = params.a;
    this.b = params.b;
    this.gx = params.gx;
    this.gy = params.gy;
    this.n = params.n;

    // The reduction polynomial has a set bit at every listed exponent.
    let modulo = ZERO;
    for (const exponent of params.coefficients) {
      modulo |= ONE << BigInt(exponent);
    }
    this.modulo = modulo;

    if (!this.isOnCurve(this.base())) {
      throw new Error(`base point of ${params.name} is off the curve`);
    }
  }

  /** Builds a named curve from the bundled inventory. */
  static named(name?: string | null): KoblitzCurve {
    const resolved =
      name === undefined || name === null || name === ''
        ? defaultCurve('koblitz')
        : name;
    return new KoblitzCurve(lookupKoblitz(resolved));
  }

  identity(): EllipticCurvePoint {
    return new EllipticCurvePoint(ZERO, ZERO, this, true);
  }

  base(): EllipticCurvePoint {
    return new EllipticCurvePoint(this.gx, this.gy, this);
  }

  isOnCurve(p: EllipticCurvePoint): boolean {
    if (p.infinity) {
      return true;
    }
    const lhs = binMod(binAdd(binSquare(p.y), binMul(p.x, p.y)), this.modulo);
    const rhs = binMod(
      binAdd(
        binAdd(binExp(p.x, 3, this.modulo), binMul(this.a, binSquare(p.x))),
        this.b
      ),
      this.modulo
    );
    return lhs === rhs;
  }

  add(p: EllipticCurvePoint, q: EllipticCurvePoint): EllipticCurvePoint {
    if (p.infinity) {
      return q;
    }
    if (q.infinity) {
      return p;
    }
    if (p.equals(this.negate(q))) {
      return this.identity();
    }
    if (p.equals(q)) {
      return this.double(p);
    }
    if (p.x === q.x) {
      return this.identity();
    }

    // beta = (y1 + y2) / (x1 + x2), where + is XOR
    const beta = binDivide(binAdd(p.y, q.y), binAdd(p.x, q.x), this.modulo);
    if (beta === undefined) {
      throw new Error(
        `cannot invert the slope denominator on curve ${this.name}`
      );
    }

    // x3 = beta^2 + beta + x1 + x2 + a
    const x3 = binAdd(
      binAdd(binAdd(binAdd(binSquare(beta), beta), p.x), q.x),
      this.a
    );
    // y3 = beta*(x1 + x3) + x3 + y1
    const y3 = binAdd(binAdd(binMul(binAdd(p.x, x3), beta), x3), p.y);

    return new EllipticCurvePoint(
      binMod(x3, this.modulo),
      binMod(y3, this.modulo),
      this
    );
  }

  double(p: EllipticCurvePoint): EllipticCurvePoint {
    if (p.infinity || p.x === ZERO) {
      return this.identity();
    }
    if (p.equals(this.negate(p))) {
      return this.identity();
    }

    // beta = x1 + y1/x1
    const quotient = binDivide(p.y, p.x, this.modulo);
    if (quotient === undefined) {
      throw new Error(`cannot invert ${p.x} on curve ${this.name}`);
    }
    const beta = binAdd(p.x, quotient);

    // x2 = beta^2 + beta + a
    const x2 = binAdd(binAdd(binSquare(beta), beta), this.a);
    // y2 = x1^2 + beta*x2 + x2
    const y2 = binAdd(binAdd(binSquare(p.x), binMul(beta, x2)), x2);

    return new EllipticCurvePoint(
      binMod(x2, this.modulo),
      binMod(y2, this.modulo),
      this
    );
  }

  /** Over a binary field `-y` is `x XOR y`. */
  negate(p: EllipticCurvePoint): EllipticCurvePoint {
    if (p.infinity) {
      return p;
    }
    return new EllipticCurvePoint(p.x, binAdd(p.x, p.y), this);
  }
}
