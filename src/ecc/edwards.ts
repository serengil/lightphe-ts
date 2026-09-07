/**
 * Twisted Edwards curves: `a*x^2 + y^2 = 1 + d*x^2*y^2` over `F_p`.
 *
 * Unlike the Weierstrass form the addition law is complete, so there is no
 * special case for doubling or for the neutral element `(0, 1)`.
 */

import { mod, modInverse, ZERO, ONE } from '../commons/mathUtils.js';
import { defaultCurve, lookupEdwards } from './curves/index.js';
import type { CurveForm } from './curves/index.js';
import { Curve, EllipticCurvePoint } from './point.js';

export class EdwardsCurve implements Curve {
  readonly name: string;
  readonly form: CurveForm = 'edwards';
  readonly a: bigint;
  readonly b: bigint = ZERO;
  readonly d: bigint;
  readonly modulo: bigint;
  readonly n: bigint;
  private readonly gx: bigint;
  private readonly gy: bigint;

  constructor(params: {
    name: string;
    a: bigint;
    d: bigint;
    p: bigint;
    gx: bigint;
    gy: bigint;
    n: bigint;
  }) {
    this.name = params.name;
    this.modulo = params.p;
    this.a = mod(params.a, params.p);
    this.d = mod(params.d, params.p);
    this.gx = mod(params.gx, params.p);
    this.gy = mod(params.gy, params.p);
    this.n = params.n;
  }

  /** Builds a named curve from the bundled inventory. */
  static named(name?: string | null): EdwardsCurve {
    const resolved =
      name === undefined || name === null || name === ''
        ? defaultCurve('edwards')
        : name;
    return new EdwardsCurve(lookupEdwards(resolved));
  }

  identity(): EllipticCurvePoint {
    return new EllipticCurvePoint(ZERO, ONE, this);
  }

  base(): EllipticCurvePoint {
    return new EllipticCurvePoint(this.gx, this.gy, this);
  }

  isOnCurve(p: EllipticCurvePoint): boolean {
    const x2 = p.x * p.x;
    const y2 = p.y * p.y;
    const lhs = mod(this.a * x2 + y2, this.modulo);
    const rhs = mod(this.d * x2 * y2 + ONE, this.modulo);
    return lhs === rhs;
  }

  /**
   * The complete twisted Edwards addition law:
   * `x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)`,
   * `y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)`.
   */
  add(p: EllipticCurvePoint, q: EllipticCurvePoint): EllipticCurvePoint {
    const common = this.d * p.x * q.x * p.y * q.y;

    const numX = mod(p.x * q.y + p.y * q.x, this.modulo);
    const denX = mod(ONE + common, this.modulo);
    const invX = modInverse(denX, this.modulo);

    const numY = mod(p.y * q.y - this.a * p.x * q.x, this.modulo);
    const denY = mod(ONE - common, this.modulo);
    const invY = modInverse(denY, this.modulo);

    return new EllipticCurvePoint(
      mod(numX * invX, this.modulo),
      mod(numY * invY, this.modulo),
      this
    );
  }

  /** The addition law is complete, so doubling is addition with equal operands. */
  double(p: EllipticCurvePoint): EllipticCurvePoint {
    return this.add(p, p);
  }

  negate(p: EllipticCurvePoint): EllipticCurvePoint {
    return new EllipticCurvePoint(mod(-p.x, this.modulo), p.y, this);
  }
}
