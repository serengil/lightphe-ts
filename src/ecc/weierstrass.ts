/** Short Weierstrass curves: `y^2 = x^3 + a*x + b` over the prime field `F_p`. */

import { mod, modInverse, modPow, ZERO, TWO } from '../commons/mathUtils.js';
import { defaultCurve, lookupWeierstrass } from './curves/index.js';
import type { CurveForm } from './curves/index.js';
import { Curve, EllipticCurvePoint } from './point.js';

const THREE = 3n;

export class WeierstrassCurve implements Curve {
  readonly name: string;
  readonly form: CurveForm = 'weierstrass';
  readonly a: bigint;
  readonly b: bigint;
  readonly d: bigint = ZERO;
  readonly modulo: bigint;
  readonly n: bigint;
  private readonly gx: bigint;
  private readonly gy: bigint;

  constructor(params: {
    name: string;
    a: bigint;
    b: bigint;
    p: bigint;
    gx: bigint;
    gy: bigint;
    n: bigint;
  }) {
    this.name = params.name;
    this.modulo = params.p;
    this.a = mod(params.a, params.p);
    this.b = mod(params.b, params.p);
    this.gx = mod(params.gx, params.p);
    this.gy = mod(params.gy, params.p);
    this.n = params.n;
  }

  /** Builds a named curve from the bundled inventory. */
  static named(name?: string | null): WeierstrassCurve {
    const resolved =
      name === undefined || name === null || name === ''
        ? defaultCurve('weierstrass')
        : name;
    return new WeierstrassCurve(lookupWeierstrass(resolved));
  }

  /**
   * Builds a curve from explicit parameters. Boneh-Goh-Nissim uses this to
   * generate a fresh supersingular curve for every key pair.
   */
  static custom(
    a: bigint,
    b: bigint,
    p: bigint,
    g: [bigint, bigint],
    n: bigint
  ): WeierstrassCurve {
    if (p <= ZERO) {
      throw new Error('a custom weierstrass curve needs a positive modulus');
    }
    return new WeierstrassCurve({
      name: 'custom',
      a,
      b,
      p,
      gx: g[0],
      gy: g[1],
      n,
    });
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
    const lhs = mod(p.y * p.y, this.modulo);
    const rhs = mod(
      modPow(p.x, THREE, this.modulo) + this.a * p.x + this.b,
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

    // beta = (y2 - y1) / (x2 - x1)
    const dx = mod(q.x - p.x, this.modulo);
    const beta = mod((q.y - p.y) * modInverse(dx, this.modulo), this.modulo);
    return this.fromSlope(beta, p, q.x);
  }

  double(p: EllipticCurvePoint): EllipticCurvePoint {
    if (p.infinity || p.y === ZERO) {
      return this.identity();
    }

    // beta = (3*x^2 + a) / (2*y)
    const den = mod(p.y * TWO, this.modulo);
    const beta = mod(
      (THREE * p.x * p.x + this.a) * modInverse(den, this.modulo),
      this.modulo
    );
    return this.fromSlope(beta, p, p.x);
  }

  /**
   * Finishes a chord or tangent computation:
   * `x3 = beta^2 - x1 - x2`, `y3 = beta*(x1 - x3) - y1`.
   */
  private fromSlope(
    beta: bigint,
    p: EllipticCurvePoint,
    x2: bigint
  ): EllipticCurvePoint {
    const x3 = mod(beta * beta - p.x - x2, this.modulo);
    const y3 = mod(beta * (p.x - x3) - p.y, this.modulo);

    const result = new EllipticCurvePoint(x3, y3, this);
    if (!this.isOnCurve(result)) {
      throw new Error(
        `computed ${result.toString()} which is off curve ${this.name}`
      );
    }
    return result;
  }

  negate(p: EllipticCurvePoint): EllipticCurvePoint {
    if (p.infinity) {
      return p;
    }
    return new EllipticCurvePoint(p.x, mod(-p.y, this.modulo), this);
  }
}
