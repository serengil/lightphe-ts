/**
 * Pairings computed with Miller's algorithm on short Weierstrass curves.
 *
 * Two flavours are implemented:
 *
 * - the Weil pairing over `F_p`, for curves whose full `r`-torsion already
 *   lives in `E(F_p)`;
 * - the modified Tate pairing over `F_{p^2}` with the distortion map
 *   `phi(x, y) = (-x, i*y)`, for supersingular curves `y^2 = x^3 + a*x` with
 *   embedding degree 2. This is the flavour Boneh-Goh-Nissim needs.
 *
 * The pairing `e_r(P, Q)` maps two `r`-torsion points to an `r`-th root of
 * unity and is bilinear: `e(aP, bQ) = e(P, Q)^(ab)`.
 *
 * Reference: Washington, *Elliptic Curves: Number Theory and Cryptography*,
 * chapter 11.
 */

import {
  bitLength,
  mod,
  modInverse,
  ZERO,
  ONE,
  TWO,
} from '../commons/mathUtils.js';
import { FP2 } from './fp2.js';
import { Curve, EllipticCurvePoint, sameCurve } from './point.js';

const THREE = 3n;
const FOUR = 4n;

/**
 * The outcome of a pairing computation.
 *
 * Supersingular curves with embedding degree 2 land in the quadratic extension
 * and set `extended`; every other curve returns a base field element.
 */
export interface PairingResult {
  readonly extended: boolean;
  readonly base?: bigint;
  readonly value?: FP2;
}

/**
 * Reports whether the curve is `y^2 = x^3 + a*x` with `a != 0` over a field
 * with `p = 3 (mod 4)`. Such curves are supersingular with embedding degree 2.
 */
export function isSupersingularEmbedding2(curve: Curve): boolean {
  if (curve.form !== 'weierstrass') {
    return false;
  }
  if (curve.b !== ZERO || curve.a === ZERO) {
    return false;
  }
  return mod(curve.modulo, FOUR) === THREE;
}

/**
 * Computes `e_r(p, q)` for the torsion order `r`, dispatching between the Weil
 * and the modified Tate pairing based on the curve.
 */
export function pairing(
  p: EllipticCurvePoint,
  q: EllipticCurvePoint,
  r: bigint
): PairingResult {
  const curve = p.curve;
  if (curve.form !== 'weierstrass') {
    throw new Error('pairings need a weierstrass curve');
  }
  if (!sameCurve(curve, q.curve)) {
    throw new Error('points are not on the same curve');
  }
  if (p.isIdentity() || q.isIdentity()) {
    return { extended: false, base: ONE };
  }

  const modulus = curve.modulo;

  // When r divides p-1 the full r-torsion is already rational over F_p and the
  // plain Weil pairing suffices, so only take the extension path when it is not.
  const pMinusOne = modulus - ONE;
  if (isSupersingularEmbedding2(curve) && mod(pMinusOne, r) !== ZERO) {
    // P == Q is allowed here: the distortion map moves Q off the subgroup
    // spanned by P, so e(P, phi(P)) stays non-degenerate.
    requireTorsion(p, r, 'P');
    if (!p.equals(q)) {
      requireTorsion(q, r, 'Q');
    }
    return { extended: true, value: tatePairingSupersingular(p, q, r) };
  }

  if (p.equals(q)) {
    // The Weil pairing is alternating.
    return { extended: false, base: ONE };
  }
  requireTorsion(p, r, 'P');
  requireTorsion(q, r, 'Q');

  return { extended: false, base: weilPairing(p, q, r) };
}

function requireTorsion(p: EllipticCurvePoint, r: bigint, label: string): void {
  if (!p.multiply(r).isIdentity()) {
    throw new Error(`${label} = ${p.toString()} is not an ${r}-torsion point`);
  }
}

/* -------------------------------------------------------------------------- */
/* Weil pairing over F_p                                                       */
/* -------------------------------------------------------------------------- */

/**
 * Evaluates the Miller line function
 * `g_{T,P}(R) = l_{T,P}(R) / v_{T+P}(R)` in `F_p`.
 */
function lineEval(
  t: EllipticCurvePoint,
  p: EllipticCurvePoint,
  r: EllipticCurvePoint
): bigint {
  if (t.isIdentity() || p.isIdentity() || r.isIdentity()) {
    return ONE;
  }
  const modulus = t.curve.modulo;

  const sum = t.add(p);
  if (sum.isIdentity()) {
    // Vertical line through T.
    return mod(r.x - t.x, modulus);
  }

  const lambda = slope(t, p);

  // numerator = yR - yT - lambda*(xR - xT)
  const num = mod(r.y - t.y - lambda * (r.x - t.x), modulus);

  // denominator = xR - x_{T+P}
  const den = mod(r.x - sum.x, modulus);
  if (den === ZERO) {
    return num !== ZERO ? num : ONE;
  }

  return mod(num * modInverse(den, modulus), modulus);
}

/**
 * Returns the slope of the chord through `t` and `p`, or of the tangent at `t`
 * when the two points coincide.
 */
function slope(t: EllipticCurvePoint, p: EllipticCurvePoint): bigint {
  const curve = t.curve;
  const modulus = curve.modulo;

  let num: bigint;
  let den: bigint;
  if (t.equals(p)) {
    num = THREE * t.x * t.x + curve.a;
    den = t.y * TWO;
  } else {
    num = p.y - t.y;
    den = p.x - t.x;
  }
  return mod(num * modInverse(mod(den, modulus), modulus), modulus);
}

/** Computes `f_{r,P}(R)` over `F_p`. */
function miller(
  p: EllipticCurvePoint,
  r: EllipticCurvePoint,
  order: bigint
): bigint {
  if (p.isIdentity() || r.isIdentity()) {
    return ONE;
  }
  const modulus = p.curve.modulo;

  let f = ONE;
  let t = p;

  for (let i = bitLength(order) - 2; i >= 0; i--) {
    if (t.isIdentity()) {
      f = mod(f * f, modulus);
    } else {
      const g = lineEval(t, t, r);
      f = mod(f * f * g, modulus);
      t = t.add(t);
    }

    if ((order >> BigInt(i)) & ONE) {
      if (t.isIdentity()) {
        t = p;
      } else {
        f = mod(f * lineEval(t, p, r), modulus);
        t = t.add(p);
      }
    }
  }
  return mod(f, modulus);
}

/**
 * Picks a point `S` that avoids the degenerate cases of the Weil pairing
 * computation.
 */
function auxiliaryPoint(
  p: EllipticCurvePoint,
  q: EllipticCurvePoint
): EllipticCurvePoint {
  const curve = p.curve;
  const g = curve.base();

  const bad = [p, p.negate(), q, q.negate(), p.sub(q), q.sub(p), p.add(q)];

  let limit = 1000;
  if (curve.n > ZERO && curve.n < BigInt(limit)) {
    limit = Number(curve.n);
  }

  let s = curve.identity();
  for (let k = 1; k < limit; k++) {
    s = s.add(g);
    if (s.isIdentity()) {
      continue;
    }
    if (bad.some((point) => s.equals(point))) {
      continue;
    }
    if (q.add(s).isIdentity() || p.sub(s).isIdentity()) {
      continue;
    }
    return s;
  }
  throw new Error(
    `no suitable auxiliary point for the Weil pairing on ${curve.name}`
  );
}

/** Computes the standard Weil pairing over `F_p`. */
function weilPairing(
  p: EllipticCurvePoint,
  q: EllipticCurvePoint,
  r: bigint
): bigint {
  const modulus = p.curve.modulo;

  const s = auxiliaryPoint(p, q);
  const negS = s.negate();
  const qPlusS = q.add(s);
  const pMinusS = p.sub(s);

  const fpQpS = miller(p, qPlusS, r);
  const fpS = miller(p, s, r);
  const fqPmS = miller(q, pMinusS, r);
  const fqNegS = miller(q, negS, r);

  if (fpS === ZERO || fqPmS === ZERO) {
    throw new Error('degenerate Weil pairing, try different input points');
  }

  const num = mod(fpQpS * fqNegS, modulus);
  const den = mod(fpS * fqPmS, modulus);
  return mod(num * modInverse(den, modulus), modulus);
}

/* -------------------------------------------------------------------------- */
/* Modified Tate pairing over F_{p^2}                                          */
/* -------------------------------------------------------------------------- */

/**
 * Evaluates the Miller line function at a point whose coordinates live in
 * `F_{p^2}`.
 */
function lineEvalFP2(
  t: EllipticCurvePoint,
  p: EllipticCurvePoint,
  xr: FP2,
  yr: FP2
): FP2 {
  if (t.isIdentity() || p.isIdentity()) {
    return FP2.one();
  }
  const modulus = t.curve.modulo;

  const sum = t.add(p);
  if (sum.isIdentity()) {
    return xr.sub(FP2.fromBase(t.x), modulus);
  }

  const lambda = slope(t, p);

  // numerator = yR - yT - lambda*(xR - xT)
  const num = yr
    .sub(FP2.fromBase(t.y), modulus)
    .sub(
      FP2.fromBase(lambda).mul(xr.sub(FP2.fromBase(t.x), modulus), modulus),
      modulus
    );

  const den = xr.sub(FP2.fromBase(sum.x), modulus);
  if (den.isZero()) {
    return num.isZero() ? FP2.one() : num;
  }
  return num.mul(den.inverse(modulus), modulus);
}

/** Computes `f_{r,P}(R)` where `R` has coordinates in `F_{p^2}`. */
function millerFP2(p: EllipticCurvePoint, xr: FP2, yr: FP2, r: bigint): FP2 {
  if (p.isIdentity()) {
    return FP2.one();
  }
  const modulus = p.curve.modulo;

  let f = FP2.one();
  let t = p;

  for (let i = bitLength(r) - 2; i >= 0; i--) {
    if (t.isIdentity()) {
      f = f.mul(f, modulus);
    } else {
      const g = lineEvalFP2(t, t, xr, yr);
      f = f.mul(f, modulus).mul(g, modulus);
      t = t.add(t);
    }

    if ((r >> BigInt(i)) & ONE) {
      if (t.isIdentity()) {
        t = p;
      } else {
        f = f.mul(lineEvalFP2(t, p, xr, yr), modulus);
        t = t.add(p);
      }
    }
  }
  return f;
}

/**
 * Computes `e_r(P, Q) = f_{r,P}(phi(Q))^((p^2-1)/r)` for a supersingular curve
 * with the distortion map `phi(x, y) = (-x, i*y)`.
 */
function tatePairingSupersingular(
  p: EllipticCurvePoint,
  q: EllipticCurvePoint,
  r: bigint
): FP2 {
  const modulus = p.curve.modulo;

  // phi(Q) = (-x_Q, i*y_Q)
  const xPhi = new FP2(mod(-q.x, modulus), ZERO);
  const yPhi = new FP2(ZERO, mod(q.y, modulus));

  const f = millerFP2(p, xPhi, yPhi, r);

  // Final exponentiation with (p^2 - 1) / r.
  const exponent = (modulus * modulus - ONE) / r;
  return f.exp(exponent, modulus);
}
