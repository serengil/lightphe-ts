/**
 * Elliptic curve arithmetic over prime and binary fields in short Weierstrass,
 * twisted Edwards and Koblitz form, together with the Weil and modified Tate
 * pairings.
 *
 * This is a self-contained port of the LightECC library; nothing here reaches
 * outside the standard library.
 */

import { ZERO, ONE } from '../commons/mathUtils.js';
import type { CurveForm } from './curves/index.js';
import { defaultCurve, listCurves } from './curves/index.js';
import { EdwardsCurve } from './edwards.js';
import { FP2 } from './fp2.js';
import { KoblitzCurve } from './koblitz.js';
import { pairing, PairingResult } from './pairing.js';
import { Curve, EllipticCurvePoint } from './point.js';
import { WeierstrassCurve } from './weierstrass.js';

export { FP2 } from './fp2.js';
export { EllipticCurvePoint, sameCurve } from './point.js';
export type { Curve } from './point.js';
export { WeierstrassCurve } from './weierstrass.js';
export { EdwardsCurve } from './edwards.js';
export { KoblitzCurve } from './koblitz.js';
export {
  pairing,
  isSupersingularEmbedding2,
  type PairingResult,
} from './pairing.js';
export * from './curves/index.js';

/** Configuration for a curve built from explicit parameters. */
export interface CustomCurveConfig {
  a: bigint;
  b: bigint;
  p: bigint;
  G: [bigint, bigint];
  n: bigint;
}

/**
 * Bundles a curve with its base point, neutral element and order. This is the
 * entry point the cryptosystems use.
 */
export class LightECC {
  readonly curve: Curve;
  readonly G: EllipticCurvePoint;
  readonly O: EllipticCurvePoint;
  readonly n: bigint;
  readonly modulo: bigint;

  /**
   * Builds a curve of the given form. An omitted form defaults to Weierstrass
   * and an omitted curve name defaults to that form's standard curve.
   *
   * Pass `curveName: 'custom'` together with `config` to build a curve from
   * explicit parameters, which is what Boneh-Goh-Nissim does for every key pair.
   */
  constructor(options?: {
    formName?: CurveForm | string | null;
    curveName?: string | null;
    config?: CustomCurveConfig;
  }) {
    const formName = options?.formName;
    const curveName = options?.curveName;
    const config = options?.config;

    const form: CurveForm =
      formName === undefined || formName === null || formName === ''
        ? 'weierstrass'
        : (formName as CurveForm);

    if (curveName === 'custom') {
      if (config === undefined) {
        throw new Error('a custom curve needs a config');
      }
      if (form !== 'weierstrass') {
        throw new Error('custom curves are only supported in weierstrass form');
      }
      this.curve = WeierstrassCurve.custom(
        config.a,
        config.b,
        config.p,
        config.G,
        config.n
      );
    } else {
      switch (form) {
        case 'weierstrass':
          this.curve = WeierstrassCurve.named(curveName);
          break;
        case 'edwards':
          this.curve = EdwardsCurve.named(curveName);
          break;
        case 'koblitz':
          this.curve = KoblitzCurve.named(curveName);
          break;
        default:
          throw new Error(`unsupported curve form "${String(form)}"`);
      }
    }

    this.G = this.curve.base();
    this.O = this.curve.identity();
    this.n = this.curve.n;
    this.modulo = this.curve.modulo;

    if (!this.curve.isOnCurve(this.G)) {
      throw new Error(
        `base point ${this.G.toString()} is off curve ${this.curve.name}`
      );
    }

    // Validate n by computing (n-1)*G + G rather than n*G: scalar
    // multiplication short-circuits when the scalar equals the declared order,
    // which would make the check vacuous.
    if (this.n > ZERO) {
      const total = this.G.multiply(this.n - ONE).add(this.G);
      if (!total.isIdentity()) {
        throw new Error(
          `n*G is not the identity element on curve ${this.curve.name}`
        );
      }
    }
  }

  /** The curve form. */
  get form(): CurveForm {
    return this.curve.form;
  }

  /** The curve name. */
  get name(): string {
    return this.curve.name;
  }

  /** Validates coordinates and returns the corresponding curve point. */
  point(x: bigint, y: bigint): EllipticCurvePoint {
    return EllipticCurvePoint.create(x, y, this.curve);
  }

  /** Computes `e_n(p, q)` with the curve order as the torsion order. */
  pairing(
    p: EllipticCurvePoint,
    q: EllipticCurvePoint,
    r?: bigint
  ): PairingResult {
    return pairing(p, q, r ?? this.n);
  }

  /**
   * Computes a pairing and requires that it land in `F_{p^2}`, which is what
   * Boneh-Goh-Nissim's homomorphic multiplication needs.
   */
  pairingFP2(p: EllipticCurvePoint, q: EllipticCurvePoint, r?: bigint): FP2 {
    const result = this.pairing(p, q, r);
    if (!result.extended || result.value === undefined) {
      throw new Error(
        'Boneh-Goh-Nissim requires a supersingular curve with embedding degree 2. ' +
          'The pairing returned an F_p element instead of an F_{p^2} element.'
      );
    }
    return result.value;
  }
}

/** Lists every curve name available for a form. */
export function listCurveNames(form: CurveForm): string[] {
  return listCurves(form);
}

/** The default curve for a form. */
export function getDefaultCurve(form: CurveForm): string {
  return defaultCurve(form);
}
