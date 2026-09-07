/** Parameter shapes for the bundled elliptic curve inventory. */

/** The shape of a curve equation. */
export type CurveForm = 'weierstrass' | 'edwards' | 'koblitz';

/** Parameters of `y^2 = x^3 + a*x + b` over `F_p`. */
export interface WeierstrassParams {
  readonly name: string;
  readonly a: bigint;
  readonly b: bigint;
  readonly p: bigint;
  readonly gx: bigint;
  readonly gy: bigint;
  readonly n: bigint;
}

/** Parameters of `a*x^2 + y^2 = 1 + d*x^2*y^2` over `F_p`. */
export interface EdwardsParams {
  readonly name: string;
  readonly a: bigint;
  readonly d: bigint;
  readonly p: bigint;
  readonly gx: bigint;
  readonly gy: bigint;
  readonly n: bigint;
}

/**
 * Parameters of `y^2 + x*y = x^3 + a*x^2 + b` over `F_{2^m}`.
 *
 * `coefficients` lists the exponents of the set bits of the reduction
 * polynomial, most significant first.
 */
export interface KoblitzParams {
  readonly name: string;
  readonly m: number;
  readonly coefficients: readonly number[];
  readonly a: bigint;
  readonly b: bigint;
  readonly gx: bigint;
  readonly gy: bigint;
  readonly n: bigint;
}
