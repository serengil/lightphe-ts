/**
 * The curve inventory: standard parameter sets grouped by curve form.
 *
 * The tables are read-only, and lookups hand back the stored object rather than
 * a copy, so callers must not mutate what they get.
 */

import { WEIERSTRASS_CURVES } from './weierstrassData.js';
import { EDWARDS_CURVES } from './edwardsData.js';
import { KOBLITZ_CURVES } from './koblitzData.js';
import type {
  CurveForm,
  EdwardsParams,
  KoblitzParams,
  WeierstrassParams,
} from './types.js';

export type {
  CurveForm,
  EdwardsParams,
  KoblitzParams,
  WeierstrassParams,
} from './types.js';
export { WEIERSTRASS_CURVES } from './weierstrassData.js';
export { EDWARDS_CURVES } from './edwardsData.js';
export { KOBLITZ_CURVES } from './koblitzData.js';

/** Every supported curve form. */
export const FORMS: readonly CurveForm[] = [
  'weierstrass',
  'edwards',
  'koblitz',
];

/** The curve each form falls back to when none is named. */
export const DEFAULT_CURVES: Readonly<Record<CurveForm, string>> = {
  weierstrass: 'secp256k1',
  edwards: 'ed25519',
  koblitz: 'k163',
};

/** Returns the curve used when a form is selected without naming a curve. */
export function defaultCurve(form: CurveForm): string {
  const name = DEFAULT_CURVES[form];
  if (name === undefined) {
    throw new Error(`unsupported curve form "${form}"`);
  }
  return name;
}

/** Returns the named short Weierstrass curve. */
export function lookupWeierstrass(name: string): WeierstrassParams {
  const params = WEIERSTRASS_CURVES.find((curve) => curve.name === name);
  if (params === undefined) {
    throw new Error(`unsupported weierstrass curve "${name}"`);
  }
  return params;
}

/** Returns the named twisted Edwards curve. */
export function lookupEdwards(name: string): EdwardsParams {
  const params = EDWARDS_CURVES.find((curve) => curve.name === name);
  if (params === undefined) {
    throw new Error(`unsupported edwards curve "${name}"`);
  }
  return params;
}

/** Returns the named Koblitz curve. */
export function lookupKoblitz(name: string): KoblitzParams {
  const params = KOBLITZ_CURVES.find((curve) => curve.name === name);
  if (params === undefined) {
    throw new Error(`unsupported koblitz curve "${name}"`);
  }
  return params;
}

/** Returns the sorted names of every curve available for a form. */
export function listCurves(form: CurveForm): string[] {
  switch (form) {
    case 'weierstrass':
      return WEIERSTRASS_CURVES.map((curve) => curve.name).sort();
    case 'edwards':
      return EDWARDS_CURVES.map((curve) => curve.name).sort();
    case 'koblitz':
      return KOBLITZ_CURVES.map((curve) => curve.name).sort();
    default:
      throw new Error(`unsupported curve form "${String(form)}"`);
  }
}
