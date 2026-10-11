/** Cryptosystem construction, shared by `LightPHE` and `Ciphertext`. */

import type { CurveForm } from '../ecc/index.js';
import { Algorithm, type AlgorithmName } from '../models/Algorithm.js';
import type { Homomorphic } from '../models/Homomorphic.js';
import type { Keys, RequiredKeys } from '../models/types.js';
import { Benaloh } from './Benaloh.js';
import { BonehGohNissim } from './BonehGohNissim.js';
import { CastagnosLaguillaumie } from './CastagnosLaguillaumie.js';
import { DamgardJurik } from './DamgardJurik.js';
import { ElGamal } from './ElGamal.js';
import { EllipticCurveElGamal } from './EllipticCurveElGamal.js';
import { GoldwasserMicali } from './GoldwasserMicali.js';
import { IshaiPaskin } from './IshaiPaskin.js';
import { JoyeLibert } from './JoyeLibert.js';
import { NaccacheStern } from './NaccacheStern.js';
import { OkamotoUchiyama } from './OkamotoUchiyama.js';
import { Paillier } from './Paillier.js';
import { RSA } from './RSA.js';
import { SanderYoungYung } from './SanderYoungYung.js';

export { Benaloh } from './Benaloh.js';
export { BonehGohNissim, type BGNValue } from './BonehGohNissim.js';
export {
  CastagnosLaguillaumie,
  type CLPair,
  type Form,
} from './CastagnosLaguillaumie.js';
export { DamgardJurik } from './DamgardJurik.js';
export { ElGamal } from './ElGamal.js';
export { EllipticCurveElGamal, type ECPair } from './EllipticCurveElGamal.js';
export { GoldwasserMicali } from './GoldwasserMicali.js';
export {
  IshaiPaskin,
  DECISION_TREE_OUTPUT_NOT_SUPPORTED_MSG,
} from './IshaiPaskin.js';
export { JoyeLibert, FLOAT_NOT_SUPPORTED_MSG } from './JoyeLibert.js';
export { NaccacheStern } from './NaccacheStern.js';
export { OkamotoUchiyama } from './OkamotoUchiyama.js';
export { Paillier } from './Paillier.js';
export { RSA } from './RSA.js';
export { SanderYoungYung } from './SanderYoungYung.js';

/** Options accepted when building a cryptosystem. */
export interface BuildOptions {
  keys?: Keys | null;
  keySize?: number | null;
  form?: CurveForm | string | null;
  curve?: string | null;
  plaintextLimit?: number | bigint | null;
  maxTries?: number;
}

/**
 * The required-key spec of each algorithm, keyed by its user-facing name.
 *
 * Exponential ElGamal reuses ElGamal's key structure.
 */
export const REQUIRED_KEYS_BY_ALGORITHM: Readonly<
  Record<string, RequiredKeys>
> = {
  [Algorithm.RSA]: RSA.REQUIRED_KEYS,
  [Algorithm.ElGamal]: ElGamal.REQUIRED_KEYS,
  [Algorithm.ExponentialElGamal]: ElGamal.REQUIRED_KEYS,
  [Algorithm.EllipticCurveElGamal]: EllipticCurveElGamal.REQUIRED_KEYS,
  [Algorithm.Paillier]: Paillier.REQUIRED_KEYS,
  [Algorithm.DamgardJurik]: DamgardJurik.REQUIRED_KEYS,
  [Algorithm.OkamotoUchiyama]: OkamotoUchiyama.REQUIRED_KEYS,
  [Algorithm.Benaloh]: Benaloh.REQUIRED_KEYS,
  [Algorithm.NaccacheStern]: NaccacheStern.REQUIRED_KEYS,
  [Algorithm.GoldwasserMicali]: GoldwasserMicali.REQUIRED_KEYS,
  [Algorithm.SanderYoungYung]: SanderYoungYung.REQUIRED_KEYS,
  [Algorithm.BonehGohNissim]: BonehGohNissim.REQUIRED_KEYS,
  [Algorithm.JoyeLibert]: JoyeLibert.REQUIRED_KEYS,
  [Algorithm.CastagnosLaguillaumie]: CastagnosLaguillaumie.REQUIRED_KEYS,
  [Algorithm.IshaiPaskin]: IshaiPaskin.REQUIRED_KEYS,
};

/**
 * Builds a cryptosystem for the named algorithm.
 *
 * Options that do not apply to the chosen algorithm are ignored, which is what
 * lets callers pass the same bag of settings for any of them.
 */
export function buildCryptosystem(
  algorithmName: AlgorithmName | string,
  options: BuildOptions = {}
): Homomorphic {
  const { keys, keySize, form, curve, plaintextLimit } = options;
  const maxTries = options.maxTries ?? 10000;

  switch (algorithmName) {
    case Algorithm.RSA:
      return new RSA({ keys, keySize, maxTries });
    case Algorithm.ElGamal:
      return new ElGamal({ keys, keySize });
    case Algorithm.ExponentialElGamal:
      return new ElGamal({ keys, keySize, exponential: true });
    case Algorithm.EllipticCurveElGamal:
      return new EllipticCurveElGamal({ keys, keySize, form, curve });
    case Algorithm.Paillier:
      return new Paillier({ keys, keySize });
    case Algorithm.DamgardJurik:
      return new DamgardJurik({ keys, keySize });
    case Algorithm.OkamotoUchiyama:
      return new OkamotoUchiyama({ keys, keySize });
    case Algorithm.Benaloh:
      return new Benaloh({ keys, keySize, plaintextLimit, maxTries });
    case Algorithm.NaccacheStern:
      return new NaccacheStern({ keys, keySize, maxTries });
    case Algorithm.GoldwasserMicali:
      return new GoldwasserMicali({ keys, keySize, maxTries });
    case Algorithm.SanderYoungYung:
      return new SanderYoungYung({ keys, keySize, plaintextLimit });
    case Algorithm.BonehGohNissim:
      return new BonehGohNissim({ keys, keySize, maxTries });
    case Algorithm.JoyeLibert:
      return new JoyeLibert({ keys, keySize, maxTries });
    case Algorithm.CastagnosLaguillaumie:
      return new CastagnosLaguillaumie({ keys, keySize, maxTries });
    case Algorithm.IshaiPaskin:
      return new IshaiPaskin({ keys, keySize });
    default:
      throw new Error(`unimplemented algorithm - ${algorithmName}`);
  }
}
