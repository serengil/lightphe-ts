/** Catalano-Fiore transform adding one multiplication to additive cryptosystems. */

import { mod, randomBelow } from '../commons/mathUtils.js';
import { encode } from '../commons/serialization.js';
import type { CurveForm } from '../ecc/index.js';
import { Algorithm } from './Algorithm.js';
import { Ciphertext } from './Ciphertext.js';
import type { Homomorphic } from './Homomorphic.js';
import type { Keys } from './types.js';

/** Name of the transform as the boost option of LightPHE. */
export const CATALANO_FIORE = 'Catalano-Fiore';

/**
 * Additively homomorphic algorithms whose plaintext space `Z_M` is public, and
 * which can decrypt any value in it.
 */
export const CATALANO_FIORE_SUPPORTED_ALGORITHMS: readonly string[] = [
  Algorithm.Paillier,
  Algorithm.DamgardJurik,
  Algorithm.BressonCatalanoPointcheval,
  Algorithm.CamenischShoup,
  Algorithm.EllipticCurvePaillier,
  Algorithm.JoyeLibert,
  Algorithm.CastagnosLaguillaumie,
  Algorithm.NaccacheStern,
  Algorithm.Benaloh,
  Algorithm.DamgardGeislerKroigaard,
];

const DISCRETE_LOGARITHM_REASON =
  'its decryption solves discrete logarithm, which is' +
  ' infeasible for the uniformly random values the transform encrypts';
const NATIVE_MULTIPLICATION_REASON =
  'it already supports one multiplication natively';

/** Reasons of algorithms that cannot be upgraded. */
const UNSUPPORTED_REASONS: Readonly<Record<string, string>> = {
  [Algorithm.ExponentialElGamal]: DISCRETE_LOGARITHM_REASON,
  [Algorithm.EllipticCurveElGamal]: DISCRETE_LOGARITHM_REASON,
  [Algorithm.OkamotoUchiyama]:
    'its plaintext modulus p is secret, so the encryptor cannot' +
    ' compute m - b mod p',
  [Algorithm.Regev]:
    'multiplying with uniformly random constants exceeds its noise budget',
  [Algorithm.LyubashevskyPeikertRegev]:
    'multiplying with uniformly random constants exceeds its noise budget',
  [Algorithm.MLKEM]:
    'it is homomorphic with respect to xor only, without addition',
  [Algorithm.GoldwasserMicali]:
    'it encrypts integers bit by bit and supports xor only,' +
    ' without multiplication with a constant',
  [Algorithm.BonehGohNissim]: NATIVE_MULTIPLICATION_REASON,
  [Algorithm.BrakerskiVaikuntanathan]: NATIVE_MULTIPLICATION_REASON,
  [Algorithm.FreemanBonehGohNissim]: NATIVE_MULTIPLICATION_REASON,
  [Algorithm.GentryHaleviVaikuntanathan]: NATIVE_MULTIPLICATION_REASON,
  [Algorithm.GentrySahaiWaters]:
    'it already supports multiplications of bits natively',
};

/**
 * What the transform needs from a built LightPHE instance: its public
 * operations only.
 */
export interface CatalanoFioreBase {
  readonly algorithmName: string;
  readonly cs: Homomorphic;
  readonly form?: CurveForm | string | null;
  readonly curve?: string | null;
  encrypt(plaintext: bigint): unknown;
  decrypt(ciphertext: Ciphertext): unknown;
}

/** Builds a LightPHE instance of the same class with the given keys. */
type CatalanoFioreBaseConstructor = new (options: {
  algorithmName: string;
  keys: Keys;
  form?: CurveForm | string | null;
  curve?: string | null;
}) => CatalanoFioreBase;

/**
 * Catalano-Fiore transform upgrades a linearly homomorphic cryptosystem to
 * support one homomorphic multiplication, i.e. evaluating degree-2 functions
 * such as dot products of two encrypted vectors, variances or squared
 * distances. It wraps a built LightPHE instance, and uses its public
 * operations only: encryption, decryption, homomorphic addition and
 * multiplication with a constant. So, the underlying cryptosystem is used as
 * is, and the transform is as secure as it is.
 *
 * Plaintext space is `Z_M`, where M is the plaintext modulo of the underlying
 * cryptosystem.
 *   - encryption of m: `(a, Enc(b))` where b is uniformly random in `Z_M` and
 *     `a = m - b`. a is in clear, but reveals nothing as b is uniformly random
 *     and secret.
 *   - addition: `(a1 + a2, Enc(b1) + Enc(b2))`
 *   - multiplication: `m1 m2 = a1 a2 + a1 b2 + a2 b1 + b1 b2`, so the result is
 *     `alpha = Enc(a1 a2) + a1 Enc(b2) + a2 Enc(b1)`, which encrypts
 *     `m1 m2 - b1 b2`, together with the pair `(Enc(b1), Enc(b2))` to restore
 *     `b1 b2` in decryption.
 *   - decryption of a multiplied ciphertext: `Dec(alpha)` plus the sum of
 *     `Dec(Enc(b1)) Dec(Enc(b2))` for all pairs.
 * Multiplied ciphertexts can be added with each other, with non-multiplied
 * ciphertexts and with plain constants, and they can be multiplied with plain
 * constants. But they cannot be multiplied with ciphertexts again.
 *
 * Notice that a multiplied ciphertext keeps a pair of ciphertexts for every
 * product it contains, so its size grows with the number of products summed.
 * For instance, dot product of two encrypted vectors of length d has d pairs.
 * The pairs also reveal which ciphertexts were multiplied, but not their
 * values.
 *
 * Encryption and homomorphic operations require the public key only, and
 * decryption requires the private key of the underlying cryptosystem. Only
 * integers are supported.
 *
 * It is enabled with the boost option of LightPHE, e.g.
 * `new LightPHE({ algorithmName: 'Paillier', boost: 'Catalano-Fiore' })`,
 * whose encrypt and decrypt then use this class.
 *
 * Ref: Catalano, D., Fiore, D. (2015). Using Linearly-Homomorphic Encryption
 * to Evaluate Degree-2 Functions on Encrypted Data. ACM CCS 2015.
 */
export class CatalanoFiore {
  /** The wrapped cryptosystem, built without the transform. */
  readonly cs: CatalanoFioreBase;
  readonly plaintextModulo: bigint;

  /**
   * The transform that ciphertexts keep a reference to for homomorphic
   * operations. It must not carry the private key, as ciphertexts are sent to
   * other parties.
   */
  readonly public: CatalanoFiore;

  /**
   * @param cs - built cryptosystem of a supported additively homomorphic
   *   algorithm.
   */
  constructor(cs: CatalanoFioreBase) {
    const algorithmName = cs.algorithmName;
    if (!CATALANO_FIORE_SUPPORTED_ALGORITHMS.includes(algorithmName)) {
      const reason =
        UNSUPPORTED_REASONS[algorithmName] ??
        'it is not additively homomorphic';
      throw new Error(
        `Catalano-Fiore transform does not support ${algorithmName} because ${reason}. ` +
          `Supported algorithms are ${CATALANO_FIORE_SUPPORTED_ALGORITHMS.join(', ')}.`
      );
    }
    this.cs = cs;
    this.plaintextModulo = cs.cs.plaintextModulo;

    if (cs.cs.keys.private_key == null) {
      this.public = this;
    } else {
      const Base = cs.constructor as CatalanoFioreBaseConstructor;
      const publicCs = new Base({
        algorithmName,
        keys: { public_key: deepClone(cs.cs.keys.public_key!) },
        form: cs.form,
        curve: cs.curve,
      });
      this.public = new CatalanoFiore(publicCs);
    }
  }

  /**
   * Encrypts a plaintext as `(a, Enc(b))` where `a = m - b` and b is uniformly
   * random. The plaintext is reduced modulo M.
   */
  encrypt(plaintext: unknown): CatalanoFioreCiphertext {
    if (!(
      typeof plaintext === 'bigint' ||
      (typeof plaintext === 'number' && Number.isInteger(plaintext))
    )) {
      throw new Error(
        'Catalano-Fiore transform supports integers only, ' +
          `but plaintext is ${typeName(plaintext)}`
      );
    }
    const modulo = this.plaintextModulo;
    const b = randomBelow(modulo);
    return new CatalanoFioreCiphertext({
      cf: this.public,
      a: mod(BigInt(plaintext) - b, modulo),
      beta: this.cs.encrypt(b) as Ciphertext,
    });
  }

  /** Decrypts a ciphertext created by the transform. Requires the private key. */
  decrypt(ciphertext: CatalanoFioreCiphertext): bigint {
    if (!(ciphertext instanceof CatalanoFioreCiphertext)) {
      throw new Error('Ciphertext must be created by Catalano-Fiore transform');
    }
    if (this.cs.cs.keys.private_key == null) {
      throw new Error('You must have private key to perform decryption');
    }

    const modulo = this.plaintextModulo;
    const decrypt = (c: Ciphertext): bigint => this.cs.decrypt(c) as bigint;
    if (!ciphertext.isMultiplied) {
      return mod(ciphertext.a! + decrypt(ciphertext.beta!), modulo);
    }

    let result = decrypt(ciphertext.alpha!);
    for (const [beta1, beta2] of ciphertext.pairs) {
      result += decrypt(beta1) * decrypt(beta2);
    }
    return mod(result, modulo);
  }
}

/**
 * Ciphertext of Catalano-Fiore transform. It is either non-multiplied as
 * `(a, beta)`, or multiplied as `(alpha, pairs)`.
 */
export class CatalanoFioreCiphertext {
  readonly cf: CatalanoFiore;
  readonly a?: bigint;
  readonly beta?: Ciphertext;
  readonly alpha?: Ciphertext;
  readonly pairs: ReadonlyArray<readonly [Ciphertext, Ciphertext]>;
  readonly isMultiplied: boolean;

  constructor(options: {
    cf: CatalanoFiore;
    a?: bigint;
    beta?: Ciphertext;
    alpha?: Ciphertext;
    pairs?: ReadonlyArray<readonly [Ciphertext, Ciphertext]>;
  }) {
    this.cf = options.cf;
    this.a = options.a;
    this.beta = options.beta;
    this.alpha = options.alpha;
    this.pairs = options.pairs ?? [];
    this.isMultiplied = options.alpha !== undefined;
  }

  /**
   * Converts the ciphertext into a json serializable form to send it to
   * another party. Keys are not included, receiver restores it with
   * `fromDict` of its LightPHE.
   */
  toDict(): Record<string, unknown> {
    return encode(this) as Record<string, unknown>;
  }

  toString(): string {
    if (this.isMultiplied) {
      return `CatalanoFioreCiphertext(multiplied, ${this.pairs.length} pairs)`;
    }
    return 'CatalanoFioreCiphertext(non-multiplied)';
  }

  /** Homomorphic addition with another ciphertext or a plain integer. */
  add(
    other: CatalanoFioreCiphertext | number | bigint
  ): CatalanoFioreCiphertext {
    const modulo = this.cf.plaintextModulo;

    if (isInteger(other)) {
      const constant = BigInt(other);
      // adding a plain constant requires no homomorphic operation for a
      // non-multiplied one
      if (!this.isMultiplied) {
        return new CatalanoFioreCiphertext({
          cf: this.cf,
          a: mod(this.a! + constant, modulo),
          beta: this.beta,
        });
      }
      return new CatalanoFioreCiphertext({
        cf: this.cf,
        alpha: this.alpha!.add(this.encryptPlain(mod(constant, modulo))),
        pairs: this.pairs,
      });
    }

    this.checkSameSystem(other);
    const that = other as CatalanoFioreCiphertext;

    if (!this.isMultiplied && !that.isMultiplied) {
      return new CatalanoFioreCiphertext({
        cf: this.cf,
        a: mod(this.a! + that.a!, modulo),
        beta: this.beta!.add(that.beta!),
      });
    }

    const first = this.toMultiplied();
    const second = that.toMultiplied();
    return new CatalanoFioreCiphertext({
      cf: this.cf,
      alpha: first.alpha!.add(second.alpha!),
      pairs: [...first.pairs, ...second.pairs],
    });
  }

  /** Homomorphic subtraction of another ciphertext or a plain integer. */
  subtract(
    other: CatalanoFioreCiphertext | number | bigint
  ): CatalanoFioreCiphertext {
    if (isInteger(other)) {
      return this.add(-BigInt(other));
    }
    this.checkSameSystem(other);
    return this.add((other as CatalanoFioreCiphertext).negate());
  }

  /** Homomorphic negation: the result decrypts to `-m`. */
  negate(): CatalanoFioreCiphertext {
    return this.multiply(-1n);
  }

  /** Homomorphic multiplication with another ciphertext, or with a plain integer. */
  multiply(
    other: CatalanoFioreCiphertext | number | bigint
  ): CatalanoFioreCiphertext {
    const modulo = this.cf.plaintextModulo;

    if (isInteger(other)) {
      const constant = mod(BigInt(other), modulo);
      if (!this.isMultiplied) {
        return new CatalanoFioreCiphertext({
          cf: this.cf,
          a: mod(this.a! * constant, modulo),
          beta: this.beta!.multiply(constant),
        });
      }
      // scaling the first ciphertext of each pair scales the product b1 b2
      return new CatalanoFioreCiphertext({
        cf: this.cf,
        alpha: this.alpha!.multiply(constant),
        pairs: this.pairs.map(
          ([beta1, beta2]) => [beta1.multiply(constant), beta2] as const
        ),
      });
    }

    if (!(other instanceof CatalanoFioreCiphertext)) {
      throw new Error(
        'Catalano-Fiore ciphertexts can be multiplied with a ciphertext or an integer, ' +
          `but it is ${typeName(other)}`
      );
    }
    this.checkSameSystem(other);

    if (this.isMultiplied || other.isMultiplied) {
      throw new Error(
        'Catalano-Fiore transform supports only one multiplication. ' +
          'Multiplied ciphertexts cannot be multiplied with ciphertexts again.'
      );
    }

    // Enc(a1 a2) + a1 Enc(b2) + a2 Enc(b1) encrypts m1 m2 - b1 b2
    const alpha = this.encryptPlain(mod(this.a! * other.a!, modulo))
      .add(other.beta!.multiply(this.a!))
      .add(this.beta!.multiply(other.a!));
    return new CatalanoFioreCiphertext({
      cf: this.cf,
      alpha,
      pairs: [[this.beta!, other.beta!]],
    });
  }

  /**
   * Represents a non-multiplied ciphertext `(a, Enc(b))` as a multiplied one
   * with `alpha = Enc(a) + Enc(b)` and no pairs.
   */
  toMultiplied(): CatalanoFioreCiphertext {
    if (this.isMultiplied) {
      return this;
    }
    const alpha = this.encryptPlain(this.a!).add(this.beta!);
    return new CatalanoFioreCiphertext({ cf: this.cf, alpha, pairs: [] });
  }

  private encryptPlain(plaintext: bigint): Ciphertext {
    return this.cf.cs.encrypt(plaintext) as Ciphertext;
  }

  private checkSameSystem(other: unknown): void {
    if (!(other instanceof CatalanoFioreCiphertext)) {
      throw new Error(
        'Catalano-Fiore ciphertexts can be added to a ciphertext or an integer, ' +
          `but it is ${typeName(other)}`
      );
    }
    if (other.cf.plaintextModulo !== this.cf.plaintextModulo) {
      throw new Error('Ciphertexts belong to different cryptosystems');
    }
  }
}

function isInteger(value: unknown): value is number | bigint {
  return (
    typeof value === 'bigint' ||
    (typeof value === 'number' && Number.isInteger(value))
  );
}

function typeName(value: unknown): string {
  if (value === null) {
    return 'null';
  }
  if (Array.isArray(value)) {
    return 'list';
  }
  if (typeof value === 'number') {
    return Number.isInteger(value) ? 'int' : 'float';
  }
  if (typeof value === 'object') {
    return (value as object).constructor?.name ?? 'object';
  }
  return typeof value;
}

/** Deep-clones plain key material so the public copy shares nothing mutable. */
function deepClone<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((item: unknown) => deepClone(item)) as unknown as T;
  }
  if (typeof value === 'object' && value !== null) {
    const result: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      result[key] = deepClone(entry);
    }
    return result as T;
  }
  return value;
}
