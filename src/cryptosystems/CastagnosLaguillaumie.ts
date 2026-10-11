import { Logger } from '../commons/logger.js';
import {
  bitLength,
  gcd,
  isPrime,
  isqrt,
  jacobiSymbol,
  mod,
  modInverse,
  modPow,
  pow2,
  randPrime,
  randomRange,
  sqrtMod,
  ONE,
  TWO,
  ZERO,
} from '../commons/mathUtils.js';
import { Algorithm } from '../models/Algorithm.js';
import { Homomorphic } from '../models/Homomorphic.js';
import type { CiphertextValue, Keys, RequiredKeys } from '../models/types.js';

const logger = new Logger('lightphe-ts/cryptosystems/CastagnosLaguillaumie.ts');

/** A binary quadratic form `ax^2 + bxy + cy^2`, represented as `[a, b, c]`. */
export type Form = readonly [bigint, bigint, bigint];

/** A Castagnos-Laguillaumie ciphertext: the pair of forms `[g^r, f^m h^r]`. */
export type CLPair = readonly [Form, Form];

/**
 * Castagnos-Laguillaumie is homomorphic with respect to addition, and supports
 * multiplying a ciphertext by a known plain constant. It is an ElGamal-like
 * scheme in the class group of an imaginary quadratic order of discriminant
 * `Δp = -p^3 q`, which has a subgroup F of order p with an easy discrete
 * logarithm. So, decryption does not require brute force.
 *
 * Ref: Castagnos, G., Laguillaumie, F. (2015). Linearly Homomorphic Encryption
 * from DDH. CT-RSA 2015. https://eprint.iacr.org/2015/047
 */
export class CastagnosLaguillaumie extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['p', 'q', 'g', 'h'],
    private_key: ['x'],
  };

  /** The fundamental discriminant `Δk = -pq`. */
  readonly deltaK: bigint;

  /** The non-maximal order discriminant `Δp = -p^3 q`. */
  readonly deltaP: bigint;

  /** Upper bound for random exponents. */
  readonly bound: bigint;

  constructor(options?: {
    keys?: Keys | null;
    keySize?: number | null;
    maxTries?: number;
  }) {
    super();
    this.keys =
      options?.keys ??
      this.generateKeys(options?.keySize ?? 1024, {
        maxTries: options?.maxTries ?? 10000,
      });
    const p = this.keys.public_key!.p as bigint;
    const q = this.keys.public_key!.q as bigint;

    this.deltaK = -(p * q);
    this.deltaP = p * p * this.deltaK;
    this.bound = findBound(this.deltaK);

    this.plaintextModulo = p;
    this.ciphertextModulo = -this.deltaP;
  }

  get requiredKeys(): RequiredKeys {
    return CastagnosLaguillaumie.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.CastagnosLaguillaumie;
  }

  /**
   * Generates a key pair.
   *
   * @param keySize - bit length of the fundamental discriminant `Δk = -pq`.
   */
  generateKeys(keySize: number, options?: { maxTries?: number }): Keys {
    const maxTries = options?.maxTries ?? 10000;

    // p defines the message space Z_p. q must be greater than 4p to keep
    // the forms of the subgroup F reduced.
    const pSize = Math.max(4, Math.floor(keySize / 4));
    const qSize = keySize - pSize;

    for (let i = 0; i < maxTries; i++) {
      const p = randPrime(pow2(pSize - 1), pow2(pSize) - ONE);
      const q = randPrime(pow2(qSize - 1), pow2(qSize) - ONE);

      // pq = 3 mod 4 makes Δk = -pq a fundamental discriminant
      if ((p * q) % 4n !== 3n || jacobiSymbol(p, q) !== -1) {
        continue;
      }

      const deltaK = -(p * q);
      const deltaP = p * p * deltaK;

      const g = findGenerator(p, q, deltaK, deltaP);
      if (g === undefined) {
        continue;
      }

      const x = randomRange(ONE, findBound(deltaK));
      const h = formPow(g, x, deltaP);

      return {
        public_key: { p, q, g: [...g], h: [...h] },
        private_key: { x },
      };
    }

    throw new Error(`Failed to generate keys after ${maxTries} attempts`);
  }

  /** Castagnos-Laguillaumie draws a fresh random exponent per encryption. */
  generateRandomKey(): bigint {
    return randomRange(ONE, this.bound);
  }

  encrypt(plaintext: bigint, randomKey?: bigint | bigint[]): CiphertextValue {
    const g = toForm(this.keys.public_key!.g);
    const h = toForm(this.keys.public_key!.h);
    const r =
      typeof randomKey === 'bigint' && randomKey !== ZERO
        ? randomKey
        : this.generateRandomKey();

    const c1 = formPow(g, r, this.deltaP);
    const c2 = compose(
      this.fPow(plaintext),
      formPow(h, r, this.deltaP),
      this.deltaP
    );
    return [c1, c2] as CLPair;
  }

  decrypt(ciphertext: CiphertextValue): bigint {
    const p = this.keys.public_key!.p as bigint;
    const x = this.keys.private_key!.x as bigint;
    const [c1, c2] = toPair(ciphertext);

    // f^m = c2 / c1^x
    const c1x = formPow(c1, x, this.deltaP);
    const fm = compose(c2, inverse(c1x), this.deltaP);

    if (formsEqual(fm, identity(this.deltaP))) {
      return ZERO;
    }

    // discrete logarithm in F is easy: f^m = (p^2, L(m) p, *)
    // where L(m) is congruent to m^-1 modulo p
    const [a, b] = fm;
    if (a !== p * p || mod(b, p) !== ZERO) {
      throw new Error('Decryption failed. Ciphertext does not belong to keys.');
    }

    return modInverse(b / p, p);
  }

  /** Homomorphic addition: the result decrypts to `m1 + m2`. */
  override add(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): CiphertextValue {
    const [a1, a2] = toPair(ciphertext1);
    const [b1, b2] = toPair(ciphertext2);
    return [
      compose(a1, b1, this.deltaP),
      compose(a2, b2, this.deltaP),
    ] as CLPair;
  }

  /** Multiplies a ciphertext by a known plain constant. */
  override multiplyByConstant(
    ciphertext: CiphertextValue,
    constant: bigint
  ): CiphertextValue {
    let k = constant;
    if (k >= this.plaintextModulo) {
      k = k % this.plaintextModulo;
      logger.debug(
        `Castagnos-Laguillaumie can encrypt messages [0, ${this.plaintextModulo}). ` +
          `Seems constant exceeded this limit. New constant is ${k}`
      );
    }
    const [c1, c2] = toPair(ciphertext);
    return [formPow(c1, k, this.deltaP), formPow(c2, k, this.deltaP)] as CLPair;
  }

  override reencrypt(ciphertext: CiphertextValue): CiphertextValue {
    const neutralEncrypted = this.encrypt(ZERO);
    return this.add(ciphertext, neutralEncrypted);
  }

  /**
   * Computes `f^m` in closed form, where `f = (p^2, p, *)` generates the
   * subgroup F of order p.
   */
  private fPow(m: bigint): Form {
    const p = this.keys.public_key!.p as bigint;
    const reduced = mod(m, p);
    if (reduced === ZERO) {
      return identity(this.deltaP);
    }

    // L(m) is the odd integer in [-p, p] congruent to m^-1 modulo p
    let l = modInverse(reduced, p);
    if (l % TWO === ZERO) {
      l = l - p;
    }

    const a = p * p;
    const b = l * p;
    return reduce([a, b, (b * b - this.deltaP) / (4n * a)]);
  }
}

/**
 * Upper bound for exponents. Class number of `Δk` is about
 * `sqrt(|Δk|) log(|Δk|)`, and an additional 40 bits makes exponents
 * statistically close to uniform.
 */
function findBound(deltaK: bigint): bigint {
  const magnitude = -deltaK;
  return isqrt(magnitude) * BigInt(bitLength(magnitude)) * pow2(40);
}

/**
 * Finds `g = [φp^-1(r^2)]^p` where r is an ideal above a small split prime.
 * Then g belongs to the subgroup of p-th powers in `Cl(Δp)`.
 */
function findGenerator(
  p: bigint,
  q: bigint,
  deltaK: bigint,
  deltaP: bigint
): Form | undefined {
  for (let r = 3n; r < 10000n; r += TWO) {
    if (!isPrime(r) || r === p || r === q) {
      continue;
    }
    if (jacobiSymbol(mod(deltaK, r), r) !== 1) {
      continue;
    }

    // prime form above r in Cl(Δk). b must be odd and b^2 = Δk mod 4r
    let b = sqrtMod(deltaK, r)!;
    if (b % TWO === ZERO) {
      b = r - b;
    }
    const rForm: Form = [r, b, (b * b - deltaK) / (4n * r)];

    // squaring prevents being in 2-torsion of the class group
    const r2 = compose(rForm, rForm, deltaK);
    if (r2[0] % p === ZERO) {
      continue;
    }

    // lift from Cl(Δk) to Cl(Δp) via φp^-1(a, b, c) = (a, bp, cp^2)
    const lifted = reduce([r2[0], r2[1] * p, r2[2] * p * p]);
    const g = formPow(lifted, p, deltaP);

    if (!formsEqual(g, identity(deltaP))) {
      return g;
    }
  }
  return undefined;
}

/* -------------------------------------------------------------------------- */
/* binary quadratic form arithmetic                                            */
/* Ref: Cohen, H. (1993). A Course in Computational Algebraic Number Theory.   */
/* -------------------------------------------------------------------------- */

/** Principal form of the class group for a discriminant `delta = 1 mod 4`. */
function identity(delta: bigint): Form {
  return [ONE, ONE, (ONE - delta) / 4n];
}

/** Inverse of a reduced form in the class group. */
function inverse(f: Form): Form {
  const [a, b, c] = f;
  return reduce([a, -b, c]);
}

/** Finds the equivalent form with `-a < b <= a`. */
function normalize(f: Form): Form {
  const [a, b, c] = f;
  const r = floorDiv(a - b, TWO * a);
  return [a, b + TWO * r * a, a * r * r + b * r + c];
}

/**
 * Finds the unique reduced form equivalent to f, i.e. `|b| <= a <= c`, and
 * `b >= 0` if `a = |b|` or `a = c` (Cohen Algorithm 5.4.2).
 */
function reduce(f: Form): Form {
  let [a, b, c] = f;
  if (!(-a < b && b <= a)) {
    [a, b, c] = normalize([a, b, c]);
  }

  while (a > c) {
    [a, b, c] = normalize([c, -b, a]);
  }

  if (a === c && b < ZERO) {
    b = -b;
  }

  return [a, b, c];
}

/** Composition of two forms with discriminant delta (Cohen Algorithm 5.4.7). */
function compose(f1: Form, f2: Form, delta: bigint): Form {
  let first = f1;
  let second = f2;
  if (first[0] > second[0]) {
    [first, second] = [second, first];
  }
  const [a1, b1] = first;
  const [a2, b2, c2] = second;

  const s = (b1 + b2) / TWO;
  const n = b2 - s;

  // y1 = (a2/d)^-1 mod (a1/d), i.e. the coefficient of a2 in u a2 + v a1 = d
  const d = gcd(a1, a2);
  const y1 = modPow(a2 / d, -ONE, a1 / d);

  // x2 = (s/d1)^-1 mod (d/d1), so that x2 s - y2 d = d1
  const d1 = gcd(s, d);
  const x2 = modPow(s / d1, -ONE, d / d1);
  const y2 = (x2 * s - d1) / d;

  const v1 = a1 / d1;
  const v2 = a2 / d1;
  const r = mod(y1 * y2 * n - x2 * c2, v1);
  const b3 = b2 + TWO * v2 * r;
  const a3 = v1 * v2;
  const c3 = (b3 * b3 - delta) / (4n * a3);
  return reduce([a3, b3, c3]);
}

/** Exponentiation in the class group with square and multiply. */
function formPow(f: Form, exponent: bigint, delta: bigint): Form {
  let result = identity(delta);
  let base = f;
  let e = exponent;
  while (e > ZERO) {
    if (e & ONE) {
      result = compose(result, base, delta);
    }
    base = compose(base, base, delta);
    e >>= ONE;
  }
  return result;
}

function formsEqual(f1: Form, f2: Form): boolean {
  return f1[0] === f2[0] && f1[1] === f2[1] && f1[2] === f2[2];
}

/** Floor division, matching Python's `//` rather than truncating towards 0. */
function floorDiv(a: bigint, b: bigint): bigint {
  const quotient = a / b;
  return a % b !== ZERO && a < ZERO !== b < ZERO ? quotient - ONE : quotient;
}

function toForm(value: unknown): Form {
  const [a, b, c] = value as readonly bigint[];
  return [a, b, c];
}

function toPair(value: CiphertextValue): CLPair {
  const [c1, c2] = value as readonly CiphertextValue[];
  return [toForm(c1), toForm(c2)];
}
