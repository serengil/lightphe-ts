/**
 * The quadratic extension field `F_{p^2}`, represented as `a + b*i` with
 * `i^2 = -1`.
 *
 * That representation is only valid when `p = 3 (mod 4)`, which is exactly the
 * case for the supersingular curves Boneh-Goh-Nissim builds.
 */

import { mod, modInverse, ZERO, ONE } from '../commons/mathUtils.js';

export class FP2 {
  readonly a: bigint;
  readonly b: bigint;

  constructor(a: bigint, b: bigint) {
    this.a = a;
    this.b = b;
  }

  /** The multiplicative identity `1 + 0i`. */
  static one(): FP2 {
    return new FP2(ONE, ZERO);
  }

  /** The additive identity `0 + 0i`. */
  static zero(): FP2 {
    return new FP2(ZERO, ZERO);
  }

  /** Embeds an element of `F_p` into `F_{p^2}`. */
  static fromBase(a: bigint): FP2 {
    return new FP2(a, ZERO);
  }

  /** Reports whether this is the additive identity. */
  isZero(): boolean {
    return this.a === ZERO && this.b === ZERO;
  }

  /** Reports whether this is the multiplicative identity. */
  isOne(): boolean {
    return this.a === ONE && this.b === ZERO;
  }

  /** Reports whether two elements are identical. */
  equals(other: FP2): boolean {
    return this.a === other.a && this.b === other.b;
  }

  /** Returns `this + other` modulo `p`. */
  add(other: FP2, p: bigint): FP2 {
    return new FP2(mod(this.a + other.a, p), mod(this.b + other.b, p));
  }

  /** Returns `this - other` modulo `p`. */
  sub(other: FP2, p: bigint): FP2 {
    return new FP2(mod(this.a - other.a, p), mod(this.b - other.b, p));
  }

  /** Returns `this * other` modulo `p`: `(a+bi)(c+di) = (ac-bd) + (ad+bc)i`. */
  mul(other: FP2, p: bigint): FP2 {
    const ac = this.a * other.a;
    const bd = this.b * other.b;
    const ad = this.a * other.b;
    const bc = this.b * other.a;
    return new FP2(mod(ac - bd, p), mod(ad + bc, p));
  }

  /** Returns `this^-1` modulo `p`: `(a+bi)^-1 = (a-bi) / (a^2+b^2)`. */
  inverse(p: bigint): FP2 {
    const norm = mod(this.a * this.a + this.b * this.b, p);
    if (norm === ZERO) {
      throw new Error('cannot invert zero in F_{p^2}');
    }
    const inv = modInverse(norm, p);
    return new FP2(mod(this.a * inv, p), mod(-this.b * inv, p));
  }

  /** Returns `this^n` modulo `p`; a negative exponent inverts the base first. */
  exp(n: bigint, p: bigint): FP2 {
    if (n === ZERO) {
      return FP2.one();
    }
    let base: FP2 = this;
    let exponent = n;
    if (exponent < ZERO) {
      base = this.inverse(p);
      exponent = -exponent;
    }

    let result = FP2.one();
    while (exponent > ZERO) {
      if (exponent & ONE) {
        result = result.mul(base, p);
      }
      base = base.mul(base, p);
      exponent >>= ONE;
    }
    return result;
  }

  toString(): string {
    return `${this.a} + ${this.b}*i`;
  }

  /** Returns the pair `[a, b]`, the shape the Python library exposes as a tuple. */
  toTuple(): [bigint, bigint] {
    return [this.a, this.b];
  }
}
