/**
 * Carry-less arithmetic in GF(2^m).
 *
 * A field element is a bit string packed into a `bigint`: bit `i` is the
 * coefficient of `x^i`. Addition is XOR, so nothing in this file carries.
 */

const ZERO = 0n;
const ONE = 1n;

/** Returns the degree of the polynomial `a`, or -1 for the zero polynomial. */
function degree(a: bigint): number {
  return a === ZERO ? -1 : a.toString(2).length - 1;
}

/** Returns `a + b`, which in GF(2) is `a XOR b`. */
export function binAdd(a: bigint, b: bigint): bigint {
  return a ^ b;
}

/** Returns the carry-less product of `a` and `b`. */
export function binMul(a: bigint, b: bigint): bigint {
  let result = ZERO;
  let shifted = a;
  let remaining = b;
  while (remaining > ZERO) {
    if (remaining & ONE) {
      result ^= shifted;
    }
    shifted <<= ONE;
    remaining >>= ONE;
  }
  return result;
}

/** Returns `a * a`, which spreads the bits of `a` to even positions. */
export function binSquare(a: bigint): bigint {
  let result = ZERO;
  let remaining = a;
  let i = 0n;
  while (remaining > ZERO) {
    if (remaining & ONE) {
      result |= ONE << (2n * i);
    }
    remaining >>= ONE;
    i += ONE;
  }
  return result;
}

/** Reduces `a` modulo the polynomial `m`. */
export function binMod(a: bigint, m: bigint): bigint {
  const degM = degree(m);
  if (degM <= 0) {
    return a;
  }
  let r = a;
  for (let degR = degree(r); degR >= degM; degR = degree(r)) {
    r ^= m << BigInt(degR - degM);
  }
  return r;
}

/** Returns the quotient of the polynomial division `a / m`. */
export function binQuo(a: bigint, m: bigint): bigint {
  const degM = degree(m);
  let q = ZERO;
  let r = a;
  for (let degR = degree(r); degR >= degM && r !== ZERO; degR = degree(r)) {
    const shift = BigInt(degR - degM);
    q |= ONE << shift;
    r ^= m << shift;
  }
  return q;
}

/**
 * Returns `a^-1 mod m` via the extended Euclidean algorithm over GF(2), or
 * `undefined` when `a` is not invertible.
 */
export function binInverse(a: bigint, m: bigint): bigint | undefined {
  let x = a;
  let y = m;
  let p1 = ONE;
  let p2 = ZERO;

  while (y !== ONE) {
    if (y === ZERO) {
      return undefined;
    }
    const q = binQuo(x, y);
    const r = binMod(x, y);
    [x, y] = [y, r];
    const pa = p1 ^ binMul(q, p2);
    [p1, p2] = [p2, pa];
  }
  return p2;
}

/** Returns `a * b^-1 mod m`, or `undefined` when `b` is not invertible. */
export function binDivide(a: bigint, b: bigint, m: bigint): bigint | undefined {
  const inv = binInverse(b, m);
  if (inv === undefined) {
    return undefined;
  }
  return binMod(binMul(a, inv), m);
}

/** Returns `a^e mod m` for a small non-negative exponent `e`. */
export function binExp(a: bigint, e: number, m: bigint): bigint {
  let result = ONE;
  let base = binMod(a, m);
  let exponent = e;
  while (exponent > 0) {
    if (exponent & 1) {
      result = binMod(binMul(base, result), m);
    }
    base = binMod(binSquare(base), m);
    exponent >>= 1;
  }
  return result;
}
