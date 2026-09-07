/**
 * Number-theoretic helpers over `bigint`.
 *
 * These stand in for the parts of `sympy` that LightPHE leans on: primality
 * testing, prime generation, factorisation of smooth numbers, the Jacobi
 * symbol, modular square roots and the Chinese remainder theorem.
 *
 * Randomness comes from the platform CSPRNG (`crypto.getRandomValues` in the
 * browser, `crypto.randomFillSync` in Node) rather than `Math.random`.
 */

export const ZERO = 0n;
export const ONE = 1n;
export const TWO = 2n;

/* -------------------------------------------------------------------------- */
/* randomness                                                                  */
/* -------------------------------------------------------------------------- */

type CryptoLike = { getRandomValues(array: Uint8Array): Uint8Array };

let cryptoImpl: CryptoLike | undefined;

function getCrypto(): CryptoLike {
  if (cryptoImpl !== undefined) {
    return cryptoImpl;
  }
  const g = globalThis as { crypto?: CryptoLike };
  if (g.crypto != null && typeof g.crypto.getRandomValues === 'function') {
    cryptoImpl = g.crypto;
    return cryptoImpl;
  }

  // Node 16/17 has no global WebCrypto. Reaching for the built-in module works
  // in the CommonJS build; the ESM build only runs on Node 18+, where the
  // global above has already answered.
  if (typeof require === 'function') {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const nodeCrypto = require('crypto') as {
      randomFillSync(buffer: Uint8Array): Uint8Array;
    };
    cryptoImpl = {
      getRandomValues: (array: Uint8Array) => nodeCrypto.randomFillSync(array),
    };
    return cryptoImpl;
  }

  throw new Error(
    'lightphe-ts needs a cryptographic random source: no global crypto.getRandomValues was found'
  );
}

function randomBytes(length: number): Uint8Array {
  const buffer = new Uint8Array(length);
  getCrypto().getRandomValues(buffer);
  return buffer;
}

/** Returns a uniform random value in `[0, 2^bits)`. */
export function randomBits(bits: number): bigint {
  if (bits <= 0) {
    throw new Error(`bit length ${bits} must be positive`);
  }
  const byteCount = Math.ceil(bits / 8);
  const bytes = randomBytes(byteCount);
  let value = ZERO;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  // Trim the bits we drew past the requested width.
  const excess = BigInt(byteCount * 8 - bits);
  return value >> excess;
}

/** Returns a uniform random value in `[0, bound)`. */
export function randomBelow(bound: bigint): bigint {
  if (bound <= ZERO) {
    throw new Error(`upper bound ${bound} must be positive`);
  }
  const bits = bitLength(bound);
  // Rejection sampling keeps the distribution uniform.
  for (;;) {
    const candidate = randomBits(bits);
    if (candidate < bound) {
      return candidate;
    }
  }
}

/** Returns a uniform random value in the inclusive range `[lo, hi]`. */
export function randomRange(lo: bigint, hi: bigint): bigint {
  if (lo > hi) {
    throw new Error(`empty range [${lo}, ${hi}]`);
  }
  return lo + randomBelow(hi - lo + ONE);
}

/** Returns a uniform random value in `[1, n)` that is coprime to `n`. */
export function randomCoprime(n: bigint): bigint {
  if (n < TWO) {
    throw new Error(`modulus ${n} must be at least 2`);
  }
  for (let i = 0; i < 10000; i++) {
    const r = randomBelow(n);
    if (r !== ZERO && gcd(r, n) === ONE) {
      return r;
    }
  }
  throw new Error(`no unit found modulo ${n}`);
}

/* -------------------------------------------------------------------------- */
/* basic arithmetic                                                            */
/* -------------------------------------------------------------------------- */

/** Returns the absolute value of `a`. */
export function abs(a: bigint): bigint {
  return a < ZERO ? -a : a;
}

/** Returns the number of bits needed to represent `|a|`. */
export function bitLength(a: bigint): number {
  const v = abs(a);
  if (v === ZERO) {
    return 0;
  }
  return v.toString(2).length;
}

/**
 * Returns `a mod m` with the sign of `m`, matching Python's `%` operator
 * rather than JavaScript's remainder.
 */
export function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r !== ZERO && r < ZERO !== m < ZERO ? r + m : r;
}

/** Returns the greatest common divisor of `a` and `b`. */
export function gcd(a: bigint, b: bigint): bigint {
  let x = abs(a);
  let y = abs(b);
  while (y !== ZERO) {
    [x, y] = [y, x % y];
  }
  return x;
}

/** Reports whether `gcd(a, b) === 1`. */
export function isCoprime(a: bigint, b: bigint): boolean {
  return gcd(a, b) === ONE;
}

/** Returns `a^-1 mod m`, or throws when `a` is not invertible. */
export function modInverse(a: bigint, m: bigint): bigint {
  if (m <= ZERO) {
    throw new Error(`modulus ${m} must be positive`);
  }
  let [old_r, r] = [mod(a, m), m];
  let [old_s, s] = [ONE, ZERO];
  while (r !== ZERO) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== ONE) {
    throw new Error(`${a} is not invertible modulo ${m}`);
  }
  return mod(old_s, m);
}

/**
 * Returns `base^exponent mod modulus`.
 *
 * A negative exponent inverts the base first, the way Python's three-argument
 * `pow` does.
 */
export function modPow(
  base: bigint,
  exponent: bigint,
  modulus: bigint
): bigint {
  if (modulus === ZERO) {
    throw new Error('modulus must not be zero');
  }
  if (modulus === ONE) {
    return ZERO;
  }
  if (exponent < ZERO) {
    return modPow(modInverse(base, modulus), -exponent, modulus);
  }
  let result = ONE;
  let b = mod(base, modulus);
  let e = exponent;
  while (e > ZERO) {
    if (e & ONE) {
      result = (result * b) % modulus;
    }
    b = (b * b) % modulus;
    e >>= ONE;
  }
  return result;
}

/** Returns `base^exponent` for a non-negative exponent. */
export function pow(base: bigint, exponent: bigint): bigint {
  if (exponent < ZERO) {
    throw new Error('exponent must be non-negative');
  }
  return base ** exponent;
}

/** Returns the integer square root of `n` (floor of the real square root). */
export function isqrt(n: bigint): bigint {
  if (n < ZERO) {
    throw new Error('cannot take the square root of a negative number');
  }
  if (n < TWO) {
    return n;
  }
  // Newton's method, seeded from the bit length so it converges quickly.
  let x = ONE << BigInt(Math.ceil(bitLength(n) / 2));
  for (;;) {
    const next = (x + n / x) >> ONE;
    if (next >= x) {
      return x;
    }
    x = next;
  }
}

/* -------------------------------------------------------------------------- */
/* primality                                                                   */
/* -------------------------------------------------------------------------- */

const SMALL_PRIMES: bigint[] = [
  2n,
  3n,
  5n,
  7n,
  11n,
  13n,
  17n,
  19n,
  23n,
  29n,
  31n,
  37n,
  41n,
  43n,
  47n,
  53n,
  59n,
  61n,
  67n,
  71n,
  73n,
  79n,
  83n,
  89n,
  97n,
  101n,
  103n,
  107n,
  109n,
  113n,
  127n,
  131n,
  137n,
  139n,
  149n,
  151n,
  157n,
  163n,
  167n,
  173n,
  179n,
  181n,
  191n,
  193n,
  197n,
  199n,
  211n,
  223n,
  227n,
  229n,
  233n,
  239n,
  241n,
  251n,
];

/**
 * Miller-Rabin primality test with `rounds` random bases, plus trial division
 * by the small primes. The error probability is below `4^-rounds`.
 */
export function isPrime(n: bigint, rounds = 40): boolean {
  if (n < TWO) {
    return false;
  }
  for (const p of SMALL_PRIMES) {
    if (n === p) {
      return true;
    }
    if (n % p === ZERO) {
      return false;
    }
  }

  // Write n - 1 = d * 2^r with d odd.
  let d = n - ONE;
  let r = 0;
  while ((d & ONE) === ZERO) {
    d >>= ONE;
    r += 1;
  }

  const nMinusOne = n - ONE;
  const witness = (a: bigint): boolean => {
    let x = modPow(a, d, n);
    if (x === ONE || x === nMinusOne) {
      return false;
    }
    for (let i = 1; i < r; i++) {
      x = (x * x) % n;
      if (x === nMinusOne) {
        return false;
      }
    }
    return true;
  };

  // Deterministic bases first: below 3.3e24 these alone decide the answer.
  const deterministicBases = [
    2n,
    3n,
    5n,
    7n,
    11n,
    13n,
    17n,
    19n,
    23n,
    29n,
    31n,
    37n,
  ];
  for (const a of deterministicBases) {
    if (a >= n) {
      break;
    }
    if (witness(a)) {
      return false;
    }
  }
  if (n < 3317044064679887385961981n) {
    return true;
  }

  for (let i = 0; i < rounds; i++) {
    const a = randomRange(TWO, n - TWO);
    if (witness(a)) {
      return false;
    }
  }
  return true;
}

/** Returns the smallest prime strictly greater than `n`. */
export function nextPrime(n: bigint): bigint {
  if (n < TWO) {
    return TWO;
  }
  let candidate = n + ONE;
  if ((candidate & ONE) === ZERO) {
    if (candidate === TWO) {
      return TWO;
    }
    candidate += ONE;
  }
  while (!isPrime(candidate)) {
    candidate += TWO;
  }
  return candidate;
}

/** Returns the largest prime strictly less than `n`, or `undefined` if none. */
export function prevPrime(n: bigint): bigint | undefined {
  if (n <= TWO) {
    return undefined;
  }
  if (n === 3n) {
    return TWO;
  }
  let candidate = n - ONE;
  if ((candidate & ONE) === ZERO) {
    candidate -= ONE;
  }
  while (candidate >= 3n) {
    if (isPrime(candidate)) {
      return candidate;
    }
    candidate -= TWO;
  }
  return TWO;
}

/**
 * Returns a random prime in `[lo, hi)`, following the same draw-then-round-up
 * strategy as `sympy.randprime` so key generation behaves like the Python
 * original.
 */
export function randPrime(lo: bigint, hi: bigint): bigint {
  if (lo >= hi) {
    throw new Error(`empty range [${lo}, ${hi})`);
  }
  const n = randomRange(lo - ONE, hi);
  let p = nextPrime(n);
  if (p >= hi) {
    const previous = prevPrime(hi);
    if (previous === undefined) {
      throw new Error(`no primes exist in [${lo}, ${hi})`);
    }
    p = previous;
  }
  if (p < lo) {
    throw new Error(`no primes exist in [${lo}, ${hi})`);
  }
  return p;
}

/**
 * Returns `2^exponent`, or 0 for a negative exponent.
 *
 * Python evaluates `2 ** negative` to a float that later truncates to zero;
 * several key generators rely on that when the requested key size is small.
 */
export function pow2(exponent: number): bigint {
  return exponent < 0 ? ZERO : ONE << BigInt(exponent);
}

/** Returns a random prime of exactly `bits` bits. */
export function randPrimeOfBits(bits: number): bigint {
  if (bits < 2) {
    throw new Error(`prime size ${bits} is too small`);
  }
  const lo = ONE << BigInt(bits - 1);
  const hi = ONE << BigInt(bits);
  return randPrime(lo, hi);
}

/**
 * Returns the distinct prime factors of `n` in ascending order.
 *
 * Trial division only, which is all the smooth plaintext moduli of Benaloh and
 * Naccache-Stern need.
 */
export function primeFactors(n: bigint): bigint[] {
  if (n <= ZERO) {
    throw new Error(`cannot factor non-positive ${n}`);
  }
  const factors: bigint[] = [];
  let remaining = n;
  let d = TWO;
  while (remaining > ONE) {
    if (isPrime(remaining)) {
      factors.push(remaining);
      break;
    }
    if (d * d > remaining) {
      factors.push(remaining);
      break;
    }
    if (remaining % d === ZERO) {
      factors.push(d);
      while (remaining % d === ZERO) {
        remaining /= d;
      }
    }
    d = d === TWO ? 3n : d + TWO;
    if (bitLength(d) > 40) {
      throw new Error(`${n} is not smooth enough to factor by trial division`);
    }
  }
  return factors;
}

/**
 * Returns the full factorisation of `n` as a map from prime to exponent, the
 * shape `sympy.factorint` returns.
 */
export function factorInt(n: bigint): Map<bigint, number> {
  if (n <= ZERO) {
    throw new Error(`cannot factor non-positive ${n}`);
  }
  const result = new Map<bigint, number>();
  let remaining = n;
  let d = TWO;
  while (remaining > ONE) {
    if (isPrime(remaining)) {
      result.set(remaining, (result.get(remaining) ?? 0) + 1);
      break;
    }
    if (d * d > remaining) {
      result.set(remaining, (result.get(remaining) ?? 0) + 1);
      break;
    }
    while (remaining % d === ZERO) {
      result.set(d, (result.get(d) ?? 0) + 1);
      remaining /= d;
    }
    d = d === TWO ? 3n : d + TWO;
    if (bitLength(d) > 40) {
      throw new Error(`${n} is not smooth enough to factor by trial division`);
    }
  }
  return result;
}

/* -------------------------------------------------------------------------- */
/* quadratic residues                                                          */
/* -------------------------------------------------------------------------- */

/** Returns the Jacobi symbol `(a/n)` for odd positive `n`. */
export function jacobiSymbol(a: bigint, n: bigint): number {
  if (n <= ZERO || (n & ONE) === ZERO) {
    throw new Error(`Jacobi symbol needs an odd positive modulus, got ${n}`);
  }
  let x = mod(a, n);
  let m = n;
  let result = 1;
  while (x !== ZERO) {
    while ((x & ONE) === ZERO) {
      x >>= ONE;
      const r = m % 8n;
      if (r === 3n || r === 5n) {
        result = -result;
      }
    }
    [x, m] = [m, x];
    if (x % 4n === 3n && m % 4n === 3n) {
      result = -result;
    }
    x = mod(x, m);
  }
  return m === ONE ? result : 0;
}

/**
 * Returns a square root of `a` modulo the odd prime `p` via Tonelli-Shanks,
 * or `undefined` when `a` is a quadratic non-residue.
 */
export function sqrtMod(a: bigint, p: bigint): bigint | undefined {
  const value = mod(a, p);
  if (value === ZERO) {
    return ZERO;
  }
  if (p === TWO) {
    return value;
  }
  if (jacobiSymbol(value, p) !== 1) {
    return undefined;
  }

  // p = 3 (mod 4) has the closed form a^((p+1)/4).
  if (p % 4n === 3n) {
    return modPow(value, (p + ONE) >> TWO, p);
  }

  // Write p - 1 = q * 2^s with q odd.
  let q = p - ONE;
  let s = 0;
  while ((q & ONE) === ZERO) {
    q >>= ONE;
    s += 1;
  }

  // Find a quadratic non-residue z.
  let z = TWO;
  while (jacobiSymbol(z, p) !== -1) {
    z += ONE;
    if (z >= p) {
      return undefined;
    }
  }

  let m = s;
  let c = modPow(z, q, p);
  let t = modPow(value, q, p);
  let r = modPow(value, (q + ONE) >> ONE, p);

  while (t !== ONE) {
    let i = 0;
    let t2 = t;
    while (t2 !== ONE) {
      t2 = (t2 * t2) % p;
      i += 1;
      if (i === m) {
        return undefined;
      }
    }
    let b = c;
    for (let j = 0; j < m - i - 1; j++) {
      b = (b * b) % p;
    }
    m = i;
    c = (b * b) % p;
    t = (t * c) % p;
    r = (r * b) % p;
  }
  return r;
}

/** Returns every square root of `a` modulo the odd prime `p`, in ascending order. */
export function sqrtModAll(a: bigint, p: bigint): bigint[] {
  const root = sqrtMod(a, p);
  if (root === undefined) {
    return [];
  }
  const other = mod(-root, p);
  if (other === root) {
    return [root];
  }
  return root < other ? [root, other] : [other, root];
}

/* -------------------------------------------------------------------------- */
/* Chinese remainder theorem                                                   */
/* -------------------------------------------------------------------------- */

/**
 * Solves `x = residues[i] (mod moduli[i])` and returns `[x, combinedModulus]`,
 * mirroring `sympy.ntheory.modular.solve_congruence`. The moduli must be
 * pairwise coprime; `undefined` comes back when they are not.
 */
export function solveCongruence(
  congruences: Array<[bigint, bigint]>
): [bigint, bigint] | undefined {
  if (congruences.length === 0) {
    return undefined;
  }
  let [x, m] = [mod(congruences[0][0], congruences[0][1]), congruences[0][1]];

  for (let i = 1; i < congruences.length; i++) {
    const [residue, modulus] = congruences[i];
    if (!isCoprime(m, modulus)) {
      return undefined;
    }
    const inv = modInverse(m, modulus);
    const diff = mod((residue - x) * inv, modulus);
    x = x + m * diff;
    m = m * modulus;
    x = mod(x, m);
  }
  return [x, m];
}
