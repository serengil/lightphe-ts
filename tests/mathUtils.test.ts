/**
 * Tests for the number-theoretic layer.
 *
 * The Python library gets these from `sympy`; this port implements them, so
 * they are covered here.
 */

import { mathUtils, pheUtils } from '../src';

const {
  bitLength,
  factorInt,
  gcd,
  isCoprime,
  isPrime,
  isqrt,
  jacobiSymbol,
  mod,
  modInverse,
  modPow,
  nextPrime,
  pow2,
  prevPrime,
  primeFactors,
  randPrime,
  randPrimeOfBits,
  randomBelow,
  randomBits,
  randomCoprime,
  randomRange,
  solveCongruence,
  sqrtMod,
  sqrtModAll,
} = mathUtils;

describe('basic arithmetic', () => {
  it('takes a Python-style modulus', () => {
    expect(mod(7n, 3n)).toBe(1n);
    // JavaScript's % would give -1 here; Python and this helper give 2
    expect(mod(-7n, 3n)).toBe(2n);
    expect(mod(0n, 5n)).toBe(0n);
  });

  it('computes greatest common divisors', () => {
    expect(gcd(12n, 18n)).toBe(6n);
    expect(gcd(-12n, 18n)).toBe(6n);
    expect(gcd(17n, 5n)).toBe(1n);
    expect(gcd(0n, 9n)).toBe(9n);
    expect(isCoprime(9n, 28n)).toBe(true);
    expect(isCoprime(9n, 27n)).toBe(false);
  });

  it('reports bit lengths', () => {
    expect(bitLength(0n)).toBe(0);
    expect(bitLength(1n)).toBe(1);
    expect(bitLength(255n)).toBe(8);
    expect(bitLength(256n)).toBe(9);
    expect(bitLength(-256n)).toBe(9);
  });

  it('raises two to a power, clamping negatives to zero', () => {
    expect(pow2(0)).toBe(1n);
    expect(pow2(10)).toBe(1024n);
    // Python evaluates 2 ** negative to a float that truncates to zero
    expect(pow2(-5)).toBe(0n);
  });

  it('takes integer square roots', () => {
    expect(isqrt(0n)).toBe(0n);
    expect(isqrt(1n)).toBe(1n);
    expect(isqrt(15n)).toBe(3n);
    expect(isqrt(16n)).toBe(4n);
    expect(isqrt(10n ** 40n)).toBe(10n ** 20n);
    expect(() => isqrt(-1n)).toThrow();
  });

  it('inverts modulo a modulus', () => {
    expect(modInverse(3n, 11n)).toBe(4n);
    expect((3n * modInverse(3n, 11n)) % 11n).toBe(1n);
    expect(modInverse(-3n, 11n)).toBe(7n);
    expect(() => modInverse(4n, 8n)).toThrow(/not invertible/);
  });

  it('exponentiates modulo a modulus, including negative exponents', () => {
    expect(modPow(2n, 10n, 1000n)).toBe(24n);
    expect(modPow(2n, 0n, 7n)).toBe(1n);
    expect(modPow(5n, 3n, 13n)).toBe(8n);
    // a negative exponent inverts the base first, the way Python's pow does
    expect(modPow(3n, -1n, 11n)).toBe(4n);
    expect(modPow(7n, 5n, 1n)).toBe(0n);
    expect(() => modPow(2n, 3n, 0n)).toThrow();
  });
});

describe('primality', () => {
  it('recognises small primes and composites', () => {
    expect(isPrime(0n)).toBe(false);
    expect(isPrime(1n)).toBe(false);
    expect(isPrime(2n)).toBe(true);
    expect(isPrime(3n)).toBe(true);
    expect(isPrime(4n)).toBe(false);
    expect(isPrime(-7n)).toBe(false);
    for (const p of [11n, 101n, 8191n, 104729n]) {
      expect(isPrime(p)).toBe(true);
    }
    for (const c of [9n, 15n, 561n, 1105n, 104730n]) {
      expect(isPrime(c)).toBe(false);
    }
  });

  it('recognises a large prime and its neighbours', () => {
    // 2^521 - 1, a Mersenne prime
    const p = 2n ** 521n - 1n;
    expect(isPrime(p)).toBe(true);
    expect(isPrime(p + 2n)).toBe(false);
  });

  it('walks to the next and previous prime', () => {
    expect(nextPrime(1n)).toBe(2n);
    expect(nextPrime(2n)).toBe(3n);
    expect(nextPrime(7n)).toBe(11n);
    expect(nextPrime(100n)).toBe(101n);
    expect(prevPrime(2n)).toBeUndefined();
    expect(prevPrime(3n)).toBe(2n);
    expect(prevPrime(11n)).toBe(7n);
    expect(prevPrime(100n)).toBe(97n);
  });

  it('draws a random prime from a range', () => {
    for (let i = 0; i < 10; i++) {
      const p = randPrime(1000n, 2000n);
      expect(isPrime(p)).toBe(true);
      expect(p).toBeGreaterThanOrEqual(1000n);
      expect(p).toBeLessThan(2000n);
    }
    expect(() => randPrime(10n, 10n)).toThrow(/empty range/);
  });

  it('draws a random prime of an exact bit length', () => {
    for (const bits of [16, 32, 64]) {
      const p = randPrimeOfBits(bits);
      expect(isPrime(p)).toBe(true);
      expect(bitLength(p)).toBe(bits);
    }
    expect(() => randPrimeOfBits(1)).toThrow(/too small/);
  });

  it('factors smooth numbers', () => {
    expect(primeFactors(1n)).toEqual([]);
    expect(primeFactors(2n)).toEqual([2n]);
    expect(primeFactors(12n)).toEqual([2n, 3n]);
    // 255255 = 3 * 5 * 7 * 11 * 13 * 17, the Naccache-Stern sigma
    expect(primeFactors(255255n)).toEqual([3n, 5n, 7n, 11n, 13n, 17n]);
    expect(() => primeFactors(0n)).toThrow(/non-positive/);
  });

  it('reports factor multiplicities', () => {
    expect([...factorInt(12n)]).toEqual([
      [2n, 2],
      [3n, 1],
    ]);
    expect([...factorInt(1n)]).toEqual([]);
    expect([...factorInt(97n)]).toEqual([[97n, 1]]);
    expect(() => factorInt(-3n)).toThrow(/non-positive/);
  });
});

describe('quadratic residues', () => {
  it('computes Jacobi symbols', () => {
    // (a/p) for the prime 7: 1, 2 and 4 are residues, the rest are not
    expect(jacobiSymbol(1n, 7n)).toBe(1);
    expect(jacobiSymbol(2n, 7n)).toBe(1);
    expect(jacobiSymbol(3n, 7n)).toBe(-1);
    expect(jacobiSymbol(4n, 7n)).toBe(1);
    expect(jacobiSymbol(7n, 7n)).toBe(0);
    // composite modulus
    expect(jacobiSymbol(1001n, 9907n)).toBe(-1);
    expect(jacobiSymbol(-1n, 5n)).toBe(1);
    expect(() => jacobiSymbol(3n, 8n)).toThrow(/odd positive modulus/);
  });

  it('takes modular square roots for both prime shapes', () => {
    // p = 3 (mod 4) uses the closed form
    const p1 = 23n;
    const root1 = sqrtMod(2n, p1);
    expect(root1).toBeDefined();
    expect((root1! * root1!) % p1).toBe(2n);

    // p = 1 (mod 4) needs the full Tonelli-Shanks loop
    const p2 = 29n;
    const root2 = sqrtMod(6n, p2);
    expect(root2).toBeDefined();
    expect((root2! * root2!) % p2).toBe(6n);

    expect(sqrtMod(0n, 23n)).toBe(0n);
    expect(sqrtMod(5n, 2n)).toBe(1n);
    // a quadratic non-residue has no root
    expect(sqrtMod(5n, 23n)).toBeUndefined();
  });

  it('returns both roots in ascending order', () => {
    const roots = sqrtModAll(2n, 23n);
    expect(roots).toHaveLength(2);
    expect(roots[0]).toBeLessThan(roots[1]);
    for (const root of roots) {
      expect((root * root) % 23n).toBe(2n);
    }
    expect(sqrtModAll(0n, 23n)).toEqual([0n]);
    expect(sqrtModAll(5n, 23n)).toEqual([]);
  });
});

describe('Chinese remainder theorem', () => {
  it('solves a system of congruences', () => {
    // x = 2 (mod 3), x = 3 (mod 5), x = 2 (mod 7) -> x = 23 (mod 105)
    const solution = solveCongruence([
      [2n, 3n],
      [3n, 5n],
      [2n, 7n],
    ]);
    expect(solution).toEqual([23n, 105n]);
  });

  it('handles a single congruence', () => {
    expect(solveCongruence([[7n, 5n]])).toEqual([2n, 5n]);
  });

  it('reports failure for non-coprime moduli and empty systems', () => {
    expect(solveCongruence([])).toBeUndefined();
    expect(
      solveCongruence([
        [1n, 4n],
        [2n, 6n],
      ])
    ).toBeUndefined();
  });
});

describe('randomness', () => {
  it('stays inside the requested bounds', () => {
    for (let i = 0; i < 50; i++) {
      const below = randomBelow(100n);
      expect(below).toBeGreaterThanOrEqual(0n);
      expect(below).toBeLessThan(100n);

      const ranged = randomRange(10n, 20n);
      expect(ranged).toBeGreaterThanOrEqual(10n);
      expect(ranged).toBeLessThanOrEqual(20n);

      const bits = randomBits(8);
      expect(bits).toBeGreaterThanOrEqual(0n);
      expect(bits).toBeLessThan(256n);
    }
  });

  it('draws units modulo n', () => {
    for (let i = 0; i < 20; i++) {
      const r = randomCoprime(35n);
      expect(gcd(r, 35n)).toBe(1n);
      expect(r).toBeGreaterThan(0n);
      expect(r).toBeLessThan(35n);
    }
  });

  it('rejects degenerate bounds', () => {
    expect(() => randomBelow(0n)).toThrow(/must be positive/);
    expect(() => randomRange(5n, 4n)).toThrow(/empty range/);
    expect(() => randomBits(0)).toThrow(/must be positive/);
    expect(() => randomCoprime(1n)).toThrow(/at least 2/);
  });
});

describe('fixed point conversion', () => {
  it('scales a real to an exact integer', () => {
    expect(pheUtils.scaleToInteger(1.5, 2)).toBe(150n);
    expect(pheUtils.scaleToInteger(6, 5)).toBe(600000n);
    expect(pheUtils.scaleToInteger(-2.5, 1)).toBe(-25n);
    expect(pheUtils.scaleToInteger(0, 5)).toBe(0n);
    // 1.05 is not exactly representable, so its expansion sits just above 105
    expect(pheUtils.scaleToInteger(1.05, 2)).toBe(105n);
    expect(() => pheUtils.scaleToInteger(Number.NaN, 2)).toThrow(/non-finite/);
  });

  it('splits a real into a dividend over a power of ten', () => {
    expect(pheUtils.fractionize(1.5, 1000n)).toEqual([15n, 10n]);
    expect(pheUtils.fractionize(1.05, 1000n)).toEqual([105n, 100n]);
    expect(pheUtils.fractionize(1.5, 10n ** 9n, 5)).toEqual([150000n, 100000n]);
    // a whole float still reads as one decimal place, as Python's str() shows it
    expect(pheUtils.fractionize(6, 1000n)).toEqual([60n, 10n]);
    // the dividend is reduced by the modulus, so a small one wraps it
    expect(pheUtils.fractionize(1.5, 1000n, 5)).toEqual([0n, 100000n]);
  });

  it('normalises plain values onto the message space', () => {
    const modulo = 1000003n;
    expect(pheUtils.normalizeInput(17, modulo)).toBe(17n);
    expect(pheUtils.normalizeInput(17n, modulo)).toBe(17n);
    // values past the modulus wrap around
    expect(pheUtils.normalizeInput(modulo + 5n, modulo)).toBe(5n);

    // a non-negative real becomes dividend * divisor^-1
    const normalized = pheUtils.normalizeInput(1.05, modulo);
    expect((normalized * 100n) % modulo).toBe(105n);

    expect(() => pheUtils.normalizeInput(-1.5, modulo)).toThrow(
      /negative not implemented/
    );
  });

  it('reads a binary-string modulus, as Koblitz curves report theirs', () => {
    expect(pheUtils.normalizeInput(5, '1000')).toBe(5n);
    expect(pheUtils.normalizeInput(9, '1000')).toBe(1n);
  });
});
