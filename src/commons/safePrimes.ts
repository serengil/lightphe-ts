/** Safe prime generation for Bresson-Catalano-Pointcheval and Camenisch-Shoup. */

import { isPrime, nextPrime, randomBits, ONE, TWO } from './mathUtils.js';

/** Small primes to sieve safe prime candidates before primality tests. */
const SMALL_PRIMES: readonly bigint[] = (() => {
  const primes: bigint[] = [];
  for (let p = 3n; p < 2000n; p = nextPrime(p)) {
    primes.push(p);
  }
  return primes;
})();

/**
 * Finds a safe prime `p = 2p' + 1` where `p'` is also prime.
 *
 * @param bits - bit length of p.
 * @param maxTries - maximum number of tries, multiplied by 100 candidates.
 */
export function findSafePrime(bits: number, maxTries: number): bigint {
  for (let i = 0; i < maxTries * 100; i++) {
    const pPrime = randomBits(bits - 1) | (ONE << BigInt(bits - 2)) | ONE;
    const p = TWO * pPrime + ONE;

    // sieve with small primes first, as primality tests are expensive
    if (
      SMALL_PRIMES.some(
        (s) => (pPrime % s === 0n || p % s === 0n) && s < pPrime
      )
    ) {
      continue;
    }

    // a single round rejects almost every composite before the full tests
    if (isPrime(pPrime, 1) && isPrime(p, 1) && isPrime(pPrime) && isPrime(p)) {
      return p;
    }
  }
  throw new Error(`Failed to find a ${bits}-bit safe prime`);
}
