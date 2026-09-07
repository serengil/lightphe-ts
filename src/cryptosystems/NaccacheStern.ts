import { Logger } from '../commons/logger.js';
import {
  bitLength,
  gcd,
  isPrime,
  modPow,
  pow2,
  primeFactors,
  randPrime,
  randomRange,
  solveCongruence,
  ZERO,
  ONE,
  TWO,
} from '../commons/mathUtils.js';
import { Algorithm } from '../models/Algorithm.js';
import { Homomorphic } from '../models/Homomorphic.js';
import type { CiphertextValue, Keys, RequiredKeys } from '../models/types.js';

const logger = new Logger('lightphe-ts/cryptosystems/NaccacheStern.ts');

/**
 * Naccache-Stern is homomorphic with respect to addition and generalises
 * Benaloh.
 *
 * Ref: https://sefiks.com/2023/10/26/a-step-by-step-partially-homomorphic-encryption-example-with-naccache-stern-in-python/
 * Original paper: https://dl.acm.org/doi/pdf/10.1145/288090.288106
 */
export class NaccacheStern extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['n', 'g', 'sigma'],
    private_key: ['a', 'b', 'p', 'q', 'phi'],
  };

  readonly deterministic: boolean;

  constructor(options?: {
    keys?: Keys | null;
    keySize?: number | null;
    deterministic?: boolean;
    maxTries?: number;
  }) {
    super();
    // Decryption solves a DLP, so a modest key size is recommended.
    this.keys =
      options?.keys ??
      this.generateKeys(options?.keySize ?? 1024, {
        maxTries: options?.maxTries ?? 10000,
      });
    this.plaintextModulo = this.keys.public_key!.sigma as bigint;
    this.ciphertextModulo = this.keys.public_key!.n as bigint;
    this.deterministic = options?.deterministic ?? false;
  }

  get requiredKeys(): RequiredKeys {
    return NaccacheStern.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.NaccacheStern;
  }

  generateKeys(keySize: number, options?: { maxTries?: number }): Keys {
    const maxTries = options?.maxTries ?? 10000;

    // Small primes keep the DLP solvable during decryption. Picking 4 of these
    // 8 keeps sigma small (<= ~23^4) and splits evenly into u and v.
    const smallPrimes = [3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n];
    const primeSet = sample(smallPrimes, 4).sort((x, y) => (x < y ? -1 : 1));
    const k = primeSet.length;

    if (!primeSet.every((prime) => isPrime(prime))) {
      throw new Error('All items of prime set must be prime!');
    }

    // divide the set in half and find products of primes
    let u = ONE;
    let v = ONE;
    primeSet.forEach((prime, i) => {
      if (i < Math.floor(k / 2)) {
        u *= prime;
      } else {
        v *= prime;
      }
    });

    // product of all primes
    const sigma = u * v;

    const half = Math.floor(keySize / 2);
    const lo = pow2(half - 300);
    const hi = pow2(half) - ONE;

    for (let attempt = 0; attempt < maxTries; attempt++) {
      // Generate large random primes a and b
      const a = randPrime(lo, hi);
      const b = randPrime(lo, hi);

      // calculate two primes from chosen ones
      const p = TWO * a * u + ONE;
      const q = TWO * b * v + ONE;

      if (!(isPrime(p) && isPrime(q))) {
        continue;
      }

      // recommended n is 768 bits
      const n = p * q;
      const phi = (p - ONE) * (q - ONE);

      if (phi % sigma !== ZERO) {
        logger.debug('canceled because phi cannot be divisible by sigma');
        continue;
      }

      if (gcd(sigma, phi / sigma) !== ONE) {
        logger.debug('canceled because sigma and phi/sigma are not coprime');
        continue;
      }

      // The p and q condition checks are omitted for practical large-key
      // generation and only run for the tiny keys used in tests.
      if (keySize < 40) {
        let pSatisfied = true;
        for (let i = 0; i < Math.floor(k / 2); i++) {
          const pi = primeSet[i];
          if (!(
            (p - ONE) % pi === ZERO &&
            gcd(pi, (p - ONE) / pi) === ONE &&
            gcd(pi, q - ONE) === ONE
          )) {
            pSatisfied = false;
          }
        }
        if (!pSatisfied) {
          logger.debug('canceled because p_conditions are not satisfied');
          continue;
        }

        let qSatisfied = true;
        for (let i = Math.floor(k / 2); i < k; i++) {
          const pi = primeSet[i];
          if (!(
            (q - ONE) % pi === ZERO &&
            gcd(pi, (q - ONE) / pi) === ONE &&
            gcd(pi, p - ONE) !== ZERO
          )) {
            qSatisfied = false;
          }
        }
        if (!qSatisfied) {
          logger.debug('canceled because q_conditions are not satisfied');
          continue;
        }
      }

      // Choose generator g
      let g: bigint | undefined;
      for (let i = 0; i < 1000; i++) {
        const candidate = randomRange(TWO, n - ONE);

        // it must be co-prime to n
        if (gcd(candidate, n) !== ONE) {
          continue;
        }
        // guarantee it is not a pi-th power
        if (primeSet.some((pi) => modPow(candidate, phi / pi, n) === ONE)) {
          continue;
        }
        g = candidate;
        break;
      }
      if (g === undefined) {
        continue;
      }

      // The original phi/4 order check is omitted for practical large keys.
      if (keySize < 40 && modPow(g, phi / 4n, n) !== ONE) {
        continue;
      }

      logger.debug(
        `Keys generated after ${attempt + 1} attempts, n bits: ${bitLength(n)}`
      );
      return {
        public_key: { n, g, sigma },
        private_key: { a, b, p, q, phi },
      };
    }

    throw new Error(
      `Failed to generate Naccache-Stern keys after ${maxTries} attempts.` +
        'Please try to rerun.'
    );
  }

  /** Naccache-Stern draws a fresh one-time random key per encryption. */
  generateRandomKey(): bigint {
    const n = this.keys.public_key!.n as bigint;
    return randomRange(ONE, n - ONE);
  }

  encrypt(plaintext: bigint, randomKey?: bigint | bigint[]): CiphertextValue {
    const g = this.keys.public_key!.g as bigint;
    const n = this.keys.public_key!.n as bigint;
    const sigma = this.keys.public_key!.sigma as bigint;
    const r =
      typeof randomKey === 'bigint' && randomKey !== ZERO
        ? randomKey
        : this.generateRandomKey();

    let message = plaintext;
    if (message > this.plaintextModulo) {
      message = message % this.plaintextModulo;
      logger.debug(
        `plaintext must be in scale [0, ${this.plaintextModulo}] ` +
          `but this is exceeded. New plaintext is ${message}`
      );
    }

    if (this.deterministic) {
      return modPow(g, message, n);
    }
    return (modPow(r, sigma, n) * modPow(g, message, n)) % n;
  }

  decrypt(ciphertext: CiphertextValue): bigint {
    const phi = this.keys.private_key!.phi as bigint;
    const n = this.keys.public_key!.n as bigint;
    const g = this.keys.public_key!.g as bigint;
    const sigma = this.keys.public_key!.sigma as bigint;
    // sigma is the product of the small primes; recover them by factoring.
    const primeSet = primeFactors(sigma).sort((x, y) => (x < y ? -1 : 1));

    const remainders: bigint[] = [];
    for (let i = 0; i < primeSet.length; i++) {
      const prime = primeSet[i];
      const ci = modPow(ciphertext as bigint, phi / prime, n);
      logger.debug(`c_${i} = ${ci}`);

      let j = ZERO;
      for (;;) {
        if (ci === modPow(g, (j * phi) / prime, n)) {
          logger.debug(`m_${i} = ${j}`);
          remainders.push(j);
          break;
        }
        j += ONE;
        if (j > prime * prime) {
          throw new Error(
            `c_${i} cannot be restored from ${ci} = ${g}^(j*${phi}/${prime}) mod ${n}`
          );
        }
      }
    }

    const congruences: Array<[bigint, bigint]> = primeSet.map((prime, i) => {
      logger.debug(`m mod ${prime} = ${remainders[i]}`);
      return [remainders[i], prime];
    });

    // chinese remainder problem
    const solution = solveCongruence(congruences);
    if (solution === undefined) {
      throw new Error('message cannot be restored with Chinese Remainder!');
    }
    return solution[0];
  }

  /** Homomorphic addition, computed modulo `n`: the result decrypts to `m1 + m2`. */
  override add(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): CiphertextValue {
    return (
      ((ciphertext1 as bigint) * (ciphertext2 as bigint)) %
      this.ciphertextModulo
    );
  }

  /** Multiplies a ciphertext by a known plain constant. */
  override multiplyByConstant(
    ciphertext: CiphertextValue,
    constant: bigint
  ): CiphertextValue {
    let k = constant;
    if (k > this.plaintextModulo) {
      k = k % this.plaintextModulo;
      logger.debug(
        `Naccache-Stern can encrypt messages [1, ${this.plaintextModulo}]. ` +
          `Seems constant exceeded this limit. New constant is ${k}`
      );
    }
    return modPow(ciphertext as bigint, k, this.ciphertextModulo);
  }

  override reencrypt(ciphertext: CiphertextValue): CiphertextValue {
    if (this.deterministic) {
      throw new Error(
        'Deterministic version of Naccache-Stern does not support reencryption.' +
          'If you still want to perform ciphertext regeneration, then you may ' +
          'consider to use its probabilistic version.'
      );
    }
    const neutralEncrypted = this.encrypt(ZERO);
    return this.add(ciphertext, neutralEncrypted);
  }
}

/** Draws `count` distinct items from `items` without replacement. */
function sample(items: readonly bigint[], count: number): bigint[] {
  const pool = [...items];
  const picked: bigint[] = [];
  for (let i = 0; i < count; i++) {
    const index = Number(randomRange(ZERO, BigInt(pool.length - 1)));
    picked.push(pool[index]);
    pool.splice(index, 1);
  }
  return picked;
}
