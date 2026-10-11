import { Logger } from '../commons/logger.js';
import {
  gcd,
  isPrime,
  jacobiSymbol,
  modInverse,
  modPow,
  pow2,
  randPrime,
  randomRange,
  ONE,
  TWO,
  ZERO,
} from '../commons/mathUtils.js';
import { Algorithm } from '../models/Algorithm.js';
import { Homomorphic } from '../models/Homomorphic.js';
import type { CiphertextValue, Keys, RequiredKeys } from '../models/types.js';

const logger = new Logger('lightphe-ts/cryptosystems/JoyeLibert.ts');

/**
 * Floats are represented as `dividend * divisor^-1` where the divisor is a power
 * of 10, but powers of 10 are not invertible in the plaintext space `Z_{2^k}`.
 */
export const FLOAT_NOT_SUPPORTED_MSG =
  'Joye-Libert does not support float values because its plaintext space is Z_{2^k}' +
  ' where powers of 10 have no modular inverse. Use integers instead.';

/**
 * Joye-Libert is homomorphic with respect to addition, and supports
 * multiplying a ciphertext by a known plain constant. It generalises
 * Goldwasser-Micali from 1 bit to k bit messages by using 2^k-th power residue
 * symbols, so messages live in `Z_{2^k}`.
 *
 * Ref: Joye, M., Libert, B. (2013). Efficient Cryptosystems from 2^k-th Power
 * Residue Symbols. EUROCRYPT 2013. https://eprint.iacr.org/2013/435
 */
export class JoyeLibert extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['n', 'y', 'k'],
    private_key: ['p'],
  };

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
    this.plaintextModulo = pow2(Number(this.keys.public_key!.k as bigint));
    this.ciphertextModulo = this.keys.public_key!.n as bigint;
  }

  get requiredKeys(): RequiredKeys {
    return JoyeLibert.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.JoyeLibert;
  }

  generateKeys(keySize: number, options?: { maxTries?: number }): Keys {
    const maxTries = options?.maxTries ?? 10000;
    const primeSize = Math.floor(keySize / 2);

    // message space is Z_{2^k}. p - 1 must be divisible by 2^k, and the
    // remaining part of p must be large enough to keep factoring n hard.
    const k = Math.max(1, Math.floor(keySize / 4));
    const twoK = pow2(k);

    // picking a prime p such that p = 1 mod 2^k
    let p: bigint | undefined;
    for (let i = 0; i < maxTries; i++) {
      const t = randomRange(pow2(primeSize - k - 1), pow2(primeSize - k) - ONE);
      const candidate = t * twoK + ONE;
      if (isPrime(candidate)) {
        p = candidate;
        break;
      }
    }
    if (p === undefined) {
      throw new Error(
        `Failed to find prime p = 1 mod 2^${k} in ${maxTries} tries`
      );
    }

    // picking a prime modulus q
    let q = randPrime(pow2(primeSize - 1), pow2(primeSize) - ONE);
    while (q === p) {
      q = randPrime(pow2(primeSize - 1), pow2(primeSize) - ONE);
    }

    const n = p * q;

    // y must be a quadratic non-residue modulo both p and q,
    // so y is in J_n \ QR_n (jacobi symbol 1 but not a square)
    for (let i = 0; i < maxTries; i++) {
      const y = randomRange(TWO, n - ONE);
      if (gcd(y, n) !== ONE) {
        continue;
      }
      if (jacobiSymbol(y, p) === -1 && jacobiSymbol(y, q) === -1) {
        return {
          public_key: { n, y, k: BigInt(k) },
          private_key: { p },
        };
      }
    }
    throw new Error(`Failed to find suitable y in ${maxTries} tries`);
  }

  /** Joye-Libert draws a fresh random key coprime to `n` per encryption. */
  generateRandomKey(): bigint {
    const n = this.keys.public_key!.n as bigint;
    for (;;) {
      const x = randomRange(ONE, n - ONE);
      if (gcd(x, n) === ONE) {
        return x;
      }
    }
  }

  encrypt(plaintext: bigint, randomKey?: bigint | bigint[]): CiphertextValue {
    const n = this.keys.public_key!.n as bigint;
    const y = this.keys.public_key!.y as bigint;
    const k = this.keys.public_key!.k as bigint;
    const x =
      typeof randomKey === 'bigint' && randomKey !== ZERO
        ? randomKey
        : this.generateRandomKey();

    let m = plaintext;
    if (m >= this.plaintextModulo) {
      m = m % this.plaintextModulo;
      logger.debug(
        `Joye-Libert can encrypt messages [0, ${this.plaintextModulo}). ` +
          `Seems plaintext exceeded this limit. New plaintext is ${m}`
      );
    }

    return (modPow(y, m, n) * modPow(x, TWO ** k, n)) % n;
  }

  decrypt(ciphertext: CiphertextValue): bigint {
    const p = this.keys.private_key!.p as bigint;
    const y = this.keys.public_key!.y as bigint;
    const k = Number(this.keys.public_key!.k as bigint);
    const exponent = (p - ONE) >> BigInt(k);

    // z = D^m mod p where D = y^((p-1)/2^k) has order exactly 2^k,
    // so m can be restored bit by bit
    let z = modPow(ciphertext as bigint, exponent, p);
    let dInv = modInverse(modPow(y, exponent, p), p);

    let m = ZERO;
    let b = ONE;
    for (let j = 1; j < k; j++) {
      if (modPow(z, pow2(k - j), p) !== ONE) {
        m += b;
        z = (z * dInv) % p;
      }
      b *= TWO;
      dInv = (dInv * dInv) % p;
    }

    if (z !== ONE) {
      m += b;
    }

    return m;
  }

  /** Homomorphic addition: the result decrypts to `m1 + m2`. */
  override add(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): CiphertextValue {
    const n = this.keys.public_key!.n as bigint;
    return ((ciphertext1 as bigint) * (ciphertext2 as bigint)) % n;
  }

  /** Multiplies a ciphertext by a known plain constant. */
  override multiplyByConstant(
    ciphertext: CiphertextValue,
    constant: bigint
  ): CiphertextValue {
    const n = this.keys.public_key!.n as bigint;
    let k = constant;
    if (k >= this.plaintextModulo) {
      k = k % this.plaintextModulo;
      logger.debug(
        `Joye-Libert can encrypt messages [0, ${this.plaintextModulo}). ` +
          `Seems constant exceeded this limit. New constant is ${k}`
      );
    }
    return modPow(ciphertext as bigint, k, n);
  }

  override reencrypt(ciphertext: CiphertextValue): CiphertextValue {
    const neutralEncrypted = this.encrypt(ZERO);
    return this.add(ciphertext, neutralEncrypted);
  }
}
