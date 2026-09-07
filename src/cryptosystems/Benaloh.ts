import { Logger } from '../commons/logger.js';
import {
  gcd,
  modPow,
  nextPrime,
  pow2,
  primeFactors,
  randPrime,
  randomRange,
  ZERO,
  ONE,
  TWO,
} from '../commons/mathUtils.js';
import { Algorithm } from '../models/Algorithm.js';
import { Homomorphic } from '../models/Homomorphic.js';
import type { CiphertextValue, Keys, RequiredKeys } from '../models/types.js';

const logger = new Logger('lightphe-ts/cryptosystems/Benaloh.ts');

/**
 * Benaloh is homomorphic with respect to addition over a small block size `r`;
 * plaintexts live in `[0, r)`.
 */
export class Benaloh extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['y', 'r', 'n'],
    private_key: ['p', 'q', 'phi', 'x'],
  };

  constructor(options?: {
    keys?: Keys | null;
    keySize?: number | null;
    plaintextLimit?: number | bigint | null;
    maxTries?: number;
  }) {
    super();
    this.keys =
      options?.keys ??
      this.generateKeys(options?.keySize ?? 1024, {
        plaintextLimit: options?.plaintextLimit,
        maxTries: options?.maxTries ?? 10000,
      });
    this.plaintextModulo = this.keys.public_key!.r as bigint;
    this.ciphertextModulo = this.keys.public_key!.n as bigint;
  }

  get requiredKeys(): RequiredKeys {
    return Benaloh.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.Benaloh;
  }

  generateKeys(
    keySize: number,
    options?: {
      maxTries?: number;
      plaintextLimit?: number | bigint | null;
    }
  ): Keys {
    const maxTries = options?.maxTries ?? 10000;
    const plaintextLimit =
      options?.plaintextLimit === undefined || options.plaintextLimit === null
        ? null
        : BigInt(options.plaintextLimit);

    const half = Math.floor(keySize / 2);
    const lo = pow2(half - 300);
    const hi = pow2(half) - ONE;

    for (let attempt = 0; attempt < maxTries; attempt++) {
      const p = randPrime(lo, hi);
      const q = randPrime(lo, hi);

      const n = p * q;
      const phi = (p - ONE) * (q - ONE);

      // Generate the block size r; plaintexts will be allowed in [0, r-1].
      const r =
        plaintextLimit === null
          ? randPrime(1000n, 2000n)
          : nextPrime(plaintextLimit);

      // block size r checks
      const rDividesPMinusOne = (p - ONE) % r === ZERO;
      if (!(
        // r should divide p-1 without remainder
        rDividesPMinusOne &&
        // r and (p - 1) / r must be coprimes
        gcd(r, (p - ONE) / r) === ONE &&
        // r and q-1 must be coprimes
        gcd(r, q - ONE) === ONE
      )) {
        continue;
      }

      const y = randomRange(TWO, n);
      if (gcd(y, n) !== ONE) {
        continue;
      }

      // to guarantee correct decryption, none of r's prime factors may satisfy
      // y^(phi/factor) = 1 mod n
      let decryptionGuaranteed = true;
      for (const primeFactor of primeFactors(r)) {
        if (modPow(y, phi / primeFactor, n) === ONE) {
          decryptionGuaranteed = false;
        }
      }
      if (!decryptionGuaranteed) {
        logger.debug('decryption not guaranteed, retrying...');
        continue;
      }

      const x = modPow(y, phi / r, n);
      if (x !== ONE) {
        return {
          public_key: { y, r, n },
          private_key: { p, q, phi, x },
        };
      }
    }

    throw new Error(
      `Failed to generate Benaloh keys after ${maxTries} attempts.` +
        `Please try to rerun or consider to decrese plaintextLimit=${String(plaintextLimit)}.`
    );
  }

  generateRandomKey(): bigint {
    const n = this.keys.public_key!.n as bigint;
    for (;;) {
      const u = randomRange(ONE, n);
      if (gcd(u, n) === ONE) {
        return u;
      }
    }
  }

  encrypt(plaintext: bigint, randomKey?: bigint | bigint[]): CiphertextValue {
    const y = this.keys.public_key!.y as bigint;
    const r = this.keys.public_key!.r as bigint;
    const n = this.keys.public_key!.n as bigint;

    const u =
      typeof randomKey === 'bigint' && randomKey !== ZERO
        ? randomKey
        : this.generateRandomKey();

    let message = plaintext;
    if (message > r) {
      const original = message;
      message = message % r;
      logger.info(
        `Benaloh lets you to encrypt messages in [0, r=${r}).` +
          `But your plaintext ${original} exceeds this limit.` +
          `New plaintext is ${message}`
      );
    }

    const c = (modPow(y, message, n) * modPow(u, r, n)) % n;
    if (gcd(c, n) !== ONE) {
      logger.debug('ciphertext is not co-prime with n!');
    }
    return c;
  }

  decrypt(ciphertext: CiphertextValue): bigint {
    const n = this.keys.public_key!.n as bigint;
    const r = this.keys.public_key!.r as bigint;
    const phi = this.keys.private_key!.phi as bigint;
    const x = this.keys.private_key!.x as bigint;

    const a = modPow(ciphertext as bigint, phi / r, n);

    // Solve the small discrete log x^md = a mod n by exhaustive search.
    let md = ZERO;
    for (;;) {
      if (modPow(x, md, n) === a) {
        return md;
      }
      md += ONE;
      if (md > r) {
        throw new Error(`Message cannot be restored in [0, ${n}]`);
      }
    }
  }

  /** Homomorphic addition, computed modulo `n`: the result decrypts to `m1 + m2`. */
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
    if (k > this.plaintextModulo) {
      k = k % this.plaintextModulo;
      logger.info(
        `Benaloh can encrypt messages [1, ${this.plaintextModulo}]. ` +
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
