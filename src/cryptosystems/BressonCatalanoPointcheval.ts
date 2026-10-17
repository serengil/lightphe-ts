import { Logger } from '../commons/logger.js';
import {
  gcd,
  modInverse,
  modPow,
  randomRange,
  ONE,
  TWO,
  ZERO,
} from '../commons/mathUtils.js';
import { findSafePrime } from '../commons/safePrimes.js';
import { Algorithm } from '../models/Algorithm.js';
import { Homomorphic } from '../models/Homomorphic.js';
import type {
  CiphertextValue,
  KeyPart,
  Keys,
  RandomKey,
  RequiredKeys,
} from '../models/types.js';

const logger = new Logger(
  'lightphe-ts/cryptosystems/BressonCatalanoPointcheval.ts'
);

/**
 * Bresson-Catalano-Pointcheval is homomorphic with respect to addition, and
 * supports multiplying a ciphertext by a known plain constant. It is an
 * ElGamal-like scheme in `Z_{n^2}*` with a double trapdoor decryption
 * mechanism. A ciphertext can be decrypted either with the secret exponent a
 * (local trapdoor), or with the factorization of n (master trapdoor) without
 * knowing a.
 *
 * An authority holding the master key publishes n and g, then every user
 * generates its own key pair on top of them. The authority can decrypt
 * ciphertexts of all those users, so this is a key escrow mechanism by design.
 *
 * Ref: Bresson, E., Catalano, D., Pointcheval, D. (2003). A Simple Public-Key
 * Cryptosystem with a Double Trapdoor Decryption Mechanism and Its
 * Applications. ASIACRYPT 2003.
 */
export class BressonCatalanoPointcheval extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['n', 'g', 'h'],
    private_key: ['a'],
    // authority may keep the master trapdoor only
    alternative_private_key: ['p', 'q'],
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
    const n = this.keys.public_key!.n as bigint;
    this.plaintextModulo = n;
    this.ciphertextModulo = n * n;
  }

  get requiredKeys(): RequiredKeys {
    return BressonCatalanoPointcheval.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.BressonCatalanoPointcheval;
  }

  generateKeys(keySize: number, options?: { maxTries?: number }): Keys {
    const maxTries = options?.maxTries ?? 10000;

    if (keySize < 16) {
      throw new Error(
        `Key size ${keySize} is too small for Bresson-Catalano-Pointcheval`
      );
    }

    // p = 2p' + 1 and q = 2q' + 1 are safe primes
    const primeSize = Math.floor(keySize / 2);
    const p = findSafePrime(primeSize, maxTries);
    let q = findSafePrime(primeSize, maxTries);
    while (q === p) {
      q = findSafePrime(primeSize, maxTries);
    }

    const n = p * q;
    const nSquare = n * n;
    const pPrime = (p - ONE) / TWO;
    const qPrime = (q - ONE) / TWO;

    // g is a square in Z_{n^2}* of maximal order, so that g^(p'q') = 1 + kn
    // mod n^2 for some k co-prime to n. k is required by the master trapdoor.
    let g: bigint | undefined;
    for (let i = 0; i < maxTries; i++) {
      const alpha = randomRange(TWO, nSquare - ONE);
      if (gcd(alpha, n) !== ONE) {
        continue;
      }
      const candidate = modPow(alpha, TWO, nSquare);
      const k = (modPow(candidate, pPrime * qPrime, nSquare) - ONE) / n;
      if (
        gcd(k, n) === ONE &&
        modPow(candidate, pPrime, n) !== ONE &&
        modPow(candidate, qPrime, n) !== ONE
      ) {
        g = candidate;
        break;
      }
    }
    if (g === undefined) {
      throw new Error(
        `Failed to find a suitable generator in ${maxTries} tries`
      );
    }

    // local trapdoor
    const a = randomRange(ONE, nSquare / TWO);
    const h = modPow(g, a, nSquare);

    return {
      public_key: { n, g, h },
      // p and q are the master trapdoor
      private_key: { a, p, q },
    };
  }

  /**
   * Generates a key pair for a new user sharing n and g of this cryptosystem.
   * It requires the public key only. The private key of the new user has its
   * local trapdoor a only, not the master trapdoor.
   */
  override generateUserKeys(): Keys {
    const n = this.keys.public_key!.n as bigint;
    const g = this.keys.public_key!.g as bigint;
    const nSquare = n * n;
    const a = randomRange(ONE, nSquare / TWO);
    return {
      public_key: { n, g, h: modPow(g, a, nSquare) },
      private_key: { a },
    };
  }

  /** Bresson-Catalano-Pointcheval draws a fresh random key per encryption. */
  generateRandomKey(): bigint {
    const n = this.keys.public_key!.n as bigint;
    return randomRange(ONE, n * n - ONE);
  }

  /**
   * Encrypts a plaintext as `A = g^r mod n^2` and `B = h^r (1 + mn) mod n^2`.
   */
  encrypt(plaintext: bigint, randomKey?: RandomKey): bigint[] {
    const n = this.keys.public_key!.n as bigint;
    const g = this.keys.public_key!.g as bigint;
    const h = this.keys.public_key!.h as bigint;
    const nSquare = n * n;
    const r =
      typeof randomKey === 'bigint' && randomKey !== ZERO
        ? randomKey
        : this.generateRandomKey();

    let m = plaintext;
    if (m >= n) {
      m = m % n;
      logger.debug(
        `Bresson-Catalano-Pointcheval can encrypt messages [0, ${n}). ` +
          `Seems plaintext exceeded this limit. New plaintext is ${m}`
      );
    }

    const aPart = modPow(g, r, nSquare);
    const bPart = (modPow(h, r, nSquare) * (ONE + m * n)) % nSquare;
    return [aPart, bPart];
  }

  /** Decrypts a ciphertext with the local trapdoor a. */
  decrypt(ciphertext: CiphertextValue): bigint {
    if (this.keys.private_key?.a === undefined) {
      throw new Error(
        'Private key does not have the local trapdoor a. ' +
          'Use decryptWithMasterKey if you have the master key.'
      );
    }

    const n = this.keys.public_key!.n as bigint;
    const a = this.keys.private_key.a as bigint;
    const nSquare = n * n;
    const [aPart, bPart] = ciphertext as readonly bigint[];

    // B / A^a = (1 + mn) mod n^2
    const restored =
      (bPart * modInverse(modPow(aPart, a, nSquare), nSquare)) % nSquare;
    return this.lx(restored);
  }

  /**
   * Decrypts a ciphertext with the master trapdoor, which is the factorization
   * of n. It does not require the local trapdoor a, so the master key can
   * decrypt ciphertexts of any key pair sharing the same n and g.
   *
   * @param ciphertext - encrypted message.
   * @param publicKey - public key of the user who the ciphertext was encrypted
   *   for. Public key of this cryptosystem is used if you do not set this.
   */
  override decryptWithMasterKey(
    ciphertext: CiphertextValue,
    publicKey?: KeyPart | null
  ): bigint {
    const privateKey = this.keys.private_key ?? {};
    if (privateKey.p === undefined || privateKey.q === undefined) {
      throw new Error('Private key does not have the master trapdoor p and q');
    }

    const n = this.keys.public_key!.n as bigint;
    const g = this.keys.public_key!.g as bigint;
    const userPublicKey = publicKey ?? this.keys.public_key!;
    if (userPublicKey.n !== n || userPublicKey.g !== g) {
      throw new Error(
        'Ciphertext was not encrypted for a user of this master key ' +
          'as it does not share the same n and g'
      );
    }
    const h = userPublicKey.h as bigint;
    const p = privateKey.p as bigint;
    const q = privateKey.q as bigint;
    const nSquare = n * n;
    const order = ((p - ONE) / TWO) * ((q - ONE) / TWO);
    const [aPart, bPart] = ciphertext as readonly bigint[];

    // g^(p'q') = 1 + kn, so x^(p'q') = 1 + (log_g x) k n for any power x of g
    const kInv = modInverse(this.lx(modPow(g, order, nSquare)), n);
    const aModN = (this.lx(modPow(h, order, nSquare)) * kInv) % n;
    const rModN = (this.lx(modPow(aPart, order, nSquare)) * kInv) % n;
    const gamma = (aModN * rModN) % n;

    // B / g^gamma = g^(n t) (1 + mn) for some t, and g^(n t p'q') = 1 mod n^2
    const masked =
      (bPart * modInverse(modPow(g, gamma, nSquare), nSquare)) % nSquare;
    return (this.lx(modPow(masked, order, nSquare)) * modInverse(order, n)) % n;
  }

  /** Homomorphic addition: the result decrypts to `m1 + m2`. */
  override add(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): bigint[] {
    const n = this.keys.public_key!.n as bigint;
    const nSquare = n * n;
    const [a1, b1] = ciphertext1 as readonly bigint[];
    const [a2, b2] = ciphertext2 as readonly bigint[];
    return [(a1 * a2) % nSquare, (b1 * b2) % nSquare];
  }

  /** Multiplies a ciphertext by a known plain constant. */
  override multiplyByConstant(
    ciphertext: CiphertextValue,
    constant: bigint
  ): bigint[] {
    const n = this.keys.public_key!.n as bigint;
    const nSquare = n * n;

    let k = constant;
    if (k >= this.plaintextModulo) {
      k = k % this.plaintextModulo;
      logger.debug(
        `Bresson-Catalano-Pointcheval can encrypt messages [0, ${n}). ` +
          `Seems constant exceeded this limit. New constant is ${k}`
      );
    }

    const [aPart, bPart] = ciphertext as readonly bigint[];
    return [modPow(aPart, k, nSquare), modPow(bPart, k, nSquare)];
  }

  override reencrypt(ciphertext: CiphertextValue): bigint[] {
    return this.add(ciphertext, this.encrypt(ZERO));
  }

  /** The `L` function of Paillier-like schemes: `(x - 1) / n`. */
  private lx(x: bigint): bigint {
    const n = this.keys.public_key!.n as bigint;
    return (x - ONE) / n;
  }
}
