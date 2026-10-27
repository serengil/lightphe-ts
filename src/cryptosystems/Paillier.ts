import { Logger } from '../commons/logger.js';
import {
  gcd,
  modInverse,
  modPow,
  pow2,
  randPrime,
  randomRange,
  ZERO,
  ONE,
} from '../commons/mathUtils.js';
import * as thresholdUtils from '../commons/threshold.js';
import * as zkp from '../commons/zkp.js';
import { Algorithm } from '../models/Algorithm.js';
import { Homomorphic } from '../models/Homomorphic.js';
import type {
  CiphertextValue,
  Keys,
  MembershipProof,
  PaillierKnowledgeProof,
  PartialDecryption,
  RandomKey,
  RandomnessProof,
  RequiredKeys,
} from '../models/types.js';

const logger = new Logger('lightphe-ts/cryptosystems/Paillier.ts');

const MEMBERSHIP_DOMAIN = 'lightphe/paillier/membership';
const KNOWLEDGE_DOMAIN = 'lightphe/paillier/knowledge';
const PARTIAL_DECRYPTION_DOMAIN = 'lightphe/paillier/partial-decryption';

/**
 * Paillier is homomorphic with respect to addition, and also supports raising a
 * ciphertext to a plaintext exponent.
 *
 * Ref: https://sefiks.com/2023/04/03/a-step-by-step-partially-homomorphic-encryption-example-with-paillier-in-python/
 */
export class Paillier extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['g', 'n'],
    private_key: ['phi'],
  };

  constructor(options?: { keys?: Keys | null; keySize?: number | null }) {
    super();
    this.keys = options?.keys ?? this.generateKeys(options?.keySize ?? 1024);
    const n = this.keys.public_key!.n as bigint;
    this.plaintextModulo = n;
    this.ciphertextModulo = n * n;
  }

  get requiredKeys(): RequiredKeys {
    return Paillier.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.Paillier;
  }

  generateKeys(keySize: number): Keys {
    const hi = pow2(Math.floor(keySize / 2)) - ONE;

    // picking prime moduli p and q
    const p = randPrime(200n, hi);
    const q = randPrime(200n, hi);

    const n = p * q;
    const phi = (p - ONE) * (q - ONE);
    const g = ONE + n;

    return {
      public_key: { g, n },
      private_key: { phi },
    };
  }

  /** Paillier draws a fresh random key coprime to `n` per encryption. */
  generateRandomKey(): bigint {
    const n = this.keys.public_key!.n as bigint;
    for (;;) {
      const r = randomRange(ZERO, n);
      if (gcd(r, n) === ONE) {
        return r;
      }
    }
  }

  encrypt(plaintext: bigint, randomKey?: bigint | bigint[]): CiphertextValue {
    const g = this.keys.public_key!.g as bigint;
    const n = this.keys.public_key!.n as bigint;
    const r =
      typeof randomKey === 'bigint' && randomKey !== ZERO
        ? randomKey
        : this.generateRandomKey();

    if (gcd(r, n) !== ONE) {
      throw new Error('random key must be coprime to n');
    }
    const nSquared = n * n;
    return (modPow(g, plaintext, nSquared) * modPow(r, n, nSquared)) % nSquared;
  }

  decrypt(ciphertext: CiphertextValue): bigint {
    const phi = this.keys.private_key!.phi as bigint;
    const n = this.keys.public_key!.n as bigint;
    const mu = modInverse(phi, n);

    return (this.lx(modPow(ciphertext as bigint, phi, n * n)) * mu) % n;
  }

  /**
   * Splits the private key into shares. Any threshold many shareholders can
   * decrypt a ciphertext together, but fewer shareholders cannot. If keys are
   * generated with safe primes, verification keys are published to verify
   * partial decryptions.
   *
   * @returns public key and share of each shareholder.
   */
  override generateThresholdKeys(threshold: number, parties: number): Keys[] {
    return thresholdUtils.generatePaillierThresholdKeys(
      this.keys,
      ONE,
      this.ciphertextModulo,
      threshold,
      parties
    );
  }

  /**
   * Decrypts a ciphertext partially with the share of a shareholder, and
   * optionally proves that it is computed with the share behind the
   * verification key.
   *
   * @param prove - set this to true to attach a zero-knowledge proof of
   *   correctness. Keys must be generated with safe primes.
   */
  override partialDecrypt(
    ciphertext: CiphertextValue,
    prove = false
  ): PartialDecryption {
    return thresholdUtils.paillierPartialDecrypt(
      this.keys,
      ciphertext as bigint,
      this.ciphertextModulo,
      prove,
      PARTIAL_DECRYPTION_DOMAIN
    );
  }

  /** Verifies that a partial decryption is computed with the share of its shareholder. */
  override verifyPartialDecryption(
    ciphertext: CiphertextValue,
    partialDecryption: unknown
  ): boolean {
    return thresholdUtils.verifyPaillierPartialDecryption(
      this.keys,
      ciphertext as bigint,
      partialDecryption,
      this.ciphertextModulo,
      PARTIAL_DECRYPTION_DOMAIN
    );
  }

  /**
   * Restores plaintext from partial decryptions of threshold many
   * shareholders. If verify is true, partial decryptions with invalid or
   * missing proofs are discarded.
   *
   * @param verify - set this to true to check proofs of partial decryptions.
   *   Default is false, then a wrong partial decryption of a cheating
   *   shareholder causes a wrong plaintext silently. Keys must be generated
   *   with safe primes.
   */
  override combinePartialDecryptions(
    ciphertext: CiphertextValue,
    partialDecryptions: readonly unknown[],
    verify = false
  ): bigint {
    return thresholdUtils.combinePaillierPartialDecryptions(
      this.keys,
      ciphertext as bigint,
      partialDecryptions,
      this.ciphertextModulo,
      verify,
      PARTIAL_DECRYPTION_DOMAIN
    );
  }

  /**
   * Decrypts a ciphertext and proves that decryption is correct. Randomness of
   * the ciphertext is the proof, and anyone having public key can check it.
   */
  override decryptWithProof(
    ciphertext: CiphertextValue
  ): [bigint, RandomnessProof] {
    const plaintext = this.decrypt(ciphertext);
    const proof = zkp.provePaillierDecryption(
      ciphertext as bigint,
      plaintext,
      this.keys.public_key!.n as bigint,
      this.keys.private_key!.phi as bigint
    );
    return [plaintext, proof];
  }

  /** Verifies that a ciphertext is decrypted to the given plaintext with public key only. */
  override verifyDecryption(
    ciphertext: CiphertextValue,
    plaintext: unknown,
    proof: unknown
  ): boolean {
    return zkp.verifyPaillierDecryption(
      ciphertext,
      plaintext,
      proof,
      this.keys.public_key!.n as bigint
    );
  }

  /**
   * Encrypts a plaintext and proves that it is one of the given values
   * without revealing which one, e.g. a vote is 0 or 1. 1-out-of-k proof of
   * Damgard and Jurik shows that `c * g^-v` is an n-th power for one of the
   * values v.
   *
   * @param context - public data bound to the proof, e.g. id of the voter.
   */
  override encryptWithProof(
    plaintext: bigint,
    values: readonly bigint[],
    context?: unknown
  ): [CiphertextValue, MembershipProof] {
    const r = this.generateRandomKey();
    const ciphertext = this.encrypt(plaintext, r);
    const proof = this.proveMembership(
      ciphertext,
      plaintext,
      r,
      values,
      context
    );
    return [ciphertext, proof];
  }

  /**
   * Proves that a ciphertext encrypts one of the given values, without
   * revealing which one. Encryptor of the ciphertext knows its plaintext and
   * random key, e.g. a ciphertext restored homomorphically from ciphertexts
   * encrypted by the prover.
   */
  override proveMembership(
    ciphertext: CiphertextValue,
    plaintext: bigint,
    randomKey: RandomKey,
    values: readonly bigint[],
    context?: unknown
  ): MembershipProof {
    const n = this.keys.public_key!.n as bigint;
    const modulo = n * n;
    return zkp.proveNthPowerOr({
      n,
      modulo,
      us: zkp.paillierMembershipCandidates(
        ciphertext as bigint,
        values,
        n,
        modulo
      ),
      r: randomKey as bigint,
      index: values.indexOf(plaintext),
      domain: MEMBERSHIP_DOMAIN,
      context: [values, context ?? null],
    });
  }

  /** Random key of the homomorphic sum of ciphertexts, as `r^n` multiplies. */
  override combineRandomKeys(randomKeys: readonly RandomKey[]): bigint {
    const n = this.keys.public_key!.n as bigint;
    const modulo = n * n;
    return (randomKeys as readonly bigint[]).reduce(
      (combined, randomKey) => (combined * randomKey) % modulo,
      ONE
    );
  }

  /** Verifies that a ciphertext encrypts one of the given values with public key only. */
  override verifyCiphertext(
    ciphertext: CiphertextValue,
    proof: unknown,
    values: readonly bigint[],
    context?: unknown
  ): boolean {
    if (typeof ciphertext !== 'bigint') {
      return false;
    }
    const n = this.keys.public_key!.n as bigint;
    const modulo = n * n;
    if (
      ciphertext <= ZERO ||
      ciphertext >= modulo ||
      gcd(ciphertext, n) !== ONE
    ) {
      return false;
    }
    return zkp.verifyNthPowerOr({
      n,
      modulo,
      us: zkp.paillierMembershipCandidates(ciphertext, values, n, modulo),
      proof,
      domain: MEMBERSHIP_DOMAIN,
      context: [values, context ?? null],
    });
  }

  /**
   * Encrypts a plaintext and proves knowledge of the plaintext and randomness
   * without revealing them. So, a copied, re-randomized or modified ciphertext
   * of someone else cannot be proven.
   */
  override encryptWithProofOfKnowledge(
    plaintext: bigint,
    context?: unknown
  ): [CiphertextValue, PaillierKnowledgeProof] {
    const n = this.keys.public_key!.n as bigint;
    const modulo = n * n;
    const r = this.generateRandomKey();
    const ciphertext = this.encrypt(plaintext, r) as bigint;
    const proof = zkp.provePaillierKnowledge({
      ciphertext,
      plaintext,
      r,
      n,
      modulo,
      domain: KNOWLEDGE_DOMAIN,
      context,
    });
    return [ciphertext, proof];
  }

  /** Verifies that the encryptor of a ciphertext knows its plaintext with public key only. */
  override verifyKnowledge(
    ciphertext: CiphertextValue,
    proof: unknown,
    context?: unknown
  ): boolean {
    const n = this.keys.public_key!.n as bigint;
    const modulo = n * n;
    return zkp.verifyPaillierKnowledge({
      ciphertext,
      proof,
      n,
      modulo,
      domain: KNOWLEDGE_DOMAIN,
      context,
    });
  }

  /**
   * Homomorphic addition, computed modulo `n^2`: the result decrypts to
   * `m1 + m2`.
   */
  override add(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): CiphertextValue {
    const n = this.keys.public_key!.n as bigint;
    return ((ciphertext1 as bigint) * (ciphertext2 as bigint)) % (n * n);
  }

  /**
   * Multiplies a ciphertext by a known plain constant: the result decrypts to
   * `m * constant`.
   */
  override multiplyByConstant(
    ciphertext: CiphertextValue,
    constant: bigint
  ): CiphertextValue {
    const n = this.keys.public_key!.n as bigint;

    let k = constant;
    if (k > this.plaintextModulo) {
      k = k % this.plaintextModulo;
      logger.debug(
        `Paillier can encrypt messages [1, ${n}]. ` +
          `Seems constant exceeded this limit. New constant is ${k}`
      );
    }
    return modPow(ciphertext as bigint, k, n * n);
  }

  override reencrypt(ciphertext: CiphertextValue): CiphertextValue {
    const neutralEncrypted = this.encrypt(ZERO);
    return this.add(ciphertext, neutralEncrypted);
  }

  /** The `L` function over the cyclic group: `(x - 1) / n`. */
  lx(x: bigint): bigint {
    const n = this.keys.public_key!.n as bigint;
    const y = x - ONE;
    if (y % n !== ZERO) {
      throw new Error(`(${x} - 1) must be divisible by ${n}`);
    }
    return y / n;
  }
}
