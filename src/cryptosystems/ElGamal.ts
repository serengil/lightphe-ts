import { Logger } from '../commons/logger.js';
import {
  bitLength,
  isPrime,
  isqrt,
  mod,
  modInverse,
  modPow,
  pow2,
  randPrime,
  randomRange,
  ZERO,
  ONE,
  TWO,
} from '../commons/mathUtils.js';
import * as thresholdUtils from '../commons/threshold.js';
import * as zkp from '../commons/zkp.js';
import { Algorithm } from '../models/Algorithm.js';
import { Homomorphic } from '../models/Homomorphic.js';
import type {
  ChallengeResponseProof,
  CiphertextValue,
  Keys,
  MembershipProof,
  PartialDecryption,
  RandomKey,
  RequiredKeys,
} from '../models/types.js';

const logger = new Logger('lightphe-ts/cryptosystems/ElGamal.ts');

const DECRYPTION_DOMAIN = 'lightphe/elgamal/decryption';
const PARTIAL_DECRYPTION_DOMAIN = 'lightphe/elgamal/partial-decryption';
const MEMBERSHIP_DOMAIN = 'lightphe/exponential-elgamal/membership';

/**
 * ElGamal is either multiplicatively or additively homomorphic.
 *
 * Regular ElGamal is homomorphic with respect to multiplication; the
 * exponential variant is homomorphic with respect to addition, at the cost of
 * having to solve a discrete logarithm during decryption.
 *
 * Ref: https://sefiks.com/2023/03/27/a-step-by-step-partially-homomorphic-encryption-example-with-elgamal-in-python/
 */
export class ElGamal extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['p', 'g', 'y'],
    private_key: ['x'],
  };

  readonly exponential: boolean;
  readonly primeOrder: boolean;

  /**
   * @param options.exponential - set this to true to make cryptosystem
   *   exponential ElGamal. Regular ElGamal is homomorphic with respect to the
   *   multiplication whereas exponential ElGamal is homomorphic with respect to
   *   the addition.
   * @param options.primeOrder - set this to true to pick g of a known prime
   *   order q while generating keys. Threshold decryption and zero-knowledge
   *   proofs require this.
   */
  constructor(options?: {
    keys?: Keys | null;
    exponential?: boolean;
    keySize?: number | null;
    primeOrder?: boolean;
  }) {
    super();
    this.exponential = options?.exponential ?? false;
    this.primeOrder = options?.primeOrder ?? false;
    this.keys = options?.keys ?? this.generateKeys(options?.keySize ?? 1024);
    const p = this.keys.public_key!.p as bigint;
    this.plaintextModulo = p;
    this.ciphertextModulo = p;
  }

  get requiredKeys(): RequiredKeys {
    return ElGamal.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return this.exponential ? Algorithm.ExponentialElGamal : Algorithm.ElGamal;
  }

  generateKeys(keySize: number): Keys {
    if (this.primeOrder) {
      return generatePrimeOrderKeys(keySize);
    }

    // picking a prime modulus p
    const p = randPrime(100n, pow2(Math.floor(keySize / 2)) - ONE);

    // picking a generator g
    const g = randomRange(TWO, isqrt(p));

    // picking a private key x
    const x = randomRange(ONE, p - TWO);

    // public key
    const y = modPow(g, x, p);

    return {
      public_key: { p, g, y },
      private_key: { x },
    };
  }

  /** ElGamal draws a fresh one-time random key per encryption. */
  generateRandomKey(): bigint {
    const p = this.keys.public_key!.p as bigint;
    return randomRange(ONE, p - ONE);
  }

  encrypt(plaintext: bigint, randomKey?: bigint | bigint[]): CiphertextValue {
    const p = this.keys.public_key!.p as bigint;
    const g = this.keys.public_key!.g as bigint;
    const y = this.keys.public_key!.y as bigint;
    const r =
      typeof randomKey === 'bigint' && randomKey !== ZERO
        ? randomKey
        : this.generateRandomKey();

    let message = plaintext;
    if (message > p) {
      message = message % p;
      logger.debug(
        `ElGamal can encrypt messages [1, ${p}]. ` +
          `Seems you exceeded this limit. New plaintext is ${message}`
      );
    }

    const c1 = modPow(g, r, p);
    const c2 = this.exponential
      ? (modPow(g, message, p) * modPow(y, r, p)) % p
      : (message * modPow(y, r, p)) % p;

    return [c1, c2];
  }

  decrypt(ciphertext: CiphertextValue): bigint {
    const [c1, c2] = ciphertext as [bigint, bigint];

    const x = this.keys.private_key!.x as bigint;
    const p = this.keys.public_key!.p as bigint;

    const mPrime = (c2 * modPow(c1, -x, p)) % p;
    return this.restorePlaintext(mPrime);
  }

  /**
   * Restores plaintext from `m' = c2 / c1^x`, which is m for ElGamal and g^m
   * for exponential ElGamal.
   */
  private restorePlaintext(mPrime: bigint): bigint {
    if (!this.exponential) {
      return mPrime;
    }

    const p = this.keys.public_key!.p as bigint;
    const g = this.keys.public_key!.g as bigint;

    // m_prime = g^m. Recover m for known m_prime and g, which is a DLP.
    let m = ZERO;
    for (;;) {
      if (modPow(g, m, p) === mPrime) {
        return m;
      }
      m += ONE;
      if (m > p) {
        throw new Error(`Cannot restore the message in [0, ${p}]`);
      }
    }
  }

  /**
   * Splits the private key into shares. Any threshold many shareholders can
   * decrypt a ciphertext together, but fewer shareholders cannot. Verification
   * keys `g^share` are published to verify partial decryptions.
   *
   * @returns public key and share of each shareholder.
   */
  override generateThresholdKeys(threshold: number, parties: number): Keys[] {
    const q = this.getOrder();
    if (BigInt(parties) >= q) {
      throw new Error(
        `Number of parties must be less than the group order ${q}`
      );
    }
    const shares = thresholdUtils.splitSecret(
      this.keys.private_key!.x as bigint,
      threshold,
      parties,
      q
    );
    const p = this.keys.public_key!.p as bigint;
    const g = this.keys.public_key!.g as bigint;
    const verificationKeys: bigint[] = [];
    for (let index = 1; index <= parties; index++) {
      verificationKeys.push(modPow(g, shares.get(index)!, p));
    }
    return thresholdUtils.buildShareKeys(
      this.keys,
      shares,
      threshold,
      parties,
      verificationKeys
    );
  }

  /**
   * Decrypts a ciphertext partially with the share of a shareholder, and
   * optionally proves that it is computed with the share behind the
   * verification key.
   *
   * @param prove - set this to true to attach a zero-knowledge proof of
   *   correctness. Combination with verify discards partial decryptions
   *   without proofs.
   * @returns index of the shareholder, `c1^share` and proof.
   */
  override partialDecrypt(
    ciphertext: CiphertextValue,
    prove = false
  ): PartialDecryption {
    const { index, share } = thresholdUtils.getThresholdKey(this.keys);
    const p = this.keys.public_key!.p as bigint;
    const g = this.keys.public_key!.g as bigint;
    const c1 = (ciphertext as [bigint, bigint])[0];
    const value = modPow(c1, share, p);
    if (!prove) {
      return { index, value };
    }
    const proof = zkp.proveDleq({
      group: this.getGroup(),
      g1: g,
      h1: modPow(g, share, p),
      g2: c1,
      h2: value,
      x: share,
      domain: PARTIAL_DECRYPTION_DOMAIN,
      context: [p, index],
    });
    return { index, value, proof };
  }

  /** Verifies that a partial decryption is computed with the share of its shareholder. */
  override verifyPartialDecryption(
    ciphertext: CiphertextValue,
    partialDecryption: unknown
  ): boolean {
    const verificationKeys = this.keys.public_key!.verification_keys as
      bigint[] | undefined;
    if (verificationKeys == null) {
      throw new Error(
        'Public key does not have verification keys of shareholders'
      );
    }
    try {
      const index = thresholdUtils.indexOf(partialDecryption);
      if (index === undefined || index < 1 || index > verificationKeys.length) {
        return false;
      }
      const { value, proof } = partialDecryption as {
        value?: unknown;
        proof?: unknown;
      };
      const p = this.keys.public_key!.p as bigint;
      return zkp.verifyDleq({
        group: this.getGroup(),
        g1: this.keys.public_key!.g as bigint,
        h1: verificationKeys[index - 1],
        g2: (ciphertext as [bigint, bigint])[0],
        h2: value as bigint,
        proof,
        domain: PARTIAL_DECRYPTION_DOMAIN,
        context: [p, index],
      });
    } catch {
      return false;
    }
  }

  /**
   * Restores plaintext from partial decryptions of threshold many
   * shareholders. If verify is true, partial decryptions with invalid or
   * missing proofs are discarded.
   *
   * @param verify - set this to true to check proofs of partial decryptions.
   *   Default is false, then a wrong partial decryption of a cheating
   *   shareholder causes a wrong plaintext silently.
   */
  override combinePartialDecryptions(
    ciphertext: CiphertextValue,
    partialDecryptions: readonly unknown[],
    verify = false
  ): bigint {
    const selected = thresholdUtils.selectPartialDecryptions(
      this.keys,
      partialDecryptions,
      verify
        ? (partialDecryption) =>
            this.verifyPartialDecryption(ciphertext, partialDecryption)
        : undefined
    );
    const p = this.keys.public_key!.p as bigint;
    const q = this.getOrder();
    const indices = selected.map(
      (partialDecryption) => partialDecryption.index
    );

    // c1^x restored in the exponent with lagrange interpolation
    let c1X = ONE;
    for (const partialDecryption of selected) {
      const coefficient = thresholdUtils.lagrangeCoefficient(
        partialDecryption.index,
        indices,
        q
      );
      const value = zkp.asInteger(partialDecryption.value);
      if (value === undefined) {
        throw new Error('Value of a partial decryption must be an integer');
      }
      c1X = (c1X * modPow(value, coefficient, p)) % p;
    }

    const mPrime =
      ((ciphertext as [bigint, bigint])[1] * modInverse(c1X, p)) % p;
    return this.restorePlaintext(mPrime);
  }

  /**
   * Decrypts a ciphertext and proves that decryption is correct without
   * revealing the private key. Chaum-Pedersen proof shows that
   * `log_g(y) = log_c1(c1^x)`.
   */
  override decryptWithProof(
    ciphertext: CiphertextValue
  ): [bigint, ChallengeResponseProof] {
    const p = this.keys.public_key!.p as bigint;
    const g = this.keys.public_key!.g as bigint;
    const y = this.keys.public_key!.y as bigint;
    const x = this.keys.private_key!.x as bigint;
    const [c1, c2] = ciphertext as [bigint, bigint];
    const c1X = modPow(c1, x, p);
    const proof = zkp.proveDleq({
      group: this.getGroup(),
      g1: g,
      h1: y,
      g2: c1,
      h2: c1X,
      x,
      domain: DECRYPTION_DOMAIN,
      context: [p, c2],
    });
    return [this.restorePlaintext((c2 * modInverse(c1X, p)) % p), proof];
  }

  /**
   * Verifies that a ciphertext is decrypted to the given plaintext with public
   * key only. Exponential ElGamal checks the plaintext in modulo q.
   */
  override verifyDecryption(
    ciphertext: CiphertextValue,
    plaintext: unknown,
    proof: unknown
  ): boolean {
    const group = this.getGroup();
    try {
      const p = this.keys.public_key!.p as bigint;
      const g = this.keys.public_key!.g as bigint;
      const [c1, c2] = ciphertext as [bigint, bigint];
      if (
        typeof plaintext !== 'bigint' ||
        !group.isMember(c1) ||
        typeof c2 !== 'bigint' ||
        c2 <= ZERO ||
        c2 >= p
      ) {
        return false;
      }

      // c1^x implied by the claimed plaintext
      let c1X: bigint;
      if (this.exponential) {
        c1X = (c2 * modPow(g, -plaintext, p)) % p;
      } else {
        if (mod(plaintext, p) === ZERO) {
          return false;
        }
        c1X = (c2 * modInverse(plaintext, p)) % p;
      }

      return zkp.verifyDleq({
        group,
        g1: g,
        h1: this.keys.public_key!.y as bigint,
        g2: c1,
        h2: c1X,
        proof,
        domain: DECRYPTION_DOMAIN,
        context: [p, c2],
      });
    } catch {
      return false;
    }
  }

  /**
   * Encrypts a plaintext and proves that it is one of the given values
   * without revealing which one, e.g. a vote is 0 or 1. Disjunctive
   * Chaum-Pedersen proof shows that `c2 / g^v` is `y^r` for one of the values
   * v. Only supported by exponential ElGamal.
   *
   * @param context - public data bound to the proof, e.g. id of the voter.
   */
  override encryptWithProof(
    plaintext: bigint,
    values: readonly bigint[],
    context?: unknown
  ): [CiphertextValue, MembershipProof] {
    this.requireExponential();
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
    this.requireExponential();
    const [c1, c2] = ciphertext as [bigint, bigint];
    return zkp.proveDleqOr({
      group: this.getGroup(),
      g1: this.keys.public_key!.g as bigint,
      h1: c1,
      g2: this.keys.public_key!.y as bigint,
      h2s: this.membershipCandidates(ciphertext, values),
      x: randomKey as bigint,
      index: values.indexOf(plaintext),
      domain: MEMBERSHIP_DOMAIN,
      context: [this.keys.public_key!.p, c2, values, context ?? null],
    });
  }

  /** Random key of the homomorphic sum of ciphertexts, as `c1 = g^r` multiplies. */
  override combineRandomKeys(randomKeys: readonly RandomKey[]): bigint {
    return (randomKeys as readonly bigint[]).reduce(
      (total, randomKey) => total + randomKey,
      ZERO
    );
  }

  /** Verifies that a ciphertext encrypts one of the given values with public key only. */
  override verifyCiphertext(
    ciphertext: CiphertextValue,
    proof: unknown,
    values: readonly bigint[],
    context?: unknown
  ): boolean {
    this.requireExponential();
    const group = this.getGroup();
    try {
      const [c1, c2] = ciphertext as [bigint, bigint];
      return zkp.verifyDleqOr({
        group,
        g1: this.keys.public_key!.g as bigint,
        h1: c1,
        g2: this.keys.public_key!.y as bigint,
        h2s: this.membershipCandidates(ciphertext, values),
        proof,
        domain: MEMBERSHIP_DOMAIN,
        context: [this.keys.public_key!.p, c2, values, context ?? null],
      });
    } catch {
      return false;
    }
  }

  /**
   * Candidates `c2 / g^v` for each value v. Ciphertext encrypts v if and only
   * if its candidate is `y^r` where `c1 = g^r`.
   */
  private membershipCandidates(
    ciphertext: CiphertextValue,
    values: readonly bigint[]
  ): bigint[] {
    const p = this.keys.public_key!.p as bigint;
    const g = this.keys.public_key!.g as bigint;
    const c2 = (ciphertext as [bigint, bigint])[1];
    return values.map((value) => (c2 * modPow(g, -value, p)) % p);
  }

  /** Throws if this is not exponential ElGamal. */
  private requireExponential(): void {
    if (!this.exponential) {
      throw new Error(
        'ElGamal does not support proving that a ciphertext encrypts one of given' +
          ' values. Use Exponential-ElGamal instead.'
      );
    }
  }

  /**
   * Encrypts a plaintext and proves knowledge of it without revealing it.
   * Schnorr proof shows knowledge of r where `c1 = g^r`, which reveals the
   * plaintext from c2. It is bound to c2, so a copied, re-randomized or
   * modified ciphertext of someone else cannot be proven.
   */
  override encryptWithProofOfKnowledge(
    plaintext: bigint,
    context?: unknown
  ): [CiphertextValue, ChallengeResponseProof] {
    const group = this.getGroup();
    const r = this.generateRandomKey();
    const ciphertext = this.encrypt(plaintext, r) as [bigint, bigint];
    const proof = zkp.proveDlog({
      group,
      g: this.keys.public_key!.g as bigint,
      h: ciphertext[0],
      x: r,
      domain: this.knowledgeDomain(),
      context: [this.keys.public_key!.p, ciphertext[1], context ?? null],
    });
    return [ciphertext, proof];
  }

  /** Verifies that the encryptor of a ciphertext knows its plaintext with public key only. */
  override verifyKnowledge(
    ciphertext: CiphertextValue,
    proof: unknown,
    context?: unknown
  ): boolean {
    const group = this.getGroup();
    try {
      const p = this.keys.public_key!.p as bigint;
      const [c1, c2] = ciphertext as [bigint, bigint];
      if (typeof c2 !== 'bigint' || c2 <= ZERO || c2 >= p) {
        return false;
      }
      return zkp.verifyDlog({
        group,
        g: this.keys.public_key!.g as bigint,
        h: c1,
        proof,
        domain: this.knowledgeDomain(),
        context: [p, c2, context ?? null],
      });
    } catch {
      return false;
    }
  }

  /** Domain of proofs of knowledge, separating ElGamal and exponential ElGamal. */
  private knowledgeDomain(): string {
    return this.exponential
      ? 'lightphe/exponential-elgamal/knowledge'
      : 'lightphe/elgamal/knowledge';
  }

  /** The subgroup of prime order q generated by g. */
  private getGroup(): zkp.ModularGroup {
    return new zkp.ModularGroup(
      this.keys.public_key!.p as bigint,
      this.getOrder()
    );
  }

  /** The prime order q of the generator g. */
  private getOrder(): bigint {
    const q = this.keys.public_key!.q as bigint | undefined;
    if (q == null) {
      throw new Error(
        'Public key does not have the order q of the generator, which threshold' +
          ' decryption and zero-knowledge proofs require. Generate new keys with' +
          ' prime_order=True to use them.'
      );
    }
    return q;
  }

  /** Homomorphic multiplication: the result decrypts to `m1 * m2`. */
  override multiply(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): CiphertextValue {
    if (this.exponential) {
      throw new Error(
        'Exponential ElGamal is not homomorphic with respect to the addition'
      );
    }
    const p = this.keys.public_key!.p as bigint;
    const a = ciphertext1 as [bigint, bigint];
    const b = ciphertext2 as [bigint, bigint];
    return [(a[0] * b[0]) % p, (a[1] * b[1]) % p];
  }

  /** Homomorphic addition: the result decrypts to `m1 + m2`. */
  override add(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): CiphertextValue {
    if (!this.exponential) {
      throw new Error(
        'Regular ElGamal is not homomorphic with respect to the addition'
      );
    }
    const p = this.keys.public_key!.p as bigint;
    const a = ciphertext1 as [bigint, bigint];
    const b = ciphertext2 as [bigint, bigint];
    return [(a[0] * b[0]) % p, (a[1] * b[1]) % p];
  }

  override multiplyByConstant(
    ciphertext: CiphertextValue,
    constant: bigint
  ): CiphertextValue {
    if (!this.exponential) {
      throw new Error(
        'ElGamal is not supporting multiplying ciphertext by a known constant'
      );
    }
    const p = this.keys.public_key!.p as bigint;
    let k = constant;
    if (k > p) {
      k = k % p;
      logger.debug(
        `ElGamal can encrypt messages [1, ${p}]. ` +
          `Seems constant exceeded this limit. New constant is ${k}`
      );
    }
    const c = ciphertext as [bigint, bigint];
    return [modPow(c[0], k, p), modPow(c[1], k, p)];
  }

  override reencrypt(ciphertext: CiphertextValue): CiphertextValue {
    // Additively homomorphic schemes re-randomise by adding an encrypted zero;
    // multiplicative ones by multiplying with an encrypted one.
    const neutralElement = this.exponential ? ZERO : ONE;
    const neutralEncrypted = this.encrypt(neutralElement);

    return this.exponential
      ? this.add(ciphertext, neutralEncrypted)
      : this.multiply(ciphertext, neutralEncrypted);
  }
}

/**
 * Generates keys where `p = k * q + 1` for a large prime q, and g has order q.
 * Threshold decryption and zero-knowledge proofs require the order of g to be
 * known and prime.
 *
 * @returns keys whose public key has q as well.
 */
function generatePrimeOrderKeys(keySize: number): Keys {
  const bits = Math.max(Math.floor(keySize / 2), 8);
  const kBits = Math.max(1, Math.min(16, Math.floor(bits / 4)));
  const qBits = bits - kBits;

  // picking a prime modulus p = k * q + 1 for a prime q
  let p = ZERO;
  let q = ZERO;
  let k = ZERO;
  let found = false;
  while (!found) {
    q = randPrime(pow2(qBits - 1), pow2(qBits));
    for (let i = 0; i < 1000; i++) {
      k = TWO * randomRange(pow2(kBits - 1), pow2(kBits));
      p = k * q + ONE;
      if (bitLength(p) <= bits && isPrime(p)) {
        found = true;
        break;
      }
    }
  }

  // picking a generator g of the subgroup of prime order q
  let g: bigint;
  for (;;) {
    g = modPow(randomRange(TWO, p - TWO), k, p);
    if (g !== ONE) {
      break;
    }
  }

  // picking a private key x
  const x = randomRange(ONE, q - ONE);

  return {
    public_key: { p, g, y: modPow(g, x, p), q },
    private_key: { x },
  };
}
