import { Logger } from '../commons/logger.js';
import { bitLength, mod, randomBits, ZERO } from '../commons/mathUtils.js';
import * as thresholdUtils from '../commons/threshold.js';
import * as zkp from '../commons/zkp.js';
import type { CurveForm } from '../ecc/index.js';
import { EllipticCurvePoint, LightECC } from '../ecc/index.js';
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

const logger = new Logger('lightphe-ts/cryptosystems/EllipticCurveElGamal.ts');

const DECRYPTION_DOMAIN = 'lightphe/elliptic-curve-elgamal/decryption';
const PARTIAL_DECRYPTION_DOMAIN =
  'lightphe/elliptic-curve-elgamal/partial-decryption';
const MEMBERSHIP_DOMAIN = 'lightphe/elliptic-curve-elgamal/membership';
const KNOWLEDGE_DOMAIN = 'lightphe/elliptic-curve-elgamal/knowledge';

/** A ciphertext: the pair of curve points `[c1, c2]`, each as `[x, y]`. */
export type ECPair = [[bigint, bigint], [bigint, bigint]];

/**
 * Elliptic Curve ElGamal is an additively homomorphic algorithm.
 *
 * Decryption has to solve the elliptic curve discrete logarithm, which is only
 * tractable while plaintexts stay small — unlike Benaloh or Naccache-Stern.
 *
 * Ref: https://sefiks.com/2018/08/21/elliptic-curve-elgamal-encryption/
 */
export class EllipticCurveElGamal extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['Qa'],
    private_key: ['ka'],
  };

  readonly ecc: LightECC;

  constructor(options?: {
    keys?: Keys | null;
    keySize?: number | null;
    form?: CurveForm | string | null;
    curve?: string | null;
  }) {
    super();
    this.ecc = new LightECC({
      formName: options?.form,
      curveName: options?.curve,
    });

    this.keys =
      options?.keys ??
      this.generateKeys(options?.keySize ?? bitLength(this.ecc.n));

    if (options?.curve != null) {
      this.keys.curve = options.curve;
    }
    if (options?.form != null) {
      this.keys.form = options.form;
    }

    this.plaintextModulo = this.ecc.modulo;
    this.ciphertextModulo = this.ecc.modulo;
  }

  get requiredKeys(): RequiredKeys {
    return EllipticCurveElGamal.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.EllipticCurveElGamal;
  }

  generateKeys(keySize: number): Keys {
    // private key
    const ka = randomBits(keySize);
    logger.debug(
      `${keySize} bit private key generated for Elliptic Curve ElGamal.`
    );

    // public key
    const Qa = this.ecc.G.multiply(ka);

    return {
      public_key: { Qa: Qa.getPoint() },
      private_key: { ka },
    };
  }

  /** Elliptic Curve ElGamal draws a fresh one-time random key per encryption. */
  generateRandomKey(): bigint {
    return randomBits(bitLength(this.ecc.n));
  }

  encrypt(plaintext: bigint, randomKey?: bigint | bigint[]): ECPair {
    // public key
    const [x, y] = this.keys.public_key!.Qa as [bigint, bigint];
    const Qa = new EllipticCurvePoint(x, y, this.ecc.curve);

    // random key
    const r =
      typeof randomKey === 'bigint' && randomKey !== 0n
        ? randomKey
        : this.generateRandomKey();

    const s = this.ecc.G.multiply(plaintext);

    const c1 = this.ecc.G.multiply(r);
    const c2 = Qa.multiply(r).add(s);

    return [c1.getPoint(), c2.getPoint()];
  }

  decrypt(ciphertext: CiphertextValue): bigint {
    // private key
    const ka = this.keys.private_key!.ka as bigint;

    const [c1Raw, c2Raw] = ciphertext as ECPair;
    const c1 = EllipticCurvePoint.restore(c1Raw[0], c1Raw[1], this.ecc.curve);
    const c2 = EllipticCurvePoint.restore(c2Raw[0], c2Raw[1], this.ecc.curve);

    const sPrime = c1.negate().multiply(ka).add(c2);

    // s_prime = k x G, so recovering k from the known s_prime and G requires
    // solving the elliptic curve discrete logarithm.
    return sPrime.divide(this.ecc.G);
  }

  /**
   * Splits the private key into shares. Any threshold many shareholders can
   * decrypt a ciphertext together, but fewer shareholders cannot. Verification
   * keys `share x G` are published to verify partial decryptions.
   *
   * @returns public key and share of each shareholder.
   */
  override generateThresholdKeys(threshold: number, parties: number): Keys[] {
    if (BigInt(parties) >= this.ecc.n) {
      throw new Error(
        `Number of parties must be less than the curve order ${this.ecc.n}`
      );
    }
    const shares = thresholdUtils.splitSecret(
      this.keys.private_key!.ka as bigint,
      threshold,
      parties,
      this.ecc.n
    );
    const verificationKeys: [bigint, bigint][] = [];
    for (let index = 1; index <= parties; index++) {
      verificationKeys.push(this.ecc.G.multiply(shares.get(index)!).getPoint());
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
   * @returns index of the shareholder, `share x c1` and proof.
   */
  override partialDecrypt(
    ciphertext: CiphertextValue,
    prove = false
  ): PartialDecryption {
    const { index, share } = thresholdUtils.getThresholdKey(this.keys);
    const c1 = this.toPoint((ciphertext as ECPair)[0]);
    const value = c1.multiply(share);
    if (!prove) {
      return { index, value: value.getPoint() };
    }
    const proof = zkp.proveDleq({
      group: new zkp.EllipticCurveGroup(this.ecc),
      g1: this.ecc.G,
      h1: this.ecc.G.multiply(share),
      g2: c1,
      h2: value,
      x: share,
      domain: PARTIAL_DECRYPTION_DOMAIN,
      context: [this.ecc.n, index],
    });
    return { index, value: value.getPoint(), proof };
  }

  /** Verifies that a partial decryption is computed with the share of its shareholder. */
  override verifyPartialDecryption(
    ciphertext: CiphertextValue,
    partialDecryption: unknown
  ): boolean {
    const verificationKeys = this.keys.public_key!.verification_keys as
      unknown[] | undefined;
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
      return zkp.verifyDleq({
        group: new zkp.EllipticCurveGroup(this.ecc),
        g1: this.ecc.G,
        h1: this.toPoint(verificationKeys[index - 1]),
        g2: this.toPoint((ciphertext as ECPair)[0]),
        h2: this.toPoint(value),
        proof,
        domain: PARTIAL_DECRYPTION_DOMAIN,
        context: [this.ecc.n, index],
      });
    } catch {
      // malformed points raise errors of the elliptic curve library
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
    const indices = selected.map(
      (partialDecryption) => partialDecryption.index
    );

    // ka x c1 restored with lagrange interpolation
    let sPrime = this.toPoint((ciphertext as ECPair)[1]);
    for (const partialDecryption of selected) {
      const coefficient = thresholdUtils.lagrangeCoefficient(
        partialDecryption.index,
        indices,
        this.ecc.n
      );
      const point = this.toPoint(partialDecryption.value);
      sPrime = sPrime.sub(point.multiply(coefficient));
    }

    // s_prime = m x G, solve ECDLP
    return sPrime.divide(this.ecc.G);
  }

  /**
   * Decrypts a ciphertext and proves that decryption is correct without
   * revealing the private key. Chaum-Pedersen proof shows that
   * `log_G(Qa) = log_c1(ka x c1)`.
   */
  override decryptWithProof(
    ciphertext: CiphertextValue
  ): [bigint, ChallengeResponseProof] {
    const ka = this.keys.private_key!.ka as bigint;
    const c1 = this.toPoint((ciphertext as ECPair)[0]);
    const c2 = this.toPoint((ciphertext as ECPair)[1]);
    const c1Ka = c1.multiply(ka);
    const proof = zkp.proveDleq({
      group: new zkp.EllipticCurveGroup(this.ecc),
      g1: this.ecc.G,
      h1: this.toPoint(this.keys.public_key!.Qa),
      g2: c1,
      h2: c1Ka,
      x: ka,
      domain: DECRYPTION_DOMAIN,
      context: [this.ecc.n, c2],
    });
    return [c2.sub(c1Ka).divide(this.ecc.G), proof];
  }

  /**
   * Verifies that a ciphertext is decrypted to the given plaintext with public
   * key only. The plaintext is checked in modulo of the curve order.
   */
  override verifyDecryption(
    ciphertext: CiphertextValue,
    plaintext: unknown,
    proof: unknown
  ): boolean {
    try {
      if (typeof plaintext !== 'bigint') {
        return false;
      }
      const c1 = this.toPoint((ciphertext as ECPair)[0]);
      const c2 = this.toPoint((ciphertext as ECPair)[1]);

      // ka x c1 implied by the claimed plaintext
      const m = mod(plaintext, this.ecc.n);
      const c1Ka = m === ZERO ? c2 : c2.sub(this.ecc.G.multiply(m));

      return zkp.verifyDleq({
        group: new zkp.EllipticCurveGroup(this.ecc),
        g1: this.ecc.G,
        h1: this.toPoint(this.keys.public_key!.Qa),
        g2: c1,
        h2: c1Ka,
        proof,
        domain: DECRYPTION_DOMAIN,
        context: [this.ecc.n, c2],
      });
    } catch {
      // malformed points raise errors of the elliptic curve library
      return false;
    }
  }

  /**
   * Encrypts a plaintext and proves that it is one of the given values
   * without revealing which one, e.g. a vote is 0 or 1. Disjunctive
   * Chaum-Pedersen proof shows that `c2 - v x G` is `r x Qa` for one of the
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
    return zkp.proveDleqOr({
      group: new zkp.EllipticCurveGroup(this.ecc),
      g1: this.ecc.G,
      h1: this.toPoint((ciphertext as ECPair)[0]),
      g2: this.toPoint(this.keys.public_key!.Qa),
      h2s: this.membershipCandidates(ciphertext, values),
      x: randomKey as bigint,
      index: values.indexOf(plaintext),
      domain: MEMBERSHIP_DOMAIN,
      context: [this.ecc.n, (ciphertext as ECPair)[1], values, context ?? null],
    });
  }

  /** Random key of the homomorphic sum of ciphertexts, as `c1 = r x G` adds. */
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
    try {
      return zkp.verifyDleqOr({
        group: new zkp.EllipticCurveGroup(this.ecc),
        g1: this.ecc.G,
        h1: this.toPoint((ciphertext as ECPair)[0]),
        g2: this.toPoint(this.keys.public_key!.Qa),
        h2s: this.membershipCandidates(ciphertext, values),
        proof,
        domain: MEMBERSHIP_DOMAIN,
        context: [
          this.ecc.n,
          (ciphertext as ECPair)[1],
          values,
          context ?? null,
        ],
      });
    } catch {
      // malformed points raise errors of the elliptic curve library
      return false;
    }
  }

  /**
   * Candidates `c2 - v x G` for each value v. Ciphertext encrypts v if and
   * only if its candidate is `r x Qa` where `c1 = r x G`.
   */
  private membershipCandidates(
    ciphertext: CiphertextValue,
    values: readonly bigint[]
  ): EllipticCurvePoint[] {
    const c2 = this.toPoint((ciphertext as ECPair)[1]);
    return values.map((value) => {
      const m = mod(value, this.ecc.n);
      return m === ZERO ? c2 : c2.sub(this.ecc.G.multiply(m));
    });
  }

  /**
   * Encrypts a plaintext and proves knowledge of it without revealing it.
   * Schnorr proof shows knowledge of r where `c1 = r x G`, which reveals the
   * plaintext from c2. It is bound to c2, so a copied, re-randomized or
   * modified ciphertext of someone else cannot be proven.
   */
  override encryptWithProofOfKnowledge(
    plaintext: bigint,
    context?: unknown
  ): [CiphertextValue, ChallengeResponseProof] {
    const r = this.generateRandomKey();
    const ciphertext = this.encrypt(plaintext, r);
    const proof = zkp.proveDlog({
      group: new zkp.EllipticCurveGroup(this.ecc),
      g: this.ecc.G,
      h: this.toPoint(ciphertext[0]),
      x: r,
      domain: KNOWLEDGE_DOMAIN,
      context: [this.ecc.n, ciphertext[1], context ?? null],
    });
    return [ciphertext, proof];
  }

  /** Verifies that the encryptor of a ciphertext knows its plaintext with public key only. */
  override verifyKnowledge(
    ciphertext: CiphertextValue,
    proof: unknown,
    context?: unknown
  ): boolean {
    try {
      // c2 must be a point on the curve
      this.toPoint((ciphertext as ECPair)[1]);
      return zkp.verifyDlog({
        group: new zkp.EllipticCurveGroup(this.ecc),
        g: this.ecc.G,
        h: this.toPoint((ciphertext as ECPair)[0]),
        proof,
        domain: KNOWLEDGE_DOMAIN,
        context: [this.ecc.n, (ciphertext as ECPair)[1], context ?? null],
      });
    } catch {
      // malformed points raise errors of the elliptic curve library
      return false;
    }
  }

  /**
   * Casts coordinates into a point on the curve, and rejects coordinates that
   * are not on it.
   */
  private toPoint(point: unknown): EllipticCurvePoint {
    if (
      !Array.isArray(point) ||
      point.length !== 2 ||
      typeof point[0] !== 'bigint' ||
      typeof point[1] !== 'bigint'
    ) {
      throw new Error('A point must be a pair of integer coordinates');
    }
    const [x, y] = point as [bigint, bigint];
    const restored = EllipticCurvePoint.restore(x, y, this.ecc.curve);
    return restored.infinity
      ? restored
      : EllipticCurvePoint.create(x, y, this.ecc.curve);
  }

  /** Homomorphic addition: the result decrypts to `m1 + m2`. */
  override add(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): ECPair {
    const [a1, a2] = ciphertext1 as ECPair;
    const [b1, b2] = ciphertext2 as ECPair;

    const curve = this.ecc.curve;
    const a = EllipticCurvePoint.restore(a1[0], a1[1], curve).add(
      EllipticCurvePoint.restore(b1[0], b1[1], curve)
    );
    const b = EllipticCurvePoint.restore(a2[0], a2[1], curve).add(
      EllipticCurvePoint.restore(b2[0], b2[1], curve)
    );

    return [a.getPoint(), b.getPoint()];
  }

  /**
   * Multiplies a ciphertext by a known plain constant: `k x E(m) = E(m * k)`.
   */
  override multiplyByConstant(
    ciphertext: CiphertextValue,
    constant: bigint
  ): ECPair {
    const [pRaw, qRaw] = ciphertext as ECPair;
    const curve = this.ecc.curve;

    const p = EllipticCurvePoint.restore(pRaw[0], pRaw[1], curve).multiply(
      constant
    );
    const q = EllipticCurvePoint.restore(qRaw[0], qRaw[1], curve).multiply(
      constant
    );

    return [p.getPoint(), q.getPoint()];
  }

  override reencrypt(ciphertext: CiphertextValue): ECPair {
    const rPrime = this.generateRandomKey();

    const [x, y] = this.keys.public_key!.Qa as [bigint, bigint];
    const Qa = new EllipticCurvePoint(x, y, this.ecc.curve);

    const [c1Raw, c2Raw] = ciphertext as ECPair;
    const c1 = EllipticCurvePoint.restore(c1Raw[0], c1Raw[1], this.ecc.curve);
    const c2 = EllipticCurvePoint.restore(c2Raw[0], c2Raw[1], this.ecc.curve);

    const c1Prime = c1.add(this.ecc.G.multiply(rPrime));
    const c2Prime = c2.add(Qa.multiply(rPrime));
    return [c1Prime.getPoint(), c2Prime.getPoint()];
  }
}
