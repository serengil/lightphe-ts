import { fromBytesBigEndian, sha256Text } from '../commons/hashing.js';
import { Logger } from '../commons/logger.js';
import {
  abs,
  bitLength,
  mod,
  modInverse,
  modPow,
  randomRange,
  ONE,
  TWO,
  ZERO,
} from '../commons/mathUtils.js';
import { findSafePrime } from '../commons/safePrimes.js';
import type { CurveForm } from '../ecc/index.js';
import { EllipticCurvePoint, LightECC } from '../ecc/index.js';
import { Algorithm } from '../models/Algorithm.js';
import { Homomorphic } from '../models/Homomorphic.js';
import type {
  CiphertextValue,
  Keys,
  RandomKey,
  RequiredKeys,
  VerifiableCiphertext,
} from '../models/types.js';

const logger = new Logger('lightphe-ts/cryptosystems/CamenischShoup.ts');

/** Challenge length of the proof in bits - soundness error is 2^-CHALLENGE_BITS. */
const CHALLENGE_BITS = 128;

/** Statistical zero-knowledge parameter of the proof in bits. */
const STATISTICAL_BITS = 80;

/**
 * Camenisch-Shoup is homomorphic with respect to addition, and supports
 * multiplying a ciphertext by a known plain constant. It is designed for
 * verifiable encryption of discrete logarithms. A prover encrypts a secret
 * such as the private key of an elliptic curve public key for a trusted third
 * party, and proves that the ciphertext really contains it without revealing
 * it. Anyone having the public key of the trusted third party can verify the
 * proof, and only the trusted third party can decrypt the ciphertext.
 *
 * Verifiable encryption has three steps run by three parties:
 *   - encryptVerifiably: prover (e.g. Alice) encrypts her secret and creates
 *     the proof
 *   - verifyEncryption: verifier (e.g. a bank) checks the proof against the
 *     public point it already knows, without learning the secret
 *   - decryptVerifiableCiphertext: trusted third party restores the secret
 * Only the last step requires the private key.
 *
 * Ciphertexts for homomorphic operations are `[u, e]` pairs. Verifiable
 * ciphertexts additionally have a validity tag v bound to a label, which makes
 * them secure against chosen ciphertext attacks. Homomorphic operations drop
 * that tag, as non-malleability and homomorphism contradict each other.
 *
 * The proof follows the paper with Fiat-Shamir heuristic. Its soundness relies
 * on the auxiliary RSA modulus n_bar, whose factorization is discarded during
 * key generation and must not be known by the prover.
 *
 * Ref: Camenisch, J., Shoup, V. (2003). Practical Verifiable Encryption and
 * Decryption of Discrete Logarithms. CRYPTO 2003.
 */
export class CamenischShoup extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['n', 'g', 'y1', 'y2', 'y3', 'n_bar', 'g_bar', 'h_bar'],
    private_key: ['x1', 'x2', 'x3'],
  };

  private readonly form?: CurveForm | string | null;
  private readonly curve?: string | null;
  private eccInstance?: LightECC;

  /**
   * @param options.form - form of the elliptic curve of the secrets to be
   *   encrypted verifiably: `weierstrass` (default), `edwards` or `koblitz`.
   * @param options.curve - elliptic curve of the secrets to be encrypted
   *   verifiably. Default is secp256k1 for weierstrass form.
   */
  constructor(options?: {
    keys?: Keys | null;
    keySize?: number | null;
    maxTries?: number;
    form?: CurveForm | string | null;
    curve?: string | null;
  }) {
    super();
    this.form = options?.form;
    this.curve = options?.curve;
    this.keys =
      options?.keys ??
      this.generateKeys(options?.keySize ?? 1024, {
        maxTries: options?.maxTries ?? 10000,
      });
    const n = this.keys.public_key!.n as bigint;
    this.plaintextModulo = n;
    this.ciphertextModulo = n * n;
  }

  /**
   * Elliptic curve of the secrets to be encrypted verifiably. Built lazily as
   * homomorphic operations do not need it.
   */
  get ecc(): LightECC {
    if (this.eccInstance === undefined) {
      this.eccInstance = new LightECC({
        formName: this.form,
        curveName: this.curve,
      });
    }
    return this.eccInstance;
  }

  get requiredKeys(): RequiredKeys {
    return CamenischShoup.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.CamenischShoup;
  }

  generateKeys(keySize: number, options?: { maxTries?: number }): Keys {
    const maxTries = options?.maxTries ?? 10000;

    if (keySize < 16) {
      throw new Error(`Key size ${keySize} is too small for Camenisch-Shoup`);
    }

    // n = pq where p = 2p' + 1 and q = 2q' + 1 are safe primes
    const [p, q] = findSafePrimePair(keySize, maxTries);
    const n = p * q;
    const nSquare = n * n;
    const pPrime = (p - ONE) / TWO;
    const qPrime = (q - ONE) / TWO;

    // g is a 2n-th power in Z_{n^2}*, so its order divides p'q'
    let g: bigint | undefined;
    for (let i = 0; i < maxTries; i++) {
      const candidate = modPow(
        randomRange(TWO, nSquare - ONE),
        TWO * n,
        nSquare
      );
      if (
        modPow(candidate, pPrime, nSquare) !== ONE &&
        modPow(candidate, qPrime, nSquare) !== ONE
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

    const [x1, x2, x3] = [0, 1, 2].map(() => randomRange(ONE, nSquare / 4n));

    // auxiliary RSA modulus for the proof. its factorization is discarded.
    const [pBar, qBar] = findSafePrimePair(keySize, maxTries);
    const nBar = pBar * qBar;
    let hBar: bigint | undefined;
    for (let i = 0; i < maxTries; i++) {
      const candidate = modPow(randomRange(TWO, nBar - ONE), TWO, nBar);
      if (candidate % pBar !== ONE && candidate % qBar !== ONE) {
        hBar = candidate;
        break;
      }
    }
    if (hBar === undefined) {
      throw new Error(
        `Failed to find a suitable generator in ${maxTries} tries`
      );
    }
    const gBar = modPow(hBar, randomRange(TWO, nBar / 4n), nBar);

    return {
      public_key: {
        n,
        g,
        y1: modPow(g, x1, nSquare),
        y2: modPow(g, x2, nSquare),
        y3: modPow(g, x3, nSquare),
        n_bar: nBar,
        g_bar: gBar,
        h_bar: hBar,
      },
      private_key: { x1, x2, x3 },
    };
  }

  /** Camenisch-Shoup draws a fresh random key per encryption. */
  generateRandomKey(): bigint {
    const n = this.keys.public_key!.n as bigint;
    const bound = n / 4n;
    return randomRange(ONE, bound > ONE ? bound : ONE);
  }

  /** Encrypts a plaintext as `u = g^r mod n^2` and `e = y1^r (1 + n)^m mod n^2`. */
  encrypt(plaintext: bigint, randomKey?: RandomKey): bigint[] {
    const n = this.keys.public_key!.n as bigint;
    const g = this.keys.public_key!.g as bigint;
    const y1 = this.keys.public_key!.y1 as bigint;
    const nSquare = n * n;
    const r =
      typeof randomKey === 'bigint' && randomKey !== ZERO
        ? randomKey
        : this.generateRandomKey();

    let m = plaintext;
    if (m >= n) {
      m = m % n;
      logger.debug(
        `Camenisch-Shoup can encrypt messages [0, ${n}). ` +
          `Seems plaintext exceeded this limit. New plaintext is ${m}`
      );
    }

    const u = modPow(g, r, nSquare);
    const e = (modPow(y1, r, nSquare) * (ONE + m * n)) % nSquare;
    return [u, e];
  }

  /** Decrypts a `[u, e]` ciphertext. */
  decrypt(ciphertext: CiphertextValue): bigint {
    const values = ciphertext as readonly bigint[];
    if (values.length !== 2) {
      throw new Error(
        'Ciphertext must be a (u, e) pair. ' +
          'Decrypt verifiable ciphertexts with their labels.'
      );
    }
    return this.recover(values[0], values[1]);
  }

  /**
   * Encrypts a plaintext secure against chosen ciphertext attacks. The
   * ciphertext can be decrypted with the same label only.
   *
   * @param plaintext - message to encrypt in `[0, n)`.
   * @param label - public data bound to the ciphertext, e.g. decryption
   *   conditions.
   * @param randomKey - one time random key for encryption.
   * @returns `[u, e, v]` where v is the validity tag.
   */
  encryptWithLabel(
    plaintext: bigint,
    label: string,
    randomKey?: bigint
  ): bigint[] {
    const n = this.keys.public_key!.n as bigint;
    const nSquare = n * n;
    const r =
      randomKey !== undefined && randomKey !== ZERO
        ? randomKey
        : this.generateRandomKey();

    const [u, e] = this.encrypt(plaintext, r);
    const tagBase = this.tagBase(u, e, label);
    const v = this.absolute(modPow(tagBase, r, nSquare));
    return [u, e, v];
  }

  /**
   * Decrypts a ciphertext created with `encryptWithLabel`. It is rejected if
   * it was modified or its label is different.
   */
  decryptWithLabel(ciphertext: readonly bigint[], label: string): bigint {
    const n = this.keys.public_key!.n as bigint;
    const x2 = this.keys.private_key!.x2 as bigint;
    const x3 = this.keys.private_key!.x3 as bigint;
    const nSquare = n * n;

    if (!Array.isArray(ciphertext) || ciphertext.length !== 3) {
      throw new Error('Verifiable ciphertext must be a (u, e, v) triple');
    }
    const [u, e, v] = ciphertext;

    const tagExponent = TWO * (x2 + this.hashTag(u, e, label) * x3);
    if (
      v !== this.absolute(v) ||
      modPow(u, tagExponent, nSquare) !== modPow(v, TWO, nSquare)
    ) {
      throw new Error(
        'Ciphertext is invalid or was encrypted with a different label'
      );
    }

    return this.recover(u, e);
  }

  /**
   * Encrypts the discrete logarithm of an elliptic curve point, e.g. a private
   * key, for the owner of this cryptosystem and proves that the ciphertext
   * contains it. Runs on prover side, e.g. Alice escrowing her wallet key to a
   * trusted third party. Only the prover can call this, because it needs the
   * secret itself. Public key of the trusted third party is enough, the
   * private key is not needed. Output is sent to the verifier, who checks it
   * with `verifyEncryption`.
   *
   * @param secret - discrete logarithm of the public point, i.e.
   *   `public point = G * secret`.
   * @param label - public data bound to the ciphertext, e.g. decryption
   *   conditions.
   */
  override encryptVerifiably(
    secret: bigint | number,
    label = ''
  ): VerifiableCiphertext {
    this.validateVerifiableEncryption();
    const pk = this.keys.public_key!;
    const n = pk.n as bigint;
    const g = pk.g as bigint;
    const y1 = pk.y1 as bigint;
    const nBar = pk.n_bar as bigint;
    const gBar = pk.g_bar as bigint;
    const hBar = pk.h_bar as bigint;
    const nSquare = n * n;
    const order = this.ecc.n;
    const bound = ONE << BigInt(CHALLENGE_BITS + STATISTICAL_BITS);

    const m = mod(BigInt(secret), order);
    if (m === ZERO) {
      throw new Error(
        'Secret must not be a multiple of the order of the curve'
      );
    }
    const publicPoint = this.ecc.G.multiply(m);

    const r = this.generateRandomKey();
    const [u, e, v] = this.encryptWithLabel(m, label, r);
    const tagBase = this.tagBase(u, e, label);

    // commitment to the secret in auxiliary group
    const s = randomRange(ONE, nBar / 4n);
    const l = (modPow(gBar, m, nBar) * modPow(hBar, s, nBar)) % nBar;

    // random masks statistically hiding the secret, r and s
    const rMask = randomRange(-(n / 4n) * bound, (n / 4n) * bound);
    const sMask = randomRange(-(nBar / 4n) * bound, (nBar / 4n) * bound);
    const mMask = randomRange(-order * bound, order * bound);

    const commitments: Array<bigint | EllipticCurvePoint> = [
      modPow(g, TWO * rMask, nSquare),
      (modPow(y1, TWO * rMask, nSquare) *
        modPow(ONE + n, TWO * mMask, nSquare)) %
        nSquare,
      modPow(tagBase, TWO * rMask, nSquare),
      this.ecc.G.multiply(mod(mMask, order)),
      (modPow(gBar, mMask, nBar) * modPow(hBar, sMask, nBar)) % nBar,
    ];

    const challenge = this.challenge(
      publicPoint,
      label,
      [u, e, v],
      l,
      commitments
    );

    return {
      ciphertext: [u, e, v],
      commitment: l,
      proof: {
        challenge,
        r: rMask - challenge * r,
        s: sMask - challenge * s,
        m: mMask - challenge * m,
      },
    };
  }

  /**
   * Verifies that a verifiable ciphertext contains the discrete logarithm of a
   * public point without decrypting it. Runs on verifier side, e.g. a bank that
   * knows Alice's public key only. The verifier cannot trust the prover's
   * word, because the prover could encrypt 0 or an unrelated key instead. This
   * checks the proof against the public point and the label that the verifier
   * already knows, so it confirms the escrow is real without learning the
   * secret. Public key of the trusted third party is enough, the private key is
   * not needed.
   *
   * @returns true if the ciphertext contains the secret of the public point.
   */
  override verifyEncryption(
    verifiableCiphertext: unknown,
    publicPoint: EllipticCurvePoint | readonly [bigint, bigint],
    label = ''
  ): boolean {
    this.validateVerifiableEncryption();
    const pk = this.keys.public_key!;
    const n = pk.n as bigint;
    const g = pk.g as bigint;
    const y1 = pk.y1 as bigint;
    const nBar = pk.n_bar as bigint;
    const gBar = pk.g_bar as bigint;
    const hBar = pk.h_bar as bigint;
    const nSquare = n * n;
    const order = this.ecc.n;

    const parsed = this.parseVerifiableCiphertext(verifiableCiphertext);
    if (parsed === undefined) {
      return false;
    }
    const [u, e, v, l, challenge, rZ, sZ, mZ] = parsed;

    const point =
      publicPoint instanceof EllipticCurvePoint
        ? publicPoint
        : new EllipticCurvePoint(
            publicPoint[0],
            publicPoint[1],
            this.ecc.curve
          );
    if (point.isIdentity()) {
      return false;
    }
    const tagBase = this.tagBase(u, e, label);

    let commitments: Array<bigint | EllipticCurvePoint>;
    try {
      commitments = [
        (modPow(u, TWO * challenge, nSquare) * modPow(g, TWO * rZ, nSquare)) %
          nSquare,
        (modPow(e, TWO * challenge, nSquare) *
          modPow(y1, TWO * rZ, nSquare) *
          modPow(ONE + n, TWO * mZ, nSquare)) %
          nSquare,
        (modPow(v, TWO * challenge, nSquare) *
          modPow(tagBase, TWO * rZ, nSquare)) %
          nSquare,
        point.multiply(challenge).add(this.ecc.G.multiply(mod(mZ, order))),
        (modPow(l, challenge, nBar) *
          modPow(gBar, mZ, nBar) *
          modPow(hBar, sZ, nBar)) %
          nBar,
      ];
    } catch {
      // not invertible or point at infinity
      return false;
    }

    return (
      challenge === this.challenge(point, label, [u, e, v], l, commitments)
    );
  }

  /**
   * Restores the secret from a verifiable ciphertext. Runs on the side of the
   * private key owner, e.g. a trusted third party, when the conditions in the
   * label are met. This is the only step requiring the private key, and the
   * only way to restore the secret. It does not check the proof, as
   * `verifyEncryption` does that.
   */
  override decryptVerifiableCiphertext(
    verifiableCiphertext: VerifiableCiphertext,
    label = ''
  ): bigint {
    const n = this.keys.public_key!.n as bigint;
    let m = this.decryptWithLabel(verifiableCiphertext.ciphertext, label);
    // proof guarantees that the secret is in (-n/2, n/2)
    if (m > n / TWO) {
      m -= n;
    }
    return mod(m, this.ecc.n);
  }

  /** Homomorphic addition. Validity tags of verifiable ciphertexts are dropped. */
  override add(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): bigint[] {
    const n = this.keys.public_key!.n as bigint;
    const nSquare = n * n;
    const c1 = ciphertext1 as readonly bigint[];
    const c2 = ciphertext2 as readonly bigint[];
    return [(c1[0] * c2[0]) % nSquare, (c1[1] * c2[1]) % nSquare];
  }

  /**
   * Multiplies a ciphertext by a known plain constant. Validity tags of
   * verifiable ciphertexts are dropped.
   */
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
        `Camenisch-Shoup can encrypt messages [0, ${n}). ` +
          `Seems constant exceeded this limit. New constant is ${k}`
      );
    }

    const c = ciphertext as readonly bigint[];
    return [modPow(c[0], k, nSquare), modPow(c[1], k, nSquare)];
  }

  override reencrypt(ciphertext: CiphertextValue): bigint[] {
    return this.add(ciphertext, this.encrypt(ZERO));
  }

  /**
   * Extracts the ciphertext, commitment and proof, and checks their types and
   * ranges.
   *
   * @returns u, e, v, l, challenge, r, s and m of the proof, or undefined if
   *   the verifiable ciphertext is malformed.
   */
  private parseVerifiableCiphertext(
    verifiableCiphertext: unknown
  ): bigint[] | undefined {
    const n = this.keys.public_key!.n as bigint;
    const nBar = this.keys.public_key!.n_bar as bigint;
    const bound = ONE << BigInt(CHALLENGE_BITS + STATISTICAL_BITS);

    if (
      typeof verifiableCiphertext !== 'object' ||
      verifiableCiphertext === null
    ) {
      return undefined;
    }
    const { ciphertext, commitment, proof } = verifiableCiphertext as Record<
      string,
      unknown
    >;
    if (
      !Array.isArray(ciphertext) ||
      ciphertext.length !== 3 ||
      typeof proof !== 'object' ||
      proof === null
    ) {
      return undefined;
    }
    const { challenge, r, s, m } = proof as Record<string, unknown>;
    const values = [
      ...(ciphertext as unknown[]),
      commitment,
      challenge,
      r,
      s,
      m,
    ];
    if (!values.every((x) => typeof x === 'bigint')) {
      return undefined;
    }
    const [u, e, v, l, c, , , mZ] = values as bigint[];

    const isValid =
      [u, e, v].every((x) => x > ZERO && x < n * n) &&
      v === this.absolute(v) &&
      l > ZERO &&
      l < nBar &&
      c >= ZERO &&
      c < ONE << BigInt(CHALLENGE_BITS) &&
      // secret must be small enough to be restored from its encryption mod n
      abs(mZ) <= TWO * this.ecc.n * bound;
    return isValid ? (values as bigint[]) : undefined;
  }

  /** Restores the plaintext from a `[u, e]` pair. */
  private recover(u: bigint, e: bigint): bigint {
    const n = this.keys.public_key!.n as bigint;
    const x1 = this.keys.private_key!.x1 as bigint;
    const nSquare = n * n;

    // (e / u^x1)^(2t) = (1 + n)^m where t = 1/2 mod n
    const twoT = TWO * modInverse(TWO, n);
    const mHat = modPow(
      (e * modInverse(modPow(u, x1, nSquare), nSquare)) % nSquare,
      twoT,
      nSquare
    );
    if (mHat % n !== ONE) {
      throw new Error('Ciphertext is invalid');
    }
    return (mHat - ONE) / n;
  }

  /** Base of the validity tag v: `y2 * y3^H(u, e, label) mod n^2`. */
  private tagBase(u: bigint, e: bigint, label: string): bigint {
    const n = this.keys.public_key!.n as bigint;
    const y2 = this.keys.public_key!.y2 as bigint;
    const y3 = this.keys.public_key!.y3 as bigint;
    const nSquare = n * n;
    return (y2 * modPow(y3, this.hashTag(u, e, label), nSquare)) % nSquare;
  }

  /**
   * Hash of a ciphertext and its label for the validity tag. It is smaller
   * than p' and q' as required by the scheme.
   */
  private hashTag(u: bigint, e: bigint, label: string): bigint {
    const n = this.keys.public_key!.n as bigint;
    const bits = Math.min(256, Math.max(1, Math.floor(bitLength(n) / 2) - 2));
    const digest = sha256Text(`tag|${u}|${e}|${label}`);
    return fromBytesBigEndian(digest) % (ONE << BigInt(bits));
  }

  /** Fiat-Shamir challenge of the proof. */
  private challenge(
    publicPoint: EllipticCurvePoint,
    label: string,
    ciphertext: readonly bigint[],
    l: bigint,
    commitments: ReadonlyArray<bigint | EllipticCurvePoint>
  ): bigint {
    const pk = this.keys.public_key!;
    // items are rendered the way Python prints them, so that proofs created by
    // either library verify in the other
    const items: string[] = CamenischShoup.REQUIRED_KEYS.public_key.map((key) =>
      String(pk[key] as bigint)
    );
    items.push(formatPoint(this.ecc.G), formatPoint(publicPoint), label);
    items.push(...ciphertext.map(String), String(l));
    items.push(
      ...commitments.map((c) =>
        c instanceof EllipticCurvePoint ? formatPoint(c) : String(c)
      )
    );
    const digest = sha256Text(`challenge|${items.join('|')}`);
    return fromBytesBigEndian(digest) % (ONE << BigInt(CHALLENGE_BITS));
  }

  /**
   * Absolute value of an element of `Z_{n^2}`, where elements greater than
   * `n^2 / 2` are considered negative.
   */
  private absolute(a: bigint): bigint {
    const n = this.keys.public_key!.n as bigint;
    const nSquare = n * n;
    return a > nSquare / TWO ? nSquare - a : a;
  }

  /**
   * Secrets must be restorable from their encryption mod n, even if they are
   * extracted from a cheating prover.
   */
  private validateVerifiableEncryption(): void {
    const n = this.keys.public_key!.n as bigint;
    const minimum = this.ecc.n << BigInt(CHALLENGE_BITS + STATISTICAL_BITS + 3);
    if (n <= minimum) {
      throw new Error(
        `Key size ${bitLength(n)} is too small for verifiable encryption. ` +
          `It must be greater than ${bitLength(minimum)} bits for this curve.`
      );
    }
  }
}

/** Renders a point the way Python prints its coordinates tuple. */
function formatPoint(point: EllipticCurvePoint): string {
  if (point.infinity) {
    return '(inf, inf)';
  }
  return `(${point.x}, ${point.y})`;
}

/** Finds two different safe primes for a modulus of keySize bits. */
function findSafePrimePair(
  keySize: number,
  maxTries: number
): [bigint, bigint] {
  const bits = Math.floor(keySize / 2);
  const p = findSafePrime(bits, maxTries);
  let q = findSafePrime(bits, maxTries);
  while (q === p) {
    q = findSafePrime(bits, maxTries);
  }
  return [p, q];
}
