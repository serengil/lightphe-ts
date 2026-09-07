import { Logger } from '../commons/logger.js';
import {
  gcd,
  isPrime,
  modPow,
  pow2,
  randPrime,
  randomRange,
  sqrtModAll,
  ZERO,
  ONE,
  TWO,
} from '../commons/mathUtils.js';
import { EllipticCurvePoint, FP2, LightECC } from '../ecc/index.js';
import { Algorithm } from '../models/Algorithm.js';
import { Homomorphic } from '../models/Homomorphic.js';
import type { CiphertextValue, Keys, RequiredKeys } from '../models/types.js';

const logger = new Logger('lightphe-ts/cryptosystems/BonehGohNissim.ts');

/** A Boneh-Goh-Nissim ciphertext: a curve point, or an `F_{p^2}` element. */
export type BGNValue = EllipticCurvePoint | FP2;

/**
 * Boneh-Goh-Nissim is homomorphic with respect to addition, and somewhat
 * homomorphic with respect to multiplication: a ciphertext can be multiplied
 * exactly once, after which it lives in the pairing target group `G_T`.
 *
 * Ref: https://sefiks.com/2026/04/02/a-step-by-step-somewhat-homomorphic-encryption-example-with-boneh-goh-nissim-in-python/
 */
export class BonehGohNissim extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['curve', 'G', 'u', 'h', 'l'],
    private_key: ['q1', 'q2'],
    nested: { curve: ['a', 'b', 'p', 'G', 'n'] },
  };

  ec!: LightECC;

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

    const curve = this.keys.public_key!.curve as {
      a: bigint;
      b: bigint;
      p: bigint;
      G: [bigint, bigint];
      n: bigint;
    };
    this.ec = new LightECC({
      formName: 'weierstrass',
      curveName: 'custom',
      config: {
        a: curve.a,
        b: curve.b,
        p: curve.p,
        G: curve.G,
        n: curve.n,
      },
    });

    this.plaintextModulo = this.hasPrivateKey()
      ? (this.keys.private_key!.q2 as bigint)
      : curve.n;
    this.ciphertextModulo = this.ec.modulo;
  }

  get requiredKeys(): RequiredKeys {
    return BonehGohNissim.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.BonehGohNissim;
  }

  generateKeys(keySize: number, options?: { maxTries?: number }): Keys {
    const maxTries = options?.maxTries ?? 10000;
    const half = Math.floor(keySize / 2);

    let q1 = ZERO;
    let q2 = ZERO;
    let n = ZERO;
    let p = ZERO;
    let l = ZERO;
    let generator: [bigint, bigint] | undefined;
    const a = ONE;
    const b = ZERO;
    let built = false;

    for (let keyAttempt = 0; keyAttempt < maxTries; keyAttempt++) {
      // choose large odd distinct primes q1 and q2
      q1 = randPrime(pow2(half), pow2(half + 1));
      q2 = randPrime(pow2(half), pow2(half + 1));
      while (q1 === q2) {
        q2 = randPrime(pow2(half), pow2(half + 1));
      }

      n = q1 * q2;

      // Find l such that p = n*l - 1 is prime and p = 3 (mod 4).
      // Supersingularity of y^2 = x^3 + x requires p = 3 (mod 4). Since n is
      // odd (a product of two odd primes), n*l = 0 (mod 4) iff l = 0 (mod 4),
      // so multiples of four are iterated systematically.
      let found: bigint | undefined;
      for (let candidate = 4; candidate <= maxTries * 4 + 4; candidate += 4) {
        const pCandidate = n * BigInt(candidate) - ONE;
        if (isPrime(pCandidate)) {
          found = BigInt(candidate);
          break;
        }
      }
      if (found === undefined) {
        logger.debug(
          `No valid l found for attempt ${keyAttempt + 1}, retrying`
        );
        continue;
      }

      l = found;
      p = n * l - ONE;
      generator = findGenerator(p, maxTries);

      try {
        this.ec = new LightECC({
          formName: 'weierstrass',
          curveName: 'custom',
          config: { a, b, p, G: generator, n },
        });
      } catch {
        logger.debug(
          `Curve order validation failed for attempt ${keyAttempt + 1}, retrying`
        );
        continue;
      }

      logger.debug('Curve order validated.');
      logger.debug(`q1 = ${q1}, q2 = ${q2}, n = ${n}, p = ${p}, l = ${l}`);
      built = true;
      break;
    }

    if (!built || generator === undefined) {
      throw new Error(`Failed to generate keys after ${maxTries} attempts`);
    }

    let r = ZERO;
    for (;;) {
      r = randomRange(TWO, n - ONE);
      if (gcd(r, n) === ONE) {
        break;
      }
    }

    const u = this.ec.G.multiply(r);
    const h = u.multiply(q2);

    return {
      public_key: {
        curve: { a, b, p, G: generator, n },
        G: generator,
        u: u.getPoint(),
        h: h.getPoint(),
        l,
      },
      private_key: { q1, q2 },
    };
  }

  private hasPrivateKey(): boolean {
    return (
      this.keys.private_key != null && this.keys.private_key.q2 !== undefined
    );
  }

  /** Boneh-Goh-Nissim draws a fresh one-time random key per encryption. */
  generateRandomKey(): bigint {
    if (this.hasPrivateKey()) {
      const q2 = this.keys.private_key!.q2 as bigint;
      return randomRange(ONE, q2 - ONE);
    }

    const n = (this.keys.public_key!.curve as { n: bigint }).n;
    logger.warn(
      'Private key is not available. Random key will be bounded by n' +
        ' instead of q2. Encryption will work for small plaintexts,' +
        ' but negative number encoding via plaintextModulo will not' +
        ' round-trip correctly because plaintextModulo is set to n' +
        ' (public) instead of q2 (private).'
    );
    return randomRange(ONE, n - ONE);
  }

  encrypt(
    plaintext: bigint,
    randomKey?: bigint | bigint[]
  ): EllipticCurvePoint {
    const r =
      typeof randomKey === 'bigint' && randomKey !== ZERO
        ? randomKey
        : this.generateRandomKey();
    const G = this.ec.G;
    const raw = this.keys.public_key!.h as [bigint, bigint];
    const h = new EllipticCurvePoint(raw[0], raw[1], this.ec.curve);
    return G.multiply(plaintext).add(h.multiply(r));
  }

  /**
   * Decrypts either a `G1` ciphertext (a curve point, from encryption or
   * addition) or a `G_T` ciphertext (an `F_{p^2}` element, from homomorphic
   * multiplication).
   */
  decrypt(ciphertext: CiphertextValue): bigint {
    const q1 = this.keys.private_key!.q1 as bigint;
    const q2 = this.keys.private_key!.q2 as bigint;

    if (ciphertext instanceof FP2) {
      return this.decryptGT(ciphertext, q1, q2);
    }

    const point = ciphertext as EllipticCurvePoint;
    const G = this.ec.G;

    const mP = point.multiply(q1);
    const P = G.multiply(q1);

    // P has order q2, so the DLP result is in [0, q2).
    if (mP.equals(this.ec.O)) {
      return ZERO;
    }

    for (let i = ONE; i < q2; i += ONE) {
      if (P.multiply(i).equals(mP)) {
        return i;
      }
    }

    throw new Error('Decryption failed');
  }

  /**
   * Decrypts a `G_T` ciphertext, the result of homomorphic multiplication.
   *
   * `e(C1, C2)^q1 = e(G, G)^(q1 * m1 * m2)`, so solving the DLP with base
   * `e(G, G)^q1` and target `e(C1, C2)^q1` recovers `m1 * m2`.
   */
  private decryptGT(ciphertext: FP2, q1: bigint, q2: bigint): bigint {
    const p = this.ec.modulo;
    const G = this.ec.G;

    // e(G, G) — the pairing of the generator with itself via the distortion map
    const eGG = this.ec.pairingFP2(G, G);

    const base = eGG.exp(q1, p);
    const target = ciphertext.exp(q1, p);

    // brute-force DLP in G_T; the result is in [0, q2)
    if (target.isOne()) {
      return ZERO;
    }

    let acc = FP2.one();
    for (let i = ONE; i < q2; i += ONE) {
      acc = acc.mul(base, p);
      if (acc.equals(target)) {
        return i;
      }
    }

    throw new Error('Decryption of G_T ciphertext failed');
  }

  /** Homomorphic addition, in `G1` or in `G_T` depending on the operands. */
  override add(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): BGNValue {
    if (
      ciphertext1 instanceof EllipticCurvePoint &&
      ciphertext2 instanceof EllipticCurvePoint
    ) {
      return ciphertext1.add(ciphertext2);
    }

    if (ciphertext1 instanceof FP2 && ciphertext2 instanceof FP2) {
      return ciphertext1.mul(ciphertext2, this.ec.modulo);
    }

    throw new Error('Both ciphertexts must be of the same type for addition.');
  }

  /**
   * Homomorphic multiplication via the bilinear pairing.
   *
   * The result is an element of `F_{p^2}` — the pairing target group `G_T` —
   * and not a point on the curve, so it cannot be multiplied again.
   */
  override multiply(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): FP2 {
    if (ciphertext1 instanceof FP2 || ciphertext2 instanceof FP2) {
      throw new Error(
        'Boneh-Goh-Nissim only supports multiplication ciphertexts once!'
      );
    }
    return this.ec.pairingFP2(
      ciphertext1 as EllipticCurvePoint,
      ciphertext2 as EllipticCurvePoint
    );
  }

  /** Multiplies a ciphertext by a known plain constant. */
  override multiplyByConstant(
    ciphertext: CiphertextValue,
    constant: bigint
  ): BGNValue {
    if (ciphertext instanceof EllipticCurvePoint) {
      return ciphertext.multiply(constant);
    }
    if (ciphertext instanceof FP2) {
      // In G_T scalar multiplication of the plaintext is exponentiation.
      return ciphertext.exp(constant, this.ec.modulo);
    }

    throw new Error(
      'Ciphertext must be either an EllipticCurvePoint or an F_{p^2} element ' +
        'for multiplication by constant.'
    );
  }

  override reencrypt(ciphertext: CiphertextValue): EllipticCurvePoint {
    const raw = this.keys.public_key!.h as [bigint, bigint];
    const h = new EllipticCurvePoint(raw[0], raw[1], this.ec.curve);
    const r = this.generateRandomKey();
    return (ciphertext as EllipticCurvePoint).add(h.multiply(r));
  }
}

/** Finds a point on `y^2 = x^3 + x mod p` to use as the curve generator. */
function findGenerator(p: bigint, maxTries = 10000): [bigint, bigint] {
  if (!isPrime(p)) {
    throw new Error('p must be prime');
  }

  for (let i = 0; i < maxTries; i++) {
    const x = randomRange(ZERO, p - ONE);
    const rhs = (modPow(x, 3n, p) + x) % p;
    const roots = sqrtModAll(rhs, p);
    if (roots.length > 0) {
      return [x, roots[0]];
    }
  }

  throw new Error(`Failed to find a generator after ${maxTries} attempts`);
}
