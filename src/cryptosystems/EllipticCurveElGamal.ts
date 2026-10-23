import { Logger } from '../commons/logger.js';
import { bitLength, randomBits } from '../commons/mathUtils.js';
import type { CurveForm } from '../ecc/index.js';
import { EllipticCurvePoint, LightECC } from '../ecc/index.js';
import { Algorithm } from '../models/Algorithm.js';
import { Homomorphic } from '../models/Homomorphic.js';
import type { CiphertextValue, Keys, RequiredKeys } from '../models/types.js';

const logger = new Logger('lightphe-ts/cryptosystems/EllipticCurveElGamal.ts');

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
