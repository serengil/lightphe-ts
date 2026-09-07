/**
 * LightPHE — a lightweight partially homomorphic encryption library.
 *
 * Build a cryptosystem, encrypt on-premises, evaluate in the cloud without ever
 * handing over the private key, then decrypt on-premises again.
 */

import * as fs from 'fs';

import { validateKeys } from './commons/keyValidator.js';
import { deserializeKeys, serializeKeys } from './commons/keySerializer.js';
import { Logger } from './commons/logger.js';
import { mod, ZERO } from './commons/mathUtils.js';
import { fractionize, normalizeInput } from './commons/pheUtils.js';
import { buildCryptosystem, type BuildOptions } from './cryptosystems/index.js';
import type { CurveForm } from './ecc/index.js';
import type { AlgorithmName } from './models/Algorithm.js';
import { Ciphertext } from './models/Ciphertext.js';
import { Homomorphic } from './models/Homomorphic.js';
import { EncryptedTensor, Fraction } from './models/Tensor.js';
import type { CiphertextValue, Keys } from './models/types.js';

const logger = new Logger('lightphe-ts/index.ts');

/** The version of this package. */
export const VERSION = '0.0.1';

/** Options accepted by the `LightPHE` constructor. */
export interface LightPHEOptions {
  /** RSA | ElGamal | Exponential-ElGamal | EllipticCurve-ElGamal | Paillier |
   * Damgard-Jurik | Okamoto-Uchiyama | Benaloh | Naccache-Stern |
   * Goldwasser-Micali | Sander-Young-Yung | Boneh-Goh-Nissim */
  algorithmName: AlgorithmName | string;

  /** An existing private/public key pair to use instead of generating one. */
  keys?: Keys | null;

  /** Path to a key file previously written by {@link LightPHE.exportKeys}. */
  keyFile?: string | null;

  /** Key size in bits. */
  keySize?: number | null;

  /** Digits kept after the decimal point in homomorphic tensor operations. */
  precision?: number;

  /**
   * The form of the elliptic curve: `weierstrass` (default), `edwards` or
   * `koblitz`. Only used when `algorithmName` is `EllipticCurve-ElGamal`.
   */
  form?: CurveForm | string | null;

  /**
   * The elliptic curve to use, for example `ed25519` and `ed448` for the
   * Edwards form, `secp256k1` for Weierstrass, or `k-409` for Koblitz. See
   * https://github.com/serengil/LightECC?tab=readme-ov-file#supported-curves
   * for the full list. Only used when `algorithmName` is
   * `EllipticCurve-ElGamal`.
   */
  curve?: string | null;

  /**
   * Upper bound for plaintext values. Only used when `algorithmName` is
   * `Benaloh` or `Sander-Young-Yung`.
   */
  plaintextLimit?: number | bigint | null;

  /**
   * Maximum attempts to generate keys, 10000 by default. RSA, Benaloh,
   * Naccache-Stern and Goldwasser-Micali may need several attempts; other
   * algorithms ignore this.
   */
  maxTries?: number;
}

/** Options accepted when encrypting. */
export interface EncryptOptions {
  /** Set to true to suppress the tensor encryption progress log. */
  silent?: boolean;
}

export class LightPHE {
  static readonly VERSION = VERSION;

  readonly algorithmName: AlgorithmName | string;
  readonly precision: number;
  readonly form?: CurveForm | string | null;
  readonly curve?: string | null;

  /** The cryptosystem this instance was built around. */
  readonly cs: Homomorphic;

  constructor(options: LightPHEOptions) {
    this.algorithmName = options.algorithmName;
    this.precision = options.precision ?? 5;
    this.form = options.form;
    this.curve = options.curve;

    let keys = options.keys ?? null;
    if (options.keyFile != null) {
      keys = this.restoreKeys(options.keyFile);
    }

    if (keys != null) {
      validateKeys(options.algorithmName, keys);
    }

    const buildOptions: BuildOptions = {
      keys,
      keySize: options.keySize,
      form: options.form,
      curve: options.curve,
      plaintextLimit: options.plaintextLimit,
      maxTries: options.maxTries ?? 10000,
    };
    this.cs = buildCryptosystem(options.algorithmName, buildOptions);
  }

  /**
   * Encrypts a plaintext with the built cryptosystem. Only the public key is
   * needed, so this can run wherever the data lives.
   */
  encrypt(plaintext: number | bigint, options?: EncryptOptions): Ciphertext;
  encrypt(plaintext: number[], options?: EncryptOptions): EncryptedTensor;
  encrypt(
    plaintext: number | bigint | number[],
    options?: EncryptOptions
  ): Ciphertext | EncryptedTensor;
  encrypt(
    plaintext: number | bigint | number[],
    options?: EncryptOptions
  ): Ciphertext | EncryptedTensor {
    if (this.cs.keys.public_key == null) {
      throw new Error('You must have public key to perform encryption');
    }

    if (Array.isArray(plaintext)) {
      return this.encryptTensor(plaintext, options?.silent ?? false);
    }

    const ciphertext = this.cs.encrypt(
      normalizeInput(plaintext, this.cs.plaintextModulo)
    );

    const publicKeys: Keys = { ...this.cs.keys };
    delete publicKeys.private_key;

    return new Ciphertext({
      algorithmName: this.algorithmName,
      keys: publicKeys,
      value: ciphertext,
      form: this.form,
      curve: this.curve,
    });
  }

  /** Decrypts a ciphertext. The private key is required. */
  decrypt(ciphertext: Ciphertext): bigint;
  decrypt(ciphertext: EncryptedTensor): number[];
  decrypt(ciphertext: Ciphertext | EncryptedTensor): bigint | number[];
  decrypt(ciphertext: Ciphertext | EncryptedTensor): bigint | number[] {
    if (this.cs.keys.private_key == null) {
      throw new Error('You must have private key to perform decryption');
    }
    if (this.cs.keys.public_key == null) {
      throw new Error('You must have public key to perform decryption');
    }

    if (ciphertext instanceof EncryptedTensor) {
      return this.decryptTensor(ciphertext);
    }

    return this.cs.decrypt(ciphertext.value);
  }

  /** Encrypts a tensor of real numbers element by element. */
  private encryptTensor(tensor: number[], silent: boolean): EncryptedTensor {
    const encryptedZero = this.cs.encrypt(ZERO);
    const divisorEncrypted = this.cs.encrypt(10n ** BigInt(this.precision));

    const started = Date.now();
    const encryptedTensor = tensor.map((m) =>
      encryptFloat(m, divisorEncrypted, this.cs, this.precision, encryptedZero)
    );
    if (!silent) {
      logger.debug(
        `Encrypting tensors: ${tensor.length} items in ${
          (Date.now() - started) / 1000
        } seconds`
      );
    }

    // The tensor travels without the private key so it is safe to hand off.
    const publicCs = Object.create(
      Object.getPrototypeOf(this.cs) as object
    ) as Homomorphic;
    Object.assign(publicCs, this.cs);
    publicCs.keys = { ...this.cs.keys };
    delete publicCs.keys.private_key;

    return new EncryptedTensor({
      fractions: encryptedTensor,
      cs: publicCs,
      precision: this.precision,
    });
  }

  /** Decrypts an encrypted tensor back to plain real numbers. */
  private decryptTensor(encryptedTensor: EncryptedTensor): number[] {
    return encryptedTensor.fractions.map((c) => {
      if (!(c instanceof Fraction)) {
        throw new Error('Ciphertext items must be type of Fraction');
      }

      const absDividend = this.cs.decrypt(c.absDividend);
      const divisor = this.cs.decrypt(c.divisor);

      return (c.sign * Number(absDividend)) / Number(divisor);
    });
  }

  /**
   * Generates a different ciphertext that decrypts to the same plaintext. Only
   * the public key is needed.
   */
  regenerateCiphertext(ciphertext: Ciphertext): Ciphertext {
    if (this.cs.keys.public_key == null) {
      throw new Error('You must have public key to perform decryption');
    }

    const ciphertextNew = this.cs.reencrypt(ciphertext.value);
    return new Ciphertext({
      algorithmName: this.algorithmName,
      keys: this.cs.keys,
      value: ciphertextNew,
      form: this.form,
      curve: this.curve,
    });
  }

  /**
   * Writes the keys to a file.
   *
   * @param targetFile - where to write.
   * @param isPublic - set to true to drop the private key before writing, which
   *   is what makes the file safe to publish.
   */
  exportKeys(targetFile: string, isPublic = false): void {
    const keys = this.cs.keys;
    let privateKey: Keys['private_key'];

    if (isPublic && keys.private_key != null) {
      privateKey = keys.private_key;
      delete keys.private_key;
    }

    if (!isPublic) {
      logger.warn(
        'You did not set public arg to True. So, exported key has private key information.' +
          'Do not share this to anyone'
      );
    }

    fs.writeFileSync(targetFile, serializeKeys(keys), { encoding: 'utf-8' });

    // restore the private key if it was dropped
    if (privateKey !== undefined) {
      this.cs.keys.private_key = privateKey;
    }
  }

  /** Reads a key pair back from a file written by {@link exportKeys}. */
  restoreKeys(targetFile: string): Keys {
    const text = fs.readFileSync(targetFile, { encoding: 'utf-8' });

    let keys: Keys;
    try {
      keys = deserializeKeys(text);
    } catch {
      throw new Error(
        `The content of the file ${targetFile} does not represent a valid dictionary.`
      );
    }

    if ('private_key' in keys) {
      logger.info(`private-public key pair is restored from ${targetFile}`);
    } else if ('public_key' in keys) {
      logger.info(`public key is restored from ${targetFile}`);
    } else {
      throw new Error(`File ${targetFile} must have public_key key`);
    }
    return keys;
  }

  /**
   * Wraps a raw ciphertext payload back into a `Ciphertext`, which carries the
   * keys needed to evaluate on it. Use this to rebuild a ciphertext received
   * over the wire.
   */
  createCiphertextObj(ciphertext: CiphertextValue): Ciphertext {
    return new Ciphertext({
      algorithmName: this.algorithmName,
      keys: this.cs.keys,
      value: ciphertext,
      form: this.form,
      curve: this.curve,
    });
  }
}

/**
 * Encrypts one real number into a `Fraction`.
 *
 * @param m - the value to encrypt.
 * @param divisorEncrypted - the pre-computed encrypted scale factor.
 * @param cs - the cryptosystem.
 * @param precision - digits kept after the decimal point.
 * @param encryptedZero - a pre-computed encryption of zero.
 */
export function encryptFloat(
  m: number,
  divisorEncrypted: CiphertextValue,
  cs: Homomorphic,
  precision: number,
  encryptedZero: CiphertextValue
): Fraction {
  try {
    if (m === 0) {
      // Very common in real embeddings, so it is worth short-circuiting.
      return new Fraction({
        dividend: encryptedZero,
        divisor: divisorEncrypted,
        absDividend: encryptedZero,
        sign: 1,
      });
    }

    const scale = 10n ** BigInt(precision);

    if (Number.isInteger(m)) {
      const value = BigInt(m);
      const dividendEncrypted = cs.encrypt(
        mod(value, cs.plaintextModulo) * scale
      );
      const absDividendEncrypted =
        m > 0
          ? dividendEncrypted
          : cs.encrypt(
              mod(value < 0n ? -value : value, cs.plaintextModulo) * scale
            );

      return new Fraction({
        dividend: dividendEncrypted,
        divisor: divisorEncrypted,
        absDividend: absDividendEncrypted,
        sign: m >= 0 ? 1 : -1,
      });
    }

    // Reducing the float modulo the plaintext modulo first keeps very large
    // values inside the message space.
    const limit = Number(cs.plaintextModulo);
    const [dividend] = fractionize(
      m > limit ? m % limit : m,
      cs.plaintextModulo,
      precision
    );
    const magnitude = Math.abs(m);
    const absDividend =
      m > 0
        ? dividend
        : fractionize(
            magnitude > limit ? magnitude % limit : magnitude,
            cs.plaintextModulo,
            precision
          )[0];

    const dividendEncrypted = cs.encrypt(dividend);
    const absDividendEncrypted =
      m > 0 ? dividendEncrypted : cs.encrypt(absDividend);

    return new Fraction({
      dividend: dividendEncrypted,
      divisor: divisorEncrypted,
      absDividend: absDividendEncrypted,
      sign: m >= 0 ? 1 : -1,
    });
  } catch (err) {
    logger.error(`Exception while running encryptFloat: ${String(err)}`);
    throw err;
  }
}

export {
  Algorithm,
  type AlgorithmName,
  ALGORITHM_NAMES,
} from './models/Algorithm.js';
export { Ciphertext } from './models/Ciphertext.js';
export { EncryptedTensor, Fraction } from './models/Tensor.js';
export { Homomorphic } from './models/Homomorphic.js';
export type {
  CiphertextValue,
  Keys,
  KeyPart,
  RequiredKeys,
} from './models/types.js';
export { Logger, LogLevel } from './commons/logger.js';
export { validateKeys } from './commons/keyValidator.js';
export { serializeKeys, deserializeKeys } from './commons/keySerializer.js';
export * as pheUtils from './commons/pheUtils.js';
export * as mathUtils from './commons/mathUtils.js';
export {
  buildCryptosystem,
  REQUIRED_KEYS_BY_ALGORITHM,
  type BuildOptions,
  RSA,
  ElGamal,
  Paillier,
  DamgardJurik,
  OkamotoUchiyama,
  Benaloh,
  NaccacheStern,
  GoldwasserMicali,
  EllipticCurveElGamal,
  SanderYoungYung,
  BonehGohNissim,
  type ECPair,
  type BGNValue,
} from './cryptosystems/index.js';
export {
  LightECC,
  EllipticCurvePoint,
  FP2,
  WeierstrassCurve,
  EdwardsCurve,
  KoblitzCurve,
  pairing,
  isSupersingularEmbedding2,
  listCurveNames,
  getDefaultCurve,
  FORMS,
  DEFAULT_CURVES,
  type CurveForm,
  type Curve,
  type PairingResult,
  type CustomCurveConfig,
} from './ecc/index.js';

export default LightPHE;
