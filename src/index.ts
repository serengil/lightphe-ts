/**
 * LightPHE — a lightweight partially homomorphic encryption library.
 *
 * Build a cryptosystem, encrypt on-premises, evaluate in the cloud without ever
 * handing over the private key, then decrypt on-premises again.
 */

import * as fs from 'fs';

import * as classifiers from './commons/classifiers.js';
import { validateKeys } from './commons/keyValidator.js';
import { deserializeKeys, serializeKeys } from './commons/keySerializer.js';
import { Logger } from './commons/logger.js';
import { mod, ONE, ZERO } from './commons/mathUtils.js';
import * as nearestNeighbors from './commons/nearestNeighbors.js';
import { fractionize, normalizeInput } from './commons/pheUtils.js';
import * as secureAggregation from './commons/secureAggregation.js';
import * as thresholdUtils from './commons/threshold.js';
import * as zkp from './commons/zkp.js';
import { buildCryptosystem, type BuildOptions } from './cryptosystems/index.js';
import { GSW_FLOAT_NOT_SUPPORTED_MSG } from './cryptosystems/GentrySahaiWaters.js';
import { FLOAT_NOT_SUPPORTED_MSG } from './cryptosystems/JoyeLibert.js';
import type { CurveForm, EllipticCurvePoint } from './ecc/index.js';
import { Algorithm, type AlgorithmName } from './models/Algorithm.js';
import {
  CATALANO_FIORE,
  CatalanoFiore,
  CatalanoFioreCiphertext,
} from './models/CatalanoFiore.js';
import {
  Ciphertext,
  FLOAT_NOT_SUPPORTED_MESSAGES,
} from './models/Ciphertext.js';
import { Homomorphic } from './models/Homomorphic.js';
import { EncryptedTensor, Fraction } from './models/Tensor.js';
import type {
  ArgmaxClient,
  ArgmaxMessage,
  CiphertextValue,
  DecisionTree,
  DecisionTreeServerState,
  DecryptionProof,
  Keys,
  KnowledgeProof,
  MembershipProof,
  NumericDecisionTree,
  OneHotProof,
  PartialDecryption,
  RangeProof,
  VerifiableCiphertext,
} from './models/types.js';

const logger = new Logger('lightphe-ts/index.ts');

/** The version of this package. */
export const VERSION = '0.0.4';

/** Algorithms rejecting floats and tensors, as they are scaled by powers of 10. */
const TENSOR_NOT_SUPPORTED_ALGORITHMS: readonly string[] = [
  Algorithm.Regev,
  Algorithm.BrakerskiVaikuntanathan,
  Algorithm.FreemanBonehGohNissim,
  Algorithm.GentryHaleviVaikuntanathan,
  Algorithm.LyubashevskyPeikertRegev,
  Algorithm.MLKEM,
];

/** Partial decryption of a fraction of an encrypted tensor. */
export interface TensorPartialDecryption {
  abs_dividend: PartialDecryption;
  divisor: PartialDecryption;
}

/** Encrypted query of encrypted k nearest neighbor search. */
export interface EncryptedKnnQuery {
  /** Encrypted entries of the query vector. */
  query: Ciphertext[];
  /** Encrypted squared norm of the query vector. */
  norm: Ciphertext;
}

/** Encrypted result of encrypted k nearest neighbor search. */
export interface KnnResult {
  /** Encrypted indices of the k nearest vectors from the nearest one. */
  indices: Ciphertext[];
  /** Encrypted labels of the k nearest vectors, if labels are set. */
  labels?: Ciphertext[];
}

/** An encrypted model update, or an encrypted sum of model updates. */
export interface EncryptedUpdate {
  /** Ciphertexts of chunks of packed values. */
  chunks: Ciphertext[];
  /** Layout of packing. */
  layout: secureAggregation.PackingLayout;
  /** Number of updates it contains. */
  count: number;
}

/** Decrypted sum and mean of model updates. */
export interface Aggregate {
  sum: number[];
  mean: number[];
  count: number;
}

/** Reports whether a value is an integer, either a bigint or an integral number. */
function isInteger(value: unknown): value is number | bigint {
  return (
    typeof value === 'bigint' ||
    (typeof value === 'number' && Number.isInteger(value))
  );
}

/** Ciphertexts `encrypt` returns, depending on the boost option. */
export type BoostedCiphertext<Boost> = Boost extends typeof CATALANO_FIORE
  ? CatalanoFioreCiphertext
  : Ciphertext;

/** Input of a decision tree: bits and depth, or features and bit length. */
export interface DecisionTreeInput {
  /** Ishai-Paskin only. Input bits (answers to the questions), each 0 or 1. */
  bits?: readonly number[];
  /** Ishai-Paskin only. Maximum number of decisions on a path of the tree. */
  depth?: number;
  /** Damgard-Geisler-Kroigaard only. Numeric features each in `[0, 2^bitLength)`. */
  features?: readonly (number | bigint)[];
  /** Damgard-Geisler-Kroigaard only. Number of bits of features and thresholds. */
  bitLength?: number;
}

/** Options accepted by the `LightPHE` constructor. */
export interface LightPHEOptions<
  Boost extends string | null | undefined = string | null | undefined,
> {
  /** RSA | ElGamal | Exponential-ElGamal | EllipticCurve-ElGamal | Paillier |
   * Damgard-Jurik | Okamoto-Uchiyama | Benaloh | Naccache-Stern |
   * Goldwasser-Micali | Sander-Young-Yung | Boneh-Goh-Nissim | Joye-Libert |
   * Castagnos-Laguillaumie | Ishai-Paskin | Damgard-Geisler-Kroigaard |
   * Bresson-Catalano-Pointcheval | Camenisch-Shoup | EllipticCurve-Paillier |
   * Regev | Brakerski-Vaikuntanathan | Freeman-Boneh-Goh-Nissim |
   * Gentry-Halevi-Vaikuntanathan | Lyubashevsky-Peikert-Regev | ML-KEM |
   * Gentry-Sahai-Waters */
  algorithmName: AlgorithmName | string;

  /** An existing private/public key pair to use instead of generating one. */
  keys?: Keys | null;

  /** Path to a key file previously written by {@link LightPHE.exportKeys}. */
  keyFile?: string | null;

  /**
   * Key size in bits. For Regev, it is the lattice dimension. For
   * Brakerski-Vaikuntanathan, Lyubashevsky-Peikert-Regev and
   * Gentry-Sahai-Waters, it is the ring degree. For ML-KEM, it is the
   * parameter set: 512, 768 or 1024. For Freeman-Boneh-Goh-Nissim, it is the
   * bit length of the field size. For Gentry-Halevi-Vaikuntanathan, it is the
   * lattice dimension in [2, 8].
   */
  keySize?: number | null;

  /** Digits kept after the decimal point in homomorphic tensor operations. */
  precision?: number;

  /**
   * The form of the elliptic curve: `weierstrass` (default), `edwards` or
   * `koblitz`. Only used when `algorithmName` is `EllipticCurve-ElGamal` or
   * `Camenisch-Shoup`. Camenisch-Shoup uses it for verifiable encryption.
   */
  form?: CurveForm | string | null;

  /**
   * The elliptic curve to use, for example `ed25519` and `ed448` for the
   * Edwards form, `secp256k1` for Weierstrass, or `k-409` for Koblitz. See
   * https://github.com/serengil/LightECC?tab=readme-ov-file#supported-curves
   * for the full list. Only used when `algorithmName` is
   * `EllipticCurve-ElGamal` or `Camenisch-Shoup`. Camenisch-Shoup uses it for
   * verifiable encryption.
   */
  curve?: string | null;

  /**
   * Upper bound for plaintext values. Only used when `algorithmName` is
   * `Benaloh`, `Sander-Young-Yung`, `Regev`, `Brakerski-Vaikuntanathan`,
   * `Freeman-Boneh-Goh-Nissim`, `Gentry-Halevi-Vaikuntanathan` or
   * `Lyubashevsky-Peikert-Regev`.
   */
  plaintextLimit?: number | bigint | null;

  /**
   * Maximum attempts to generate keys, 10000 by default. RSA, Benaloh,
   * Naccache-Stern, Goldwasser-Micali, Boneh-Goh-Nissim, Joye-Libert,
   * Castagnos-Laguillaumie, Damgard-Geisler-Kroigaard,
   * Bresson-Catalano-Pointcheval and Camenisch-Shoup may need several
   * attempts; other algorithms ignore this.
   */
  maxTries?: number;

  /**
   * Upgrades the algorithm with a transform. Options:
   *  - `Catalano-Fiore`: lets ciphertexts of an additively homomorphic
   *    algorithm be multiplied once. Then, encrypt returns ciphertexts
   *    supporting one multiplication, and only integers are supported.
   *    Supported for Paillier, Damgard-Jurik, Bresson-Catalano-Pointcheval,
   *    Camenisch-Shoup, EllipticCurve-Paillier, Joye-Libert,
   *    Castagnos-Laguillaumie, Naccache-Stern, Benaloh and
   *    Damgard-Geisler-Kroigaard.
   */
  boost?: Boost;

  /**
   * Picks the generator of a known prime order while generating keys. Default
   * is false. Threshold decryption and zero-knowledge proofs require this.
   * Only used when `algorithmName` is `ElGamal` or `Exponential-ElGamal`.
   */
  primeOrder?: boolean;

  /**
   * Generates the modulus as a product of two safe primes. Default is false.
   * Proofs of partial decryption in threshold decryption require this. Only
   * used when `algorithmName` is `Paillier` or `Damgard-Jurik`.
   */
  safePrimes?: boolean;
}

/** Options accepted when encrypting. */
export interface EncryptOptions {
  /** Set to true to suppress the tensor encryption progress log. */
  silent?: boolean;
}

export class LightPHE<Boost extends string | null | undefined = undefined> {
  static readonly VERSION = VERSION;

  readonly algorithmName: AlgorithmName | string;
  readonly precision: number;
  readonly form?: CurveForm | string | null;
  readonly curve?: string | null;

  /** The cryptosystem this instance was built around. */
  readonly cs: Homomorphic;

  // public-key-only cryptosystem shared by ciphertexts, built on first use
  private publicCs: Homomorphic | null = null;

  // Catalano-Fiore transform wraps a copy of this instance without the transform
  private readonly catalanoFiore: CatalanoFiore | null;

  constructor(options: LightPHEOptions<Boost>) {
    this.algorithmName = options.algorithmName;
    this.precision = options.precision ?? 5;
    this.form = options.form;
    this.curve = options.curve;

    let keys = options.keys ?? null;
    if (options.keyFile != null) {
      keys = this.restoreKeys(options.keyFile);
    }

    if (
      options.safePrimes === true &&
      keys == null &&
      (options.algorithmName === Algorithm.Paillier ||
        options.algorithmName === Algorithm.DamgardJurik)
    ) {
      keys = thresholdUtils.generateSafePaillierKeys(
        options.keySize ?? 1024,
        options.maxTries ?? 10000,
        options.algorithmName === Algorithm.DamgardJurik ? 2 : undefined
      );
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
      primeOrder: options.primeOrder ?? false,
    };
    this.cs = buildCryptosystem(options.algorithmName, buildOptions);

    this.catalanoFiore = null;
    const boost = options.boost;
    if (boost != null) {
      if (boost !== CATALANO_FIORE) {
        throw new Error(
          `Unknown boost ${boost}. Options are: ${CATALANO_FIORE}`
        );
      }
      this.catalanoFiore = new CatalanoFiore(this.withoutBoost());
    }
  }

  /** Wraps a payload into a ciphertext carrying public keys only. */
  private publicCiphertext(value: CiphertextValue): Ciphertext {
    if (this.publicCs == null) {
      const publicKeys: Keys = { ...this.cs.keys };
      delete publicKeys.private_key;
      const ciphertext = new Ciphertext({
        algorithmName: this.algorithmName,
        keys: publicKeys,
        value,
        form: this.form,
        curve: this.curve,
      });
      this.publicCs = ciphertext.cs;
      return ciphertext;
    }

    return new Ciphertext({
      algorithmName: this.algorithmName,
      keys: this.publicCs.keys,
      value,
      form: this.form,
      curve: this.curve,
      cs: this.publicCs,
    });
  }

  /** A shallow copy of this instance without the boost. */
  private withoutBoost(): LightPHE {
    const copy = Object.create(LightPHE.prototype) as LightPHE;
    Object.assign(copy, this, { catalanoFiore: null });
    return copy;
  }

  /**
   * Encrypts a plaintext with the built cryptosystem. Only the public key is
   * needed, so this can run wherever the data lives. The ciphertext supports
   * one multiplication if Catalano-Fiore boost is set.
   */
  encrypt(
    plaintext: number | bigint,
    options?: EncryptOptions
  ): BoostedCiphertext<Boost>;
  encrypt(plaintext: number[], options?: EncryptOptions): EncryptedTensor;
  encrypt(
    plaintext: number | bigint | number[],
    options?: EncryptOptions
  ): BoostedCiphertext<Boost> | EncryptedTensor;
  encrypt(
    plaintext: number | bigint | number[],
    options?: EncryptOptions
  ): Ciphertext | EncryptedTensor | CatalanoFioreCiphertext {
    if (this.cs.keys.public_key == null) {
      throw new Error('You must have public key to perform encryption');
    }

    if (this.catalanoFiore !== null) {
      return this.catalanoFiore.encrypt(plaintext);
    }

    const floatNotSupported = FLOAT_NOT_SUPPORTED_MESSAGES[this.algorithmName];
    if (
      TENSOR_NOT_SUPPORTED_ALGORITHMS.includes(this.algorithmName) &&
      (Array.isArray(plaintext) ||
        (typeof plaintext === 'number' && !Number.isInteger(plaintext)))
    ) {
      throw new Error(floatNotSupported);
    }

    if (
      this.algorithmName === Algorithm.GentrySahaiWaters &&
      !(
        plaintext === 0 ||
        plaintext === 1 ||
        plaintext === ZERO ||
        plaintext === ONE
      )
    ) {
      throw new Error(GSW_FLOAT_NOT_SUPPORTED_MSG);
    }

    if (Array.isArray(plaintext)) {
      return this.encryptTensor(plaintext, options?.silent ?? false);
    }

    if (
      typeof plaintext === 'number' &&
      !Number.isInteger(plaintext) &&
      this.algorithmName === Algorithm.JoyeLibert
    ) {
      throw new Error(FLOAT_NOT_SUPPORTED_MSG);
    }

    const ciphertext = this.cs.encrypt(
      normalizeInput(plaintext, this.cs.plaintextModulo)
    );

    return this.publicCiphertext(ciphertext);
  }

  /** Decrypts a ciphertext. The private key is required. */
  decrypt(ciphertext: Ciphertext | CatalanoFioreCiphertext): bigint;
  decrypt(ciphertext: EncryptedTensor): number[];
  decrypt(
    ciphertext: Ciphertext | EncryptedTensor | CatalanoFioreCiphertext
  ): bigint | number[];
  decrypt(
    ciphertext: Ciphertext | EncryptedTensor | CatalanoFioreCiphertext
  ): bigint | number[] {
    if (this.cs.keys.private_key == null) {
      throw new Error('You must have private key to perform decryption');
    }
    if (this.cs.keys.public_key == null) {
      throw new Error('You must have public key to perform decryption');
    }

    if (ciphertext instanceof CatalanoFioreCiphertext) {
      const catalanoFiore =
        this.catalanoFiore ?? new CatalanoFiore(this.withoutBoost());
      return catalanoFiore.decrypt(ciphertext);
    }

    if (ciphertext instanceof EncryptedTensor) {
      return this.decryptTensor(ciphertext);
    }

    return this.cs.decrypt(ciphertext.value);
  }

  /**
   * Decrypts a ciphertext with the master key instead of the private key of
   * its owner. The master key can decrypt ciphertexts of all users sharing it.
   * Only supported by Bresson-Catalano-Pointcheval.
   *
   * @param ciphertext - encrypted message of any user.
   */
  decryptWithMasterKey(ciphertext: Ciphertext): bigint;
  decryptWithMasterKey(ciphertext: EncryptedTensor): number[];
  decryptWithMasterKey(
    ciphertext: Ciphertext | EncryptedTensor
  ): bigint | number[];
  decryptWithMasterKey(
    ciphertext: Ciphertext | EncryptedTensor
  ): bigint | number[] {
    this.requireKey('private_key', 'perform decryption');
    this.requireKey('public_key', 'perform decryption');

    if (ciphertext instanceof EncryptedTensor) {
      const publicKey = ciphertext.cs.keys.public_key;
      return this.decryptTensor(ciphertext, (c) =>
        this.cs.decryptWithMasterKey(c, publicKey)
      );
    }

    return this.cs.decryptWithMasterKey(
      ciphertext.value,
      ciphertext.keys?.public_key
    );
  }

  /**
   * Generates a key pair for a new user of a master key. Public key of the
   * authority holding the master key is enough to generate it. The master key
   * can decrypt ciphertexts encrypted for the new user, but the new user
   * cannot decrypt ciphertexts of others. Only supported by
   * Bresson-Catalano-Pointcheval.
   *
   * @returns private - public key pair of the new user.
   */
  generateUserKeys(): Keys {
    this.requireKey('public_key', 'generate user keys');
    return this.cs.generateUserKeys();
  }

  /**
   * Encrypts the discrete logarithm of an elliptic curve point, e.g. a private
   * key, for the owner of this cryptosystem and proves that the ciphertext
   * contains it. Runs on prover side, e.g. Alice escrowing her wallet key to a
   * trusted third party. Only the prover can call this, because it needs the
   * secret itself. Public key of the trusted third party is enough, the
   * private key is not needed. Output is sent to the verifier, who checks it
   * with {@link verifyEncryption}. Only supported by Camenisch-Shoup.
   *
   * @param secret - discrete logarithm of the public point, i.e.
   *   `public point = G * secret`.
   * @param label - public data bound to the ciphertext, e.g. decryption
   *   conditions. The ciphertext cannot be decrypted with a different label.
   * @returns ciphertext, commitment and proof.
   */
  encryptVerifiably(secret: number | bigint, label = ''): VerifiableCiphertext {
    this.requireKey('public_key', 'perform encryption');
    return this.cs.encryptVerifiably(secret, label);
  }

  /**
   * Verifies that a verifiable ciphertext contains the discrete logarithm of a
   * public point without decrypting it. Runs on verifier side, e.g. a bank that
   * knows Alice's public key only. The verifier cannot trust the prover's
   * word, because the prover could encrypt 0 or an unrelated key instead. This
   * checks the proof against the public point and the label that the verifier
   * already knows, so it confirms the escrow is real without learning the
   * secret. Public key of the trusted third party is enough, the private key is
   * not needed. Only supported by Camenisch-Shoup.
   *
   * @param verifiableCiphertext - created by {@link encryptVerifiably}.
   * @param publicPoint - public point known by the verifier, as a point or as
   *   `[x, y]` coordinates.
   * @param label - label that the ciphertext is expected to be bound to.
   * @returns true if the ciphertext contains the secret of the public point.
   */
  verifyEncryption(
    verifiableCiphertext: VerifiableCiphertext | Record<string, unknown>,
    publicPoint: EllipticCurvePoint | readonly [bigint, bigint],
    label = ''
  ): boolean {
    this.requireKey('public_key', 'verify encryption');
    return this.cs.verifyEncryption(verifiableCiphertext, publicPoint, label);
  }

  /**
   * Restores the secret from a verifiable ciphertext. Runs on the side of the
   * private key owner, e.g. a trusted third party, when the conditions in the
   * label are met. This is the only step requiring the private key, and the
   * only way to restore the secret. It does not check the proof, as
   * {@link verifyEncryption} does that. Only supported by Camenisch-Shoup.
   *
   * @param verifiableCiphertext - created by {@link encryptVerifiably}.
   * @param label - label used in encryption.
   * @returns discrete logarithm of the public point.
   */
  decryptVerifiableCiphertext(
    verifiableCiphertext: VerifiableCiphertext,
    label = ''
  ): bigint {
    this.requireKey('private_key', 'perform decryption');
    return this.cs.decryptVerifiableCiphertext(verifiableCiphertext, label);
  }

  /**
   * Splits the private key into shares for threshold decryption. Any
   * threshold many shareholders can decrypt a ciphertext together, but fewer
   * shareholders cannot. Runs on dealer side. Threshold parameters are added
   * into the public key, and the private key is dropped from this
   * cryptosystem afterwards, so export the public key again. Supported by
   * ElGamal, Exponential-ElGamal, EllipticCurve-ElGamal, Paillier and
   * Damgard-Jurik. ElGamal and Exponential-ElGamal keys must be generated with
   * `primeOrder: true`.
   *
   * @param threshold - minimum number of shareholders required to decrypt.
   * @param parties - total number of shareholders.
   * @returns public key and share of each shareholder. Each item must be sent
   *   to its own shareholder secretly.
   */
  generateThresholdKeys(threshold: number, parties: number): Keys[] {
    this.requireKey('private_key', 'generate threshold keys');
    this.requireKey('public_key', 'generate threshold keys');
    thresholdUtils.validateThreshold(threshold, parties);

    const shareKeys = this.cs.generateThresholdKeys(threshold, parties);

    // dealer forgets the private key, and public key now has threshold parameters
    delete this.cs.keys.private_key;
    this.publicCs = null;

    return shareKeys;
  }

  /**
   * Decrypts a ciphertext partially with the share of a shareholder. Partial
   * decryption reveals nothing about the plaintext alone. Runs on shareholder
   * side.
   *
   * @param options.prove - set this to true to attach a zero-knowledge proof
   *   that the partial decryption is computed with the share of this
   *   shareholder. Default is false. Supported by ElGamal,
   *   Exponential-ElGamal, EllipticCurve-ElGamal, and Paillier and
   *   Damgard-Jurik with keys generated with `safePrimes: true`.
   * @returns partial decryption to be sent to the combiner.
   */
  partialDecrypt(
    ciphertext: Ciphertext | CatalanoFioreCiphertext,
    options?: { prove?: boolean }
  ): PartialDecryption;
  partialDecrypt(
    ciphertext: EncryptedTensor,
    options?: { prove?: boolean }
  ): TensorPartialDecryption[];
  partialDecrypt(
    ciphertext: Ciphertext | EncryptedTensor | CatalanoFioreCiphertext,
    options?: { prove?: boolean }
  ): PartialDecryption | TensorPartialDecryption[];
  partialDecrypt(
    ciphertext: Ciphertext | EncryptedTensor | CatalanoFioreCiphertext,
    options?: { prove?: boolean }
  ): PartialDecryption | TensorPartialDecryption[] {
    const prove = options?.prove ?? false;
    if (this.cs.keys.threshold_key == null) {
      throw new Error(
        'You must have threshold key to perform partial decryption'
      );
    }

    if (ciphertext instanceof CatalanoFioreCiphertext) {
      throw new Error(
        'Ciphertexts supporting multiplication do not support threshold decryption'
      );
    }

    if (ciphertext instanceof EncryptedTensor) {
      return ciphertext.fractions.map((c) => ({
        abs_dividend: this.cs.partialDecrypt(c.absDividend, prove),
        divisor: this.cs.partialDecrypt(c.divisor, prove),
      }));
    }

    return this.cs.partialDecrypt(ciphertext.value, prove);
  }

  /**
   * Restores plaintext from partial decryptions of at least threshold many
   * shareholders. Public key is enough, so anyone can combine them.
   *
   * @param partialDecryptions - outputs of {@link partialDecrypt} of
   *   shareholders.
   * @param options.verify - set this to true to check zero-knowledge proofs of
   *   partial decryptions, and discard invalid or unproven ones. Default is
   *   false, then a cheating shareholder can cause a wrong plaintext silently.
   *   Supported by ElGamal, Exponential-ElGamal, EllipticCurve-ElGamal, and
   *   Paillier and Damgard-Jurik with keys generated with `safePrimes: true`.
   * @returns restored message.
   */
  combinePartialDecryptions(
    ciphertext: Ciphertext,
    partialDecryptions: readonly PartialDecryption[] | readonly unknown[],
    options?: { verify?: boolean }
  ): bigint;
  combinePartialDecryptions(
    ciphertext: EncryptedTensor,
    partialDecryptions: readonly TensorPartialDecryption[][],
    options?: { verify?: boolean }
  ): number[];
  combinePartialDecryptions(
    ciphertext: Ciphertext | EncryptedTensor,
    partialDecryptions: readonly unknown[],
    options?: { verify?: boolean }
  ): bigint | number[];
  combinePartialDecryptions(
    ciphertext: Ciphertext | EncryptedTensor,
    partialDecryptions: readonly unknown[],
    options?: { verify?: boolean }
  ): bigint | number[] {
    const verify = options?.verify ?? false;
    this.requireKey('public_key', 'combine partial decryptions');

    if (ciphertext instanceof EncryptedTensor) {
      const partials =
        partialDecryptions as readonly TensorPartialDecryption[][];
      return ciphertext.fractions.map((c, k) => {
        const absDividend = this.cs.combinePartialDecryptions(
          c.absDividend,
          partials.map((p) => p[k].abs_dividend),
          verify
        );
        const divisor = this.cs.combinePartialDecryptions(
          c.divisor,
          partials.map((p) => p[k].divisor),
          verify
        );
        return (c.sign * Number(absDividend)) / Number(divisor);
      });
    }

    return this.cs.combinePartialDecryptions(
      ciphertext.value,
      partialDecryptions,
      verify
    );
  }

  /**
   * Verifies that a partial decryption is computed with the share of its
   * shareholder. Public key is enough. Partial decryption must be created
   * with `prove: true`. {@link combinePartialDecryptions} does this if
   * `verify: true` and discards invalid ones, so this is useful to find a
   * cheating shareholder. Supported by ElGamal, Exponential-ElGamal,
   * EllipticCurve-ElGamal, and Paillier and Damgard-Jurik with keys generated
   * with `safePrimes: true`.
   */
  verifyPartialDecryption(
    ciphertext: Ciphertext,
    partialDecryption: PartialDecryption | Record<string, unknown>
  ): boolean {
    this.requireKey('public_key', 'verify partial decryption');
    return this.cs.verifyPartialDecryption(ciphertext.value, partialDecryption);
  }

  /**
   * Decrypts a ciphertext and proves that the decryption is correct, without
   * revealing the private key. Runs on private key owner side, e.g. a
   * tallying authority announcing the result of an election. Supported by
   * ElGamal, Exponential-ElGamal (keys generated with `primeOrder: true`),
   * EllipticCurve-ElGamal, Paillier and Damgard-Jurik.
   *
   * @returns restored message, same as decrypt, and the proof of correct
   *   decryption to be shared with the verifier.
   */
  decryptWithProof(ciphertext: Ciphertext): [bigint, DecryptionProof] {
    this.requireKey('private_key', 'perform decryption');
    this.requireKey('public_key', 'perform decryption');
    if (!(ciphertext instanceof Ciphertext)) {
      throw new Error(
        'Proofs of correct decryption are supported for Ciphertext only'
      );
    }
    return this.cs.decryptWithProof(ciphertext.value);
  }

  /**
   * Verifies that a ciphertext is decrypted to the given plaintext. Public key
   * is enough, so anyone can check the announced plaintext.
   *
   * @param proof - output of {@link decryptWithProof}.
   */
  verifyDecryption(
    ciphertext: Ciphertext,
    plaintext: number | bigint,
    proof: DecryptionProof | Record<string, unknown> | null | undefined
  ): boolean {
    this.requireKey('public_key', 'verify decryption');
    return this.cs.verifyDecryption(
      ciphertext.value,
      isInteger(plaintext) ? BigInt(plaintext) : plaintext,
      proof
    );
  }

  /**
   * Encrypts a plaintext and proves that it is one of the allowed values,
   * without revealing which one. For instance, a voter proves that the
   * encrypted vote is 0 or 1, so cannot cheat with a vote of 100 in the
   * homomorphic tally. Public key is enough. Supported by Exponential-ElGamal
   * (keys generated with `primeOrder: true`), EllipticCurve-ElGamal, Paillier
   * and Damgard-Jurik.
   *
   * @param plaintext - message to encrypt, must be one of values.
   * @param options.values - allowed values. Default is `[0, 1]`.
   * @param options.context - public data bound to the proof, e.g. id of the
   *   voter, so that the proof cannot be copied for another context.
   * @returns encrypted message and the proof that it encrypts one of values.
   */
  encryptWithProof(
    plaintext: number | bigint,
    options?: { values?: readonly (number | bigint)[]; context?: unknown }
  ): [Ciphertext, MembershipProof] {
    this.requireKey('public_key', 'perform encryption');
    const values = this.normalizeValues(options?.values);
    if (!isInteger(plaintext)) {
      throw new Error('Plaintext must be an integer');
    }
    const normalized = normalizeInput(plaintext, this.cs.plaintextModulo);
    if (!values.includes(normalized)) {
      throw new Error('Plaintext must be one of the allowed values');
    }

    const [ciphertext, proof] = this.cs.encryptWithProof(
      normalized,
      values,
      options?.context
    );
    return [this.publicCiphertext(ciphertext), proof];
  }

  /**
   * Verifies that a ciphertext encrypts one of the allowed values without
   * decrypting it. Public key is enough, e.g. anyone can check the ballots of
   * an election.
   *
   * @param proof - output of {@link encryptWithProof}.
   * @param options.values - allowed values. Default is `[0, 1]`.
   * @param options.context - public data that the proof is expected to be
   *   bound to.
   */
  verifyCiphertext(
    ciphertext: Ciphertext,
    proof: MembershipProof | Record<string, unknown> | null | undefined,
    options?: { values?: readonly (number | bigint)[]; context?: unknown }
  ): boolean {
    this.requireKey('public_key', 'verify ciphertext');
    const values = this.normalizeValues(options?.values);
    if (!(ciphertext instanceof Ciphertext)) {
      return false;
    }
    return this.cs.verifyCiphertext(
      ciphertext.value,
      proof,
      values,
      options?.context
    );
  }

  /**
   * Encrypts a plaintext and proves that the encryptor knows it, without
   * revealing it. For instance, a bidder of a sealed-bid auction proves
   * knowledge of the bid, so nobody can outbid by copying someone else's
   * encrypted bid and adding 1 to it homomorphically. Public key is enough.
   * Supported by ElGamal and Exponential-ElGamal (keys generated with
   * `primeOrder: true`), EllipticCurve-ElGamal, Paillier and Damgard-Jurik.
   *
   * @param options.context - public data bound to the proof, e.g. id of the
   *   encryptor, so that the proof cannot be copied for another context.
   * @returns encrypted message and the proof of knowledge of plaintext.
   */
  encryptWithProofOfKnowledge(
    plaintext: number | bigint,
    options?: { context?: unknown }
  ): [Ciphertext, KnowledgeProof] {
    this.requireKey('public_key', 'perform encryption');
    if (!isInteger(plaintext)) {
      throw new Error('Plaintext must be an integer');
    }
    const [ciphertext, proof] = this.cs.encryptWithProofOfKnowledge(
      normalizeInput(plaintext, this.cs.plaintextModulo),
      options?.context
    );
    return [this.publicCiphertext(ciphertext), proof];
  }

  /**
   * Verifies that the encryptor of a ciphertext knows its plaintext without
   * decrypting it. Public key is enough.
   *
   * @param proof - output of {@link encryptWithProofOfKnowledge}.
   * @param options.context - public data that the proof is expected to be
   *   bound to.
   */
  verifyKnowledge(
    ciphertext: Ciphertext,
    proof: KnowledgeProof | Record<string, unknown> | null | undefined,
    options?: { context?: unknown }
  ): boolean {
    this.requireKey('public_key', 'verify knowledge');
    if (!(ciphertext instanceof Ciphertext)) {
      return false;
    }
    return this.cs.verifyKnowledge(ciphertext.value, proof, options?.context);
  }

  /**
   * Encrypts a choice among options as a one-hot vector, i.e. 1 for the
   * chosen option and 0 for others, and proves that exactly one option is
   * chosen without revealing which one. For instance, a voter votes for one
   * of many parties. Summing slots of all ballots homomorphically counts votes
   * of each option separately, so the number of options is not limited.
   * Public key is enough. Supported by Exponential-ElGamal (keys generated
   * with `primeOrder: true`), EllipticCurve-ElGamal, Paillier and
   * Damgard-Jurik.
   *
   * @param choice - index of the chosen option in `[0, options)`.
   * @param options - number of options.
   * @param extra.context - public data bound to the proof, e.g. id of the
   *   voter, so that the proof cannot be copied for another context.
   * @returns encrypted slots, one per option, and the proof that slots are 0
   *   or 1 and sum to 1.
   */
  encryptOneHot(
    choice: number,
    options: number,
    extra?: { context?: unknown }
  ): [Ciphertext[], OneHotProof] {
    this.requireKey('public_key', 'perform encryption');
    if (!Number.isInteger(choice) || !Number.isInteger(options)) {
      throw new Error('Choice and number of options must be integers');
    }
    if (options < 1) {
      throw new Error('Number of options must be at least 1');
    }
    if (choice < 0 || choice >= options) {
      throw new Error(`Choice must be in [0, ${options})`);
    }
    if (this.cs.proveMembership === Homomorphic.prototype.proveMembership) {
      throw new Error(
        `${this.algorithmName} does not support proving that a ciphertext` +
          ' encrypts one of given values'
      );
    }

    const [zero, one] = this.normalizeValues([0, 1]);
    const [ciphertexts, proof] = zkp.proveOneHot(
      this.cs,
      choice,
      options,
      [zero, one],
      extra?.context
    );
    return [ciphertexts.map((c) => this.publicCiphertext(c)), proof];
  }

  /**
   * Verifies that encrypted slots are a one-hot vector, i.e. exactly one
   * option is chosen, without decrypting them. Public key is enough.
   *
   * @param proof - output of {@link encryptOneHot}.
   * @param options.context - public data that the proof is expected to be
   *   bound to.
   */
  verifyOneHot(
    ciphertexts: readonly Ciphertext[],
    proof: OneHotProof | Record<string, unknown> | null | undefined,
    options?: { context?: unknown }
  ): boolean {
    this.requireKey('public_key', 'verify one-hot ciphertexts');
    if (
      !Array.isArray(ciphertexts) ||
      !ciphertexts.every((c) => c instanceof Ciphertext)
    ) {
      return false;
    }
    const [zero, one] = this.normalizeValues([0, 1]);
    return zkp.verifyOneHot(
      this.cs,
      ciphertexts.map((c) => c.value),
      proof,
      [zero, one],
      options?.context
    );
  }

  /**
   * Encrypts a plaintext and proves that it is in `[low, high]`, without
   * revealing it. For instance, an employee proves that the encrypted salary
   * is in a sensible range, so cannot skew the average of salaries with a
   * negative or huge value. Public key is enough. Supported by
   * Exponential-ElGamal (keys generated with `primeOrder: true`),
   * EllipticCurve-ElGamal, Paillier and Damgard-Jurik. Proof size grows with
   * the bit length of `high - low`.
   *
   * @param plaintext - message to encrypt in `[low, high]`.
   * @param low - lower bound of the range.
   * @param high - upper bound of the range.
   * @param options.context - public data bound to the proof, e.g. id of the
   *   employee, so that the proof cannot be copied for another context.
   * @returns encrypted message and the proof that it is in `[low, high]`.
   */
  encryptWithRangeProof(
    plaintext: number | bigint,
    low: number | bigint,
    high: number | bigint,
    options?: { context?: unknown }
  ): [Ciphertext, RangeProof] {
    this.requireKey('public_key', 'perform encryption');
    const values = this.normalizeRange(low, high);
    if (!isInteger(plaintext)) {
      throw new Error('Plaintext must be an integer');
    }
    const value = BigInt(plaintext);
    if (value < BigInt(low) || value > BigInt(high)) {
      throw new Error(`Plaintext must be in [${low}, ${high}]`);
    }

    const [ciphertext, proof] = zkp.proveRange(
      this.cs,
      value,
      BigInt(low),
      BigInt(high),
      values,
      options?.context
    );
    return [this.publicCiphertext(ciphertext), proof];
  }

  /**
   * Verifies that a ciphertext encrypts a value in `[low, high]` without
   * decrypting it. Public key is enough.
   *
   * @param proof - output of {@link encryptWithRangeProof}.
   * @param options.context - public data that the proof is expected to be
   *   bound to.
   */
  verifyRange(
    ciphertext: Ciphertext,
    proof: RangeProof | Record<string, unknown> | null | undefined,
    low: number | bigint,
    high: number | bigint,
    options?: { context?: unknown }
  ): boolean {
    this.requireKey('public_key', 'verify range');
    const values = this.normalizeRange(low, high);
    if (!(ciphertext instanceof Ciphertext)) {
      return false;
    }
    return zkp.verifyRange(
      this.cs,
      ciphertext.value,
      proof,
      BigInt(low),
      BigInt(high),
      values,
      options?.context
    );
  }

  /**
   * Validates bounds of a range proof, and normalizes low, 0 and 1 as encrypt
   * does.
   */
  private normalizeRange(
    low: unknown,
    high: unknown
  ): [bigint, bigint, bigint] {
    if (!isInteger(low) || !isInteger(high)) {
      throw new Error('Bounds of the range must be integers');
    }
    if (BigInt(low) > BigInt(high)) {
      throw new Error(
        `Lower bound ${low} must not be greater than upper bound ${high}`
      );
    }
    if (BigInt(high) - BigInt(low) >= this.cs.plaintextModulo) {
      throw new Error('Range must be narrower than the plaintext modulo');
    }
    const modulo = this.cs.plaintextModulo;
    return [
      normalizeInput(BigInt(low), modulo),
      normalizeInput(ZERO, modulo),
      normalizeInput(ONE, modulo),
    ];
  }

  /**
   * Validates allowed values of a proof and normalizes them as encrypt does.
   *
   * @param values - allowed values. Default is `[0, 1]`.
   */
  private normalizeValues(values?: readonly unknown[]): bigint[] {
    const allowed = values ?? [0, 1];
    if (
      !Array.isArray(allowed) ||
      allowed.length === 0 ||
      !allowed.every(isInteger)
    ) {
      throw new Error('Allowed values must be a non-empty list of integers');
    }
    const normalized = (allowed as (number | bigint)[]).map((value) =>
      normalizeInput(value, this.cs.plaintextModulo)
    );
    if (new Set(normalized).size !== normalized.length) {
      throw new Error('Allowed values must be distinct');
    }
    return normalized;
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

  /**
   * Decrypts an encrypted tensor back to plain real numbers.
   *
   * @param decrypt - decryption function. cryptosystem's decrypt is used if
   *   not set.
   */
  private decryptTensor(
    encryptedTensor: EncryptedTensor,
    decrypt: (c: CiphertextValue) => bigint = (c) => this.cs.decrypt(c)
  ): number[] {
    return encryptedTensor.fractions.map((c) => {
      if (!(c instanceof Fraction)) {
        throw new Error('Ciphertext items must be type of Fraction');
      }

      const absDividend = decrypt(c.absDividend);
      const divisor = decrypt(c.divisor);

      return (c.sign * Number(absDividend)) / Number(divisor);
    });
  }

  /**
   * Encrypts client's input of a decision tree owned by the server.
   * Ishai-Paskin expects bits and depth, and Damgard-Geisler-Kroigaard expects
   * features and bitLength, e.g. `encryptDecisionTreeInput([1, 0], 2)` or
   * `encryptDecisionTreeInput({ features: [30, 75], bitLength: 8 })`.
   *
   * @param bits - Ishai-Paskin only. input bits (answers to the questions)
   *   x_0, x_1, ... each 0 or 1.
   * @param depth - Ishai-Paskin only. maximum number of decisions on a path of
   *   the decision tree.
   * @returns the encrypted input, to be sent to the tree owner.
   */
  encryptDecisionTreeInput(bits: readonly number[], depth: number): bigint[][];
  encryptDecisionTreeInput(input: DecisionTreeInput): bigint[][];
  encryptDecisionTreeInput(
    bitsOrInput: readonly number[] | DecisionTreeInput,
    depth?: number
  ): bigint[][] {
    if (this.cs.keys.public_key == null) {
      throw new Error('You must have public key to perform encryption');
    }

    const input: DecisionTreeInput = Array.isArray(bitsOrInput)
      ? { bits: bitsOrInput as readonly number[], depth }
      : (bitsOrInput as DecisionTreeInput);

    const usesBits = input.bits != null || input.depth != null;
    const usesFeatures = input.features != null || input.bitLength != null;

    if (usesBits && usesFeatures) {
      throw new Error(
        'Pass either bits and depth (Ishai-Paskin) or features and bit_length' +
          ' (Damgard-Geisler-Kroigaard), not both'
      );
    }

    if (usesFeatures) {
      if (input.features == null || input.bitLength == null) {
        throw new Error('features and bit_length must be passed together');
      }
      return this.cs.encryptDecisionTreeFeatures(
        input.features,
        input.bitLength
      );
    }

    if (input.bits == null || input.depth == null) {
      throw new Error('bits and depth must be passed together');
    }
    return this.cs.encryptDecisionTreeInput(input.bits, input.depth);
  }

  /**
   * Evaluates a decision tree on encrypted input. Private key is not required.
   * Only supported by Ishai-Paskin.
   *
   * @param tree - leaf (integer) or decision node `[variableIndex, treeIf0,
   *   treeIf1]`.
   * @param encryptedInput - output of {@link encryptDecisionTreeInput}.
   * @returns the encrypted output of the tree.
   */
  evaluateDecisionTree(
    tree: DecisionTree,
    encryptedInput: readonly (readonly bigint[])[]
  ): Ciphertext {
    if (this.cs.keys.public_key == null) {
      throw new Error(
        'You must have public key to perform decision tree evaluation'
      );
    }

    const output = this.cs.evaluateDecisionTree(tree, encryptedInput);

    return this.publicCiphertext(output);
  }

  /**
   * Encrypts bits of client's value x to compare it with server's value y.
   * 1st step of secure comparison, runs on client side. Only supported by
   * Damgard-Geisler-Kroigaard.
   *
   * @param value - client's value x in `[0, 2^bitLength)`.
   * @param bitLength - number of bits of compared values.
   * @returns the encrypted input, to be sent to the server.
   */
  encryptComparisonInput(value: number | bigint, bitLength: number): bigint[] {
    this.requireKey('public_key', 'perform encryption');
    return this.cs.encryptComparisonInput(value, bitLength);
  }

  /**
   * Compares client's encrypted value x with server's value y. 2nd step of
   * secure comparison, runs on server side. Private key is not required and
   * server learns nothing about x. Only supported by Damgard-Geisler-Kroigaard.
   *
   * @param encryptedInput - output of {@link encryptComparisonInput}.
   * @param value - server's value y in `[0, 2^bitLength)`.
   * @returns the encrypted result, to be sent back to the client.
   */
  evaluateComparison(
    encryptedInput: readonly bigint[],
    value: number | bigint
  ): bigint[] {
    this.requireKey('public_key', 'perform secure comparison');
    return this.cs.evaluateComparison(encryptedInput, value);
  }

  /**
   * Restores the result of secure comparison. 3rd step of secure comparison,
   * runs on client side. Client learns only whether x <= y, but not y. Only
   * supported by Damgard-Geisler-Kroigaard.
   *
   * @param encryptedResult - output of {@link evaluateComparison}.
   * @returns true if x <= y.
   */
  decryptComparison(encryptedResult: readonly bigint[]): boolean {
    this.requireKey('private_key', 'perform decryption');
    return this.cs.decryptComparison(encryptedResult);
  }

  /**
   * Compares encrypted features with thresholds of all decision nodes. 2nd
   * step of private decision tree evaluation, runs on server side. Only
   * supported by Damgard-Geisler-Kroigaard.
   *
   * @param tree - leaf label (integer) or decision node
   *   `[featureIndex, threshold, treeIfLessOrEqual, treeIfGreater]`.
   * @param encryptedFeatures - output of {@link encryptDecisionTreeInput}.
   * @returns encrypted comparisons to be sent to the client, and the server
   *   state that must be kept secret on server side for the 4th step.
   */
  evaluateDecisionTreeComparisons(
    tree: NumericDecisionTree,
    encryptedFeatures: readonly (readonly bigint[])[]
  ): [bigint[][], DecisionTreeServerState] {
    this.requireKey('public_key', 'perform decision tree evaluation');
    return this.cs.evaluateDecisionTreeComparisons(tree, encryptedFeatures);
  }

  /**
   * Answers server's comparisons in encrypted form. Comparisons are randomly
   * flipped by the server, so client does not learn the path in the tree. 3rd
   * step of private decision tree evaluation, runs on client side. Only
   * supported by Damgard-Geisler-Kroigaard.
   *
   * @param encryptedComparisons - output of
   *   {@link evaluateDecisionTreeComparisons}.
   * @returns encrypted answers, to be sent to the server.
   */
  answerDecisionTreeComparisons(
    encryptedComparisons: readonly (readonly bigint[])[]
  ): bigint[] {
    this.requireKey('private_key', 'perform decryption');
    return this.cs.answerDecisionTreeComparisons(encryptedComparisons);
  }

  /**
   * Finds the reached leaf in encrypted form. 4th step of private decision
   * tree evaluation, runs on server side. Only supported by
   * Damgard-Geisler-Kroigaard.
   *
   * @param serverState - output of {@link evaluateDecisionTreeComparisons}.
   * @param encryptedAnswers - output of {@link answerDecisionTreeComparisons}.
   * @returns encrypted leaves, to be sent to the client.
   */
  evaluateDecisionTreeLeaves(
    serverState: DecisionTreeServerState,
    encryptedAnswers: readonly bigint[]
  ): [bigint, bigint][] {
    this.requireKey('public_key', 'perform decision tree evaluation');
    return this.cs.evaluateDecisionTreeLeaves(serverState, encryptedAnswers);
  }

  /**
   * Restores the label of the reached leaf. Client learns only this label.
   * Last step of private decision tree evaluation, runs on client side. Only
   * supported by Damgard-Geisler-Kroigaard.
   *
   * @param encryptedLeaves - output of {@link evaluateDecisionTreeLeaves}.
   * @returns label of the reached leaf.
   */
  decryptDecisionTreeOutput(
    encryptedLeaves: readonly (readonly [bigint, bigint])[]
  ): bigint {
    this.requireKey('private_key', 'perform decryption');
    return this.cs.decryptDecisionTreeOutput(encryptedLeaves);
  }

  /**
   * Finds the index of the maximum of encrypted values without decrypting
   * them. Runs on server side and talks to the client (private key owner)
   * through the client callable. Client learns only the index, and server
   * learns nothing. Index of the first maximum is returned on ties. Only
   * supported by Damgard-Geisler-Kroigaard.
   *
   * @param encryptedValues - encrypted values in `[0, 2^bitLength)`.
   * @param bitLength - number of bits of the values.
   * @param client - sends a message to the client, and returns the output of
   *   the client's {@link answerArgmax}. Locally, it can be client's
   *   `answerArgmax` directly. Otherwise, wrap your network call with it; it
   *   may return a promise.
   * @returns the encrypted index, to be decrypted by the client.
   */
  async evaluateArgmax(
    encryptedValues: readonly (Ciphertext | bigint)[],
    bitLength: number,
    client: ArgmaxClient
  ): Promise<Ciphertext> {
    this.requireKey('public_key', 'perform encrypted argmax');
    const output = await this.cs.evaluateArgmax(
      encryptedValues.map((value) =>
        value instanceof Ciphertext ? (value.value as bigint) : value
      ),
      bitLength,
      client
    );

    return this.publicCiphertext(output);
  }

  /**
   * Answers a message of the server during encrypted argmax. Runs on client
   * side. Every value decrypted here is masked with a uniformly random value.
   * Only supported by Damgard-Geisler-Kroigaard. It is bound to this instance,
   * so it can be passed as the client of {@link evaluateArgmax} directly.
   *
   * @returns response to be sent back to the server.
   */
  readonly answerArgmax = (message: ArgmaxMessage): bigint[] => {
    this.requireKey('private_key', 'perform decryption');
    return this.cs.answerArgmax(message);
  };

  /**
   * Encrypts a query vector for encrypted k nearest neighbor search. Runs on
   * client side, e.g. a user searching a face embedding in the gallery of a
   * server. Embeddings must be quantized to integers, e.g. by scaling and
   * rounding. Only supported by Damgard-Geisler-Kroigaard.
   *
   * @returns encrypted query, to be sent to the server.
   */
  encryptKnnQuery(query: readonly (number | bigint)[]): EncryptedKnnQuery {
    this.requireKey('public_key', 'perform encryption');
    this.requireKnnSupport();
    if (
      !Array.isArray(query) ||
      query.length === 0 ||
      !query.every(isInteger)
    ) {
      throw new Error('Query must be a non-empty list of integers');
    }

    const encrypted = nearestNeighbors.encryptQuery(this.cs, query.map(BigInt));
    return {
      query: encrypted.query.map((c) => this.publicCiphertext(c)),
      norm: this.publicCiphertext(encrypted.norm),
    };
  }

  /**
   * Finds the k nearest vectors of a database to an encrypted query by
   * squared euclidean distance. Runs on server side and talks to the client
   * (private key owner) through the client callable. Server learns nothing,
   * and client learns only the indices, or the labels, of the k nearest
   * vectors, but not the distances or the other vectors. Earlier index is
   * returned on ties. Only supported by Damgard-Geisler-Kroigaard.
   *
   * @param encryptedQuery - output of {@link encryptKnnQuery}.
   * @param database - vectors of the server, in plain.
   * @param k - number of nearest vectors to find.
   * @param bitLength - squared distances between the query and vectors must
   *   be less than `2^bitLength`, e.g. 24 for 128-dimensional embeddings of
   *   8-bit entries.
   * @param client - sends a message to the client, and returns the output of
   *   the client's {@link answerKnn}. Locally, it can be client's `answerKnn`
   *   directly. Otherwise, wrap your network call with it.
   * @param options.labels - optional labels of vectors, e.g. ids of people.
   *   If set, encrypted labels of the nearest vectors are returned as well.
   * @returns encrypted indices, and encrypted labels if labels are set, of the
   *   k nearest vectors from the nearest one. To be decrypted by the client.
   */
  async evaluateKnn(
    encryptedQuery: EncryptedKnnQuery,
    database: readonly (readonly (number | bigint)[])[],
    k: number,
    bitLength: number,
    client: ArgmaxClient,
    options?: { labels?: readonly (number | bigint)[] }
  ): Promise<KnnResult> {
    this.requireKey('public_key', 'perform encrypted nearest neighbor search');
    this.requireKnnSupport();

    const query = (encryptedQuery as Partial<EncryptedKnnQuery> | null)?.query;
    if (!Array.isArray(query) || query.length === 0) {
      throw new Error('Encrypted query must be an output of encryptKnnQuery');
    }
    if (!Array.isArray(database) || database.length === 0) {
      throw new Error('Database must be a non-empty list of vectors');
    }
    if (
      database.some(
        (vector) =>
          !Array.isArray(vector) ||
          vector.length !== query.length ||
          !vector.every(isInteger)
      )
    ) {
      throw new Error(
        `Every vector of the database must be a list of ${query.length} integers`
      );
    }
    if (!Number.isInteger(k) || k < 1 || k > database.length) {
      throw new Error(`k must be in [1, ${database.length}]`);
    }
    const labels = options?.labels;
    if (
      labels !== undefined &&
      (!Array.isArray(labels) ||
        labels.length !== database.length ||
        !labels.every(isInteger))
    ) {
      throw new Error('Labels must be a list of integers, one for each vector');
    }
    if (!Number.isInteger(bitLength) || bitLength < 1) {
      throw new Error('Bit length must be a positive integer');
    }
    const vectors: bigint[][] = database.map(
      (vector: readonly (number | bigint)[]) => vector.map((x) => BigInt(x))
    );
    // argmax validates that lifted values fit into the plaintext space
    const largestNorm = vectors
      .map((vector) => vector.reduce((total, x) => total + x * x, ZERO))
      .reduce((a, b) => (b > a ? b : a));
    if (largestNorm >= ONE << BigInt(bitLength)) {
      throw new Error(
        `Squared norm ${largestNorm} of a vector in the database does not fit into` +
          ` ${bitLength} bits`
      );
    }

    const valueOf = (c: Ciphertext | bigint): bigint =>
      c instanceof Ciphertext ? (c.value as bigint) : c;
    const result = await nearestNeighbors.evaluateKnn(
      this.cs,
      {
        query: query.map(valueOf),
        norm: valueOf(encryptedQuery.norm),
      },
      vectors,
      k,
      bitLength,
      client,
      labels?.map(BigInt)
    );
    return {
      indices: result.indices.map((c) => this.publicCiphertext(c)),
      ...(result.labels === undefined
        ? {}
        : { labels: result.labels.map((c) => this.publicCiphertext(c)) }),
    };
  }

  /**
   * Answers a message of the server during encrypted k nearest neighbor
   * search. Runs on client side. Every value decrypted here is masked or
   * shuffled, so client learns nothing but the final result. Only supported by
   * Damgard-Geisler-Kroigaard. It is bound to this instance, so it can be
   * passed as the client of {@link evaluateKnn} directly.
   *
   * @returns response to be sent back to the server.
   */
  readonly answerKnn = (message: ArgmaxMessage): bigint[] => {
    this.requireKey('private_key', 'perform decryption');
    this.requireKnnSupport();
    return nearestNeighbors.answerKnn(this.cs, message);
  };

  /**
   * Computes encrypted squared euclidean distances between an encrypted query
   * and encrypted vectors. Runs on the side of an untrusted cloud storing the
   * encrypted database of an owner, and requires the public key only. Both
   * the query and the vectors are encrypted, so this requires
   * `boost: 'Catalano-Fiore'` for one multiplication. Cloud learns nothing,
   * and the owner finds the nearest vectors with {@link decryptKnn}.
   *
   * @returns one encrypted distance for each vector.
   */
  evaluateKnnDistances(
    encryptedQuery: readonly CatalanoFioreCiphertext[],
    encryptedDatabase: readonly (readonly CatalanoFioreCiphertext[])[]
  ): CatalanoFioreCiphertext[] {
    this.requireKey('public_key', 'compute encrypted distances');
    if (this.catalanoFiore === null) {
      throw new Error(
        "Encrypted distances between encrypted vectors require boost='Catalano-Fiore'"
      );
    }

    const isVector = (vector: unknown): boolean =>
      Array.isArray(vector) &&
      vector.length > 0 &&
      vector.every(
        (c) => c instanceof CatalanoFioreCiphertext && !c.isMultiplied
      );

    if (!isVector(encryptedQuery)) {
      throw new Error(
        'Encrypted query must be a non-empty list of encrypted integers'
      );
    }
    if (!Array.isArray(encryptedDatabase) || encryptedDatabase.length === 0) {
      throw new Error('Encrypted database must be a non-empty list of vectors');
    }
    if (
      encryptedDatabase.some(
        (vector) => !isVector(vector) || vector.length !== encryptedQuery.length
      )
    ) {
      throw new Error(
        `Every vector of the database must be a list of ${encryptedQuery.length}` +
          ' encrypted integers'
      );
    }

    return encryptedDatabase.map((vector) => {
      let total: CatalanoFioreCiphertext | undefined;
      encryptedQuery.forEach((q, i) => {
        const difference = q.subtract(vector[i]);
        const square = difference.multiply(difference);
        total = total === undefined ? square : total.add(square);
      });
      return total!;
    });
  }

  /**
   * Finds the k nearest vectors from encrypted distances computed by
   * {@link evaluateKnnDistances}. Runs on owner side, and requires the private
   * key.
   *
   * @param k - number of nearest vectors to find.
   * @returns indices and distances of the k nearest vectors from the nearest
   *   one. Earlier index is returned on ties.
   */
  decryptKnn(
    encryptedDistances: readonly CatalanoFioreCiphertext[],
    k: number
  ): { indices: number[]; distances: bigint[] } {
    this.requireKey('private_key', 'perform decryption');
    if (!Array.isArray(encryptedDistances) || encryptedDistances.length === 0) {
      throw new Error('Encrypted distances must be a non-empty list');
    }
    if (!Number.isInteger(k) || k < 1 || k > encryptedDistances.length) {
      throw new Error(`k must be in [1, ${encryptedDistances.length}]`);
    }

    const distances = encryptedDistances.map((c) => this.decrypt(c));
    const indices = distances
      .map((_, i) => i)
      .sort((i, j) =>
        distances[i] === distances[j]
          ? i - j
          : distances[i] < distances[j]
            ? -1
            : 1
      )
      .slice(0, k);
    return { indices, distances: indices.map((i) => distances[i]) };
  }

  /**
   * Encrypts a model update of a client for secure aggregation in federated
   * learning. Values are quantized with the precision of this cryptosystem,
   * and many of them are packed into a single ciphertext, so an update needs
   * far fewer ciphertexts than its length. Public key is enough. Clients must
   * use the same key, length, precision, maxValue and maxClients. Supported
   * by Paillier and Damgard-Jurik.
   *
   * @param update - model update, e.g. gradients or weights.
   * @param maxValue - absolute values of the update must be at most this,
   *   e.g. the clipping bound of gradients.
   * @param maxClients - maximum number of updates to be aggregated. Slots of
   *   ciphertexts are wide enough to sum this many updates without overflow.
   * @returns chunks of ciphertexts, the layout of packing, and the number of
   *   updates it contains.
   */
  encryptUpdate(
    update: readonly number[],
    maxValue: number,
    maxClients: number
  ): EncryptedUpdate {
    this.requireKey('public_key', 'perform encryption');
    this.requireAggregationSupport();
    if (!Array.isArray(update)) {
      throw new Error('Update must be a list of numbers');
    }

    const layout = secureAggregation.buildLayout(
      update.length,
      this.precision,
      maxValue,
      maxClients,
      this.cs.plaintextModulo
    );
    const plaintexts = secureAggregation.pack(update, layout);
    return {
      chunks: plaintexts.map((plaintext) =>
        this.publicCiphertext(this.cs.encrypt(plaintext))
      ),
      layout,
      count: 1,
    };
  }

  /**
   * Sums encrypted updates of clients chunk by chunk. Runs on server side, and
   * requires the public key only. Server learns nothing about updates or their
   * sum.
   *
   * @param encryptedUpdates - outputs of {@link encryptUpdate} or
   *   {@link aggregateUpdates}.
   */
  aggregateUpdates(
    encryptedUpdates: readonly EncryptedUpdate[]
  ): EncryptedUpdate {
    this.requireKey('public_key', 'aggregate updates');
    this.requireAggregationSupport();
    if (!Array.isArray(encryptedUpdates) || encryptedUpdates.length === 0) {
      throw new Error('Encrypted updates must be a non-empty list');
    }

    const layout = encryptedUpdates[0].layout;
    if (
      encryptedUpdates.some(
        (update) => !secureAggregation.sameLayout(update.layout, layout)
      )
    ) {
      throw new Error(
        'Encrypted updates must have the same layout, i.e. the same length,' +
          ' precision, max_value and max_clients'
      );
    }
    const count = encryptedUpdates.reduce(
      (total, update) => total + update.count,
      0
    );
    if (count > layout.max_clients) {
      throw new Error(
        `Sum of ${count} updates would overflow slots packed for at most` +
          ` ${layout.max_clients} clients`
      );
    }

    let chunks = [...encryptedUpdates[0].chunks];
    for (const update of encryptedUpdates.slice(1)) {
      chunks = chunks.map((total, i) => total.add(update.chunks[i]));
    }
    return { chunks, layout, count };
  }

  /**
   * Decrypts an encrypted sum of updates partially with the share of a
   * shareholder, e.g. a member of a committee of clients. Shareholders decrypt
   * sums only, never individual updates.
   *
   * @param encryptedSum - output of {@link aggregateUpdates}.
   * @param options.prove - set this to true to attach proofs of correct
   *   partial decryption. Keys must be generated with `safePrimes: true`.
   * @returns one partial decryption for each chunk, to be sent to the
   *   combiner.
   */
  partialDecryptAggregate(
    encryptedSum: EncryptedUpdate,
    options?: { prove?: boolean }
  ): PartialDecryption[] {
    this.requireAggregationSupport();
    return encryptedSum.chunks.map((chunk) =>
      this.partialDecrypt(chunk, options)
    );
  }

  /**
   * Restores the sum and the mean of updates from partial decryptions of at
   * least threshold many shareholders. Public key is enough.
   *
   * @param partialDecryptions - outputs of {@link partialDecryptAggregate} of
   *   shareholders.
   * @param options.verify - set this to true to check proofs of partial
   *   decryptions, and discard invalid or unproven ones.
   */
  combineAggregate(
    encryptedSum: EncryptedUpdate,
    partialDecryptions: readonly (readonly PartialDecryption[])[],
    options?: { verify?: boolean }
  ): Aggregate {
    this.requireKey('public_key', 'combine partial decryptions');
    this.requireAggregationSupport();
    const plaintexts = encryptedSum.chunks.map((chunk, i) =>
      this.cs.combinePartialDecryptions(
        chunk.value,
        partialDecryptions.map((partials) => partials[i]),
        options?.verify ?? false
      )
    );
    return this.unpackAggregate(encryptedSum, plaintexts);
  }

  /**
   * Restores the sum and the mean of updates with the private key, if a
   * single party holds it instead of a committee.
   */
  decryptAggregate(encryptedSum: EncryptedUpdate): Aggregate {
    this.requireKey('private_key', 'perform decryption');
    this.requireAggregationSupport();
    const plaintexts = encryptedSum.chunks.map((chunk) =>
      this.cs.decrypt(chunk.value)
    );
    return this.unpackAggregate(encryptedSum, plaintexts);
  }

  /** Unpacks decrypted chunks of a sum of updates. */
  private unpackAggregate(
    encryptedSum: EncryptedUpdate,
    plaintexts: readonly bigint[]
  ): Aggregate {
    const count = encryptedSum.count;
    const sum = secureAggregation.unpack(
      plaintexts,
      encryptedSum.layout,
      count
    );
    return { sum, mean: sum.map((x) => x / count), count };
  }

  /** Throws if the algorithm does not support secure aggregation. */
  private requireAggregationSupport(): void {
    if (
      this.algorithmName !== Algorithm.Paillier &&
      this.algorithmName !== Algorithm.DamgardJurik
    ) {
      throw new Error(
        `${this.algorithmName} does not support secure aggregation.` +
          ' Use Paillier or Damgard-Jurik instead.'
      );
    }
  }

  /**
   * Classifies encrypted features with a private linear model, i.e. finds the
   * class of the greatest score `<w_i, x> + b_i`, e.g. logistic regression or
   * a linear SVM. Runs on server side and talks to the client (private key
   * owner) through the client callable. Client learns only the predicted
   * class, and server learns nothing. Only supported by
   * Damgard-Geisler-Kroigaard.
   *
   * @param encryptedFeatures - features encrypted by the client. Floats must
   *   be quantized to integers, e.g. by scaling and rounding.
   * @param weights - integer weights of each class.
   * @param bitLength - absolute values of scores must be less than
   *   `2^bitLength`.
   * @param client - sends a message to the client, and returns the output of
   *   the client's {@link answerArgmax}.
   * @param options.biases - optional integer bias of each class.
   * @returns encrypted index of the predicted class, to be decrypted by the
   *   client. Earlier class is returned on ties.
   */
  async evaluateHyperplane(
    encryptedFeatures: readonly Ciphertext[],
    weights: readonly (readonly (number | bigint)[])[],
    bitLength: number,
    client: ArgmaxClient,
    options?: { biases?: readonly (number | bigint)[] }
  ): Promise<Ciphertext> {
    this.requireKey('public_key', 'perform encrypted classification');
    this.requireClassifierSupport();
    classifiers.validateModelShape({ weights });
    const biases = options?.biases ?? weights.map(() => 0);
    if (![...weights.flat(), ...biases].every(isInteger)) {
      throw new Error(
        'Weights and biases must be integers. Quantize them first.'
      );
    }
    if (biases.length !== weights.length) {
      throw new Error('There must be a bias for each class');
    }
    if (
      !Array.isArray(encryptedFeatures) ||
      encryptedFeatures.length !== weights[0].length ||
      !encryptedFeatures.every((c) => c instanceof Ciphertext)
    ) {
      throw new Error(
        `Encrypted features must be a list of ${weights[0].length} ciphertexts`
      );
    }
    if (!Number.isInteger(bitLength) || bitLength < 1) {
      throw new Error('Bit length must be a positive integer');
    }

    const output = await classifiers.evaluateHyperplane(
      this.cs,
      encryptedFeatures.map((c) => c.value as bigint),
      weights.map((w) => w.map(BigInt)),
      biases.map(BigInt),
      bitLength,
      client
    );
    return this.publicCiphertext(output);
  }

  /**
   * Encrypts categorical features for naive bayes classification as one-hot
   * vectors. Runs on client side. Only supported by
   * Damgard-Geisler-Kroigaard.
   *
   * @param features - value of each feature in `[0, domain size)`.
   * @param domainSizes - number of values of each feature, which the server
   *   shares as a part of its model.
   * @returns encrypted input, to be sent to the server.
   */
  encryptNaiveBayesInput(
    features: readonly number[],
    domainSizes: readonly number[]
  ): Ciphertext[][] {
    this.requireKey('public_key', 'perform encryption');
    this.requireClassifierSupport();
    if (
      !Array.isArray(features) ||
      !Array.isArray(domainSizes) ||
      features.length === 0 ||
      features.length !== domainSizes.length
    ) {
      throw new Error('There must be a domain size for each feature');
    }
    features.forEach((feature, j) => {
      const size = domainSizes[j];
      if (!Number.isInteger(size) || size < 1) {
        throw new Error('Domain sizes must be positive integers');
      }
      if (!Number.isInteger(feature) || feature < 0 || feature >= size) {
        throw new Error(
          `Feature ${feature} must be an integer in [0, ${size})`
        );
      }
    });

    const encrypted = classifiers.encryptNaiveBayesInput(
      this.cs,
      features,
      domainSizes
    );
    return encrypted.map((oneHot) =>
      oneHot.map((c) => this.publicCiphertext(c))
    );
  }

  /**
   * Classifies encrypted categorical features with a private naive bayes
   * model, i.e. finds the class of the greatest
   * `log P(c) + sum of log P(x_j | c)`. Runs on server side and talks to the
   * client (private key owner) through the client callable. Client learns
   * only the predicted class, and server learns nothing. Only supported by
   * Damgard-Geisler-Kroigaard.
   *
   * @param encryptedInput - output of {@link encryptNaiveBayesInput}.
   * @param priors - P(c) of each class.
   * @param likelihoods - `P(x_j = v | c)` for class c, feature j and value v,
   *   i.e. `likelihoods[c][j][v]`. Probabilities must be positive, e.g.
   *   smoothed with Laplace smoothing.
   * @param client - sends a message to the client, and returns the output of
   *   the client's {@link answerArgmax}.
   * @param options.precision - number of decimal digits kept from log
   *   probabilities. Default is 3. Greater values need more bits for scores.
   * @returns encrypted index of the predicted class, to be decrypted by the
   *   client. Earlier class is returned on ties.
   */
  async evaluateNaiveBayes(
    encryptedInput: readonly (readonly Ciphertext[])[],
    priors: readonly number[],
    likelihoods: readonly (readonly (readonly number[])[])[],
    client: ArgmaxClient,
    options?: { precision?: number }
  ): Promise<Ciphertext> {
    const precision = options?.precision ?? 3;
    this.requireKey('public_key', 'perform encrypted classification');
    this.requireClassifierSupport();
    classifiers.validateModelShape({ likelihoods });
    if (!Array.isArray(priors) || priors.length !== likelihoods.length) {
      throw new Error('There must be a prior for each class');
    }
    const domainSizes = likelihoods[0].map((values) => values.length);
    if (
      !Array.isArray(encryptedInput) ||
      encryptedInput.length !== domainSizes.length ||
      encryptedInput.some(
        (oneHot, j) =>
          !Array.isArray(oneHot) ||
          oneHot.length !== domainSizes[j] ||
          !oneHot.every((c) => c instanceof Ciphertext)
      )
    ) {
      throw new Error(
        `Encrypted input must be one-hot vectors of domain sizes [${domainSizes.join(', ')}]`
      );
    }
    if (!Number.isInteger(precision) || precision < 0) {
      throw new Error('Precision must be a non-negative integer');
    }

    const [quantizedPriors, quantizedLikelihoods, bitLength] =
      classifiers.quantizeNaiveBayes(priors, likelihoods, precision);
    const output = await classifiers.evaluateNaiveBayes(
      this.cs,
      encryptedInput.map((oneHot: readonly Ciphertext[]) =>
        oneHot.map((c) => c.value as bigint)
      ),
      quantizedPriors,
      quantizedLikelihoods,
      bitLength,
      client
    );
    return this.publicCiphertext(output);
  }

  /** Throws if the algorithm does not support encrypted classification. */
  private requireClassifierSupport(): void {
    if (this.algorithmName !== Algorithm.DamgardGeislerKroigaard) {
      throw new Error(
        `${this.algorithmName} does not support encrypted classification.` +
          ' Use Damgard-Geisler-Kroigaard instead.'
      );
    }
  }

  /** Throws if the algorithm does not support encrypted nearest neighbor search. */
  private requireKnnSupport(): void {
    if (this.algorithmName !== Algorithm.DamgardGeislerKroigaard) {
      throw new Error(
        `${this.algorithmName} does not support encrypted nearest neighbor search.` +
          ' Use Damgard-Geisler-Kroigaard instead.'
      );
    }
  }

  /** Throws if the cryptosystem does not have the given key. */
  private requireKey(
    keyType: 'public_key' | 'private_key',
    action: string
  ): void {
    if (this.cs.keys[keyType] == null) {
      throw new Error(
        `You must have ${keyType.replace('_', ' ')} to ${action}`
      );
    }
  }

  /**
   * Generates a different ciphertext that decrypts to the same plaintext. Only
   * the public key is needed.
   */
  regenerateCiphertext(
    ciphertext: Ciphertext | CatalanoFioreCiphertext
  ): Ciphertext {
    if (this.cs.keys.public_key == null) {
      throw new Error('You must have public key to perform decryption');
    }

    if (ciphertext instanceof CatalanoFioreCiphertext) {
      throw new Error(
        'Ciphertexts supporting multiplication cannot be regenerated. ' +
          'Encrypt the plaintext again instead.'
      );
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
export {
  CatalanoFiore,
  CatalanoFioreCiphertext,
  CATALANO_FIORE,
  CATALANO_FIORE_SUPPORTED_ALGORITHMS,
} from './models/CatalanoFiore.js';
export { EncryptedTensor, Fraction } from './models/Tensor.js';
export { Homomorphic } from './models/Homomorphic.js';
export type {
  ArgmaxClient,
  ArgmaxMessage,
  ChallengeResponseProof,
  CiphertextValue,
  DecisionTree,
  DecisionTreeServerState,
  DecryptionProof,
  Keys,
  KeyPart,
  KnowledgeProof,
  MembershipProof,
  NumericDecisionTree,
  OneHotProof,
  PaillierKnowledgeProof,
  PartialDecryption,
  RandomKey,
  RandomnessProof,
  RangeProof,
  RequiredKeys,
  VerifiableCiphertext,
} from './models/types.js';
export { Logger, LogLevel } from './commons/logger.js';
export { validateKeys } from './commons/keyValidator.js';
export { serializeKeys, deserializeKeys } from './commons/keySerializer.js';
export * as pheUtils from './commons/pheUtils.js';
export * as mathUtils from './commons/mathUtils.js';
export * as zkp from './commons/zkp.js';
export * as threshold from './commons/threshold.js';
export * as secureAggregation from './commons/secureAggregation.js';
export * as classifiers from './commons/classifiers.js';
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
  JoyeLibert,
  CastagnosLaguillaumie,
  IshaiPaskin,
  DamgardGeislerKroigaard,
  BressonCatalanoPointcheval,
  CamenischShoup,
  EllipticCurvePaillier,
  Regev,
  BrakerskiVaikuntanathan,
  FreemanBonehGohNissim,
  GentryHaleviVaikuntanathan,
  LyubashevskyPeikertRegev,
  MLKEM,
  GentrySahaiWaters,
  FLOAT_NOT_SUPPORTED_MSG,
  REGEV_FLOAT_NOT_SUPPORTED_MSG,
  BV_FLOAT_NOT_SUPPORTED_MSG,
  FBGN_FLOAT_NOT_SUPPORTED_MSG,
  GHV_FLOAT_NOT_SUPPORTED_MSG,
  GHV_INSECURE_WARNING_MSG,
  LPR_FLOAT_NOT_SUPPORTED_MSG,
  MLKEM_FLOAT_NOT_SUPPORTED_MSG,
  GSW_FLOAT_NOT_SUPPORTED_MSG,
  DECISION_TREE_OUTPUT_NOT_SUPPORTED_MSG,
  type ECPair,
  type BGNValue,
  type CLPair,
  type Form,
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
