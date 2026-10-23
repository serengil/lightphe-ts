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
  Keys,
  NumericDecisionTree,
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
];

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
   * Gentry-Halevi-Vaikuntanathan */
  algorithmName: AlgorithmName | string;

  /** An existing private/public key pair to use instead of generating one. */
  keys?: Keys | null;

  /** Path to a key file previously written by {@link LightPHE.exportKeys}. */
  keyFile?: string | null;

  /**
   * Key size in bits. For Regev, it is the lattice dimension. For
   * Brakerski-Vaikuntanathan, it is the ring degree. For
   * Freeman-Boneh-Goh-Nissim, it is the bit length of the field size. For
   * Gentry-Halevi-Vaikuntanathan, it is the lattice dimension in [2, 8].
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
   * `Freeman-Boneh-Goh-Nissim` or `Gentry-Halevi-Vaikuntanathan`.
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
  CiphertextValue,
  DecisionTree,
  DecisionTreeServerState,
  Keys,
  KeyPart,
  NumericDecisionTree,
  RandomKey,
  RequiredKeys,
  VerifiableCiphertext,
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
  FLOAT_NOT_SUPPORTED_MSG,
  REGEV_FLOAT_NOT_SUPPORTED_MSG,
  BV_FLOAT_NOT_SUPPORTED_MSG,
  FBGN_FLOAT_NOT_SUPPORTED_MSG,
  GHV_FLOAT_NOT_SUPPORTED_MSG,
  GHV_INSECURE_WARNING_MSG,
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
