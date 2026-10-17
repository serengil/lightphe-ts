/** The signature every LightPHE cryptosystem implements. */

import type { EllipticCurvePoint } from '../ecc/point.js';
import type {
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
} from './types.js';

export abstract class Homomorphic {
  /** The private/public key pair this cryptosystem was built with. */
  keys!: Keys;

  /** Upper bound of the message space. */
  plaintextModulo!: bigint;

  /** Modulus every ciphertext operation is reduced by. */
  ciphertextModulo!: bigint;

  /**
   * The required-field spec for user-supplied keys. Each subclass declares its
   * own as a static member; this instance getter exposes it for validation.
   */
  abstract get requiredKeys(): RequiredKeys;

  /** The user-facing name of this algorithm. */
  abstract getAlgorithmName(): string;

  /** Generates a fresh key pair. */
  abstract generateKeys(keySize: number, options?: unknown): Keys;

  /** Draws the one-time random value an encryption needs. */
  abstract generateRandomKey(): RandomKey;

  /** Encrypts a plaintext. */
  abstract encrypt(plaintext: bigint, randomKey?: RandomKey): CiphertextValue;

  /** Decrypts a ciphertext. */
  abstract decrypt(ciphertext: CiphertextValue): bigint;

  /** Evaluates `E(m1 + m2)`. */
  add(
    _ciphertext1: CiphertextValue,
    _ciphertext2: CiphertextValue
  ): CiphertextValue {
    throw new Error(
      `${this.getAlgorithmName()} is not homomorphic with respect to the addition`
    );
  }

  /** Evaluates `E(m1 * m2)`. */
  multiply(
    _ciphertext1: CiphertextValue,
    _ciphertext2: CiphertextValue
  ): CiphertextValue {
    throw new Error(
      `${this.getAlgorithmName()} is not homomorphic with respect to the multiplication`
    );
  }

  /** Evaluates `E(m1 ^ m2)`. */
  xor(
    _ciphertext1: CiphertextValue,
    _ciphertext2: CiphertextValue
  ): CiphertextValue {
    throw new Error(
      `${this.getAlgorithmName()} is not homomorphic with respect to the exclusive or`
    );
  }

  /** Evaluates `E(m1 & m2)`. */
  homomorphicAnd(
    _ciphertext1: CiphertextValue,
    _ciphertext2: CiphertextValue
  ): CiphertextValue {
    throw new Error(
      `${this.getAlgorithmName()} is not homomorphic with respect to the bitwise and`
    );
  }

  /** Evaluates `E(m * k)` for a known integer `k`. */
  multiplyByConstant(
    _ciphertext: CiphertextValue,
    _constant: bigint
  ): CiphertextValue {
    throw new Error(
      `${this.getAlgorithmName()} is not supporting multiplying ciphertext by a known constant`
    );
  }

  /** Encrypts the input bits of a decision tree. */
  encryptDecisionTreeInput(
    _bits: readonly number[],
    _depth: number
  ): bigint[][] {
    throw new Error(
      `${this.getAlgorithmName()} does not support evaluating decision trees` +
        ' with bits and depth'
    );
  }

  /** Evaluates a decision tree on encrypted input bits. */
  evaluateDecisionTree(
    _tree: DecisionTree,
    _encryptedInput: readonly (readonly bigint[])[]
  ): CiphertextValue {
    throw new Error(
      `${this.getAlgorithmName()} does not support evaluating decision trees`
    );
  }

  /** Encrypts bits of a value to be compared with a value of the server. */
  encryptComparisonInput(
    _value: bigint | number,
    _bitLength: number
  ): bigint[] {
    throw new Error(
      `${this.getAlgorithmName()} does not support secure comparison`
    );
  }

  /** Compares the client's encrypted value with the server's plain value. */
  evaluateComparison(
    _encryptedInput: readonly bigint[],
    _value: bigint | number
  ): bigint[] {
    throw new Error(
      `${this.getAlgorithmName()} does not support secure comparison`
    );
  }

  /** Restores the result of a secure comparison. */
  decryptComparison(_encryptedResult: readonly bigint[]): boolean {
    throw new Error(
      `${this.getAlgorithmName()} does not support secure comparison`
    );
  }

  /** Encrypts numeric features of a decision tree input. */
  encryptDecisionTreeFeatures(
    _features: readonly (bigint | number)[],
    _bitLength: number
  ): bigint[][] {
    throw new Error(
      `${this.getAlgorithmName()} does not support private decision tree evaluation` +
        ' with features and bit_length'
    );
  }

  /** Compares encrypted features with thresholds of all decision nodes. */
  evaluateDecisionTreeComparisons(
    _tree: NumericDecisionTree,
    _encryptedFeatures: readonly (readonly bigint[])[]
  ): [bigint[][], DecisionTreeServerState] {
    throw new Error(
      `${this.getAlgorithmName()} does not support private decision tree evaluation`
    );
  }

  /** Answers the server's comparisons in encrypted form. */
  answerDecisionTreeComparisons(
    _encryptedComparisons: readonly (readonly bigint[])[]
  ): bigint[] {
    throw new Error(
      `${this.getAlgorithmName()} does not support private decision tree evaluation`
    );
  }

  /** Finds the reached leaf of a decision tree in encrypted form. */
  evaluateDecisionTreeLeaves(
    _serverState: DecisionTreeServerState,
    _encryptedAnswers: readonly bigint[]
  ): [bigint, bigint][] {
    throw new Error(
      `${this.getAlgorithmName()} does not support private decision tree evaluation`
    );
  }

  /** Restores the label of the reached leaf. */
  decryptDecisionTreeOutput(
    _encryptedLeaves: readonly (readonly [bigint, bigint])[]
  ): bigint {
    throw new Error(
      `${this.getAlgorithmName()} does not support private decision tree evaluation`
    );
  }

  /** Finds the index of the maximum of encrypted values with the client's help. */
  evaluateArgmax(
    _encryptedValues: readonly bigint[],
    _bitLength: number,
    _client: ArgmaxClient
  ): Promise<bigint> {
    return Promise.reject(
      new Error(`${this.getAlgorithmName()} does not support encrypted argmax`)
    );
  }

  /** Answers a message of the server during encrypted argmax. */
  answerArgmax(_message: ArgmaxMessage): bigint[] {
    throw new Error(
      `${this.getAlgorithmName()} does not support encrypted argmax`
    );
  }

  /** Decrypts a ciphertext with the master key instead of its owner's key. */
  decryptWithMasterKey(
    _ciphertext: CiphertextValue,
    _publicKey?: KeyPart | null
  ): bigint {
    throw new Error(
      `${this.getAlgorithmName()} does not support master key decryption`
    );
  }

  /** Generates a key pair for a new user of a master key. */
  generateUserKeys(): Keys {
    throw new Error(
      `${this.getAlgorithmName()} does not support generating user keys sharing a master key`
    );
  }

  /** Encrypts the discrete logarithm of a curve point with a proof. */
  encryptVerifiably(
    _secret: bigint | number,
    _label?: string
  ): VerifiableCiphertext {
    throw new Error(
      `${this.getAlgorithmName()} does not support verifiable encryption`
    );
  }

  /** Verifies that a verifiable ciphertext contains the secret of a point. */
  verifyEncryption(
    _verifiableCiphertext: unknown,
    _publicPoint: EllipticCurvePoint | readonly [bigint, bigint],
    _label?: string
  ): boolean {
    throw new Error(
      `${this.getAlgorithmName()} does not support verifiable encryption`
    );
  }

  /** Restores the secret from a verifiable ciphertext. */
  decryptVerifiableCiphertext(
    _verifiableCiphertext: VerifiableCiphertext,
    _label?: string
  ): bigint {
    throw new Error(
      `${this.getAlgorithmName()} does not support verifiable encryption`
    );
  }

  /** Returns a different ciphertext that decrypts to the same plaintext. */
  reencrypt(_ciphertext: CiphertextValue): CiphertextValue {
    throw new Error(
      `${this.getAlgorithmName()} does not support re-encryption`
    );
  }
}
