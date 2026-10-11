/** The signature every LightPHE cryptosystem implements. */

import type {
  CiphertextValue,
  DecisionTree,
  Keys,
  RequiredKeys,
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
  abstract generateRandomKey(): bigint;

  /** Encrypts a plaintext. */
  abstract encrypt(
    plaintext: bigint,
    randomKey?: bigint | bigint[]
  ): CiphertextValue;

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
      `${this.getAlgorithmName()} does not support evaluating decision trees`
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

  /** Returns a different ciphertext that decrypts to the same plaintext. */
  reencrypt(_ciphertext: CiphertextValue): CiphertextValue {
    throw new Error(
      `${this.getAlgorithmName()} does not support re-encryption`
    );
  }
}
