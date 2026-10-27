/** Shared value and key shapes. */

import type { FP2 } from '../ecc/fp2.js';
import type { EllipticCurvePoint } from '../ecc/point.js';

/**
 * A ciphertext payload.
 *
 * The concrete shape depends on the cryptosystem: a single integer for RSA and
 * Paillier, a `[c1, c2]` pair for ElGamal, a bit vector for Goldwasser-Micali,
 * a curve point or an `F_{p^2}` element for Boneh-Goh-Nissim, and so on. The
 * cryptosystem that produced a value is the one that knows how to read it.
 */
export type CiphertextValue =
  bigint | EllipticCurvePoint | FP2 | readonly CiphertextValue[];

/**
 * A decision tree: either an integer leaf, or a decision node
 * `[variableIndex, treeIf0, treeIf1]` that continues with `treeIf0` when the
 * input bit at `variableIndex` is 0, and with `treeIf1` when it is 1.
 */
export type DecisionTree =
  number | bigint | readonly [number, DecisionTree, DecisionTree];

/** One half of a key pair: a bag of named big integers (or nested structures). */
export type KeyPart = Record<string, unknown>;

/** A private/public key pair as the cryptosystems store it. */
export interface Keys {
  public_key?: KeyPart;
  private_key?: KeyPart;
  /** Set for Elliptic Curve ElGamal so a restored key remembers its curve. */
  curve?: string;
  /** Set for Elliptic Curve ElGamal so a restored key remembers its form. */
  form?: string;
  [key: string]: unknown;
}

/**
 * The required-field spec a cryptosystem publishes so user-supplied keys can be
 * validated before use.
 */
export interface RequiredKeys {
  /** Sub-fields that must be present in `keys.public_key`. */
  public_key: readonly string[];
  /** Sub-fields that must be present in `keys.private_key`, when it is given. */
  private_key: readonly string[];
  /**
   * Sub-fields required inside a `public_key` entry that is itself a dictionary,
   * keyed by that entry's name.
   */
  nested?: Readonly<Record<string, readonly string[]>>;
  /**
   * Sub-fields accepted in `keys.private_key` instead of the required ones,
   * e.g. the master trapdoor of Bresson-Catalano-Pointcheval.
   */
  alternative_private_key?: readonly string[];
}

/**
 * The one-time randomness of an encryption: an integer for most cryptosystems,
 * a vector for Regev and Brakerski-Vaikuntanathan, a pair for
 * Freeman-Boneh-Goh-Nissim, or a matrix for Gentry-Halevi-Vaikuntanathan.
 */
export type RandomKey =
  bigint | readonly bigint[] | readonly (readonly bigint[])[];

/**
 * A decision tree on numeric features: either an integer leaf, or a decision
 * node `[featureIndex, threshold, treeIfLessOrEqual, treeIfGreater]` that
 * continues with `treeIfLessOrEqual` when the feature at `featureIndex` is less
 * than or equal to `threshold`, and with `treeIfGreater` otherwise.
 */
export type NumericDecisionTree =
  | number
  | bigint
  | readonly [
      number,
      number | bigint,
      NumericDecisionTree,
      NumericDecisionTree,
    ];

/**
 * What the server keeps secret between the comparison and leaf steps of a
 * private decision tree evaluation with Damgard-Geisler-Kroigaard.
 */
export interface DecisionTreeServerState {
  tree: NumericDecisionTree;
  flips: number[];
}

/**
 * A message the server sends to the client during encrypted argmax with
 * Damgard-Geisler-Kroigaard.
 */
export interface ArgmaxMessage {
  type: 'masked_difference' | 'comparisons' | 'products' | string;
  payload: readonly unknown[];
}

/**
 * Reaches the client (private key owner) during encrypted argmax: it sends a
 * message and returns the client's answer. Locally, it can be the client's
 * `answerArgmax` directly. Otherwise, wrap a network call with it.
 */
export type ArgmaxClient = (
  message: ArgmaxMessage
) => bigint[] | Promise<bigint[]>;

/** A Camenisch-Shoup ciphertext of a secret together with its proof. */
export interface VerifiableCiphertext {
  /** `[u, e, v]` where v is the validity tag bound to the label. */
  ciphertext: readonly bigint[];
  /** Commitment to the secret in the auxiliary group. */
  commitment: bigint;
  /** Fiat-Shamir proof that the ciphertext contains the secret. */
  proof: { challenge: bigint; r: bigint; s: bigint; m: bigint };
}

/**
 * A Chaum-Pedersen proof of equal discrete logarithms, or a Schnorr proof of
 * knowledge of a discrete logarithm, made non-interactive with Fiat-Shamir.
 */
export interface ChallengeResponseProof {
  challenge: bigint;
  response: bigint;
}

/**
 * A disjunctive proof that a ciphertext encrypts one of the allowed values,
 * without revealing which one. Proofs of other values are simulated.
 */
export interface MembershipProof {
  challenges: bigint[];
  responses: bigint[];
}

/**
 * Proof of correct decryption of Paillier and Damgard-Jurik: the randomness of
 * the ciphertext, which reveals nothing about the private key.
 */
export interface RandomnessProof {
  randomness: bigint;
}

/**
 * Proof of knowledge of the plaintext and randomness of a Paillier or
 * Damgard-Jurik ciphertext. Field names match the Python library.
 */
export interface PaillierKnowledgeProof {
  challenge: bigint;
  plaintext_response: bigint;
  randomness_response: bigint;
}

/** Proof that a ciphertext encrypts a value in a range, built from its bits. */
export interface RangeProof {
  /** Encryption of the lower bound, and encryptions of the bits. */
  ciphertexts: CiphertextValue[];
  /** Proofs that the parts encrypt the lower bound, and 0 or 1. */
  proofs: MembershipProof[];
}

/** Proof that encrypted slots are a one-hot vector. */
export interface OneHotProof {
  /** Proofs that each slot is 0 or 1. */
  slots: MembershipProof[];
  /** Proof that the slots sum to 1. */
  sum: MembershipProof;
}

/** Proof of correct decryption: Chaum-Pedersen or randomness of the ciphertext. */
export type DecryptionProof = ChallengeResponseProof | RandomnessProof;

/** Proof that the encryptor of a ciphertext knows its plaintext. */
export type KnowledgeProof = ChallengeResponseProof | PaillierKnowledgeProof;

/** A partial decryption of a shareholder in threshold decryption. */
export interface PartialDecryption {
  /** Index of the shareholder in `[1, parties]`. */
  index: number;
  /** `c1^share` for ElGamal, a point for Elliptic Curve ElGamal, `c^share` for Paillier. */
  value: bigint | [bigint, bigint];
  /** Optional proof that the value is computed with the share of the shareholder. */
  proof?: ChallengeResponseProof;
}
