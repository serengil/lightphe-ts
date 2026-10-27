/**
 * Classification over encrypted data. Client (private key owner) encrypts its
 * features, and server evaluates its private model on them, so client learns
 * only the predicted class, and server learns nothing about the features.
 *   - hyperplane: class scores `<w_i, x> + b_i` are linear in the encrypted
 *     features. They are shifted by `2^bitLength` to be non-negative, which
 *     keeps the argmax.
 *   - naive bayes: client encrypts each categorical feature as a one-hot
 *     vector, so the score `log P(c) + sum of log P(x_j | c)` is linear in it.
 *     Log probabilities are quantized, and the log probabilities of each
 *     feature are shifted by their minimum, which adds the same constant to
 *     scores of all classes, so it keeps the argmax.
 *   - argmax: interactive argmax of Damgard-Geisler-Kroigaard on encrypted
 *     scores.
 *
 * Ref: Bost, R., Popa, R. A., Tu, S., Goldwasser, S. (2015). Machine Learning
 * Classification over Encrypted Data. NDSS 2015.
 */

import type { Homomorphic } from '../models/Homomorphic.js';
import type { ArgmaxClient } from '../models/types.js';
import { bitLength, mod, ONE, ZERO } from './mathUtils.js';
import { roundHalfEven } from './pheUtils.js';

/**
 * Finds the class of the greatest score `<w_i, x> + b_i` for encrypted
 * features x.
 *
 * @param cs - Damgard-Geisler-Kroigaard cryptosystem having the public key.
 * @param bitLengthOfScores - absolute values of scores must be less than
 *   `2^bitLengthOfScores`.
 * @returns encrypted index of the predicted class.
 */
export function evaluateHyperplane(
  cs: Homomorphic,
  encryptedFeatures: readonly bigint[],
  weights: readonly (readonly bigint[])[],
  biases: readonly bigint[],
  bitLengthOfScores: number,
  client: ArgmaxClient
): Promise<bigint> {
  const u = cs.plaintextModulo;
  const offset = ONE << BigInt(bitLengthOfScores);
  const scores = weights.map((classWeights, c) => {
    let score = cs.encrypt(mod(biases[c] + offset, u));
    classWeights.forEach((weight, i) => {
      if (mod(weight, u) !== ZERO) {
        score = cs.add(
          score,
          cs.multiplyByConstant(encryptedFeatures[i], mod(weight, u))
        );
      }
    });
    return score as bigint;
  });
  // scores are in [0, 2^(bitLength + 1)) after the shift
  return cs.evaluateArgmax(scores, bitLengthOfScores + 1, client);
}

/**
 * Quantizes log probabilities of a naive bayes model to non-negative
 * integers.
 *
 * @param priors - P(c) of each class.
 * @param likelihoods - `P(x_j = v | c)` for class c, feature j and value v,
 *   i.e. `likelihoods[c][j][v]`.
 * @param precision - number of decimal digits kept from log probabilities.
 * @returns quantized priors, quantized likelihoods, and the bit length that
 *   scores are less than 2 to the power of.
 */
export function quantizeNaiveBayes(
  priors: readonly number[],
  likelihoods: readonly (readonly (readonly number[])[])[],
  precision: number
): [bigint[], bigint[][][], number] {
  const scale = 10 ** precision;

  const log = (probability: unknown): number => {
    if (
      typeof probability !== 'number' ||
      !(probability > 0 && probability <= 1)
    ) {
      throw new Error(
        `Probabilities must be in (0, 1], got ${String(probability)}. Smooth zero` +
          ' probabilities, e.g. with Laplace smoothing.'
      );
    }
    return Math.log(probability);
  };

  const logPriors = priors.map(log);
  const lowestPrior = Math.min(...logPriors);
  const quantizedPriors = logPriors.map((x) =>
    roundHalfEven((x - lowestPrior) * scale)
  );

  const features = likelihoods[0].length;
  const quantizedLikelihoods: bigint[][][] = likelihoods.map(() => []);
  for (let j = 0; j < features; j++) {
    const logs = likelihoods.map((classLikelihoods) =>
      classLikelihoods[j].map(log)
    );
    const lowest = Math.min(...logs.map((values) => Math.min(...values)));
    logs.forEach((values, c) => {
      quantizedLikelihoods[c].push(
        values.map((x) => roundHalfEven((x - lowest) * scale))
      );
    });
  }

  const max = (values: readonly bigint[]): bigint =>
    values.reduce((a, b) => (b > a ? b : a));
  const largest = max(
    quantizedPriors.map(
      (prior, c) =>
        prior +
        quantizedLikelihoods[c].reduce(
          (total, values) => total + max(values),
          ZERO
        )
    )
  );
  return [
    quantizedPriors,
    quantizedLikelihoods,
    Math.max(1, bitLength(largest)),
  ];
}

/**
 * Encrypts categorical features as one-hot vectors. Runs on client side.
 *
 * @param features - value of each feature in `[0, domain size)`.
 * @param domainSizes - number of values of each feature.
 * @returns `E(1)` at the value, and `E(0)` elsewhere, for each feature.
 */
export function encryptNaiveBayesInput(
  cs: Homomorphic,
  features: readonly number[],
  domainSizes: readonly number[]
): bigint[][] {
  return features.map((feature, j) =>
    Array.from(
      { length: domainSizes[j] },
      (_, value) => cs.encrypt(value === feature ? ONE : ZERO) as bigint
    )
  );
}

/**
 * Finds the most probable class of a naive bayes model for encrypted one-hot
 * features.
 *
 * @param cs - Damgard-Geisler-Kroigaard cryptosystem having the public key.
 * @param priors - quantized log priors.
 * @param likelihoods - quantized log likelihoods.
 * @param bitLengthOfScores - scores are less than `2^bitLengthOfScores`.
 * @returns encrypted index of the predicted class.
 */
export function evaluateNaiveBayes(
  cs: Homomorphic,
  encryptedInput: readonly (readonly bigint[])[],
  priors: readonly bigint[],
  likelihoods: readonly (readonly (readonly bigint[])[])[],
  bitLengthOfScores: number,
  client: ArgmaxClient
): Promise<bigint> {
  const u = cs.plaintextModulo;
  const scores = priors.map((prior, c) => {
    let score = cs.encrypt(mod(prior, u));
    encryptedInput.forEach((oneHot, j) => {
      oneHot.forEach((bit, v) => {
        const value = likelihoods[c][j][v];
        if (mod(value, u) !== ZERO) {
          score = cs.add(score, cs.multiplyByConstant(bit, mod(value, u)));
        }
      });
    });
    return score as bigint;
  });
  return cs.evaluateArgmax(scores, bitLengthOfScores, client);
}

/** Checks that every class of a model has the same shape. */
export function validateModelShape(model: {
  weights?: unknown;
  likelihoods?: unknown;
}): void {
  const { weights, likelihoods } = model;
  if (weights !== undefined) {
    if (!Array.isArray(weights) || weights.length === 0) {
      throw new Error('Weights must be a non-empty list of class weights');
    }
    const length = (weights[0] as unknown[]).length;
    if (weights.some((w) => !Array.isArray(w) || w.length !== length)) {
      throw new Error('Every class must have the same number of weights');
    }
  }
  if (likelihoods !== undefined) {
    if (!Array.isArray(likelihoods) || likelihoods.length === 0) {
      throw new Error(
        'Likelihoods must be a non-empty list of class likelihoods'
      );
    }
    const shape = (likelihoods[0] as unknown[][]).map(
      (values) => values.length
    );
    const sameShape = (c: unknown): boolean =>
      Array.isArray(c) &&
      c.length === shape.length &&
      c.every(
        (values, j) => Array.isArray(values) && values.length === shape[j]
      );
    if (!likelihoods.every(sameShape)) {
      throw new Error(
        'Every class must have likelihoods of the same features and values'
      );
    }
  }
}
