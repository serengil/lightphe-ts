import { LightPHE, Logger } from '../src';
import * as classifiers from '../src/commons/classifiers';
import { randomInt } from './helpers';

const logger = new Logger('tests/classifiers.test.ts');

// 512-bit keys have the same 32-bit plaintext space as 1024-bit keys, but are faster.
// they are not secure, and are for testing only.
const clientCs = new LightPHE({
  algorithmName: 'Damgard-Geisler-Kroigaard',
  keySize: 512,
});
const serverCs = new LightPHE({
  algorithmName: 'Damgard-Geisler-Kroigaard',
  keys: { public_key: clientCs.cs.keys.public_key },
});

async function classifyHyperplane(
  features: number[],
  weights: number[][],
  bitLength: number,
  biases?: number[]
): Promise<number> {
  const encryptedFeatures = features.map((x) => clientCs.encrypt(x));
  const encryptedClass = await serverCs.evaluateHyperplane(
    encryptedFeatures,
    weights,
    bitLength,
    clientCs.answerArgmax,
    { biases }
  );
  return Number(clientCs.decrypt(encryptedClass));
}

async function classifyNaiveBayes(
  features: number[],
  priors: number[],
  likelihoods: number[][][]
): Promise<number> {
  const domainSizes = likelihoods[0].map((values) => values.length);
  const encryptedInput = clientCs.encryptNaiveBayesInput(features, domainSizes);
  const encryptedClass = await serverCs.evaluateNaiveBayes(
    encryptedInput,
    priors,
    likelihoods,
    clientCs.answerArgmax
  );
  return Number(clientCs.decrypt(encryptedClass));
}

function argmax(scores: number[]): number {
  return scores.indexOf(Math.max(...scores));
}

describe('encrypted classifiers', () => {
  it('matches plain argmax of hyperplanes', async () => {
    for (let round = 0; round < 8; round++) {
      const weights = Array.from({ length: 4 }, () =>
        Array.from({ length: 6 }, () => randomInt(-20, 20))
      );
      const biases = Array.from({ length: 4 }, () => randomInt(-100, 100));
      const features = Array.from({ length: 6 }, () => randomInt(-30, 30));
      const scores = weights.map(
        (ws, c) =>
          ws.reduce((total, w, i) => total + w * features[i], 0) + biases[c]
      );
      // scores are in (-2^13, 2^13)
      expect(await classifyHyperplane(features, weights, 13, biases)).toBe(
        argmax(scores)
      );
    }

    logger.info('✅ Encrypted hyperplane classification matches plain argmax');
  });

  it('breaks ties and classifies binary', async () => {
    // earlier class on ties
    expect(
      await classifyHyperplane(
        [1, 1],
        [
          [2, 0],
          [0, 2],
          [1, 1],
        ],
        4
      )
    ).toBe(0);

    // a binary linear classifier is a hyperplane of two classes: 0 and w
    const weights = [3, -2, 5];
    for (const features of [
      [1, 4, 0],
      [2, 1, 1],
    ]) {
      const positive =
        weights.reduce((total, w, i) => total + w * features[i], 0) - 4 > 0;
      expect(
        await classifyHyperplane(features, [[0, 0, 0], weights], 8, [0, -4])
      ).toBe(Number(positive));
    }
  });

  it('approves credit with logistic regression', async () => {
    // bank owns a logistic regression model, and a customer applies with encrypted
    // features. Customer learns only whether the loan is approved, and bank learns nothing.
    // features: income in thousands, debt in thousands, years of employment, late payments
    const floatWeights = [0.042, -0.065, 0.31, -0.9];
    const floatBias = -1.2;
    const weights = [
      [0, 0, 0, 0],
      floatWeights.map((w) => Math.round(w * 1000)),
    ];
    const biases = [0, Math.round(floatBias * 1000)];

    for (const features of [
      [85, 20, 6, 0],
      [30, 45, 1, 3],
      [55, 10, 3, 1],
    ]) {
      const logit =
        floatWeights.reduce((total, w, i) => total + w * features[i], 0) +
        floatBias;
      const approved = await classifyHyperplane(features, weights, 16, biases);
      expect(approved).toBe(Number(logit > 0));
    }
  });

  it('matches plain naive bayes predictions', async () => {
    const domainSizes = [2, 3, 2];
    const priors = [0.5, 0.3, 0.2];
    const likelihoods = priors.map(() =>
      domainSizes.map((size) => {
        const values = Array.from(
          { length: size },
          () => 0.05 + 0.95 * Math.random()
        );
        const total = values.reduce((a, b) => a + b, 0);
        return values.map((v) => v / total);
      })
    );

    for (let f0 = 0; f0 < domainSizes[0]; f0++) {
      for (let f1 = 0; f1 < domainSizes[1]; f1++) {
        for (let f2 = 0; f2 < domainSizes[2]; f2++) {
          const features = [f0, f1, f2];
          const scores = priors.map(
            (prior, c) =>
              Math.log(prior) +
              features.reduce(
                (total, v, j) => total + Math.log(likelihoods[c][j][v]),
                0
              )
          );
          const ranked = [...scores].sort((a, b) => b - a);
          // quantization with precision 3 cannot separate scores closer than about 10^-2
          if (ranked[0] - ranked[1] < 1e-2) {
            continue;
          }
          expect(await classifyNaiveBayes(features, priors, likelihoods)).toBe(
            argmax(scores)
          );
        }
      }
    }

    logger.info('✅ Encrypted naive bayes matches plain prediction');
  });

  it('diagnoses with naive bayes', async () => {
    // clinic owns a naive bayes model trained on patient records, and a patient sends
    // encrypted symptoms. Patient learns only the most likely diagnosis, and clinic
    // learns nothing.
    // symptoms: fever (no, yes), cough (none, dry, wet), fatigue (no, yes)
    // diagnoses: cold, flu, allergy
    const records: number[][][] = [
      [
        [0, 2, 0],
        [0, 2, 1],
        [1, 2, 0],
        [0, 1, 0],
        [0, 2, 0],
      ],
      [
        [1, 1, 1],
        [1, 2, 1],
        [1, 1, 1],
        [1, 1, 0],
        [0, 1, 1],
      ],
      [
        [0, 0, 0],
        [0, 1, 0],
        [0, 0, 1],
        [0, 0, 0],
      ],
    ];
    const domainSizes = [2, 3, 2];
    const total = records.reduce((sum, rows) => sum + rows.length, 0);
    const priors = records.map((rows) => rows.length / total);

    // laplace smoothing keeps probabilities positive
    const likelihoods = records.map((rows) =>
      domainSizes.map((size, j) =>
        Array.from(
          { length: size },
          (_, v) =>
            (rows.filter((row) => row[j] === v).length + 1) /
            (rows.length + size)
        )
      )
    );

    expect(await classifyNaiveBayes([1, 1, 1], priors, likelihoods)).toBe(1); // flu
    expect(await classifyNaiveBayes([0, 2, 0], priors, likelihoods)).toBe(0); // cold
    expect(await classifyNaiveBayes([0, 0, 0], priors, likelihoods)).toBe(2); // allergy
  });

  it('quantizes naive bayes', () => {
    const [priors, likelihoods, bitLength] = classifiers.quantizeNaiveBayes(
      [0.25, 0.75],
      [[[0.5, 0.5]], [[0.1, 0.9]]],
      3
    );
    // log probabilities are shifted by their minimum, so the smallest one is 0
    const all = likelihoods.flat(2);
    expect(priors.reduce((a, b) => (b < a ? b : a))).toBe(0n);
    expect(all.reduce((a, b) => (b < a ? b : a))).toBe(0n);
    expect(all.every((x) => x >= 0n)).toBe(true);
    const max = (values: bigint[]): bigint =>
      values.reduce((a, b) => (b > a ? b : a));
    const largest = max(
      priors.map(
        (p, c) => p + likelihoods[c].reduce((total, v) => total + max(v), 0n)
      )
    );
    expect(largest < 2n ** BigInt(bitLength)).toBe(true);
  });

  it('rejects invalid inputs', async () => {
    const encryptedFeatures = [1, 2].map((x) => clientCs.encrypt(x));
    const client = clientCs.answerArgmax;

    await expect(
      serverCs.evaluateHyperplane(encryptedFeatures, [[1, 2], [3]], 8, client)
    ).rejects.toThrow('same number of weights');
    await expect(
      serverCs.evaluateHyperplane(encryptedFeatures, [[1, 0.5]], 8, client)
    ).rejects.toThrow('must be integers');
    await expect(
      serverCs.evaluateHyperplane(encryptedFeatures, [[1, 2, 3]], 8, client)
    ).rejects.toThrow('list of 3 ciphertexts');
    await expect(
      serverCs.evaluateHyperplane(encryptedFeatures, [[1, 2]], 8, client, {
        biases: [1, 2],
      })
    ).rejects.toThrow('bias for each class');
    await expect(
      serverCs.evaluateHyperplane(encryptedFeatures, [[1, 2]], 40, client)
    ).rejects.toThrow('too small for argmax');

    const likelihoods = [[[0.5, 0.5]], [[0.2, 0.8]]];
    const encryptedInput = clientCs.encryptNaiveBayesInput([1], [2]);
    await expect(
      serverCs.evaluateNaiveBayes(
        encryptedInput,
        [0.5, 0.5],
        [[[1.0, 0.0]], [[0.2, 0.8]]],
        client
      )
    ).rejects.toThrow('Smooth zero probabilities');
    await expect(
      serverCs.evaluateNaiveBayes(encryptedInput, [1.0], likelihoods, client)
    ).rejects.toThrow('prior for each class');
    await expect(
      serverCs.evaluateNaiveBayes(
        clientCs.encryptNaiveBayesInput([1], [3]),
        [0.5, 0.5],
        likelihoods,
        client
      )
    ).rejects.toThrow('domain sizes');
    expect(() => clientCs.encryptNaiveBayesInput([2], [2])).toThrow(
      'must be an integer in'
    );

    const paillier = new LightPHE({ algorithmName: 'Paillier', keySize: 64 });
    expect(() => paillier.encryptNaiveBayesInput([0], [2])).toThrow(
      'does not support encrypted classification'
    );
  });
});
