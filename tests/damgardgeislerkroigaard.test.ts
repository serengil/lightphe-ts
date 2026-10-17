import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import {
  LightPHE,
  Logger,
  mathUtils,
  type ArgmaxMessage,
  type Ciphertext,
  type NumericDecisionTree,
} from '../src';
import { valuesEqual } from './helpers';

const logger = new Logger('tests/damgardgeislerkroigaard.test.ts');

const ALGORITHM = 'Damgard-Geisler-Kroigaard';
const cs = new LightPHE({ algorithmName: ALGORITHM, keySize: 50 });

// secure comparison and private decision trees
const protocolCs = new LightPHE({ algorithmName: ALGORITHM, keySize: 256 });
const serverCs = new LightPHE({
  algorithmName: ALGORITHM,
  keys: { public_key: protocolCs.cs.keys.public_key },
});

type DecisionNode = readonly [
  number,
  number,
  NumericDecisionTree,
  NumericDecisionTree,
];

function evaluatePlainTree(
  tree: NumericDecisionTree,
  features: readonly number[]
): bigint {
  let node = tree;
  while (Array.isArray(node)) {
    const [featureIndex, threshold, left, right] = node as DecisionNode;
    node = features[featureIndex] <= threshold ? left : right;
  }
  return BigInt(node as number);
}

function runPrivateDecisionTree(
  tree: NumericDecisionTree,
  features: number[],
  bitLength: number
): bigint {
  // client
  const encryptedFeatures = protocolCs.encryptDecisionTreeInput({
    features,
    bitLength,
  });
  // server
  const [encryptedComparisons, serverState] =
    serverCs.evaluateDecisionTreeComparisons(tree, encryptedFeatures);
  // client
  const encryptedAnswers =
    protocolCs.answerDecisionTreeComparisons(encryptedComparisons);
  // server
  const encryptedLeaves = serverCs.evaluateDecisionTreeLeaves(
    serverState,
    encryptedAnswers
  );
  // client
  return protocolCs.decryptDecisionTreeOutput(encryptedLeaves);
}

async function runArgmax(values: number[], bitLength: number): Promise<bigint> {
  const encryptedValues = values.map((value) => protocolCs.encrypt(value));
  const encryptedIndex = await serverCs.evaluateArgmax(
    encryptedValues,
    bitLength,
    protocolCs.answerArgmax
  );
  return protocolCs.decrypt(encryptedIndex);
}

function argmax(values: readonly number[]): bigint {
  return BigInt(values.indexOf(Math.max(...values)));
}

/** A seeded random number generator, so that argmax cases are reproducible. */
function seededRandom(seed: number): (lo: number, hi: number) => number {
  let state = seed;
  return (lo, hi) => {
    state = (state * 1103515245 + 12345) % 2 ** 31;
    return lo + (state % (hi - lo + 1));
  };
}

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-ts-'));
}

describe('Damgard-Geisler-Kroigaard', () => {
  it('is additively homomorphic and supports scalar multiplication', () => {
    const tic = Date.now();
    const modulo = cs.cs.plaintextModulo;

    const m1 = 3n;
    const m2 = 4n;

    const c1 = cs.encrypt(m1);
    const c2 = cs.encrypt(m2);

    // proof of decryption
    expect(cs.decrypt(c1)).toBe(m1);
    expect(cs.decrypt(c2)).toBe(m2);

    // homomorphic addition
    expect(cs.decrypt(c1.add(c2))).toBe((m1 + m2) % modulo);

    // homomorphic scalar multiplication
    expect(cs.decrypt(c1.multiply(m2))).toBe((m1 * m2) % modulo);
    expect(cs.decrypt(c1.multiplyByConstant(m2))).toBe((m1 * m2) % modulo);

    // negative plaintexts and addition wrapping around the plaintext modulo
    const c3 = cs.encrypt(-2);
    expect(cs.decrypt(c3)).toBe(modulo - 2n);
    expect(cs.decrypt(c1.add(c3))).toBe(m1 - 2n);
    expect(cs.decrypt(cs.encrypt(modulo - 1n).add(c1))).toBe(m1 - 1n);

    // re-randomization
    const c1Prime = cs.regenerateCiphertext(c1);
    expect(valuesEqual(c1Prime.value, c1.value)).toBe(false);
    expect(cs.decrypt(c1Prime)).toBe(m1);

    // unsupported homomorphic operations
    expect(() => c1.multiply(c2)).toThrow();
    expect(() => c1.xor(c2)).toThrow();
    expect(() => c1.and(c2)).toThrow();

    logger.info(
      `✅ Damgard-Geisler-Kroigaard api test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });

  it('restores all plaintexts in a small space', () => {
    const smallCs = new LightPHE({ algorithmName: ALGORITHM, keySize: 32 });
    const modulo = smallCs.cs.plaintextModulo;
    for (let m = 0n; m < modulo; m++) {
      expect(smallCs.decrypt(smallCs.encrypt(m))).toBe(m);
    }
    logger.info(
      `✅ Damgard-Geisler-Kroigaard restored all ${modulo} plaintexts`
    );
  });

  it('works with predefined keys', () => {
    const restoredCs = new LightPHE({
      algorithmName: ALGORITHM,
      keys: cs.cs.keys,
    });
    const c1 = cs.encrypt(2);
    const c2 = restoredCs.encrypt(5);
    expect(restoredCs.decrypt(c1.add(c2))).toBe(7n);
    expect(cs.decrypt(c1.add(c2))).toBe(7n);
    logger.info('✅ Damgard-Geisler-Kroigaard predefined keys test succeeded');
  });

  it('encrypts with the public key only', () => {
    const publicCs = new LightPHE({
      algorithmName: ALGORITHM,
      keys: { public_key: cs.cs.keys.public_key },
    });
    const c1 = publicCs.encrypt(6);
    expect(cs.decrypt(c1)).toBe(6n);

    expect(() => publicCs.decrypt(c1)).toThrow();
    logger.info('✅ Damgard-Geisler-Kroigaard public key only test succeeded');
  });

  it('works with 1024-bit keys', () => {
    const tic = Date.now();
    const largeCs = new LightPHE({ algorithmName: ALGORITHM, keySize: 1024 });
    const m1 = 123456789n;
    const m2 = 987654321n;
    const c1 = largeCs.encrypt(m1);
    const c2 = largeCs.encrypt(m2);
    expect(largeCs.decrypt(c1.add(c2))).toBe(m1 + m2);
    expect(largeCs.decrypt(c1.multiply(10))).toBe(m1 * 10n);

    // floats and tensors
    const c3 = largeCs.encrypt(1.5);
    expect(largeCs.decrypt(c3.multiply(4))).toBe(6n);
    const encTensor = largeCs.encrypt([1.5, 2.25, 3.5], { silent: true });
    expect(largeCs.decrypt(encTensor)).toEqual([1.5, 2.25, 3.5]);
    expect(largeCs.decrypt(encTensor.add(encTensor))).toEqual([3.0, 4.5, 7.0]);
    expect(largeCs.decrypt(encTensor.multiply(2))).toEqual([3.0, 4.5, 7.0]);

    logger.info(
      `✅ Damgard-Geisler-Kroigaard 1024-bit key test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });

  it('compares all pairs securely', () => {
    const tic = Date.now();
    const bitLength = 4;
    for (let x = 0; x < 2 ** bitLength; x++) {
      const encryptedX = protocolCs.encryptComparisonInput(x, bitLength);
      expect(encryptedX.length).toBe(bitLength);
      for (let y = 0; y < 2 ** bitLength; y++) {
        const encryptedResult = serverCs.evaluateComparison(encryptedX, y);
        expect(encryptedResult.length).toBe(bitLength + 1);
        expect(protocolCs.decryptComparison(encryptedResult)).toBe(x <= y);
      }
    }
    logger.info(
      `✅ Damgard-Geisler-Kroigaard secure comparison test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });

  it('compares edge values securely', () => {
    const bitLength = 16;
    const maxValue = 2 ** bitLength - 1;
    for (const [x, y] of [
      [0, 0],
      [0, maxValue],
      [maxValue, 0],
      [maxValue, maxValue],
      [12345, 12345],
      [12345, 12346],
      [12346, 12345],
    ]) {
      const encryptedX = protocolCs.encryptComparisonInput(x, bitLength);
      const encryptedResult = serverCs.evaluateComparison(encryptedX, y);
      expect(protocolCs.decryptComparison(encryptedResult)).toBe(x <= y);
    }
  });

  it('rejects invalid comparison inputs', () => {
    expect(() => protocolCs.encryptComparisonInput(16, 4)).toThrow(
      'must be integers'
    );
    expect(() => protocolCs.encryptComparisonInput(-1, 4)).toThrow(
      'must be integers'
    );

    const encryptedX = protocolCs.encryptComparisonInput(3, 4);
    expect(() => serverCs.evaluateComparison(encryptedX, 16)).toThrow(
      'must be integers'
    );

    // 4-bit plaintext space cannot hold the comparison of 8-bit values
    expect(() => cs.encryptComparisonInput(3, 8)).toThrow(
      'too small to compare'
    );

    // client side requires private key
    expect(() =>
      serverCs.decryptComparison(serverCs.evaluateComparison(encryptedX, 5))
    ).toThrow('You must have private key');
  });

  it('evaluates private decision trees', () => {
    const tic = Date.now();
    // loan approval: features are 0 (age), 1 (income in thousand dollars) and
    // 2 (number of open loans), and leaves are credit limits in thousand dollars.
    //
    //                         F1: income <= 40?
    //                       /yes                 \no
    //           F0: age <= 25?               F2: open loans <= 2?
    //            /yes      \no                 /yes             \no
    //           0    F2: open loans <= 1?   F1: income <= 100?   10
    //                  /yes       \no         /yes       \no
    //                 5            0         20           50
    const tree: NumericDecisionTree = [
      1,
      40,
      [0, 25, 0, [2, 1, 5, 0]],
      [2, 2, [1, 100, 20, 50], 10],
    ];
    const bitLength = 8;

    const samples = [
      [22, 30, 0],
      [30, 30, 1],
      [30, 30, 3],
      [40, 41, 0],
      [40, 100, 2],
      [40, 101, 2],
      [50, 200, 3],
      [25, 40, 1],
    ];
    for (const features of samples) {
      const expected = evaluatePlainTree(tree, features);
      // comparisons are flipped randomly, so run each sample several times
      for (let round = 0; round < 3; round++) {
        expect(runPrivateDecisionTree(tree, features, bitLength)).toBe(
          expected
        );
      }
    }

    logger.info(
      `✅ Damgard-Geisler-Kroigaard private decision tree test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });

  it('evaluates private decision trees for all inputs', () => {
    const tree: NumericDecisionTree = [
      0,
      1,
      [1, 2, 1, 2],
      [1, 0, 3, [0, 2, 4, 5]],
    ];
    const bitLength = 2;
    for (let a = 0; a < 4; a++) {
      for (let b = 0; b < 4; b++) {
        expect(runPrivateDecisionTree(tree, [a, b], bitLength)).toBe(
          evaluatePlainTree(tree, [a, b])
        );
      }
    }
  });

  it('evaluates a private decision tree of a single leaf', () => {
    expect(runPrivateDecisionTree(7, [1, 2], 4)).toBe(7n);
  });

  it('rejects invalid decision tree inputs', () => {
    const encryptedFeatures = protocolCs.encryptDecisionTreeInput({
      features: [1, 2],
      bitLength: 4,
    });

    expect(() =>
      serverCs.evaluateDecisionTreeComparisons([2, 1, 0, 1], encryptedFeatures)
    ).toThrow('Feature index 2 does not exist');

    expect(() =>
      serverCs.evaluateDecisionTreeComparisons(
        [0, 0, 1] as unknown as NumericDecisionTree,
        encryptedFeatures
      )
    ).toThrow('Decision node must be');

    expect(() => {
      const [, serverState] = serverCs.evaluateDecisionTreeComparisons(
        [0, 1, 0, -1],
        encryptedFeatures
      );
      serverCs.evaluateDecisionTreeLeaves(serverState, [
        protocolCs.cs.encrypt(0n) as bigint,
      ]);
    }).toThrow('Leaf labels must be');

    const [, serverState] = serverCs.evaluateDecisionTreeComparisons(
      [0, 1, 0, 1],
      encryptedFeatures
    );
    expect(() => serverCs.evaluateDecisionTreeLeaves(serverState, [])).toThrow(
      'Expected 1 answers but got 0'
    );
  });

  it('is the only algorithm supporting secure comparison', () => {
    const paillierCs = new LightPHE({ algorithmName: 'Paillier', keySize: 50 });
    expect(() => paillierCs.encryptComparisonInput(1, 4)).toThrow(
      'does not support secure comparison'
    );
    expect(() => paillierCs.evaluateComparison([1n], 1)).toThrow(
      'does not support secure comparison'
    );
    expect(() =>
      paillierCs.encryptDecisionTreeInput({ features: [1], bitLength: 4 })
    ).toThrow('does not support private decision tree');
    expect(() =>
      paillierCs.evaluateDecisionTreeComparisons([0, 1, 0, 1], [[1n]])
    ).toThrow('does not support private decision tree');
  });

  it('finds the argmax of encrypted values', async () => {
    const tic = Date.now();
    const cases = [
      [5],
      [3, 9],
      [9, 3],
      [7, 7],
      [1, 7, 3, 7],
      [0, 0, 0, 0],
      [255, 0, 254],
      [10, 20, 30, 40, 50],
      [50, 40, 30, 20, 10],
      [12, 200, 3, 199, 255, 17],
    ];
    for (const values of cases) {
      // index of the first maximum on ties
      expect(await runArgmax(values, 8)).toBe(argmax(values));
    }
    logger.info(
      `✅ Damgard-Geisler-Kroigaard argmax test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });

  it('finds the argmax of random values', async () => {
    const random = seededRandom(42);
    // masks are random, so the comparison arc wraps around u in some rounds
    for (let round = 0; round < 30; round++) {
      const bitLength = [1, 4, 8, 12][random(0, 3)];
      const values = Array.from({ length: random(1, 6) }, () =>
        random(0, 2 ** bitLength - 1)
      );
      expect(await runArgmax(values, bitLength)).toBe(argmax(values));
    }
  });

  it('finds the class of a linear classifier', async () => {
    // client's encrypted features, server's private linear model with 3 classes
    const features = [3, 1, 4];
    const weights = [
      [1, 2, 0],
      [0, 1, 3],
      [2, 0, 1],
    ];

    const encryptedFeatures = features.map((feature) =>
      protocolCs.encrypt(feature)
    );

    // server computes encrypted class scores homomorphically
    const encryptedScores = weights.map((classWeights) => {
      let score = encryptedFeatures[0].multiply(classWeights[0]);
      for (let i = 1; i < classWeights.length; i++) {
        score = score.add(encryptedFeatures[i].multiply(classWeights[i]));
      }
      return score;
    });

    const encryptedClass = await serverCs.evaluateArgmax(
      encryptedScores,
      8,
      protocolCs.answerArgmax
    );

    const scores = weights.map((classWeights) =>
      classWeights.reduce((acc, w, i) => acc + w * features[i], 0)
    );
    expect(argmax(scores)).toBe(1n);
    expect(protocolCs.decrypt(encryptedClass)).toBe(1n);
  });

  it('shows only masked values to the client during argmax', async () => {
    const values = [10, 200, 30];
    const seen: string[] = [];

    const client = (message: ArgmaxMessage): bigint[] => {
      seen.push(message.type);
      return protocolCs.answerArgmax(message);
    };

    const encryptedValues = values.map((value) => protocolCs.encrypt(value));
    const encryptedIndex = await serverCs.evaluateArgmax(
      encryptedValues,
      8,
      client
    );
    expect(protocolCs.decrypt(encryptedIndex)).toBe(1n);

    // 3 round trips for each of the remaining 2 values
    expect(seen).toEqual([
      'masked_difference',
      'comparisons',
      'products',
      'masked_difference',
      'comparisons',
      'products',
    ]);
  });

  it('reaches the client asynchronously during argmax', async () => {
    // e.g. a network call returning a promise
    const client = async (message: ArgmaxMessage): Promise<bigint[]> => {
      await new Promise((resolve) => setTimeout(resolve, 1));
      return protocolCs.answerArgmax(
        JSON.parse(JSON.stringify(message, replacer), reviver)
      );
    };
    const encryptedValues = [4, 9, 2].map((value) => protocolCs.encrypt(value));
    const encryptedIndex = await serverCs.evaluateArgmax(
      encryptedValues,
      4,
      client
    );
    expect(protocolCs.decrypt(encryptedIndex)).toBe(1n);
  });

  it('finds the argmax with 1024-bit keys', async () => {
    const tic = Date.now();
    const largeCs = new LightPHE({ algorithmName: ALGORITHM, keySize: 1024 });
    const values = [40000, 65535, 3, 65534];
    const encryptedValues = values.map((value) => largeCs.encrypt(value));
    const encryptedIndex = await largeCs.evaluateArgmax(
      encryptedValues,
      16,
      largeCs.answerArgmax
    );
    expect(largeCs.decrypt(encryptedIndex)).toBe(1n);
    logger.info(
      `✅ Damgard-Geisler-Kroigaard 1024-bit argmax test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });

  it('rejects invalid argmax inputs', async () => {
    await expect(
      serverCs.evaluateArgmax([], 8, protocolCs.answerArgmax)
    ).rejects.toThrow('at least one value');

    const one = protocolCs.encrypt(1);
    await expect(
      serverCs.evaluateArgmax(
        [one, one],
        mathUtils.bitLength(protocolCs.cs.plaintextModulo),
        protocolCs.answerArgmax
      )
    ).rejects.toThrow('too small for argmax');

    expect(() =>
      protocolCs.answerArgmax({ type: 'unknown', payload: [] })
    ).toThrow('Unknown argmax message type');

    // client side requires private key
    expect(() =>
      serverCs.answerArgmax({ type: 'products', payload: [] })
    ).toThrow('You must have private key');

    const paillierCs = new LightPHE({ algorithmName: 'Paillier', keySize: 50 });
    await expect(
      paillierCs.evaluateArgmax(
        [paillierCs.encrypt(1)],
        4,
        paillierCs.answerArgmax
      )
    ).rejects.toThrow('does not support encrypted argmax');
  });

  it('validates decision tree input arguments', () => {
    // Damgard-Geisler-Kroigaard expects features and bitLength, not bits and depth
    expect(() => protocolCs.encryptDecisionTreeInput([1, 0], 2)).toThrow(
      'with bits and depth'
    );
    expect(() =>
      protocolCs.encryptDecisionTreeInput({
        features: [1],
        bitLength: 4,
        depth: 2,
      })
    ).toThrow('not both');
    expect(() =>
      protocolCs.encryptDecisionTreeInput({ features: [1] })
    ).toThrow('must be passed together');
    expect(() => protocolCs.encryptDecisionTreeInput({ bitLength: 4 })).toThrow(
      'must be passed together'
    );

    // Ishai-Paskin expects bits and depth, not features and bitLength
    const ishaiPaskinCs = new LightPHE({
      algorithmName: 'Ishai-Paskin',
      keySize: 50,
    });
    expect(() =>
      ishaiPaskinCs.encryptDecisionTreeInput({ features: [1], bitLength: 4 })
    ).toThrow('with features and bit_length');
    expect(() => ishaiPaskinCs.encryptDecisionTreeInput({ bits: [1] })).toThrow(
      'must be passed together'
    );
  });

  describe('readme examples', () => {
    const customerCs = new LightPHE({ algorithmName: ALGORITHM });
    let dir: string;
    let serverWithPublicKey: LightPHE;

    beforeAll(() => {
      // customer shares only the public key with the server
      dir = tempDir();
      const publicKeyFile = path.join(dir, 'public.txt');
      customerCs.exportKeys(publicKeyFile, true);
      serverWithPublicKey = new LightPHE({
        algorithmName: ALGORITHM,
        keyFile: publicKeyFile,
      });
      expect(serverWithPublicKey.cs.keys.private_key).toBeUndefined();
    });

    afterAll(() => {
      fs.rmSync(dir, { recursive: true, force: true });
    });

    it('evaluates a decision tree with numeric decisions', () => {
      const tic = Date.now();
      const bankCs = serverWithPublicKey;

      // features are 0 (age), 1 (income in thousand dollars) and 2 (number of open loans),
      // and leaves are credit limits in thousand dollars.
      //
      //                   F1: income <= 40?
      //                  /yes                \no
      //        F0: age <= 25?          F2: open loans <= 2?
      //         /yes      \no            /yes           \no
      //        0           5            20              10
      const creditLimitTree: NumericDecisionTree = [
        1,
        40,
        [0, 25, 0, 5],
        [2, 2, 20, 10],
      ];

      // the customer in the readme first, then every path of the tree drawn in the readme
      const expectedLimits: Array<[number[], bigint]> = [
        [[30, 75, 1], 20n],
        [[25, 40, 0], 0n],
        [[26, 40, 0], 5n],
        [[30, 41, 2], 20n],
        [[30, 41, 3], 10n],
      ];

      let encryptedComparisons: bigint[][] = [];
      let encryptedLeaves: [bigint, bigint][] = [];
      for (const [features, expectedLimit] of expectedLimits) {
        const encryptedFeatures = customerCs.encryptDecisionTreeInput({
          features,
          bitLength: 8,
        });
        let bankState;
        [encryptedComparisons, bankState] =
          bankCs.evaluateDecisionTreeComparisons(
            creditLimitTree,
            encryptedFeatures
          );
        const encryptedAnswers =
          customerCs.answerDecisionTreeComparisons(encryptedComparisons);
        encryptedLeaves = bankCs.evaluateDecisionTreeLeaves(
          bankState,
          encryptedAnswers
        );
        expect(customerCs.decryptDecisionTreeOutput(encryptedLeaves)).toBe(
          expectedLimit
        );
      }

      // bank cannot run the customer's steps
      expect(() =>
        bankCs.answerDecisionTreeComparisons(encryptedComparisons)
      ).toThrow('private key');
      expect(() => bankCs.decryptDecisionTreeOutput(encryptedLeaves)).toThrow(
        'private key'
      );

      logger.info(
        `✅ Damgard-Geisler-Kroigaard decision tree example in readme succeeded in ${(Date.now() - tic) / 1000} seconds`
      );
    });

    it('compares securely', () => {
      const clientCs = customerCs;
      const auctionCs = serverWithPublicKey;

      const encryptedBid = clientCs.encryptComparisonInput(120, 16);
      let encryptedResult = auctionCs.evaluateComparison(encryptedBid, 150);
      expect(clientCs.decryptComparison(encryptedResult)).toBe(true);

      // bid above the reserve price
      encryptedResult = auctionCs.evaluateComparison(encryptedBid, 100);
      expect(clientCs.decryptComparison(encryptedResult)).toBe(false);

      // server cannot learn the result
      expect(() => auctionCs.decryptComparison(encryptedResult)).toThrow(
        'private key'
      );

      logger.info(
        '✅ Damgard-Geisler-Kroigaard secure comparison example in readme succeeded'
      );
    });

    it('finds the argmax', async () => {
      const tic = Date.now();
      const clientCs = customerCs;
      const modelCs = serverWithPublicKey;

      const encryptedFeatures = [3, 1, 4].map((feature) =>
        clientCs.encrypt(feature)
      );

      const weights = [
        [1, 2, 0],
        [0, 1, 3],
        [2, 0, 1],
      ];
      const encryptedScores: Ciphertext[] = weights.map((classWeights) => {
        let score = encryptedFeatures[0].multiply(classWeights[0]);
        for (let i = 1; i < classWeights.length; i++) {
          score = score.add(encryptedFeatures[i].multiply(classWeights[i]));
        }
        return score;
      });

      const encryptedClass = await modelCs.evaluateArgmax(
        encryptedScores,
        8,
        clientCs.answerArgmax
      );
      expect(encryptedClass.keys.private_key).toBeUndefined();
      expect(clientCs.decrypt(encryptedClass)).toBe(1n);

      // server cannot decrypt the predicted class
      expect(() => modelCs.decrypt(encryptedClass)).toThrow('private key');

      logger.info(
        `✅ Damgard-Geisler-Kroigaard argmax example in readme succeeded in ${(Date.now() - tic) / 1000} seconds`
      );
    });
  });
});

/** JSON helpers that carry bigints over the wire, as a network client would. */
function replacer(_key: string, value: unknown): unknown {
  return typeof value === 'bigint' ? `${value.toString()}n` : value;
}

function reviver(_key: string, value: unknown): unknown {
  return typeof value === 'string' && /^\d+n$/.test(value)
    ? BigInt(value.slice(0, -1))
    : value;
}
