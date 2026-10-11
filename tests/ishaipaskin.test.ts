import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import {
  IshaiPaskin,
  LightPHE,
  Logger,
  type Ciphertext,
  type DecisionTree,
} from '../src';
import { valuesEqual } from './helpers';

const logger = new Logger('tests/ishaipaskin.test.ts');

const cs = new LightPHE({ algorithmName: 'Ishai-Paskin', keySize: 50 });
const ip = cs.cs as IshaiPaskin;

function evaluateInPlain(tree: DecisionTree, bits: readonly number[]): bigint {
  let node = tree;
  while (Array.isArray(node)) {
    const [variableIndex, treeIf0, treeIf1] = node as readonly [
      number,
      DecisionTree,
      DecisionTree,
    ];
    node = bits[variableIndex] === 1 ? treeIf1 : treeIf0;
  }
  return BigInt(node as number | bigint);
}

function findDepth(tree: DecisionTree): number {
  if (!Array.isArray(tree)) {
    return 0;
  }
  const [, treeIf0, treeIf1] = tree as readonly [
    number,
    DecisionTree,
    DecisionTree,
  ];
  return 1 + Math.max(findDepth(treeIf0), findDepth(treeIf1));
}

function allBits(numInputs: number): number[][] {
  const result: number[][] = [];
  for (let i = 0; i < 2 ** numInputs; i++) {
    const bits: number[] = [];
    for (let j = numInputs - 1; j >= 0; j--) {
      bits.push((i >> j) & 1);
    }
    result.push(bits);
  }
  return result;
}

function assertTree(tree: DecisionTree, numInputs: number, depth?: number) {
  const levels = depth ?? Math.max(1, findDepth(tree));
  for (const bits of allBits(numInputs)) {
    const encryptedInput = cs.encryptDecisionTreeInput(bits, levels);
    const output = cs.evaluateDecisionTree(tree, encryptedInput);
    expect(cs.decrypt(output)).toBe(evaluateInPlain(tree, bits));
  }
}

describe('Ishai-Paskin', () => {
  it('is additively homomorphic as Damgard-Jurik', () => {
    const m1 = 17;
    const m2 = 21;

    const c1 = cs.encrypt(m1);
    const c2 = cs.encrypt(m2);

    expect(cs.decrypt(c1.add(c2))).toBe(BigInt(m1 + m2));
    expect(cs.decrypt(c1.multiply(m2))).toBe(BigInt(m1 * m2));
    expect(cs.decrypt(c1.multiplyByConstant(m2))).toBe(BigInt(m1 * m2));

    const c1Prime = cs.regenerateCiphertext(c1);
    expect(valuesEqual(c1Prime.value, c1.value)).toBe(false);
    expect(cs.decrypt(c1Prime)).toBe(BigInt(m1));

    // unsupported homomorphic operations
    expect(() => c1.multiply(c2)).toThrow();
    expect(() => c1.xor(c2)).toThrow();

    logger.info('✅ Ishai-Paskin api test succeeded');
  });

  it('encrypts and decrypts at every level', () => {
    const n = ip.keys.public_key!.n as bigint;
    for (let level = 1; level <= 4; level++) {
      const space = n ** BigInt(level);
      // plaintext space of level s is Z_{n^s}
      for (const raw of [0n, 1n, 12345n, n + 7n, space - 1n]) {
        const m = raw % space;
        const c = ip.encryptAtLevel(m, level);
        expect(c < n ** BigInt(level + 1)).toBe(true);
        expect(ip.decryptAtLevel(c, level)).toBe(m);
      }

      // level s is additively homomorphic in Z_{n^s}
      const c1 = ip.encryptAtLevel(space - 3n, level);
      const c2 = ip.encryptAtLevel(10n, level);
      const product = (c1 * c2) % n ** BigInt(level + 1);
      expect(ip.decryptAtLevel(product, level)).toBe(7n);
    }
  });

  it('evaluates boolean decision trees', () => {
    assertTree([0, [1, 0, 1], 1], 2); // x0 OR x1
    assertTree([0, 0, [1, 0, 1]], 2); // x0 AND x1
    assertTree([1, 1, 0], 2); // NOT x1

    // shared sub trees (DAG) are evaluated once
    const x2Is0: DecisionTree = [2, 1, 0];
    const x2Is1: DecisionTree = [2, 0, 1];
    const x1XorX2: DecisionTree = [1, x2Is1, x2Is0];
    const x1XnorX2: DecisionTree = [1, x2Is0, x2Is1];
    assertTree([0, x1XorX2, x1XnorX2], 3);

    const majority: DecisionTree = [0, [1, 0, [2, 0, 1]], [1, [2, 0, 1], 1]];
    assertTree(majority, 3);
  });

  it('evaluates decision trees with non-binary leaves', () => {
    // leaves at different depths returning class labels
    const decisionTree: DecisionTree = [0, [1, 10, [2, 20, 30]], 40];
    assertTree(decisionTree, 3);

    // encrypted input can be prepared for deeper trees than evaluated one
    assertTree(decisionTree, 3, 5);

    // constant tree
    assertTree(99, 1);
  });

  it('re-randomizes the output', () => {
    const tree: DecisionTree = [0, [1, 0, 1], 1];
    const encryptedInput = cs.encryptDecisionTreeInput([1, 0], 2);
    const output1 = cs.evaluateDecisionTree(tree, encryptedInput);
    const output2 = cs.evaluateDecisionTree(tree, encryptedInput);

    // output always wraps as many layers as the tree depth
    const [level1, value1] = output1.value as readonly bigint[];
    const [level2, value2] = output2.value as readonly bigint[];
    expect(level1).toBe(2n);
    expect(level2).toBe(2n);
    expect(value1).not.toBe(value2);
    expect(cs.decrypt(output1)).toBe(1n);
    expect(cs.decrypt(output2)).toBe(1n);
  });

  it('runs the credit limit example in the readme', () => {
    // bank's secret tree: Q0 = has stable income?, Q1 = has existing debt?,
    // Q2 = owns a house?, leaves are credit limits in thousand dollars
    const creditLimitTree: DecisionTree = [0, [2, 0, 5], [1, 20, [2, 5, 10]]];

    // customer builds the cryptosystem and keeps the private key
    const customerCs = new LightPHE({
      algorithmName: 'Ishai-Paskin',
      keySize: 50,
    });

    // customer shares only the public key with the bank
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-ts-'));
    const publicKeyFile = path.join(dir, 'public.txt');
    customerCs.exportKeys(publicKeyFile, true);

    // bank builds its own cryptosystem with the customer's public key
    const bankCs = new LightPHE({
      algorithmName: 'Ishai-Paskin',
      keyFile: publicKeyFile,
    });
    expect(bankCs.cs.keys.private_key).toBeUndefined();

    // every path of the tree drawn in the readme
    const expectedLimits: Array<[number[], bigint]> = [
      [[0, 0, 0], 0n],
      [[0, 1, 0], 0n],
      [[0, 0, 1], 5n],
      [[0, 1, 1], 5n],
      [[1, 0, 0], 20n],
      [[1, 0, 1], 20n],
      [[1, 1, 0], 5n],
      [[1, 1, 1], 10n],
    ];

    const encryptedLimits: Ciphertext[] = [];
    for (const [answers, expectedLimit] of expectedLimits) {
      // customer encrypts the answers and sends them to the bank
      const encryptedAnswers = customerCs.encryptDecisionTreeInput(answers, 3);

      // bank runs its tree on encrypted answers
      const encryptedLimit = bankCs.evaluateDecisionTree(
        creditLimitTree,
        encryptedAnswers
      );
      expect(encryptedLimit.keys.private_key).toBeUndefined();

      // customer decrypts the result
      expect(customerCs.decrypt(encryptedLimit)).toBe(expectedLimit);
      encryptedLimits.push(encryptedLimit);
    }
    const encryptedLimit = encryptedLimits[encryptedLimits.length - 1];

    // bank cannot decrypt the result
    expect(() => bankCs.decrypt(encryptedLimit)).toThrow('private key');

    // output can only be decrypted, homomorphic operations are not supported
    expect(() => encryptedLimit.add(encryptedLimit)).toThrow(
      'can only be decrypted'
    );
    expect(() => encryptedLimit.multiply(2)).toThrow('can only be decrypted');
    expect(() => customerCs.regenerateCiphertext(encryptedLimit)).toThrow(
      'can only be decrypted'
    );

    fs.rmSync(dir, { recursive: true, force: true });
    logger.info('✅ Ishai-Paskin credit limit example in readme succeeded');
  });

  it('rejects invalid inputs', () => {
    const encryptedInput = cs.encryptDecisionTreeInput([1, 0], 1);

    expect(() =>
      cs.evaluateDecisionTree([0, [1, 0, 1], 1], encryptedInput)
    ).toThrow('deeper than');
    expect(() => cs.evaluateDecisionTree([2, 0, 1], encryptedInput)).toThrow(
      'out of input range'
    );
    expect(() =>
      cs.evaluateDecisionTree([0, 1] as unknown as DecisionTree, encryptedInput)
    ).toThrow('integer leaf or an array');
    expect(() => cs.encryptDecisionTreeInput([2], 1)).toThrow('bits');
    expect(() => cs.encryptDecisionTreeInput([1], 0)).toThrow('depth');
  });

  it('works with 1024-bit keys', () => {
    const largeCs = new LightPHE({
      algorithmName: 'Ishai-Paskin',
      keySize: 1024,
    });
    const majority: DecisionTree = [0, [1, 0, [2, 0, 1]], [1, [2, 0, 1], 1]];
    for (const bits of [
      [1, 0, 1],
      [0, 1, 0],
    ]) {
      const encryptedInput = largeCs.encryptDecisionTreeInput(bits, 3);
      const output = largeCs.evaluateDecisionTree(majority, encryptedInput);
      expect(largeCs.decrypt(output)).toBe(evaluateInPlain(majority, bits));
    }
  });
});
