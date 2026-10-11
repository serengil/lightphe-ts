import { modInverse, modPow, mod, ONE, ZERO } from '../commons/mathUtils.js';
import { Algorithm } from '../models/Algorithm.js';
import type { CiphertextValue, DecisionTree } from '../models/types.js';
import { DamgardJurik } from './DamgardJurik.js';

export const DECISION_TREE_OUTPUT_NOT_SUPPORTED_MSG =
  'Output of a decision tree can only be decrypted.' +
  ' Homomorphic operations are not supported on it.';

/** A value of an evaluated node: `[level, value]`, level 0 is a plain leaf. */
type LeveledValue = [number, bigint];

/**
 * Ishai-Paskin evaluates a decision tree on encrypted data. Client encrypts its
 * input bits, server holding a private decision tree evaluates it on the
 * encrypted input and returns an encryption of the output. Ciphertext size
 * depends on the depth of the tree, not on its size. The paper calls these
 * branching programs. Decision trees are their most common form, and trees
 * sharing sub trees (DAGs) are supported as well.
 *
 * It is built on length flexible Damgard-Jurik: level s encrypts messages in
 * `Z_{n^s}` into ciphertexts in `Z_{n^(s+1)}`, so a level s ciphertext fits
 * into the plaintext space of level s+1. Each level of the tree wraps one more
 * encryption layer around the result. It is also homomorphic with respect to
 * addition as Damgard-Jurik.
 *
 * Ref: Ishai, Y., Paskin, A. (2007). Evaluating Branching Programs on Encrypted
 * Data. TCC 2007. https://doi.org/10.1007/978-3-540-70936-7_31
 */
export class IshaiPaskin extends DamgardJurik {
  override getAlgorithmName(): string {
    return Algorithm.IshaiPaskin;
  }

  /**
   * Encrypts a plaintext with Damgard-Jurik at the given level.
   *
   * @param plaintext - message to encrypt in `Z_{n^level}`.
   * @param level - encryption level s. The ciphertext will be in `Z_{n^(s+1)}`.
   * @param randomKey - one time random key coprime to n.
   */
  encryptAtLevel(plaintext: bigint, level: number, randomKey?: bigint): bigint {
    const n = this.keys.public_key!.n as bigint;
    const g = this.keys.public_key!.g as bigint;
    const r =
      randomKey !== undefined && randomKey !== ZERO
        ? randomKey
        : this.generateRandomKey();
    const modulo = n ** BigInt(level + 1);
    return (
      (modPow(g, plaintext, modulo) * modPow(r, n ** BigInt(level), modulo)) %
      modulo
    );
  }

  /**
   * Decrypts a ciphertext with Damgard-Jurik at the given level.
   *
   * @returns the message in `Z_{n^level}`.
   */
  decryptAtLevel(ciphertext: bigint, level: number): bigint {
    const phi = this.keys.private_key!.phi as bigint;
    const n = this.keys.public_key!.n as bigint;
    const plaintextModulo = n ** BigInt(level);

    // randomness vanishes because the order of Z*_{n^(s+1)} is phi * n^s.
    // what remains is (1 + n)^(m * phi)
    const a = modPow(ciphertext, phi, n ** BigInt(level + 1));
    const mPhi = this.dlog(a, level);
    return mod(mPhi * modInverse(phi, plaintextModulo), plaintextModulo);
  }

  /**
   * Finds i such that `a = (1 + n)^i mod n^(s+1)` with Damgard-Jurik's
   * recursive algorithm.
   */
  private dlog(a: bigint, level: number): bigint {
    const n = this.keys.public_key!.n as bigint;
    let i = ZERO;
    for (let j = 1; j <= level; j++) {
      const nj = n ** BigInt(j);
      let t1 = (mod(a, n ** BigInt(j + 1)) - ONE) / n;
      let t2 = i;
      let factorial = ONE;
      for (let k = 2; k <= j; k++) {
        i = i - ONE;
        t2 = mod(t2 * i, nj);
        factorial *= BigInt(k);
        t1 = mod(t1 - t2 * n ** BigInt(k - 1) * modInverse(factorial, nj), nj);
      }
      i = t1;
    }
    return i;
  }

  /**
   * Encrypts the input bits of a decision tree. Each bit is encrypted at every
   * level from 1 to depth because the server decides which level it needs.
   *
   * @param bits - input bits x_0, x_1, ... each 0 or 1.
   * @param depth - maximum depth of decision trees to evaluate.
   * @returns item `[i][s - 1]` is the encryption of x_i at level s.
   */
  override encryptDecisionTreeInput(
    bits: readonly number[],
    depth: number
  ): bigint[][] {
    if (!Number.isInteger(depth) || depth < 1) {
      throw new Error(`depth must be a positive integer but it is ${depth}`);
    }

    return bits.map((bit) => {
      if (bit !== 0 && bit !== 1) {
        throw new Error(`Input must consist of bits (0 or 1) but got ${bit}`);
      }
      const levels: bigint[] = [];
      for (let level = 1; level <= depth; level++) {
        levels.push(this.encryptAtLevel(BigInt(bit), level));
      }
      return levels;
    });
  }

  /**
   * Evaluates a decision tree on encrypted input. Private key is not required.
   *
   * @param tree - leaf (integer) or decision node `[variableIndex, treeIf0,
   *   treeIf1]`. e.g. `[0, [1, 0, 1], 1]` is x_0 OR x_1.
   * @param encryptedInput - output of `encryptDecisionTreeInput`.
   * @returns `[level, ciphertext]` where ciphertext wraps level layers of
   *   encryption around the output of the tree.
   */
  override evaluateDecisionTree(
    tree: DecisionTree,
    encryptedInput: readonly (readonly bigint[])[]
  ): CiphertextValue {
    const depth = encryptedInput.length > 0 ? encryptedInput[0].length : 0;
    const memo = new Map<object, LeveledValue>();
    let [level, ciphertext] = this.evaluateNode(
      tree,
      encryptedInput,
      depth,
      memo
    );

    if (level === 0) {
      // tree is a constant, still return an encrypted output
      ciphertext = this.encryptAtLevel(ciphertext, 1);
      level = 1;
    }

    return [BigInt(level), ciphertext];
  }

  /** Evaluates a node of a decision tree bottom up. */
  private evaluateNode(
    tree: DecisionTree,
    encryptedInput: readonly (readonly bigint[])[],
    depth: number,
    memo: Map<object, LeveledValue>
  ): LeveledValue {
    const n = this.keys.public_key!.n as bigint;

    if (typeof tree === 'bigint' || Number.isInteger(tree)) {
      return [0, mod(BigInt(tree as number | bigint), n)];
    }

    if (!Array.isArray(tree) || tree.length !== 3) {
      throw new Error(
        'Decision tree node must be an integer leaf or an array of ' +
          `[variableIndex, treeIf0, treeIf1] but got ${String(tree)}`
      );
    }

    const cached = memo.get(tree);
    if (cached !== undefined) {
      return cached;
    }

    const [variableIndex, treeIf0, treeIf1] = tree as readonly [
      number,
      DecisionTree,
      DecisionTree,
    ];
    if (
      !Number.isInteger(variableIndex) ||
      variableIndex < 0 ||
      variableIndex >= encryptedInput.length
    ) {
      throw new Error(
        `Variable index ${variableIndex} is out of input range ` +
          `[0, ${encryptedInput.length})`
      );
    }

    const [level0, evaluated0] = this.evaluateNode(
      treeIf0,
      encryptedInput,
      depth,
      memo
    );
    const [level1, evaluated1] = this.evaluateNode(
      treeIf1,
      encryptedInput,
      depth,
      memo
    );

    // bring both branches to the same level by wrapping fresh encryption layers
    let level = Math.max(level0, level1);
    const value0 = this.lift(evaluated0, level0, level);
    const value1 = this.lift(evaluated1, level1, level);

    // values at level l are in Z_{n^(l+1)}, which is plaintext space of level
    // l+1. E(x)^(v1 - v0) * E(v0) = E(v0 + x * (v1 - v0)) = E(v_x)
    level += 1;
    if (level > depth) {
      throw new Error(
        `Decision tree is deeper than ${depth} levels of encrypted input`
      );
    }

    const plaintextModulo = n ** BigInt(level);
    const ciphertextModulo = n ** BigInt(level + 1);

    const encryptedBit = encryptedInput[variableIndex][level - 1];
    const difference = mod(value1 - value0, plaintextModulo);
    const ciphertext =
      (modPow(encryptedBit, difference, ciphertextModulo) *
        this.encryptAtLevel(value0, level)) %
      ciphertextModulo;

    const result: LeveledValue = [level, ciphertext];
    memo.set(tree, result);
    return result;
  }

  /** Wraps encryption layers around a value with fresh randomness. */
  private lift(value: bigint, fromLevel: number, toLevel: number): bigint {
    let lifted = value;
    for (let level = fromLevel + 1; level <= toLevel; level++) {
      lifted = this.encryptAtLevel(lifted, level);
    }
    return lifted;
  }

  override add(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): CiphertextValue {
    if (typeof ciphertext1 !== 'bigint' || typeof ciphertext2 !== 'bigint') {
      throw new Error(DECISION_TREE_OUTPUT_NOT_SUPPORTED_MSG);
    }
    return super.add(ciphertext1, ciphertext2);
  }

  override multiplyByConstant(
    ciphertext: CiphertextValue,
    constant: bigint
  ): CiphertextValue {
    if (typeof ciphertext !== 'bigint') {
      throw new Error(DECISION_TREE_OUTPUT_NOT_SUPPORTED_MSG);
    }
    return super.multiplyByConstant(ciphertext, constant);
  }

  override reencrypt(ciphertext: CiphertextValue): CiphertextValue {
    if (typeof ciphertext !== 'bigint') {
      throw new Error(DECISION_TREE_OUTPUT_NOT_SUPPORTED_MSG);
    }
    return super.reencrypt(ciphertext);
  }

  /**
   * Decrypts a ciphertext created by `encrypt`, or the `[level, ciphertext]`
   * output of a decision tree evaluation.
   */
  override decrypt(ciphertext: CiphertextValue): bigint {
    if (typeof ciphertext === 'bigint') {
      return super.decrypt(ciphertext);
    }

    const [level, wrapped] = ciphertext as readonly bigint[];
    // peel encryption layers from outer to inner
    let value = wrapped;
    for (let current = Number(level); current > 0; current--) {
      value = this.decryptAtLevel(value, current);
    }
    return value;
  }
}
