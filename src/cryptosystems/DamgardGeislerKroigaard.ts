import { Logger } from '../commons/logger.js';
import {
  bitLength as bitLengthOf,
  isPrime,
  isqrt,
  mod,
  modInverse,
  modPow,
  pow2,
  randPrime,
  randomBelow,
  randomRange,
  ONE,
  TWO,
  ZERO,
} from '../commons/mathUtils.js';
import { Algorithm } from '../models/Algorithm.js';
import { Homomorphic } from '../models/Homomorphic.js';
import type {
  ArgmaxClient,
  ArgmaxMessage,
  CiphertextValue,
  DecisionTreeServerState,
  Keys,
  NumericDecisionTree,
  RandomKey,
  RequiredKeys,
} from '../models/types.js';

const logger = new Logger(
  'lightphe-ts/cryptosystems/DamgardGeislerKroigaard.ts'
);

/** A decision node: `[featureIndex, threshold, treeIfLessOrEqual, treeIfGreater]`. */
type NumericDecisionNode = readonly [
  number,
  number | bigint,
  NumericDecisionTree,
  NumericDecisionTree,
];

/**
 * Damgard-Geisler-Kroigaard (DGK) is homomorphic with respect to addition, and
 * supports multiplying a ciphertext by a known plain constant. Messages live in
 * `Z_u` for a deliberately small prime u (up to 32 bits), which keeps
 * ciphertexts short and decryption fast. So, it is a good fit for small values
 * such as counters, votes or bits of a secure comparison. Results that exceed
 * this space wrap around, so operations producing large values (e.g. encrypted
 * dot products on float tensors) are not suitable for it.
 *
 * It is a building block of secure comparison protocols, which underlie
 * privacy-preserving machine learning tasks such as private decision tree
 * evaluation and encrypted argmax. All of them are supported here in the
 * semi-honest model, between a client holding the private key and a server.
 *
 * Ref: Damgard, I., Geisler, M., Kroigaard, M. (2007). Efficient and Secure
 * Comparison for On-Line Auctions. ACISP 2007. Correction:
 * https://eprint.iacr.org/2008/321
 *
 * Ref: Tai, R. K. H., Ma, J. P. K., Zhao, Y., Chow, S. S. M. (2017).
 * Privacy-Preserving Decision Trees Evaluation via Linear Functions. ESORICS 2017.
 */
export class DamgardGeislerKroigaard extends Homomorphic {
  static readonly REQUIRED_KEYS: RequiredKeys = {
    public_key: ['n', 'g', 'h', 'u', 't'],
    private_key: ['p', 'v_p'],
  };

  // baby-step giant-step lookup table, built once on first decryption
  private babySteps?: Map<bigint, bigint>;

  constructor(options?: {
    keys?: Keys | null;
    keySize?: number | null;
    maxTries?: number;
  }) {
    super();
    this.keys =
      options?.keys ??
      this.generateKeys(options?.keySize ?? 1024, {
        maxTries: options?.maxTries ?? 10000,
      });
    this.plaintextModulo = this.keys.public_key!.u as bigint;
    this.ciphertextModulo = this.keys.public_key!.n as bigint;
  }

  get requiredKeys(): RequiredKeys {
    return DamgardGeislerKroigaard.REQUIRED_KEYS;
  }

  getAlgorithmName(): string {
    return Algorithm.DamgardGeislerKroigaard;
  }

  generateKeys(keySize: number, options?: { maxTries?: number }): Keys {
    const maxTries = options?.maxTries ?? 10000;
    const primeSize = Math.floor(keySize / 2);

    // u is the plaintext space. it is kept small because decryption requires
    // solving a discrete logarithm in a subgroup of order u.
    const uSize = Math.min(32, Math.max(4, Math.floor(keySize / 16)));

    // v_p and v_q are the orders of the randomizer subgroup. 160 bits in the
    // paper. at least 6 bits so that there are enough primes to pick distinct
    // u, v_p and v_q
    const t = Math.min(160, Math.max(6, Math.floor(keySize / 6)));

    // the rest of p and q is filled with a random part
    const rSize = primeSize - uSize - t - 1;
    if (rSize < 2) {
      throw new Error(
        `Key size ${keySize} is too small for Damgard-Geisler-Kroigaard`
      );
    }

    const u = randPrime(pow2(uSize - 1), pow2(uSize));

    let vP = randPrime(pow2(t - 1), pow2(t));
    while (vP === u) {
      vP = randPrime(pow2(t - 1), pow2(t));
    }

    let vQ = randPrime(pow2(t - 1), pow2(t));
    while (vQ === u || vQ === vP) {
      vQ = randPrime(pow2(t - 1), pow2(t));
    }

    // picking primes p and q such that u * v_p divides p - 1 and u * v_q
    // divides q - 1
    const p = findPrime(u, vP, rSize, maxTries);
    let q = findPrime(u, vQ, rSize, maxTries);
    while (q === p) {
      q = findPrime(u, vQ, rSize, maxTries);
    }

    const n = p * q;

    // g has order u * v_p * v_q, and h has order v_p * v_q in Z_n*.
    // they are built in Z_p* and Z_q* separately, and then combined with CRT
    const gP = findElementOfOrder(p, [u, vP], maxTries);
    const gQ = findElementOfOrder(q, [u, vQ], maxTries);
    const hP = findElementOfOrder(p, [vP], maxTries);
    const hQ = findElementOfOrder(q, [vQ], maxTries);

    const g = crt(gP, gQ, p, q);
    const h = crt(hP, hQ, p, q);

    return {
      public_key: { n, g, h, u, t: BigInt(t) },
      private_key: { p, q, v_p: vP, v_q: vQ },
    };
  }

  /**
   * Damgard-Geisler-Kroigaard draws a fresh random key per encryption. In the
   * paper, it is a 2.5t bit random integer.
   */
  generateRandomKey(): bigint {
    const t = Number(this.keys.public_key!.t as bigint);
    return randomRange(ONE, pow2(Math.floor(2.5 * t)));
  }

  encrypt(plaintext: bigint, randomKey?: RandomKey): bigint {
    const n = this.keys.public_key!.n as bigint;
    const g = this.keys.public_key!.g as bigint;
    const h = this.keys.public_key!.h as bigint;
    const r =
      typeof randomKey === 'bigint' && randomKey !== ZERO
        ? randomKey
        : this.generateRandomKey();

    let m = plaintext;
    if (m >= this.plaintextModulo) {
      m = m % this.plaintextModulo;
      logger.debug(
        `Damgard-Geisler-Kroigaard can encrypt messages [0, ${this.plaintextModulo}). ` +
          `Seems plaintext exceeded this limit. New plaintext is ${m}`
      );
    }

    return (modPow(g, m, n) * modPow(h, r, n)) % n;
  }

  decrypt(ciphertext: CiphertextValue): bigint {
    const p = this.keys.private_key!.p as bigint;
    const vP = this.keys.private_key!.v_p as bigint;
    const g = this.keys.public_key!.g as bigint;
    const u = this.keys.public_key!.u as bigint;

    // c^v_p = (g^v_p)^m mod p because h^v_p = 1 mod p. g^v_p has order u in
    // Z_p* so m is the discrete logarithm of c^v_p in a small subgroup of
    // order u.
    let z = modPow(ciphertext as bigint, vP, p);
    const base = modPow(g, vP, p);

    // baby-step giant-step
    const step = isqrt(u) + ONE;
    if (this.babySteps === undefined) {
      this.babySteps = new Map();
      let value = ONE;
      for (let j = ZERO; j < step; j++) {
        if (!this.babySteps.has(value)) {
          this.babySteps.set(value, j);
        }
        value = (value * base) % p;
      }
    }

    const giant = modPow(base, -step, p);
    for (let i = ZERO; i < step; i++) {
      const j = this.babySteps.get(z);
      if (j !== undefined) {
        return (i * step + j) % u;
      }
      z = (z * giant) % p;
    }

    throw new Error('Damgard-Geisler-Kroigaard ciphertext cannot be decrypted');
  }

  /** Homomorphic addition: the result decrypts to `m1 + m2`. */
  override add(
    ciphertext1: CiphertextValue,
    ciphertext2: CiphertextValue
  ): bigint {
    const n = this.keys.public_key!.n as bigint;
    return ((ciphertext1 as bigint) * (ciphertext2 as bigint)) % n;
  }

  /** Multiplies a ciphertext by a known plain constant. */
  override multiplyByConstant(
    ciphertext: CiphertextValue,
    constant: bigint
  ): bigint {
    const n = this.keys.public_key!.n as bigint;
    let k = constant;
    if (k >= this.plaintextModulo) {
      k = k % this.plaintextModulo;
      logger.debug(
        `Damgard-Geisler-Kroigaard can encrypt messages [0, ${this.plaintextModulo}). ` +
          `Seems constant exceeded this limit. New constant is ${k}`
      );
    }
    return modPow(ciphertext as bigint, k, n);
  }

  override reencrypt(ciphertext: CiphertextValue): bigint {
    return this.add(ciphertext, this.encrypt(ZERO));
  }

  /**
   * Checks whether a ciphertext encrypts 0 without solving the discrete
   * logarithm. `c^v_p = (g^v_p)^m mod p` and `g^v_p` has order u, so it is 1
   * if and only if m = 0.
   */
  isZero(ciphertext: bigint): boolean {
    const p = this.keys.private_key!.p as bigint;
    const vP = this.keys.private_key!.v_p as bigint;
    return modPow(ciphertext, vP, p) === ONE;
  }

  /**
   * Encrypts bits of a value to be compared with a value of the server. This
   * is the 1st step of secure comparison and runs on client side.
   *
   * @param value - client's value in `[0, 2^bitLength)`.
   * @param bitLength - number of bits of compared values.
   * @returns encrypted bits, least significant bit first.
   */
  override encryptComparisonInput(
    value: bigint | number,
    bitLength: number
  ): bigint[] {
    const x = this.validateComparisonInput(value, bitLength);
    const bits: bigint[] = [];
    for (let i = 0; i < bitLength; i++) {
      bits.push(this.encrypt((x >> BigInt(i)) & ONE));
    }
    return bits;
  }

  /**
   * Compares client's encrypted value x with server's value y. This is the 2nd
   * step of secure comparison and runs on server side. Private key is not
   * required, and server learns nothing about x.
   */
  override evaluateComparison(
    encryptedInput: readonly bigint[],
    value: bigint | number
  ): bigint[] {
    return this.blindComparison(encryptedInput, value, 0);
  }

  /**
   * Restores the result of secure comparison. This is the 3rd step of secure
   * comparison and runs on client side. Client learns only whether x <= y, but
   * not y.
   */
  override decryptComparison(encryptedResult: readonly bigint[]): boolean {
    return encryptedResult.some((c) => this.isZero(c));
  }

  /**
   * Encrypts features of a client to be evaluated in server's decision tree.
   * This is the 1st step of private decision tree evaluation and runs on
   * client side.
   */
  override encryptDecisionTreeFeatures(
    features: readonly (bigint | number)[],
    bitLength: number
  ): bigint[][] {
    return features.map((feature) =>
      this.encryptComparisonInput(feature, bitLength)
    );
  }

  /**
   * Compares encrypted features with thresholds of all decision nodes. This is
   * the 2nd step of private decision tree evaluation and runs on server side.
   * Each comparison is randomly flipped, so client cannot learn the path.
   *
   * @returns encrypted comparisons to be sent to the client, and the server
   *   state that must be kept secret on server side for the last step.
   */
  override evaluateDecisionTreeComparisons(
    tree: NumericDecisionTree,
    encryptedFeatures: readonly (readonly bigint[])[]
  ): [bigint[][], DecisionTreeServerState] {
    const nodes = collectNodes(tree);
    const flips = nodes.map(() => Number(randomBelow(TWO)));

    const encryptedComparisons = nodes.map(([featureIndex, threshold], i) => {
      if (
        !Number.isInteger(featureIndex) ||
        featureIndex < 0 ||
        featureIndex >= encryptedFeatures.length
      ) {
        throw new Error(`Feature index ${featureIndex} does not exist`);
      }
      return this.blindComparison(
        encryptedFeatures[featureIndex],
        threshold,
        flips[i]
      );
    });

    return [encryptedComparisons, { tree, flips }];
  }

  /**
   * Answers the flipped comparisons of the server in encrypted form. This is
   * the 3rd step of private decision tree evaluation and runs on client side.
   */
  override answerDecisionTreeComparisons(
    encryptedComparisons: readonly (readonly bigint[])[]
  ): bigint[] {
    return encryptedComparisons.map((comparison) =>
      this.encrypt(this.decryptComparison(comparison) ? ONE : ZERO)
    );
  }

  /**
   * Finds the reached leaf in encrypted form. Path cost of a leaf is the number
   * of wrong decisions on its path, so only the reached leaf has cost 0. This
   * is the 4th step of private decision tree evaluation and runs on server
   * side.
   */
  override evaluateDecisionTreeLeaves(
    serverState: DecisionTreeServerState,
    encryptedAnswers: readonly bigint[]
  ): [bigint, bigint][] {
    const u = this.plaintextModulo;
    const { tree, flips } = serverState;

    // path cost is at most the depth of the tree, so it must not wrap around u
    if (BigInt(flips.length) >= u) {
      throw new Error(`Decision tree must have less than ${u} decision nodes`);
    }

    if (encryptedAnswers.length !== flips.length) {
      throw new Error(
        `Expected ${flips.length} answers but got ${encryptedAnswers.length}`
      );
    }

    // remove the random flip, so b = 1 if feature <= threshold
    const encryptedDecisions = encryptedAnswers.map((answer, i) =>
      flips[i] === 0 ? answer : this.negateBit(answer)
    );

    // path cost of each leaf. going left is wrong if b = 0, going right is
    // wrong if b = 1
    const leaves: Array<[bigint, bigint]> = [];
    let nodeIndex = 0;

    const traverse = (subtree: NumericDecisionTree, cost: bigint): void => {
      if (typeof subtree === 'number' || typeof subtree === 'bigint') {
        const label = BigInt(subtree);
        if (label < ZERO || label >= u) {
          throw new Error(
            `Leaf labels must be in [0, ${u}) but got ${String(subtree)}`
          );
        }
        leaves.push([cost, label]);
        return;
      }
      const b = encryptedDecisions[nodeIndex];
      nodeIndex += 1;
      const node = subtree as NumericDecisionNode;
      traverse(node[2], this.add(cost, this.negateBit(b)));
      traverse(node[3], this.add(cost, b));
    };

    traverse(tree, this.encrypt(ZERO));

    // for each leaf, client receives (r1 * cost, r2 * cost + label). only the
    // reached leaf has cost 0, others look random to the client.
    const encryptedLeaves = leaves.map(([cost, label]): [bigint, bigint] => {
      const r1 = randomRange(ONE, u - ONE);
      const r2 = randomRange(ONE, u - ONE);
      const maskedCost = this.reencrypt(this.multiplyByConstant(cost, r1));
      const maskedLabel = this.add(
        this.multiplyByConstant(cost, r2),
        this.encrypt(label)
      );
      return [maskedCost, maskedLabel];
    });

    shuffle(encryptedLeaves);
    return encryptedLeaves;
  }

  /**
   * Restores the label of the reached leaf. This is the last step of private
   * decision tree evaluation and runs on client side.
   */
  override decryptDecisionTreeOutput(
    encryptedLeaves: readonly (readonly [bigint, bigint])[]
  ): bigint {
    for (const [maskedCost, maskedLabel] of encryptedLeaves) {
      if (this.isZero(maskedCost)) {
        return this.decrypt(maskedLabel);
      }
    }
    throw new Error('None of the leaves is reached');
  }

  /**
   * Finds the index of the maximum of encrypted values without decrypting
   * them. Runs on server side and interacts with the client (private key
   * owner) through the client callable. Client learns neither the values nor
   * the comparison results, and server learns nothing. Index of the first
   * maximum is returned on ties.
   *
   * @param encryptedValues - ciphertexts of values in `[0, 2^bitLength)`.
   * @param bitLength - number of bits of the values.
   * @param client - sends a message to the client and returns its response,
   *   e.g. `answerArgmax` of the client's cryptosystem or a network call.
   * @returns ciphertext of the argmax index, to be sent to the client.
   */
  override async evaluateArgmax(
    encryptedValues: readonly bigint[],
    bitLength: number,
    client: ArgmaxClient
  ): Promise<bigint> {
    const u = this.plaintextModulo;

    if (encryptedValues.length === 0) {
      throw new Error('Argmax requires at least one value');
    }

    // z = b - a + 2^bitLength must be in the plaintext space without wrapping
    if (pow2(bitLength + 1) >= u) {
      throw new Error(
        `Plaintext space ${u} is too small for argmax of ${bitLength}-bit values. ` +
          'Use a larger key size or a smaller bit length.'
      );
    }

    // client's masked values are compared bit by bit, so u's bit length must fit
    this.validateComparisonInput(u - ONE, bitLengthOf(u));

    let maxValue = encryptedValues[0];
    let maxIndex = this.encrypt(ZERO);
    for (let index = 1; index < encryptedValues.length; index++) {
      const candidate = encryptedValues[index];
      const isGreater = await this.greaterThan(
        candidate,
        maxValue,
        bitLength,
        client
      );

      // maxValue += isGreater * (candidate - maxValue)
      // maxIndex += isGreater * (index - maxIndex)
      const valueDiff = this.add(candidate, this.negate(maxValue));
      const indexDiff = this.add(
        this.encrypt(BigInt(index)),
        this.negate(maxIndex)
      );
      const [valueUpdate, indexUpdate] = await this.multiplyWithClient(
        isGreater,
        [valueDiff, indexDiff],
        client
      );
      maxValue = this.add(maxValue, valueUpdate);
      maxIndex = this.add(maxIndex, indexUpdate);
    }

    return this.reencrypt(maxIndex);
  }

  /**
   * Answers a message of the server during encrypted argmax. Runs on client
   * side. Every value the client decrypts here is masked with a uniformly
   * random value, so client learns nothing.
   */
  override answerArgmax(message: ArgmaxMessage): bigint[] {
    const u = this.plaintextModulo;
    const { type, payload } = message;

    if (type === 'masked_difference') {
      const masked = this.decrypt(payload[0] as bigint);
      return this.encryptComparisonInput(masked, bitLengthOf(u));
    }

    if (type === 'comparisons') {
      const bits = (payload as readonly (readonly bigint[])[]).map(
        (comparison) => (this.decryptComparison(comparison) ? ONE : ZERO)
      );
      return [
        this.encrypt(bits[0]),
        this.encrypt(bits[1]),
        this.encrypt(bits[0] * bits[1]),
      ];
    }

    if (type === 'products') {
      const maskedBit = this.decrypt(payload[0] as bigint);
      return (payload.slice(1) as bigint[]).map((factor) =>
        this.encrypt((maskedBit * this.decrypt(factor)) % u)
      );
    }

    throw new Error(`Unknown argmax message type ${String(type)}`);
  }

  /**
   * Computes `E(a > b)` for encrypted a and b in `[0, 2^bitLength)` with the
   * client's help.
   */
  private async greaterThan(
    encryptedA: bigint,
    encryptedB: bigint,
    bitLength: number,
    client: ArgmaxClient
  ): Promise<bigint> {
    const u = this.plaintextModulo;
    const offset = pow2(bitLength);

    // z = a - b + 2^bitLength is in [1, 2^(bitLength + 1)), and a > b iff
    // z > 2^bitLength. client receives d = z + r mod u for a uniformly random
    // r, which reveals nothing.
    const r = randomBelow(u);
    const maskedDifference = this.add(
      this.add(encryptedA, this.negate(encryptedB)),
      this.encrypt((offset + r) % u)
    );
    const encryptedDBits = await client({
      type: 'masked_difference',
      payload: [this.reencrypt(maskedDifference)],
    });

    // a > b iff d is in the arc [start, end] of Z_u. if the arc does not wrap
    // around u, it is (d >= start) and (d <= end). otherwise, it is
    // (d >= start) or (d <= end).
    const start = (r + offset + ONE) % u;
    const end = (r + TWO * offset - ONE) % u;
    const wraps = start > end;

    // each comparison gives client a bit x_i, while server keeps a bit k_i
    // such that c_i = x_i xor k_i. random flips make x_i uniformly random for
    // the client. d >= start is the negation of d <= start - 1, and always
    // true if start = 0.
    const flips = [Number(randomBelow(TWO)), Number(randomBelow(TWO))];
    const [firstThreshold, firstNegated] =
      start === ZERO ? [u - ONE, 0] : [start - ONE, 1];

    const comparisons = [
      this.blindComparison(encryptedDBits, firstThreshold, flips[0]),
      this.blindComparison(encryptedDBits, end, flips[1]),
    ];
    const [x1, x2, x1x2] = await client({
      type: 'comparisons',
      payload: comparisons,
    });

    const k1 = BigInt(flips[0] ^ firstNegated);
    const k2 = BigInt(flips[1]);

    // c_i = k_i + (1 - 2 k_i) x_i is linear in x_i, and so is c_1 * c_2 in
    // x_1, x_2, x_1 x_2
    const c1 = this.linear([[x1, ONE - TWO * k1]], k1);
    const c2 = this.linear([[x2, ONE - TWO * k2]], k2);
    const c1c2 = this.linear(
      [
        [x1, k2 * (ONE - TWO * k1)],
        [x2, k1 * (ONE - TWO * k2)],
        [x1x2, (ONE - TWO * k1) * (ONE - TWO * k2)],
      ],
      k1 * k2
    );

    if (wraps) {
      // c1 or c2 = c1 + c2 - c1 * c2
      return this.add(this.add(c1, c2), this.negate(c1c2));
    }
    return c1c2;
  }

  /**
   * Computes `E(b * f)` for an encrypted b and each encrypted f with the
   * client's help. Client multiplies `B = b + rho` and `F = f + sigma`, both
   * uniformly random, and server restores
   * `b * f = B * F - sigma * b - rho * f - rho * sigma`.
   */
  private async multiplyWithClient(
    encryptedBit: bigint,
    encryptedFactors: readonly bigint[],
    client: ArgmaxClient
  ): Promise<bigint[]> {
    const u = this.plaintextModulo;
    const rho = randomBelow(u);
    const sigmas = encryptedFactors.map(() => randomBelow(u));

    const maskedBit = this.add(encryptedBit, this.encrypt(rho));
    const maskedFactors = encryptedFactors.map((factor, i) =>
      this.add(factor, this.encrypt(sigmas[i]))
    );
    const maskedProducts = await client({
      type: 'products',
      payload: [maskedBit, ...maskedFactors],
    });

    return encryptedFactors.map((factor, i) =>
      this.linear(
        [
          [maskedProducts[i], ONE],
          [encryptedBit, -sigmas[i]],
          [factor, -rho],
        ],
        -rho * sigmas[i]
      )
    );
  }

  /**
   * Computes `E(sum(coefficient * m) + constant)` for `[E(m), coefficient]`
   * terms.
   */
  private linear(
    terms: ReadonlyArray<readonly [bigint, bigint]>,
    constant: bigint
  ): bigint {
    const u = this.plaintextModulo;
    let result = this.encrypt(mod(constant, u));
    for (const [ciphertext, rawCoefficient] of terms) {
      const coefficient = mod(rawCoefficient, u);
      if (coefficient !== ZERO) {
        result = this.add(
          result,
          this.multiplyByConstant(ciphertext, coefficient)
        );
      }
    }
    return result;
  }

  /** Computes `E(-m)` from `E(m)`. */
  private negate(ciphertext: bigint): bigint {
    return this.multiplyByConstant(ciphertext, this.plaintextModulo - ONE);
  }

  /** Computes `E(1 - b)` from `E(b)` for a bit b. */
  private negateBit(ciphertext: bigint): bigint {
    const u = this.plaintextModulo;
    return this.add(
      this.encrypt(ONE),
      this.multiplyByConstant(ciphertext, u - ONE)
    );
  }

  /**
   * Checks that a compared value fits into bitLength bits, and the comparison
   * fits into the plaintext space.
   */
  private validateComparisonInput(
    value: bigint | number,
    bitLength: number
  ): bigint {
    if (
      !(typeof value === 'bigint' || Number.isInteger(value)) ||
      BigInt(value) < ZERO ||
      BigInt(value) >= pow2(bitLength)
    ) {
      throw new Error(
        `Compared values must be integers in [0, 2^${bitLength}) but got ${String(value)}`
      );
    }

    // values are extended by one bit to break ties. intermediate values of the
    // comparison are in [-2, 3 * (bitLength + 1) - 1] and must not wrap around u.
    if (BigInt(3 * (bitLength + 1) - 1) >= this.plaintextModulo) {
      throw new Error(
        `Plaintext space ${this.plaintextModulo} is too small to compare ` +
          `${bitLength}-bit values. Use a larger key size or a smaller bit length.`
      );
    }
    return BigInt(value);
  }

  /**
   * DGK comparison of client's encrypted x and server's plain y. Client finds
   * a zero among the returned ciphertexts if and only if x <= y (flip = 0) or
   * x > y (flip = 1).
   *
   * @param encryptedBits - encrypted bits of x, least significant bit first.
   * @param value - y.
   * @param flip - 0 or 1. server keeps it secret to hide the result from the
   *   client.
   * @returns blinded ciphertexts, shuffled and re-randomized.
   */
  private blindComparison(
    encryptedBits: readonly bigint[],
    value: bigint | number,
    flip: number
  ): bigint[] {
    const u = this.plaintextModulo;
    const length = encryptedBits.length;
    const yValue = this.validateComparisonInput(value, length);

    // compare 2x with 2y + 1 instead, so that x <= y if and only if
    // 2x < 2y + 1. this way, x and y are never equal and flipping the
    // direction is consistent.
    const xBits = [this.encrypt(ZERO), ...encryptedBits];
    const y = TWO * yValue + ONE;
    const yBits: bigint[] = [];
    for (let i = 0; i <= length; i++) {
      yBits.push((y >> BigInt(i)) & ONE);
    }

    // s = 1 looks for x < y, s = -1 looks for x > y
    const s = flip === 0 ? ONE : u - ONE;

    // c_i = s + x_i - y_i + 3 * sum_{j > i} (x_j xor y_j)
    // c_i = 0 only at the most significant differing bit, and only if
    // x_i - y_i = -s
    const blinded: bigint[] = [];
    let xorSum = this.encrypt(ZERO);
    for (let i = length; i >= 0; i--) {
      let c = this.add(this.encrypt(mod(s - yBits[i], u)), xBits[i]);
      c = this.add(c, this.multiplyByConstant(xorSum, 3n));

      const r = randomRange(ONE, u - ONE);
      blinded.push(this.reencrypt(this.multiplyByConstant(c, r)));

      const xXorY = yBits[i] === ZERO ? xBits[i] : this.negateBit(xBits[i]);
      xorSum = this.add(xorSum, xXorY);
    }

    shuffle(blinded);
    return blinded;
  }
}

/** Shuffles an array in place with a cryptographically secure random source. */
function shuffle<T>(items: T[]): void {
  for (let i = items.length - 1; i > 0; i--) {
    const j = Number(randomBelow(BigInt(i + 1)));
    [items[i], items[j]] = [items[j], items[i]];
  }
}

/** Collects `[featureIndex, threshold]` of decision nodes in pre-order. */
function collectNodes(
  tree: NumericDecisionTree
): Array<[number, bigint | number]> {
  if (typeof tree === 'number' || typeof tree === 'bigint') {
    return [];
  }
  if (!Array.isArray(tree) || tree.length !== 4) {
    throw new Error(
      'Decision node must be (feature_index, threshold, tree_if_less_or_equal,' +
        ` tree_if_greater) but got ${String(tree)}`
    );
  }
  const [featureIndex, threshold, left, right] = tree as NumericDecisionNode;
  return [
    [featureIndex, threshold],
    ...collectNodes(left),
    ...collectNodes(right),
  ];
}

/** Finds a prime p in the form of `2 * u * v * r + 1`. */
function findPrime(
  u: bigint,
  v: bigint,
  rSize: number,
  maxTries: number
): bigint {
  for (let i = 0; i < maxTries; i++) {
    const r = randomRange(pow2(rSize - 1), pow2(rSize) - ONE);
    const p = TWO * u * v * r + ONE;
    if (isPrime(p)) {
      return p;
    }
  }
  throw new Error(
    `Failed to find prime p = 1 mod 2*${u}*${v} in ${maxTries} tries`
  );
}

/**
 * Finds an element of `Z_p*` whose order is exactly the product of the given
 * distinct primes, each dividing `p - 1`.
 */
function findElementOfOrder(
  p: bigint,
  factors: readonly bigint[],
  maxTries: number
): bigint {
  const order = factors.reduce((acc, f) => acc * f, ONE);
  for (let i = 0; i < maxTries; i++) {
    const x = randomRange(TWO, p - TWO);
    const y = modPow(x, (p - ONE) / order, p);
    // order of y divides prod(factors). it is exactly that if removing any
    // prime factor does not send y to 1
    if (factors.every((f) => modPow(y, order / f, p) !== ONE)) {
      return y;
    }
  }
  throw new Error(
    `Failed to find an element of order ${order} in ${maxTries} tries`
  );
}

/** Finds x such that `x = aP mod p` and `x = aQ mod q`. */
function crt(aP: bigint, aQ: bigint, p: bigint, q: bigint): bigint {
  return mod(aP + p * mod((aQ - aP) * modInverse(p, q), q), p * q);
}
