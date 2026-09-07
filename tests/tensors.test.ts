import { EncryptedTensor, LightPHE, Logger, pheUtils } from '../src';
import { absDiff } from './helpers';

const logger = new Logger('tests/tensors.test.ts');

const THRESHOLD = 1;

const cryptosystems = new Map<string, LightPHE>();

function buildCryptosystem(algorithmName: string): LightPHE {
  let cs = cryptosystems.get(algorithmName);
  if (cs === undefined) {
    cs = new LightPHE({ algorithmName, keySize: 50 });
    logger.debug(`${algorithmName} is just built`);
    cryptosystems.set(algorithmName, cs);
  }
  return cs;
}

/**
 * A negative real has no signed representative in the message space, so it
 * comes back as its modular image. This reproduces that image in the clear so
 * the expectation can be written down.
 */
function convertNegativeFloatToInt(value: number, modulo: bigint): number {
  const limit = Number(modulo);
  const [x, y] = pheUtils.fractionize(
    ((value % limit) + limit) % limit,
    modulo,
    5
  );
  return Math.trunc(Number(x) / Number(y));
}

describe('encrypted tensors', () => {
  it('round-trips a tensor of reals', () => {
    const cs = buildCryptosystem('Paillier');

    const tensor = [
      1.005,
      2.05,
      3.005,
      4.005,
      -5.05,
      6,
      7.003005,
      -3.5 * 7.002,
    ];

    const encryptedTensors = cs.encrypt(tensor);
    const decryptedTensors = cs.decrypt(encryptedTensors);
    expect(Array.isArray(decryptedTensors)).toBe(true);

    decryptedTensors.forEach((decrypted, i) => {
      expect(absDiff(tensor[i], decrypted)).toBeLessThanOrEqual(THRESHOLD);
    });

    logger.info('✅ Tensor tests succeeded');
  });

  it('multiplies two encrypted tensors element-wise', () => {
    const cs = buildCryptosystem('RSA');

    const t1 = [1.005, 2.05, -3.5, 3.1, -4];
    const t2 = [5, 6.2, -7.002, -7.1, 8.02];

    const c1 = cs.encrypt(t1);
    const c2 = cs.encrypt(t2);

    expect(c1).toBeInstanceOf(EncryptedTensor);
    expect(c2).toBeInstanceOf(EncryptedTensor);

    const c3 = c1.multiply(c2);

    const restoredTensors = cs.decrypt(c3);
    expect(Array.isArray(restoredTensors)).toBe(true);

    restoredTensors.forEach((restored, i) => {
      expect(absDiff(t1[i] * t2[i], restored)).toBeLessThan(THRESHOLD);
    });

    expect(() => c1.add(c2)).toThrow();
    expect(() => c2.multiply(2)).toThrow();

    logger.info('✅ Homomorphic multiplication tests succeeded');
  });

  it('multiplies an encrypted tensor by a positive constant', () => {
    const cs = buildCryptosystem('Paillier');

    const t1 = [5, 6.2, 7.002, 7.002, 8.02];
    const constant = 2;
    const c1 = cs.encrypt(t1);

    const t2 = cs.decrypt(c1.multiply(constant));
    expect(Array.isArray(t2)).toBe(true);

    t2.forEach((restored, i) => {
      expect(absDiff(t1[i] * constant, restored)).toBeLessThan(THRESHOLD);
    });

    logger.info(
      '✅ Homomorphic multiplication by a positive constant tests succeeded'
    );
  });

  it('multiplies an encrypted tensor by a negative constant', () => {
    const cs = buildCryptosystem('Paillier');

    const t1 = [5, 6.2, 7.002, 7.002, 8.02];
    const constant = -2;
    const c1 = cs.encrypt(t1);
    expect(c1).toBeInstanceOf(EncryptedTensor);

    const t2 = cs.decrypt(c1.multiply(constant));
    expect(Array.isArray(t2)).toBe(true);

    t2.forEach((restored, i) => {
      expect(absDiff(t1[i] * constant, restored)).toBeLessThan(THRESHOLD);
    });

    logger.info(
      '✅ Homomorphic multiplication by a negative constant tests succeeded'
    );
  });

  it('multiplies an encrypted tensor by an integer constant', () => {
    const cs = buildCryptosystem('Paillier');

    const t1 = [5, 6.2, 7.002, 7.002, 8.02];
    const constant = 2;
    const c1 = cs.encrypt(t1);
    expect(c1).toBeInstanceOf(EncryptedTensor);

    const t2 = cs.decrypt(c1.multiply(constant));
    expect(Array.isArray(t2)).toBe(true);

    t2.forEach((restored, i) => {
      expect(absDiff(t1[i] * constant, restored)).toBeLessThan(THRESHOLD);
    });

    logger.info(
      '✅ Homomorphic multiplication with an integer constant tests succeeded'
    );
  });

  it('multiplies an encrypted tensor by a positive float constant', () => {
    const cs = buildCryptosystem('Paillier');

    const t1 = [10000.0, 15000, 20000];
    const constant = 1.05;
    const c1 = cs.encrypt(t1);

    const t2 = cs.decrypt(c1.multiply(constant));
    expect(Array.isArray(t2)).toBe(true);

    t2.forEach((restored, i) => {
      expect(absDiff(t1[i] * constant, restored)).toBeLessThan(THRESHOLD);
    });

    logger.info(
      '✅ Homomorphic multiplication with a positive float constant tests succeeded'
    );
  });

  it('multiplies an encrypted tensor by a negative float constant', () => {
    const cs = buildCryptosystem('Paillier');

    const t1 = [10000.0, 15000, 20000];
    const constant = -1.05;
    const c1 = cs.encrypt(t1);

    const t2 = cs.decrypt(c1.multiply(constant));
    expect(Array.isArray(t2)).toBe(true);

    t2.forEach((restored, i) => {
      expect(absDiff(t1[i] * constant, restored)).toBeLessThan(THRESHOLD);
    });

    logger.info(
      '✅ Homomorphic multiplication with a negative float constant tests succeeded'
    );
  });

  it('adds two encrypted tensors element-wise', () => {
    const cs = new LightPHE({ algorithmName: 'Paillier', keySize: 30 });

    const t1 = [1.005, 2.05, 3.6, -4, 4.02, -3.5];
    const t2 = [5, 6.2, -7.5, 8.02, -8.02, -4.5];

    const c1 = cs.encrypt(t1);
    const c2 = cs.encrypt(t2);
    expect(c1).toBeInstanceOf(EncryptedTensor);
    expect(c2).toBeInstanceOf(EncryptedTensor);

    const restoredTensors = cs.decrypt(c1.add(c2));
    expect(Array.isArray(restoredTensors)).toBe(true);

    restoredTensors.forEach((restored, i) => {
      const sum = t1[i] + t2[i];
      if ((t1[i] >= 0 && t2[i] >= 0) || (t1[i] < 0 && t2[i] < 0) || sum >= 0) {
        expect(absDiff(sum, restored)).toBeLessThan(THRESHOLD);
      } else {
        const expected = convertNegativeFloatToInt(sum, cs.cs.plaintextModulo);
        expect(absDiff(expected, restored)).toBeLessThan(THRESHOLD);
      }
    });

    expect(() => c1.multiply(c2)).toThrow();

    logger.info('✅ Homomorphic addition tests succeeded');
  });

  it.each(['Paillier', 'Damgard-Jurik'])(
    'multiplies and dots an encrypted tensor with a plain one (%s)',
    (algorithmName) => {
      const cs = buildCryptosystem(algorithmName);

      // suppose that these are normalized vectors
      const a = [7.11, 5.22, 5.33, 2.44, 3.55, 4.66];
      const b = [5.66, 3.77, 2.88, 4, 0, 5.99];

      const expectedSimilarity = a.reduce(
        (acc, value, i) => acc + value * b[i],
        0
      );

      const encA = cs.encrypt(a, { silent: true });
      expect(encA).toBeInstanceOf(EncryptedTensor);

      // every item is expected to carry the same divisor
      const fractions = encA.fractions;
      for (const fraction of fractions.slice(1)) {
        expect(fraction.divisor).toBe(fractions[0].divisor);
      }

      const aTimesB = cs.decrypt(encA.multiply(b));
      expect(Array.isArray(aTimesB)).toBe(true);

      for (let i = 0; i < a.length; i++) {
        expect(absDiff(a[i] * b[i], aTimesB[i])).toBeLessThan(0.1);
      }

      // dot product
      const decryptedSimilarities = cs.decrypt(encA.dot(b));
      expect(Array.isArray(decryptedSimilarities)).toBe(true);
      expect(decryptedSimilarities.length).toBeGreaterThan(0);

      expect(
        absDiff(decryptedSimilarities[0], expectedSimilarity)
      ).toBeLessThan(0.1);

      logger.info(`✅ Tensor tests succeeded for ${algorithmName}`);
    }
  );

  /**
   * A 4096-dimension embedding round trip: a real-world scale experiment rather
   * than a unit test, skipped for the same reason the Python suite skips it.
   */
  it.skip('handles a real world embedding', () => {
    const algorithmName = 'Paillier';
    logger.info('🧪 Real world embedding experiment is running');
    const cs = new LightPHE({ algorithmName, precision: 17 });

    const nDims = 4096;

    const sourceEmbedding = Array.from(
      { length: nDims },
      () => Math.random() + 1
    );
    // Zero out 90% of the entries, the way a VGG-Face embedding looks.
    for (let i = 0; i < Math.floor(nDims * 0.9); i++) {
      sourceEmbedding[Math.floor(Math.random() * nDims)] = 0.0;
    }

    const targetEmbedding = Array.from(
      { length: nDims },
      () => Math.random() + 1
    );

    const sourceEncrypted = cs.encrypt(sourceEmbedding);
    expect(sourceEncrypted).toBeInstanceOf(EncryptedTensor);

    const decryptedSimilarities = cs.decrypt(
      sourceEncrypted.dot(targetEmbedding)
    );
    const expectedSimilarity = sourceEmbedding.reduce(
      (acc, value, i) => acc + value * targetEmbedding[i],
      0
    );

    expect(absDiff(expectedSimilarity, decryptedSimilarities[0])).toBeLessThan(
      0.1
    );

    logger.info(`✅ Real world embedding test succeeded with ${algorithmName}`);
  });
});
