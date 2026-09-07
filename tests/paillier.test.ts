import { LightPHE, Logger, mathUtils } from '../src';
import { valuesEqual } from './helpers';

const logger = new Logger('tests/paillier.test.ts');

const cs = new LightPHE({ algorithmName: 'Paillier', keySize: 50 });

describe('Paillier', () => {
  it('is additively homomorphic and supports scalar multiplication', () => {
    const m1 = 17;
    const m2 = 21;

    const c1 = cs.encrypt(m1);
    const c2 = cs.encrypt(m2);

    // homomorphic addition
    expect(cs.decrypt(c1.add(c2))).toBe(BigInt(m1 + m2));

    // homomorphic scalar multiplication
    expect(cs.decrypt(c1.multiply(m2))).toBe(BigInt(m1 * m2));
    expect(cs.decrypt(c2.multiply(m1))).toBe(BigInt(m1 * m2));
    expect(cs.decrypt(c1.multiplyByConstant(m2))).toBe(BigInt(m1 * m2));
    expect(cs.decrypt(c2.multiplyByConstant(m1))).toBe(BigInt(m1 * m2));

    const c1Prime = cs.regenerateCiphertext(c1);
    expect(valuesEqual(c1Prime.value, c1.value)).toBe(false);
    expect(cs.decrypt(c1Prime)).toBe(cs.decrypt(c1));

    // unsupported homomorphic operations
    expect(() => c1.multiply(c2)).toThrow();
    expect(() => c1.xor(c2)).toThrow();

    logger.info('✅ Paillier api test succeeded');
  });

  it('handles integer, float and negative scalars', () => {
    const m1 = 1000;
    const m2 = -10;

    const c1 = cs.encrypt(m1);
    const c2 = cs.encrypt(m2);

    expect(cs.decrypt(c1.add(c2))).toBe(BigInt(m1 + m2));
    expect(cs.decrypt(c2.add(c1))).toBe(BigInt(m1 + m2));

    const k1 = 20;
    expect(cs.decrypt(c1.multiply(k1))).toBe(BigInt(m1 * k1));
    expect(cs.decrypt(c1.multiplyByConstant(k1))).toBe(BigInt(m1 * k1));

    const k2 = 1.05;
    expect(cs.decrypt(c1.multiply(k2))).toBe(BigInt(m1 * k2));
    expect(cs.decrypt(c1.multiplyByConstant(k2))).toBe(BigInt(m1 * k2));

    const k3 = -20;
    const expected = mathUtils.mod(BigInt(m1 * k3), cs.cs.plaintextModulo);
    expect(cs.decrypt(c1.multiply(k3))).toBe(expected);
    expect(cs.decrypt(c1.multiplyByConstant(k3))).toBe(expected);
  });
});
