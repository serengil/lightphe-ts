import { LightPHE, Logger } from '../src';

const logger = new Logger('tests/elgamal.test.ts');

describe('ElGamal', () => {
  it('is multiplicatively homomorphic in its regular form', () => {
    const cs = new LightPHE({ algorithmName: 'ElGamal', keySize: 50 });

    const m1 = 17;
    const m2 = 21;

    const c1 = cs.encrypt(m1);
    const c2 = cs.encrypt(m2);

    // homomorphic multiplication
    expect(cs.decrypt(c1.multiply(c2))).toBe(BigInt(m1 * m2));

    // unsupported homomorphic operations
    expect(() => c1.add(c2)).toThrow();
    expect(() => c1.xor(c2)).toThrow();
    expect(() => c1.multiply(5)).toThrow();
    expect(() => c1.multiplyByConstant(5)).toThrow();

    logger.info('✅ ElGamal api test succeeded');
  });

  it('is additively homomorphic in its exponential form', () => {
    const cs = new LightPHE({
      algorithmName: 'Exponential-ElGamal',
      keySize: 50,
    });

    const m1 = 17;
    const m2 = 21;

    const c1 = cs.encrypt(m1);
    const c2 = cs.encrypt(m2);

    // homomorphic addition
    expect(cs.decrypt(c1.add(c2))).toBe(BigInt(m1 + m2));

    // scalar multiplication
    expect(cs.decrypt(c1.multiply(m2))).toBe(BigInt(m1 * m2));
    expect(cs.decrypt(c2.multiply(m1))).toBe(BigInt(m1 * m2));
    expect(cs.decrypt(c1.multiplyByConstant(m2))).toBe(BigInt(m1 * m2));
    expect(cs.decrypt(c2.multiplyByConstant(m1))).toBe(BigInt(m1 * m2));

    // unsupported homomorphic operations
    expect(() => c1.multiply(c2)).toThrow();
    expect(() => c1.xor(c2)).toThrow();

    logger.info('✅ Exponential ElGamal api test succeeded');
  });
});
