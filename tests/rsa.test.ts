import { LightPHE, Logger } from '../src';

const logger = new Logger('tests/rsa.test.ts');

describe('RSA', () => {
  it('is multiplicatively homomorphic and rejects everything else', () => {
    const cs = new LightPHE({ algorithmName: 'RSA', keySize: 50 });

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

    logger.info('✅ RSA api test succeeded');
  });

  it('multiplies a ciphertext by an encrypted float', () => {
    const cs = new LightPHE({ algorithmName: 'RSA' });

    const m1 = 10000;
    const m2 = 1.05;

    const c1 = cs.encrypt(m1);
    const c2 = cs.encrypt(m2);

    expect(cs.decrypt(c1.multiply(c2))).toBe(BigInt(m1 * m2));

    logger.info('✅ RSA float multiplication test succeeded');
  });
});
