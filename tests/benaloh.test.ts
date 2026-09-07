import { LightPHE, Logger } from '../src';
import { bitLength } from './helpers';

const logger = new Logger('tests/benaloh.test.ts');

describe('Benaloh', () => {
  it('is additively homomorphic and supports scalar multiplication', () => {
    const cs = new LightPHE({ algorithmName: 'Benaloh', keySize: 50 });

    const n = cs.cs.keys.public_key!.n as bigint;
    const r = cs.cs.keys.public_key!.r as bigint;
    const securityLevel = bitLength(n);

    const m1 = 17;
    const m2 = 21;

    const c1 = cs.encrypt(m1);
    const c2 = cs.encrypt(m2);

    // homomorphic addition
    expect(cs.decrypt(c1.add(c2))).toBe(BigInt(m1 + m2));

    // homomorphic scalar multiplication
    expect(BigInt(m1 * m2)).toBeLessThan(r);
    expect(cs.decrypt(c1.multiply(m2))).toBe(BigInt(m1 * m2));
    expect(cs.decrypt(c2.multiply(m1))).toBe(BigInt(m1 * m2));
    expect(cs.decrypt(c1.multiplyByConstant(m2))).toBe(BigInt(m1 * m2));
    expect(cs.decrypt(c2.multiplyByConstant(m1))).toBe(BigInt(m1 * m2));

    // unsupported homomorphic operations
    expect(() => c1.multiply(c2)).toThrow();
    expect(() => c1.xor(c2)).toThrow();

    logger.info(
      `✅ Benaloh api test succeeded (${securityLevel}-bit security level)`
    );
  });
});
