import { LightPHE, Logger, mathUtils } from '../src';
import { valuesEqual } from './helpers';

const logger = new Logger('tests/castagnoslaguillaumie.test.ts');

const cs = new LightPHE({
  algorithmName: 'Castagnos-Laguillaumie',
  keySize: 50,
});

describe('Castagnos-Laguillaumie', () => {
  it('is additively homomorphic and supports scalar multiplication', () => {
    const modulo = cs.cs.plaintextModulo;

    const m1 = 17;
    const m2 = 21;

    const c1 = cs.encrypt(m1);
    const c2 = cs.encrypt(m2);

    // proof of decryption
    expect(cs.decrypt(c1)).toBe(BigInt(m1));
    expect(cs.decrypt(c2)).toBe(BigInt(m2));

    // homomorphic addition
    expect(cs.decrypt(c1.add(c2))).toBe(BigInt(m1 + m2));

    // homomorphic scalar multiplication
    expect(cs.decrypt(c1.multiply(m2))).toBe(BigInt(m1 * m2));
    expect(cs.decrypt(c1.multiplyByConstant(m2))).toBe(BigInt(m1 * m2));

    // negative plaintexts and addition wrapping around the plaintext modulo
    const c3 = cs.encrypt(-5);
    expect(cs.decrypt(c3)).toBe(modulo - 5n);
    expect(cs.decrypt(c1.add(c3))).toBe(BigInt(m1 - 5));
    expect(cs.decrypt(cs.encrypt(modulo - 1n).add(c1))).toBe(BigInt(m1 - 1));

    // re-randomization
    const c1Prime = cs.regenerateCiphertext(c1);
    expect(valuesEqual(c1Prime.value, c1.value)).toBe(false);
    expect(cs.decrypt(c1Prime)).toBe(BigInt(m1));

    // unsupported homomorphic operations
    expect(() => c1.multiply(c2)).toThrow();
    expect(() => c1.xor(c2)).toThrow();
    expect(() => c1.and(c2)).toThrow();
    logger.info('✅ Castagnos-Laguillaumie api test succeeded');
  });

  it('restores every plaintext of a small key space', () => {
    const smallCs = new LightPHE({
      algorithmName: 'Castagnos-Laguillaumie',
      keySize: 24,
    });
    const modulo = smallCs.cs.plaintextModulo;
    for (let m = 0n; m < modulo; m++) {
      expect(smallCs.decrypt(smallCs.encrypt(m))).toBe(m);
    }
    logger.info(`✅ Castagnos-Laguillaumie restored all ${modulo} plaintexts`);
  });

  it('works with predefined keys', () => {
    const restoredCs = new LightPHE({
      algorithmName: 'Castagnos-Laguillaumie',
      keys: cs.cs.keys,
    });
    const c1 = cs.encrypt(11);
    const c2 = restoredCs.encrypt(7);
    expect(restoredCs.decrypt(c1.add(c2))).toBe(18n);
    expect(cs.decrypt(c1.add(c2))).toBe(18n);
  });

  it('works with 1024-bit keys', () => {
    const largeCs = new LightPHE({
      algorithmName: 'Castagnos-Laguillaumie',
      keySize: 1024,
    });
    const m1 = 123456789n;
    const m2 = 987654321n;
    const c1 = largeCs.encrypt(m1);
    const c2 = largeCs.encrypt(m2);
    expect(largeCs.decrypt(c1.add(c2))).toBe(m1 + m2);
    expect(largeCs.decrypt(c1.multiply(1000))).toBe(m1 * 1000n);
    expect(mathUtils.bitLength(largeCs.cs.plaintextModulo)).toBeGreaterThan(
      200
    );
  });
});
