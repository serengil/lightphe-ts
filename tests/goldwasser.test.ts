import { LightPHE, Logger } from '../src';
import { bitLength } from './helpers';

const logger = new Logger('tests/goldwasser.test.ts');

describe('Goldwasser-Micali', () => {
  it('is homomorphic with respect to exclusive or', () => {
    const cs = new LightPHE({
      algorithmName: 'Goldwasser-Micali',
      keySize: 50,
    });

    const securityLevel = bitLength(cs.cs.keys.public_key!.n as bigint);

    // try different bit size messages
    const messages: Array<[number, number]> = [
      [17, 21],
      [117, 23],
      [23, 117],
      [1117, 23],
      [12, 1118],
    ];

    for (const [m1, m2] of messages) {
      const c1 = cs.encrypt(m1);
      const c2 = cs.encrypt(m2);

      // homomorphic exclusive or
      expect(cs.decrypt(c1.xor(c2))).toBe(BigInt(m1 ^ m2));

      // unsupported homomorphic operations
      expect(() => c1.multiply(c2)).toThrow();
      expect(() => c1.add(c2)).toThrow();
      expect(() => c1.multiply(5)).toThrow();
      expect(() => c1.multiplyByConstant(5)).toThrow();

      logger.info(
        `✅ Goldwasser-Micali api test succeeded for ${bitLength(BigInt(m1))}&${bitLength(
          BigInt(m2)
        )} bit plaintexts (${securityLevel} bit security level)`
      );
    }
  });
});
