import {
  EllipticCurveElGamal,
  LightPHE,
  Logger,
  listCurveNames,
  type CurveForm,
} from '../src';
import { bitLength, valuesEqual } from './helpers';

const logger = new Logger('tests/ellipticcurveelgamal.test.ts');

// Koblitz is excluded because its key generation is slow enough to be a poor
// fit for CI, matching the Python suite.
const FORMS: CurveForm[] = ['weierstrass', 'edwards']; // and 'koblitz'

describe('Elliptic Curve ElGamal', () => {
  it('is additively homomorphic on every supported form', () => {
    for (const form of FORMS) {
      const started = Date.now();
      const cs = new LightPHE({
        algorithmName: 'EllipticCurve-ElGamal',
        form,
        curve: null,
      });

      const m1 = 10;
      const m2 = 5;

      const c1 = cs.encrypt(m1);
      const c2 = cs.encrypt(m2);

      // proof of decryption
      expect(cs.decrypt(c1)).toBe(BigInt(m1));
      expect(cs.decrypt(c2)).toBe(BigInt(m2));

      // proof of re-randomization: different points, same plaintext
      const c1Prime = cs.cs.reencrypt(c1.value);
      const c2Prime = cs.cs.reencrypt(c2.value);
      expect(valuesEqual(c1.value, c1Prime)).toBe(false);
      expect(cs.cs.decrypt(c1Prime)).toBe(BigInt(m1));
      expect(cs.cs.decrypt(c2Prime)).toBe(BigInt(m2));

      // homomorphic addition and scalar multiplication
      expect(cs.decrypt(c1.add(c2))).toBe(BigInt(m1 + m2));
      expect(cs.decrypt(c1.multiply(m2))).toBe(BigInt(m1 * m2));
      expect(cs.decrypt(c2.multiply(m1))).toBe(BigInt(m1 * m2));
      expect(cs.decrypt(c1.multiplyByConstant(m2))).toBe(BigInt(m1 * m2));
      expect(cs.decrypt(c2.multiplyByConstant(m1))).toBe(BigInt(m1 * m2));

      // zero: identity element (point at infinity) cases
      const c0 = cs.encrypt(0);
      expect(cs.decrypt(c0)).toBe(0n);
      expect(cs.decrypt(c1.multiply(0))).toBe(0n);
      expect(cs.decrypt(c1.multiply(0).multiply(m2))).toBe(0n);
      expect(cs.decrypt(c0.add(c2))).toBe(BigInt(m2));
      expect(cs.decrypt(c1.multiply(0).add(c2))).toBe(BigInt(m2));
      expect(cs.cs.decrypt(cs.cs.reencrypt(c1.multiply(0).value))).toBe(0n);

      // unsupported homomorphic operations
      expect(() => c1.multiply(c2)).toThrow();
      expect(() => c1.xor(c2)).toThrow();

      logger.info(
        `✅ Elliptic Curve ElGamal api test succeeded for EC form ${form}` +
          ` in ${(Date.now() - started) / 1000} seconds.`
      );
    }
  });

  /**
   * Sweeping every bundled curve is a long experiment rather than a unit test,
   * so it is skipped by default — the Python suite disables it the same way.
   */
  it.skip('works for every curve of every form', () => {
    for (const form of FORMS) {
      for (const curve of listCurveNames(form)) {
        if (curve === 'test-curve') {
          continue;
        }

        logger.debug(
          `ℹ️ Elliptic Curve ElGamal test is running for EC form ${form}&${curve}`
        );

        const cs = new EllipticCurveElGamal({ form, curve });

        const m1 = 10n;
        const m2 = 5n;

        const c1 = cs.encrypt(m1);
        const c2 = cs.encrypt(m2);

        // encryption decryption test
        expect(cs.decrypt(c1)).toBe(m1);
        expect(cs.decrypt(c2)).toBe(m2);

        // homomorphic operations
        expect(cs.decrypt(cs.add(c1, c2))).toBe(m1 + m2);
        expect(cs.decrypt(cs.multiplyByConstant(c1, m2))).toBe(m1 * m2);

        // unsupported operations
        expect(() => cs.multiply(c1, c2)).toThrow();
        expect(() => cs.xor(c1, c2)).toThrow();

        logger.info(
          `✅ Elliptic Curve ElGamal test succeeded for EC form ${form}&${curve}` +
            ` (${bitLength(cs.ecc.n)}-bit)`
        );
      }
    }
  });
});
