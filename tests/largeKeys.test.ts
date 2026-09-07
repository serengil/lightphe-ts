import { LightPHE, Logger } from '../src';

const logger = new Logger('tests/largeKeys.test.ts');

/**
 * An experiment rather than a unit test: it walks large key sizes to show they
 * work, at a cost no CI run should pay. Skipped by default, exactly as the
 * Python suite skips it.
 *
 * Algorithm | Key Size | Key Generation | Encryption | Homomorphic | Decryption
 * --- | --- | --- | --- | --- | ---
 * Goldwasser-Micali | 1024 | 0.01 | 0.00 | 0.00 | 0.00
 * Goldwasser-Micali | 2048 | 0.08 | 0.00 | 0.00 | 0.03
 * Goldwasser-Micali | 3072 | 0.45 | 0.00 | 0.00 | 0.08
 * Goldwasser-Micali | 7680 | 11.30 | 0.00 | 0.00 | 1.21
 *
 * Benaloh | 1024 | 4.91 | 0.00 | 0.00 | 0.01
 * Benaloh | 2048 | 140.54 | 0.00 | 0.00 | 0.03
 * Benaloh | 3072 | 439.46 | 0.00 | 0.00 | 0.08
 *
 * Naccache-Stern | 1024 | 19.97 | 0.00 | 0.00 | 0.06
 */
describe.skip('large keys', () => {
  it('works across large key sizes', () => {
    const algorithms = ['Naccache-Stern', 'Goldwasser-Micali', 'Benaloh'];
    const keySizes = [1024, 2048, 3072, 7680];

    for (const keySize of keySizes) {
      for (const algorithmName of algorithms) {
        logger.debug(`Testing ${algorithmName} with key size ${keySize} bits`);

        let tic = Date.now();
        const cs = new LightPHE({ algorithmName, keySize });
        const keygenTime = (Date.now() - tic) / 1000;

        const m1 = 17;
        const m2 = 23;

        tic = Date.now();
        const c1 = cs.encrypt(m1);
        const c2 = cs.encrypt(m2);
        const encryptionTime = (Date.now() - tic) / 1000;

        let homomorphicTime = 0;
        let decryptionTime = 0;

        if (algorithmName === 'Naccache-Stern' || algorithmName === 'Benaloh') {
          tic = Date.now();
          const c3 = c1.add(c2);
          homomorphicTime = (Date.now() - tic) / 1000;

          tic = Date.now();
          const result = cs.decrypt(c3);
          decryptionTime = (Date.now() - tic) / 1000;
          expect(result).toBe(BigInt(m1 + m2));
        } else {
          tic = Date.now();
          const c3 = c1.xor(c2);
          homomorphicTime = (Date.now() - tic) / 1000;

          tic = Date.now();
          const result = cs.decrypt(c3);
          decryptionTime = (Date.now() - tic) / 1000;
          expect(result).toBe(BigInt(m1 ^ m2));
        }

        logger.info(
          `${algorithmName} | ${keySize} | ${keygenTime.toFixed(2)} | ` +
            `${encryptionTime.toFixed(2)} | ${homomorphicTime.toFixed(2)} |` +
            `${decryptionTime.toFixed(2)}`
        );
      }
    }
  });
});
