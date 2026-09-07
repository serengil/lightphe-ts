import { LightPHE, Logger, type Keys } from '../src';
import { deepClone } from './helpers';

const logger = new Logger('tests/keyValidator.test.ts');

const ALGORITHMS: Array<[string, number]> = [
  ['RSA', 50],
  ['ElGamal', 50],
  ['Exponential-ElGamal', 50],
  ['EllipticCurve-ElGamal', 50],
  ['Paillier', 50],
  ['Damgard-Jurik', 50],
  ['Okamoto-Uchiyama', 50],
  ['Benaloh', 50],
  ['Naccache-Stern', 50],
  ['Goldwasser-Micali', 50],
  ['Sander-Young-Yung', 50],
  ['Boneh-Goh-Nissim', 50],
];

describe('key validator', () => {
  it.each(ALGORITHMS)(
    '%s rejects a missing public_key field',
    (algorithmName, keySize) => {
      const cs = new LightPHE({ algorithmName, keySize, maxTries: 10000 });
      const field = cs.cs.requiredKeys.public_key[0];

      const broken = deepClone(cs.cs.keys) as Keys;
      delete broken.public_key![field];

      expect(() => new LightPHE({ algorithmName, keys: broken })).toThrow(
        new RegExp(`missing required fields.*${field}`)
      );

      logger.info(`✅ ${algorithmName}: missing public_key.${field} rejected`);
    }
  );

  it.each(ALGORITHMS)(
    '%s rejects a missing private_key field',
    (algorithmName, keySize) => {
      const cs = new LightPHE({ algorithmName, keySize, maxTries: 10000 });
      const field = cs.cs.requiredKeys.private_key[0];

      const broken = deepClone(cs.cs.keys) as Keys;
      delete broken.private_key![field];

      expect(() => new LightPHE({ algorithmName, keys: broken })).toThrow(
        new RegExp(`missing required fields.*${field}`)
      );

      logger.info(`✅ ${algorithmName}: missing private_key.${field} rejected`);
    }
  );

  it('rejects a keys object without public_key', () => {
    expect(() => new LightPHE({ algorithmName: 'RSA', keys: {} })).toThrow(
      /must contain 'public_key'/
    );
  });

  it('rejects a private key supplied without a public key', () => {
    const cs = new LightPHE({ algorithmName: 'RSA', keySize: 50 });
    const privateOnly = {
      private_key: deepClone(cs.cs.keys.private_key),
    } as Keys;
    expect(
      () => new LightPHE({ algorithmName: 'RSA', keys: privateOnly })
    ).toThrow(/must contain 'public_key'/);
  });

  it('rejects a non-object keys argument', () => {
    expect(
      () =>
        new LightPHE({
          algorithmName: 'RSA',
          keys: 'not-a-dict' as unknown as Keys,
        })
    ).toThrow(/keys must be a dict/);
  });

  it('accepts a full public key on its own, for encryption-only use', () => {
    const cs = new LightPHE({ algorithmName: 'RSA', keySize: 50 });
    const publicOnly = { public_key: deepClone(cs.cs.keys.public_key) } as Keys;
    // should not throw
    expect(
      () => new LightPHE({ algorithmName: 'RSA', keys: publicOnly })
    ).not.toThrow();
  });

  it('rejects a missing nested curve field for Boneh-Goh-Nissim', () => {
    const cs = new LightPHE({
      algorithmName: 'Boneh-Goh-Nissim',
      keySize: 50,
      maxTries: 10000,
    });
    const nested = cs.cs.requiredKeys.nested?.curve ?? [];
    expect(nested.length).toBeGreaterThan(0);
    const field = nested[0];

    const broken = deepClone(cs.cs.keys) as Keys;
    delete (broken.public_key!.curve as Record<string, unknown>)[field];

    expect(
      () => new LightPHE({ algorithmName: 'Boneh-Goh-Nissim', keys: broken })
    ).toThrow(
      new RegExp(`public_key\\.curve.*missing required fields.*${field}`)
    );

    logger.info(`✅ BGN: missing public_key.curve.${field} rejected`);
  });
});
