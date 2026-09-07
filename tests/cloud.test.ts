import { LightPHE, Logger, type CiphertextValue } from '../src';

const logger = new Logger('tests/cloud.test.ts');

// pre-generated 20-bit RSA keys
const PRIVATE = {
  private_key: { d: 30365n },
  public_key: { n: 175501n, e: 101753n },
};
const PUBLIC = { public_key: { n: 175501n, e: 101753n } };

/**
 * Homomorphic operations run fine without the private key — that is the whole
 * point of offloading them to a cloud you do not trust.
 */
function homomorphicOperations(
  c1: CiphertextValue,
  c2: CiphertextValue
): CiphertextValue {
  const cs = new LightPHE({ algorithmName: 'RSA', keys: PUBLIC });
  const c1Obj = cs.createCiphertextObj(c1);
  const c2Obj = cs.createCiphertextObj(c2);

  // decryption is impossible without the private key
  expect(() => cs.decrypt(c1Obj)).toThrow();
  expect(() => cs.decrypt(c2Obj)).toThrow();

  // no private key needed here
  const c3 = c1Obj.multiply(c2Obj);
  logger.info('✅ Cloud homomorphic operation tests done');
  return c3.value;
}

describe('cloud workflow', () => {
  it('encrypts and evaluates with the public key alone', () => {
    // both keys are on hand, but encryption only ever needs the public one
    const cs = new LightPHE({ algorithmName: 'RSA', keys: PUBLIC });
    const secretCs = new LightPHE({ algorithmName: 'RSA', keys: PRIVATE });

    const m1 = 10000;
    const c1 = cs.encrypt(m1);

    const m2 = 1.05;
    const c2 = cs.encrypt(m2);

    expect(secretCs.decrypt(c1)).toBe(BigInt(m1));
    logger.info('✅ Cloud encryption tests done');

    const c3Val = homomorphicOperations(c1.value, c2.value);
    const c3 = cs.createCiphertextObj(c3Val);

    expect(secretCs.decrypt(c3)).toBe(BigInt(m1 * m2));
    logger.info('✅ Cloud decryption tests done');
  });
});
