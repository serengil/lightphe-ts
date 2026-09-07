import { LightPHE, Logger } from '../src';

const logger = new Logger('tests/ciphertexts.test.ts');

const onpremCs = new LightPHE({ algorithmName: 'Paillier', keySize: 50 });

describe('ciphertexts', () => {
  it('never carries the private key', () => {
    const m = 17;

    const c = onpremCs.encrypt(m);

    expect(c.cs.keys.private_key).toBeUndefined();
    expect(onpremCs.cs.keys.private_key).toBeDefined();

    logger.info('✅ Private key not available in ciphertext tests done');
  });

  it('never carries the private key in an encrypted tensor', () => {
    const t = [1.5, 2.4, 3.3, 4.2, 5.1];

    const c = onpremCs.encrypt(t, { silent: true });

    expect(c.cs.keys.private_key).toBeUndefined();
    expect(onpremCs.cs.keys.private_key).toBeDefined();

    logger.info('✅ Private key not available in encrypted tensor tests done');
  });
});
