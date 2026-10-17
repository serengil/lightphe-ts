import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { LightPHE, Logger, mathUtils, type Keys } from '../src';
import { deepClone, valuesEqual } from './helpers';

const logger = new Logger('tests/bressoncatalanopointcheval.test.ts');

const ALGORITHM = 'Bresson-Catalano-Pointcheval';
const cs = new LightPHE({ algorithmName: ALGORITHM, keySize: 50 });

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-ts-'));
}

describe('Bresson-Catalano-Pointcheval', () => {
  it('is additively homomorphic and supports scalar multiplication', () => {
    const tic = Date.now();
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

    logger.info(
      `✅ Bresson-Catalano-Pointcheval api test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });

  it('has well formed keys', () => {
    const n = cs.cs.keys.public_key!.n as bigint;
    const p = cs.cs.keys.private_key!.p as bigint;
    const q = cs.cs.keys.private_key!.q as bigint;
    expect(n).toBe(p * q);
    expect(p).not.toBe(q);

    // p and q are safe primes
    for (const prime of [p, q]) {
      expect(mathUtils.modPow(2n, prime - 1n, prime)).toBe(1n);
      const pPrime = (prime - 1n) / 2n;
      expect(mathUtils.modPow(2n, pPrime - 1n, pPrime)).toBe(1n);
    }
  });

  it('decrypts with the master trapdoor', () => {
    // factorization of n decrypts without the local trapdoor a
    for (const m of [0n, 1n, 17n, 12345n, cs.cs.plaintextModulo - 1n]) {
      const c = cs.encrypt(m);
      expect(cs.decryptWithMasterKey(c)).toBe(m);
      expect(cs.decryptWithMasterKey(c.multiply(3).add(c))).toBe(
        cs.decrypt(c.multiply(4))
      );
    }
  });

  it('decrypts ciphertexts of all users with the master key', () => {
    // authority generates the master key, and publishes n and g with its public key
    const authorityCs = new LightPHE({ algorithmName: ALGORITHM, keySize: 50 });
    const authorityPublicCs = new LightPHE({
      algorithmName: ALGORITHM,
      keys: { public_key: authorityCs.cs.keys.public_key },
    });

    // each user generates its own key pair with the public key of the authority
    const aliceKeys = authorityPublicCs.generateUserKeys();
    const bobKeys = authorityPublicCs.generateUserKeys();
    expect(Object.keys(aliceKeys.private_key!)).toEqual(['a']);
    expect(aliceKeys.public_key!.n).toBe(authorityCs.cs.keys.public_key!.n);
    expect(aliceKeys.public_key!.g).toBe(authorityCs.cs.keys.public_key!.g);
    expect(aliceKeys.public_key!.h).not.toBe(bobKeys.public_key!.h);

    const aliceCs = new LightPHE({ algorithmName: ALGORITHM, keys: aliceKeys });
    const bobCs = new LightPHE({ algorithmName: ALGORITHM, keys: bobKeys });

    const aliceC = aliceCs.encrypt(123).add(aliceCs.encrypt(456));
    const bobC = bobCs.encrypt(1000).multiply(3);

    // users decrypt their own ciphertexts
    expect(aliceCs.decrypt(aliceC)).toBe(579n);
    expect(bobCs.decrypt(bobC)).toBe(3000n);

    // but not each other's
    expect(aliceCs.decrypt(bobC)).not.toBe(3000n);
    expect(bobCs.decrypt(aliceC)).not.toBe(579n);

    // users do not have the master key
    expect(() => aliceCs.decryptWithMasterKey(bobC)).toThrow('master trapdoor');

    // authority decrypts ciphertexts of all users without knowing their local trapdoors
    expect(authorityCs.decryptWithMasterKey(aliceC)).toBe(579n);
    expect(authorityCs.decryptWithMasterKey(bobC)).toBe(3000n);

    // authority may keep the master trapdoor only
    const masterKeys = deepClone(authorityCs.cs.keys) as Keys;
    delete masterKeys.private_key!.a;
    const masterCs = new LightPHE({
      algorithmName: ALGORITHM,
      keys: masterKeys,
    });
    expect(masterCs.decryptWithMasterKey(aliceC)).toBe(579n);
    expect(masterCs.decryptWithMasterKey(bobC)).toBe(3000n);
    expect(() => masterCs.decrypt(aliceC)).toThrow('local trapdoor');

    // encryption with public key of a user restored from a file is still decryptable
    const restoredCs = new LightPHE({
      algorithmName: ALGORITHM,
      keys: { public_key: bobKeys.public_key },
    });
    expect(masterCs.decryptWithMasterKey(restoredCs.encrypt(7))).toBe(7n);

    logger.info('✅ Bresson-Catalano-Pointcheval master key test succeeded');
  });

  it('decrypts tensors with the master key', () => {
    const userCs = new LightPHE({
      algorithmName: ALGORITHM,
      keys: cs.generateUserKeys(),
    });
    const encTensor = userCs.encrypt([1.5, -2.25, 3], { silent: true });
    expect(cs.decryptWithMasterKey(encTensor)).toEqual([1.5, -2.25, 3]);
    expect(cs.decryptWithMasterKey(encTensor.multiply(2))).toEqual([
      3, -4.5, 6,
    ]);
    expect(cs.decrypt(encTensor)).not.toEqual([1.5, -2.25, 3]);
  });

  it('rejects ciphertexts of another master key', () => {
    const otherCs = new LightPHE({ algorithmName: ALGORITHM, keySize: 50 });
    const c = otherCs.encrypt(5);
    expect(() => cs.decryptWithMasterKey(c)).toThrow(
      'does not share the same n and g'
    );
  });

  it('requires the private key for master key decryption', () => {
    const dir = tempDir();
    const publicKeyFile = path.join(dir, 'public.txt');
    cs.exportKeys(publicKeyFile, true);
    const publicCs = new LightPHE({
      algorithmName: ALGORITHM,
      keyFile: publicKeyFile,
    });
    const c = publicCs.encrypt(5);

    expect(() => publicCs.decryptWithMasterKey(c)).toThrow(
      'You must have private key'
    );

    // public key is enough to generate user keys
    const userKeys = publicCs.generateUserKeys();
    const userCs = new LightPHE({ algorithmName: ALGORITHM, keys: userKeys });
    expect(cs.decryptWithMasterKey(userCs.encrypt(9))).toBe(9n);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it.each(['Paillier', 'RSA', 'Damgard-Geisler-Kroigaard'])(
    'does not support master keys for %s',
    (algorithmName) => {
      const otherCs = new LightPHE({ algorithmName, keySize: 50 });
      const c = otherCs.encrypt(5);

      expect(() => otherCs.decryptWithMasterKey(c)).toThrow(
        'does not support master key decryption'
      );
      expect(() => otherCs.generateUserKeys()).toThrow(
        'does not support generating user keys'
      );
    }
  );

  it('works with predefined keys', () => {
    const restoredCs = new LightPHE({
      algorithmName: ALGORITHM,
      keys: cs.cs.keys,
    });
    const c1 = cs.encrypt(11);
    const c2 = restoredCs.encrypt(7);
    expect(restoredCs.decrypt(c1.add(c2))).toBe(18n);
    expect(cs.decrypt(c1.add(c2))).toBe(18n);
    logger.info(
      '✅ Bresson-Catalano-Pointcheval predefined keys test succeeded'
    );
  });

  it('works with exported keys', () => {
    const dir = tempDir();
    const publicKeyFile = path.join(dir, 'public.txt');
    cs.exportKeys(publicKeyFile, true);

    const publicCs = new LightPHE({
      algorithmName: ALGORITHM,
      keyFile: publicKeyFile,
    });
    const c = publicCs.encrypt(42).multiply(2);
    expect(cs.decrypt(c)).toBe(84n);

    expect(() => publicCs.decrypt(c)).toThrow('private key');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('works with 1024-bit keys', () => {
    const tic = Date.now();
    const largeCs = new LightPHE({ algorithmName: ALGORITHM, keySize: 1024 });
    const m1 = 123456789n;
    const m2 = 987654321n;
    const c1 = largeCs.encrypt(m1);
    const c2 = largeCs.encrypt(m2);
    expect(largeCs.decrypt(c1.add(c2))).toBe(m1 + m2);
    expect(largeCs.decrypt(c1.multiply(1000))).toBe(m1 * 1000n);
    expect(largeCs.decryptWithMasterKey(c1.add(c2))).toBe(m1 + m2);

    // floats and tensors
    const c3 = largeCs.encrypt(1.5);
    expect(largeCs.decrypt(c3.multiply(4))).toBe(6n);
    const encTensor = largeCs.encrypt([1.5, 2.25, 3.5], { silent: true });
    expect(largeCs.decrypt(encTensor)).toEqual([1.5, 2.25, 3.5]);
    expect(largeCs.decrypt(encTensor.dot([2, 4, 1]))).toEqual([15.5]);

    logger.info(
      `✅ Bresson-Catalano-Pointcheval 1024-bit key test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });

  it('runs the master key example in the readme', () => {
    const dir = tempDir();
    const publicKeyFile = path.join(dir, 'public.txt');

    // authority generates the master key and publishes its public key
    const authorityCs = new LightPHE({
      algorithmName: ALGORITHM,
      keySize: 256,
    });
    authorityCs.exportKeys(publicKeyFile, true);

    // each user generates its own key pair with the public key of the authority
    const publicCs = new LightPHE({
      algorithmName: ALGORITHM,
      keyFile: publicKeyFile,
    });
    const aliceCs = new LightPHE({
      algorithmName: ALGORITHM,
      keys: publicCs.generateUserKeys(),
    });
    const bobCs = new LightPHE({
      algorithmName: ALGORITHM,
      keys: publicCs.generateUserKeys(),
    });

    const aliceCiphertext = aliceCs.encrypt(100).add(aliceCs.encrypt(50));
    const bobCiphertext = bobCs.encrypt(200);

    // users decrypt their own ciphertexts only
    expect(aliceCs.decrypt(aliceCiphertext)).toBe(150n);
    expect(aliceCs.decrypt(bobCiphertext)).not.toBe(200n);

    // authority decrypts ciphertexts of all users
    expect(authorityCs.decryptWithMasterKey(aliceCiphertext)).toBe(150n);
    expect(authorityCs.decryptWithMasterKey(bobCiphertext)).toBe(200n);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
