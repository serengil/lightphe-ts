import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import {
  CamenischShoup,
  LightECC,
  LightPHE,
  Logger,
  type VerifiableCiphertext,
} from '../src';
import { randomBigInt, valuesEqual } from './helpers';

const logger = new Logger('tests/camenischshoup.test.ts');

const ALGORITHM = 'Camenisch-Shoup';
const cs = new LightPHE({ algorithmName: ALGORITHM, keySize: 50 });
const camenischShoup = cs.cs as CamenischShoup;

// verifiable encryption of secp256k1 secrets requires keys larger than 467 bits
let largeCs: LightPHE | undefined;
function getLargeCs(): LightPHE {
  largeCs ??= new LightPHE({ algorithmName: ALGORITHM, keySize: 1024 });
  return largeCs;
}

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-ts-'));
}

/** A random secret in `[1, n)`. */
function randomSecret(n: bigint): bigint {
  return randomBigInt(n - 1n) + 1n;
}

describe('Camenisch-Shoup', () => {
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
      `✅ Camenisch-Shoup api test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });

  it('has well formed keys', () => {
    const publicKey = cs.cs.keys.public_key!;
    const privateKey = cs.cs.keys.private_key!;
    const n = publicKey.n as bigint;
    const nSquare = n * n;

    for (const i of [1, 2, 3]) {
      expect(publicKey[`y${i}`]).toBe(
        mathPow(publicKey.g as bigint, privateKey[`x${i}`] as bigint, nSquare)
      );
    }

    expect(publicKey.g).not.toBe(1n);
    expect(publicKey.h_bar).not.toBe(1n);
    expect(publicKey.g_bar).not.toBe(1n);
    expect(publicKey.n_bar).not.toBe(n);
  });

  it('binds ciphertexts to labels', () => {
    for (const m of [0n, 1n, 17n, cs.cs.plaintextModulo - 1n]) {
      const ciphertext = camenischShoup.encryptWithLabel(m, 'some label');
      expect(camenischShoup.decryptWithLabel(ciphertext, 'some label')).toBe(m);

      // different label
      expect(() =>
        camenischShoup.decryptWithLabel(ciphertext, 'other label')
      ).toThrow('different label');

      // modified ciphertext
      const [u, e, v] = ciphertext;
      const nSquare = cs.cs.ciphertextModulo;
      for (const modified of [
        [u, (e * (1n + cs.cs.plaintextModulo)) % nSquare, v],
        [u, e, v + 1n],
      ]) {
        expect(() =>
          camenischShoup.decryptWithLabel(modified, 'some label')
        ).toThrow('invalid');
      }

      // labeled ciphertexts cannot be decrypted without label
      expect(() => camenischShoup.decrypt(ciphertext)).toThrow('labels');

      // homomorphic operations drop the validity tag
      const c = cs.createCiphertextObj(ciphertext).add(cs.encrypt(3));
      expect((c.value as bigint[]).length).toBe(2);
      expect(cs.decrypt(c)).toBe((m + 3n) % cs.cs.plaintextModulo);
    }
  });

  it('works with predefined keys', () => {
    const restoredCs = new LightPHE({
      algorithmName: ALGORITHM,
      keys: cs.cs.keys,
    });
    const c1 = cs.encrypt(11);
    const c2 = restoredCs.encrypt(7);
    expect(restoredCs.decrypt(c1.add(c2))).toBe(18n);
    expect(cs.decrypt(c1.add(c2))).toBe(18n);
    logger.info('✅ Camenisch-Shoup predefined keys test succeeded');
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

  it('encrypts verifiably', () => {
    const tic = Date.now();
    const large = getLargeCs();
    const ecc = new LightECC();
    const secret = randomSecret(ecc.n);
    const publicPoint = ecc.G.multiply(secret);
    const label = 'release if alice loses access';

    const verifiableCiphertext = large.encryptVerifiably(secret, label);

    // public point is accepted both as a point and as coordinates
    expect(
      large.verifyEncryption(verifiableCiphertext, publicPoint, label)
    ).toBe(true);
    expect(
      large.verifyEncryption(
        verifiableCiphertext,
        publicPoint.getPoint(),
        label
      )
    ).toBe(true);
    expect(large.decryptVerifiableCiphertext(verifiableCiphertext, label)).toBe(
      secret
    );

    // wrong label or wrong public point
    expect(
      large.verifyEncryption(verifiableCiphertext, publicPoint, 'other')
    ).toBe(false);
    expect(
      large.verifyEncryption(
        verifiableCiphertext,
        ecc.G.multiply(secret + 1n),
        label
      )
    ).toBe(false);
    expect(() =>
      large.decryptVerifiableCiphertext(verifiableCiphertext, 'other')
    ).toThrow('different label');

    logger.info(
      `✅ Camenisch-Shoup verifiable encryption test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });

  it('rejects tampered verifiable ciphertexts', () => {
    const large = getLargeCs();
    const ecc = new LightECC();
    const secret = randomSecret(ecc.n);
    const publicPoint = ecc.G.multiply(secret);
    const verifiableCiphertext = large.encryptVerifiably(secret);
    expect(large.verifyEncryption(verifiableCiphertext, publicPoint)).toBe(
      true
    );

    // modify each part of the ciphertext, commitment and proof
    for (let index = 0; index < 3; index++) {
      const ciphertext = [...verifiableCiphertext.ciphertext];
      ciphertext[index] += 1n;
      const tampered = { ...verifiableCiphertext, ciphertext };
      expect(large.verifyEncryption(tampered, publicPoint)).toBe(false);
    }

    const tamperedCommitment = {
      ...verifiableCiphertext,
      commitment: verifiableCiphertext.commitment + 1n,
    };
    expect(large.verifyEncryption(tamperedCommitment, publicPoint)).toBe(false);

    for (const field of ['challenge', 'r', 's', 'm'] as const) {
      const proof = { ...verifiableCiphertext.proof };
      proof[field] += 1n;
      const tampered: VerifiableCiphertext = { ...verifiableCiphertext, proof };
      expect(large.verifyEncryption(tampered, publicPoint)).toBe(false);
    }

    // ciphertext of another secret with the proof of this secret
    const other = large.encryptVerifiably(secret + 1n);
    const swapped = { ...verifiableCiphertext, ciphertext: other.ciphertext };
    expect(large.verifyEncryption(swapped, publicPoint)).toBe(false);

    // proof of another secret for this public point
    expect(large.verifyEncryption(other, publicPoint)).toBe(false);

    // malformed inputs
    for (const malformed of [
      {},
      { ciphertext: [1n, 2n] },
      { ...verifiableCiphertext, proof: null },
    ]) {
      expect(large.verifyEncryption(malformed, publicPoint)).toBe(false);
    }
  });

  it('restores secrets of the whole range', () => {
    const large = getLargeCs();
    const ecc = new LightECC();
    for (const secret of [1n, 2n, ecc.n - 1n]) {
      const verifiableCiphertext = large.encryptVerifiably(secret);
      expect(
        large.verifyEncryption(verifiableCiphertext, ecc.G.multiply(secret))
      ).toBe(true);
      expect(large.decryptVerifiableCiphertext(verifiableCiphertext)).toBe(
        secret
      );
    }

    // secrets are reduced to the order of the curve
    for (const secret of [ecc.n + 5n, -5n]) {
      const reduced = ((secret % ecc.n) + ecc.n) % ecc.n;
      const verifiableCiphertext = large.encryptVerifiably(secret);
      expect(
        large.verifyEncryption(verifiableCiphertext, ecc.G.multiply(reduced))
      ).toBe(true);
      expect(large.decryptVerifiableCiphertext(verifiableCiphertext)).toBe(
        reduced
      );
    }

    // public point would be the point at infinity
    for (const secret of [0n, ecc.n]) {
      expect(() => large.encryptVerifiably(secret)).toThrow(
        'multiple of the order'
      );
    }
    const verifiableCiphertext = large.encryptVerifiably(1n);
    expect(large.verifyEncryption(verifiableCiphertext, ecc.O)).toBe(false);
  });

  it('encrypts secrets of other curves verifiably', () => {
    const edwardsCs = new LightPHE({
      algorithmName: ALGORITHM,
      keys: getLargeCs().cs.keys,
      form: 'edwards',
      curve: 'ed25519',
    });
    const ecc = new LightECC({ formName: 'edwards', curveName: 'ed25519' });
    const secret = randomSecret(ecc.n);

    const verifiableCiphertext = edwardsCs.encryptVerifiably(secret);
    expect(
      edwardsCs.verifyEncryption(verifiableCiphertext, ecc.G.multiply(secret))
    ).toBe(true);
    expect(edwardsCs.decryptVerifiableCiphertext(verifiableCiphertext)).toBe(
      secret
    );
  });

  it('encrypts and verifies with the public key only', () => {
    const large = getLargeCs();
    const dir = tempDir();
    const publicKeyFile = path.join(dir, 'public.txt');
    large.exportKeys(publicKeyFile, true);
    const publicCs = new LightPHE({
      algorithmName: ALGORITHM,
      keyFile: publicKeyFile,
    });

    const ecc = new LightECC();
    const secret = randomSecret(ecc.n);

    // prover and verifier need the public key only
    const verifiableCiphertext = publicCs.encryptVerifiably(secret);
    expect(
      publicCs.verifyEncryption(verifiableCiphertext, ecc.G.multiply(secret))
    ).toBe(true);

    expect(() =>
      publicCs.decryptVerifiableCiphertext(verifiableCiphertext)
    ).toThrow('You must have private key');

    expect(large.decryptVerifiableCiphertext(verifiableCiphertext)).toBe(
      secret
    );
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('rejects small keys for verifiable encryption', () => {
    expect(() => cs.encryptVerifiably(5)).toThrow(
      'too small for verifiable encryption'
    );
    expect(() =>
      cs.verifyEncryption({}, new LightECC().G.multiply(5n))
    ).toThrow('too small for verifiable encryption');
  });

  it.each(['Paillier', 'Bresson-Catalano-Pointcheval'])(
    'does not support verifiable encryption for %s',
    (algorithmName) => {
      const otherCs = new LightPHE({ algorithmName, keySize: 50 });
      const point = new LightECC().G.multiply(5n);

      expect(() => otherCs.encryptVerifiably(5)).toThrow(
        'does not support verifiable encryption'
      );
      expect(() => otherCs.verifyEncryption({}, point)).toThrow(
        'does not support verifiable encryption'
      );
      expect(() =>
        otherCs.decryptVerifiableCiphertext({} as VerifiableCiphertext)
      ).toThrow('does not support verifiable encryption');
    }
  );

  it('works with 1024-bit keys', () => {
    const tic = Date.now();
    const large = getLargeCs();
    const m1 = 123456789n;
    const m2 = 987654321n;
    const c1 = large.encrypt(m1);
    const c2 = large.encrypt(m2);
    expect(large.decrypt(c1.add(c2))).toBe(m1 + m2);
    expect(large.decrypt(c1.multiply(1000))).toBe(m1 * 1000n);

    // floats and tensors
    const c3 = large.encrypt(1.5);
    expect(large.decrypt(c3.multiply(4))).toBe(6n);
    const encTensor = large.encrypt([1.5, 2.25, 3.5], { silent: true });
    expect(large.decrypt(encTensor)).toEqual([1.5, 2.25, 3.5]);
    expect(large.decrypt(encTensor.dot([2, 4, 1]))).toEqual([15.5]);

    logger.info(
      `✅ Camenisch-Shoup 1024-bit key test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });

  it('runs the verifiable encryption example in the readme', () => {
    const dir = tempDir();
    const publicKeyFile = path.join(dir, 'public.txt');

    // trusted third party builds the cryptosystem and publishes its public key
    const ttpCs = getLargeCs();
    ttpCs.exportKeys(publicKeyFile, true);

    // alice's wallet key pair on secp256k1
    const ecc = new LightECC({ curveName: 'secp256k1' });
    const privateKey = 123456789n;
    const publicKey = ecc.G.multiply(privateKey);

    // alice encrypts her private key for the trusted third party with a proof
    const label = 'release only if alice loses access to her wallet';
    const aliceCs = new LightPHE({
      algorithmName: ALGORITHM,
      keyFile: publicKeyFile,
    });
    const escrow = aliceCs.encryptVerifiably(privateKey, label);

    // bank verifies it with public keys only, without learning alice's private key
    const bankCs = new LightPHE({
      algorithmName: ALGORITHM,
      keyFile: publicKeyFile,
    });
    expect(bankCs.verifyEncryption(escrow, publicKey, label)).toBe(true);

    // trusted third party recovers the private key under the same label only
    expect(ttpCs.decryptVerifiableCiphertext(escrow, label)).toBe(privateKey);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});

function mathPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let b = base % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % modulus;
    }
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return result;
}
