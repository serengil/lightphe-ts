import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { LightPHE, Logger } from '../src';
import { pmod, randomBigInt, valuesEqual } from './helpers';

const logger = new Logger('tests/ellipticcurvepaillier.test.ts');

const ALGORITHM = 'EllipticCurve-Paillier';
const cs = new LightPHE({ algorithmName: ALGORITHM, keySize: 50 });

describe('Elliptic Curve Paillier', () => {
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
      `✅ Elliptic Curve Paillier api test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });

  it('has well formed keys', () => {
    const n = cs.cs.keys.public_key!.n as bigint;
    const b = cs.cs.keys.public_key!.b as bigint;
    const [x, y] = cs.cs.keys.public_key!.g as bigint[];
    const p = cs.cs.keys.private_key!.p as bigint;
    const q = cs.cs.keys.private_key!.q as bigint;
    const order = cs.cs.keys.private_key!.order as bigint;
    const nSquare = n * n;

    expect(n).toBe(p * q);
    expect(p % 3n).toBe(2n);
    expect(q % 3n).toBe(2n);

    // g is on the curve y^2 = x^3 + b mod n^2
    expect(pmod(y * y - x ** 3n - b, nSquare)).toBe(0n);

    // order is odd and divides the group exponent modulo n
    expect(order % 2n).toBe(1n);
    expect(((p + 1n) * (q + 1n)) % order).toBe(0n);
  });

  it('handles edge cases', () => {
    const modulo = cs.cs.plaintextModulo;
    for (const m of [0n, 1n, 2n, modulo - 1n]) {
      const c = cs.encrypt(m);
      expect(cs.decrypt(c)).toBe(m);

      // doubling, i.e. adding a ciphertext to itself
      expect(cs.decrypt(c.add(c))).toBe(pmod(2n * m, modulo));

      // adding inverse brings point back to the encryption of 0
      expect(cs.decrypt(c.add(c.multiply(modulo - 1n)))).toBe(0n);

      // multiplying by 0 gives the point at infinity, which is the encryption of 0
      expect(cs.decrypt(c.multiply(0))).toBe(0n);
      expect(cs.decrypt(c.multiply(0).add(c))).toBe(m);
    }
  });

  it('supports random operations', () => {
    const modulo = cs.cs.plaintextModulo;
    for (let round = 0; round < 50; round++) {
      const [m1, m2, k] = Array.from({ length: 3 }, () => randomBigInt(modulo));
      const c1 = cs.encrypt(m1);
      const c2 = cs.encrypt(m2);
      expect(cs.decrypt(c1.add(c2))).toBe(pmod(m1 + m2, modulo));
      expect(cs.decrypt(c1.multiply(k).add(c2))).toBe(
        pmod(m1 * k + m2, modulo)
      );
    }
  });

  it('rejects invalid ciphertexts', () => {
    const n = cs.cs.plaintextModulo;
    const c = cs.encrypt(5);
    const [x, y, z] = c.value as bigint[];

    // a point that is not a ciphertext
    expect(() => cs.cs.decrypt([x + 1n, y, z])).toThrow('invalid');
    expect(() => cs.cs.decrypt([1n, 1n, 1n + n])).toThrow('invalid');
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
    logger.info('✅ Elliptic Curve Paillier predefined keys test succeeded');
  });

  it('works with exported keys', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-ts-'));
    const publicKeyFile = path.join(dir, 'public.txt');
    cs.exportKeys(publicKeyFile, true);

    const publicCs = new LightPHE({
      algorithmName: ALGORITHM,
      keyFile: publicKeyFile,
    });
    const c = publicCs.encrypt(42).multiply(2);
    expect(cs.decrypt(c)).toBe(84n);

    expect(() => publicCs.decrypt(c)).toThrow('private key');

    // private key restored from file
    const privateKeyFile = path.join(dir, 'private.txt');
    cs.exportKeys(privateKeyFile);
    const restoredCs = new LightPHE({
      algorithmName: ALGORITHM,
      keyFile: privateKeyFile,
    });
    expect(restoredCs.decrypt(c.add(publicCs.encrypt(1)))).toBe(85n);
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

    // floats and tensors
    const c3 = largeCs.encrypt(1.5);
    expect(largeCs.decrypt(c3.multiply(4))).toBe(6n);
    const encTensor = largeCs.encrypt([1.5, 2.25, 3.5], { silent: true });
    expect(largeCs.decrypt(encTensor)).toEqual([1.5, 2.25, 3.5]);
    expect(largeCs.decrypt(encTensor.dot([2, 4, 1]))).toEqual([15.5]);

    logger.info(
      `✅ Elliptic Curve Paillier 1024-bit key test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });
});
