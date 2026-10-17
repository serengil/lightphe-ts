import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { LightPHE, Logger } from '../src';
import { REGEV_ETA, REGEV_LOG_Q } from '../src/cryptosystems/Regev';
import { bitLength, pmod, randomInt, valuesEqual } from './helpers';

const logger = new Logger('tests/regev.test.ts');

const cs = new LightPHE({ algorithmName: 'Regev', keySize: 64 });

// dimension giving about 128-bit security against quantum attacks
let largeCs: LightPHE | undefined;
function getLargeCs(): LightPHE {
  largeCs ??= new LightPHE({ algorithmName: 'Regev', keySize: 2048 });
  return largeCs;
}

describe('Regev', () => {
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
      `✅ Regev api test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });

  it('has well formed keys', () => {
    // b = A s + e mod q where e is small. A is expanded from the seed entry by
    // entry, here with the SHAKE-128 of node as an independent reference.
    const publicKey = cs.cs.keys.public_key!;
    const n = Number(publicKey.n as bigint);
    const q = publicKey.q as bigint;
    const seed = publicKey.seed as bigint;
    const b = publicKey.b as bigint[];
    const s = cs.cs.keys.private_key!.s as bigint[];

    expect(q).toBe(2n ** BigInt(REGEV_LOG_Q));
    expect(b.length).toBe(n);
    expect(s.length).toBe(n);
    expect(s.every((x) => x >= -REGEV_ETA && x <= REGEV_ETA)).toBe(true);

    const width = Math.ceil(
      (REGEV_LOG_Q + bitLength(BigInt(REGEV_ETA * n))) / 8
    );
    const seedBytes = Buffer.from(seed.toString(16).padStart(64, '0'), 'hex');
    const stream = crypto
      .createHash('shake128', { outputLength: n * n * width })
      .update(seedBytes)
      .digest();
    for (let i = 0; i < n; i++) {
      let inner = 0n;
      for (let j = 0; j < n; j++) {
        const slot = stream.subarray(
          (i * n + j) * width,
          (i * n + j + 1) * width
        );
        const entry =
          BigInt(`0x${Buffer.from(slot).reverse().toString('hex')}`) % q;
        inner += entry * s[j];
      }
      let error = pmod(b[i] - inner, q);
      error = error > q / 2n ? error - q : error;
      expect(error >= -BigInt(REGEV_ETA) && error <= BigInt(REGEV_ETA)).toBe(
        true
      );
    }
  });

  it('restores all plaintexts of a small space', () => {
    const smallCs = new LightPHE({
      algorithmName: 'Regev',
      keySize: 32,
      plaintextLimit: 16,
    });
    expect(smallCs.cs.plaintextModulo).toBe(16n);
    for (let m = 0; m < 16; m++) {
      expect(smallCs.decrypt(smallCs.encrypt(m))).toBe(BigInt(m));
    }
  });

  it('respects the plaintext limit', () => {
    // rounded up to a power of 2
    expect(
      new LightPHE({
        algorithmName: 'Regev',
        keySize: 32,
        plaintextLimit: 1000,
      }).cs.plaintextModulo
    ).toBe(1024n);
    expect(
      new LightPHE({ algorithmName: 'Regev', keySize: 32 }).cs.plaintextModulo
    ).toBe(2n ** 24n);

    const bigCs = new LightPHE({
      algorithmName: 'Regev',
      keySize: 32,
      plaintextLimit: 2 ** 32,
    });
    const m = 2n ** 32n - 7n;
    expect(bigCs.decrypt(bigCs.encrypt(m))).toBe(m);

    // no room for noise
    expect(
      () =>
        new LightPHE({
          algorithmName: 'Regev',
          keySize: 32,
          plaintextLimit: 2 ** 45,
        })
    ).toThrow('too large for Regev');

    expect(() => new LightPHE({ algorithmName: 'Regev', keySize: 4 })).toThrow(
      'too small for Regev'
    );
  });

  it('has room for noise', () => {
    const modulo = cs.cs.plaintextModulo;
    const m = 4567n;
    const c = cs.encrypt(m);

    // many additions
    let total = cs.encrypt(0);
    for (let i = 0; i < 1000; i++) {
      total = total.add(c);
    }
    expect(cs.decrypt(total)).toBe(pmod(1000n * m, modulo));

    // large and negative constants
    expect(cs.decrypt(c.multiply(4000))).toBe(pmod(4000n * m, modulo));
    expect(cs.decrypt(c.multiply(-3))).toBe(pmod(-3n * m, modulo));
    expect(cs.decrypt(c.multiply(modulo - 1n))).toBe(pmod(-m, modulo));

    // random linear combinations
    for (let round = 0; round < 20; round++) {
      const values = Array.from({ length: 5 }, () => randomInt(0, 1000));
      const weights = Array.from({ length: 5 }, () => randomInt(-50, 50));
      const encrypted = values.map((v) => cs.encrypt(v));
      let result = encrypted[0].multiply(weights[0]);
      for (let i = 1; i < 5; i++) {
        result = result.add(encrypted[i].multiply(weights[i]));
      }
      const expected = values.reduce(
        (acc, v, i) => acc + BigInt(v * weights[i]),
        0n
      );
      expect(cs.decrypt(result)).toBe(pmod(expected, modulo));
    }
  });

  it('does not support floats and tensors', () => {
    const c = cs.encrypt(5);
    expect(() => cs.encrypt(1.5)).toThrow('Regev does not support float');
    expect(() => cs.encrypt([1, 2, 3])).toThrow('Regev does not support float');
    expect(() => c.multiply(1.5)).toThrow('Regev does not support float');
  });

  it('works with predefined keys', () => {
    const restoredCs = new LightPHE({
      algorithmName: 'Regev',
      keys: cs.cs.keys,
    });
    const c1 = cs.encrypt(11);
    const c2 = restoredCs.encrypt(7);
    expect(restoredCs.decrypt(c1.add(c2))).toBe(18n);
    expect(cs.decrypt(c1.add(c2))).toBe(18n);
    logger.info('✅ Regev predefined keys test succeeded');
  });

  it('works with exported keys', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-ts-'));
    const publicKeyFile = path.join(dir, 'public.txt');
    cs.exportKeys(publicKeyFile, true);

    const publicCs = new LightPHE({
      algorithmName: 'Regev',
      keyFile: publicKeyFile,
    });
    const c = publicCs.encrypt(42).multiply(2);
    expect(cs.decrypt(c)).toBe(84n);

    expect(() => publicCs.decrypt(c)).toThrow('private key');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('works with 2048-dimension keys', () => {
    const tic = Date.now();
    const large = getLargeCs();
    const modulo = large.cs.plaintextModulo;
    const m1 = 1234567n;
    const m2 = 7654321n;
    const c1 = large.encrypt(m1);
    const c2 = large.encrypt(m2);
    expect((c1.value as bigint[]).length).toBe(2048 + 1);

    expect(large.decrypt(c1)).toBe(m1);
    expect(large.decrypt(c1.add(c2))).toBe(m1 + m2);
    expect(large.decrypt(c1.multiply(1000))).toBe(pmod(m1 * 1000n, modulo));
    expect(large.decrypt(c1.multiply(-1000).add(c2.multiply(3)))).toBe(
      pmod(-1000n * m1 + 3n * m2, modulo)
    );

    let total = large.encrypt(0);
    for (let i = 0; i < 1000; i++) {
      total = total.add(c1);
    }
    expect(large.decrypt(total)).toBe(pmod(1000n * m1, modulo));

    logger.info(
      `✅ Regev 2048-dimension test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });

  it('runs the readme example', () => {
    const large = getLargeCs();
    const c1 = large.encrypt(1500);
    const c2 = large.encrypt(2500);

    expect(large.decrypt(c1.add(c2))).toBe(4000n);
    expect(large.decrypt(c1.multiply(3))).toBe(4500n);
  });
});
