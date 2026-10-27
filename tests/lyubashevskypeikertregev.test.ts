import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { LightPHE, Logger } from '../src';
import {
  expand,
  LPR_ETA,
  LPR_LOG_Q,
  polyMul,
} from '../src/cryptosystems/LyubashevskyPeikertRegev';
import { pmod, randomBigInt, randomInt, valuesEqual } from './helpers';

const logger = new Logger('tests/lyubashevskypeikertregev.test.ts');

const ALGORITHM = 'Lyubashevsky-Peikert-Regev';
const cs = new LightPHE({ algorithmName: ALGORITHM, keySize: 64 });

// ring degree giving about 128-bit security against quantum attacks
let largeCs: LightPHE | undefined;
function getLargeCs(): LightPHE {
  largeCs ??= new LightPHE({ algorithmName: ALGORITHM, keySize: 2048 });
  return largeCs;
}

/** Schoolbook multiplication in `Z_q[x] / (x^d + 1)`. */
function negacyclicProduct(
  poly1: readonly bigint[],
  poly2: readonly bigint[],
  q: bigint
): bigint[] {
  const d = poly1.length;
  const result = new Array<bigint>(d).fill(0n);
  for (let i = 0; i < d; i++) {
    for (let j = 0; j < d; j++) {
      if (i + j < d) {
        result[i + j] += poly1[i] * poly2[j];
      } else {
        result[i + j - d] -= poly1[i] * poly2[j];
      }
    }
  }
  return result.map((x) => pmod(x, q));
}

/** Centered representative of x modulo q. */
function centered(x: bigint, q: bigint): bigint {
  const r = pmod(x, q);
  return r > q / 2n ? r - q : r;
}

describe('Lyubashevsky-Peikert-Regev', () => {
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
      `✅ Lyubashevsky-Peikert-Regev api test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });

  it('generates well formed keys', () => {
    // b = a s + e where e is small
    const publicKey = cs.cs.keys.public_key!;
    const d = Number(publicKey.d as bigint);
    const q = publicKey.q as bigint;
    const b = publicKey.b as bigint[];
    const s = cs.cs.keys.private_key!.s as bigint[];
    const a = expand(publicKey.seed as bigint, d);

    expect(q).toBe(2n ** BigInt(LPR_LOG_Q));
    expect(a.length).toBe(d);
    expect(b.length).toBe(d);
    expect(s.length).toBe(d);
    expect(a.every((x) => x >= 0n && x < q)).toBe(true);
    expect(s.every((x) => x >= -BigInt(LPR_ETA) && x <= BigInt(LPR_ETA))).toBe(
      true
    );

    const aS = negacyclicProduct(
      a,
      s.map((x) => pmod(x, q)),
      q
    );
    aS.forEach((x, i) => {
      const error = centered(b[i] - x, q);
      expect(error <= BigInt(LPR_ETA) && error >= -BigInt(LPR_ETA)).toBe(true);
    });
  });

  it('generates well formed ciphertexts', () => {
    // c1 = a u + e1 and c2 = constant term of b u + e2 + m q / t, where u, e1, e2 are small
    const publicKey = cs.cs.keys.public_key!;
    const d = Number(publicKey.d as bigint);
    const q = publicKey.q as bigint;
    const t = publicKey.t as bigint;
    const b = publicKey.b as bigint[];
    const a = expand(publicKey.seed as bigint, d);
    const u = cs.cs.generateRandomKey() as bigint[];
    const m = 12345n;

    const ciphertext = cs.cs.encrypt(m, u) as bigint[];
    const c1 = ciphertext.slice(0, -1);
    const c2 = ciphertext[ciphertext.length - 1];
    expect(c1.length).toBe(d);

    const uModQ = u.map((x) => pmod(x, q));
    const aU = negacyclicProduct(a, uModQ, q);
    aU.forEach((x, i) => {
      const error = centered(c1[i] - x, q);
      expect(error <= BigInt(LPR_ETA) && error >= -BigInt(LPR_ETA)).toBe(true);
    });

    const bU = negacyclicProduct(b, uModQ, q);
    const error = centered(c2 - bU[0] - m * (q / t), q);
    expect(error <= BigInt(LPR_ETA) && error >= -BigInt(LPR_ETA)).toBe(true);
  });

  it('multiplies polynomials', () => {
    const q = cs.cs.ciphertextModulo;
    for (const d of [8, 64]) {
      for (let i = 0; i < 10; i++) {
        const poly1 = Array.from({ length: d }, () => randomBigInt(q));
        const poly2 = Array.from({ length: d }, () => randomBigInt(q));
        expect(polyMul(poly1, poly2, d)).toEqual(
          negacyclicProduct(poly1, poly2, q)
        );
      }
    }
  });

  it('decrypts every plaintext of a small space', () => {
    const smallCs = new LightPHE({
      algorithmName: ALGORITHM,
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
        algorithmName: ALGORITHM,
        keySize: 32,
        plaintextLimit: 1000,
      }).cs.plaintextModulo
    ).toBe(1024n);
    expect(
      new LightPHE({ algorithmName: ALGORITHM, keySize: 32 }).cs.plaintextModulo
    ).toBe(2n ** 24n);

    const bigCs = new LightPHE({
      algorithmName: ALGORITHM,
      keySize: 32,
      plaintextLimit: 2n ** 32n,
    });
    const m = 2n ** 32n - 7n;
    expect(bigCs.decrypt(bigCs.encrypt(m))).toBe(m);

    // no room for noise
    expect(
      () =>
        new LightPHE({
          algorithmName: ALGORITHM,
          keySize: 32,
          plaintextLimit: 2n ** 45n,
        })
    ).toThrow('too large for Lyubashevsky-Peikert-Regev');

    // ring degree must be a power of 2
    for (const keySize of [4, 48, 100]) {
      expect(() => new LightPHE({ algorithmName: ALGORITHM, keySize })).toThrow(
        'must be a power of 2'
      );
    }
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
    expect(cs.decrypt(total)).toBe((1000n * m) % modulo);

    // large and negative constants
    expect(cs.decrypt(c.multiply(4000))).toBe((4000n * m) % modulo);
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
      const expected = values.reduce((sum, v, i) => sum + v * weights[i], 0);
      expect(cs.decrypt(result)).toBe(pmod(BigInt(expected), modulo));
    }
  });

  it('does not support floats and tensors', () => {
    const c = cs.encrypt(5);
    expect(() => cs.encrypt(1.5)).toThrow(
      'Lyubashevsky-Peikert-Regev does not support float'
    );
    expect(() => cs.encrypt([1, 2, 3])).toThrow(
      'Lyubashevsky-Peikert-Regev does not support float'
    );
    expect(() => c.multiply(1.5)).toThrow(
      'Lyubashevsky-Peikert-Regev does not support float'
    );
  });

  it('works with predefined keys', () => {
    const restoredCs = new LightPHE({
      algorithmName: ALGORITHM,
      keys: cs.cs.keys,
    });
    const m1 = 11;
    const m2 = 7;
    const c1 = cs.encrypt(m1);
    const c2 = restoredCs.encrypt(m2);
    expect(restoredCs.decrypt(c1.add(c2))).toBe(BigInt(m1 + m2));
    expect(cs.decrypt(c1.add(c2))).toBe(BigInt(m1 + m2));
    logger.info('✅ Lyubashevsky-Peikert-Regev predefined keys test succeeded');
  });

  it('works with exported keys', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-lpr-'));
    const publicKeyFile = path.join(dir, 'public.txt');
    cs.exportKeys(publicKeyFile, true);

    const publicCs = new LightPHE({
      algorithmName: ALGORITHM,
      keyFile: publicKeyFile,
    });
    const c = publicCs.encrypt(42).multiply(2);
    expect(cs.decrypt(c)).toBe(84n);

    expect(() => publicCs.decrypt(c)).toThrow('private key');
  });

  it('works with large keys', () => {
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
    expect(large.decrypt(c1.multiply(1000))).toBe((m1 * 1000n) % modulo);
    expect(large.decrypt(c1.multiply(-1000).add(c2.multiply(3)))).toBe(
      pmod(-1000n * m1 + 3n * m2, modulo)
    );

    let total = large.encrypt(0);
    for (let i = 0; i < 1000; i++) {
      total = total.add(c1);
    }
    expect(large.decrypt(total)).toBe((1000n * m1) % modulo);

    logger.info(
      `✅ Lyubashevsky-Peikert-Regev 2048-degree test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });
});
