import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { LightPHE, Logger } from '../src';
import {
  BV_ETA,
  BV_LOG_Q,
  expand,
  polyMul,
} from '../src/cryptosystems/BrakerskiVaikuntanathan';
import {
  bitLength,
  pmod,
  randomBigInt,
  randomInt,
  valuesEqual,
} from './helpers';

const logger = new Logger('tests/brakerskivaikuntanathan.test.ts');

const ALGORITHM = 'Brakerski-Vaikuntanathan';
const cs = new LightPHE({ algorithmName: ALGORITHM, keySize: 64 });

// ring degree giving about 128-bit security against quantum attacks
let largeCs: LightPHE | undefined;
function getLargeCs(): LightPHE {
  largeCs ??= new LightPHE({ algorithmName: ALGORITHM, keySize: 4096 });
  return largeCs;
}

/** Schoolbook multiplication in `Z_q[x] / (x^d + 1)`. */
function negacyclicProduct(
  poly1: bigint[],
  poly2: bigint[],
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

describe('Brakerski-Vaikuntanathan', () => {
  it('is additively homomorphic and supports one multiplication', () => {
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

    // homomorphic multiplication
    expect(cs.decrypt(c1.multiply(c2))).toBe(BigInt(m1 * m2));

    // homomorphic scalar multiplication
    expect(cs.decrypt(c1.multiply(m2))).toBe(BigInt(m1 * m2));
    expect(cs.decrypt(c1.multiplyByConstant(m2))).toBe(BigInt(m1 * m2));

    // negative plaintexts and addition wrapping around the plaintext modulo
    const c3 = cs.encrypt(-5);
    expect(cs.decrypt(c3)).toBe(modulo - 5n);
    expect(cs.decrypt(c1.add(c3))).toBe(BigInt(m1 - 5));
    expect(cs.decrypt(c1.multiply(c3))).toBe(modulo - BigInt(5 * m1));
    expect(cs.decrypt(cs.encrypt(modulo - 1n).add(c1))).toBe(BigInt(m1 - 1));

    // re-randomization
    const c1Prime = cs.regenerateCiphertext(c1);
    expect(valuesEqual(c1Prime.value, c1.value)).toBe(false);
    expect(cs.decrypt(c1Prime)).toBe(BigInt(m1));

    // unsupported homomorphic operations
    expect(() => c1.xor(c2)).toThrow();
    expect(() => c1.and(c2)).toThrow();

    logger.info(
      `✅ Brakerski-Vaikuntanathan api test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });

  it('has well formed keys', () => {
    // b = -(a s + t e) where e is small
    const publicKey = cs.cs.keys.public_key!;
    const d = Number(publicKey.d as bigint);
    const q = publicKey.q as bigint;
    const t = publicKey.t as bigint;
    const b = publicKey.b as bigint[];
    const s = cs.cs.keys.private_key!.s as bigint[];
    const a = expand(publicKey.seed as bigint, d);

    expect(bitLength(q)).toBe(BV_LOG_Q);
    expect(q % 2n).toBe(1n);
    expect(t & (t - 1n)).toBe(0n);
    expect(s.every((x) => x >= -BV_ETA && x <= BV_ETA)).toBe(true);

    const aS = negacyclicProduct(
      a,
      s.map((x) => pmod(x, q)),
      q
    );
    aS.forEach((x, i) => {
      // t e = -(b + a s)
      let tE = pmod(-(x + b[i]), q);
      tE = tE > q / 2n ? tE - q : tE;
      expect(pmod(tE, t)).toBe(0n);
      const e = tE / t;
      expect(e >= -BigInt(BV_ETA) && e <= BigInt(BV_ETA)).toBe(true);
    });
  });

  it('multiplies polynomials', () => {
    const q = cs.cs.ciphertextModulo;
    for (const d of [8, 64]) {
      for (let round = 0; round < 10; round++) {
        const poly1 = Array.from({ length: d }, () => randomBigInt(q));
        const poly2 = Array.from({ length: d }, () => randomBigInt(q));
        expect(polyMul(poly1, poly2, d)).toEqual(
          negacyclicProduct(poly1, poly2, q)
        );
      }
    }
  });

  it('evaluates degree-2 functions', () => {
    const modulo = cs.cs.plaintextModulo;
    for (let round = 0; round < 50; round++) {
      const [x, y, z, k] = Array.from({ length: 4 }, () =>
        randomBigInt(modulo)
      );
      const cx = cs.encrypt(x);
      const cy = cs.encrypt(y);
      const cz = cs.encrypt(z);

      expect(cs.decrypt(cx.multiply(cx))).toBe(pmod(x * x, modulo));

      // product of sums, sums of products, and mixing products with fresh ciphertexts
      expect(cs.decrypt(cx.add(cy).multiply(cz))).toBe(
        pmod((x + y) * z, modulo)
      );
      expect(cs.decrypt(cx.multiply(cy).add(cz.multiply(cz)).add(cx))).toBe(
        pmod(x * y + z * z + x, modulo)
      );
      expect(cs.decrypt(cx.add(cx.multiply(cy)))).toBe(pmod(x + x * y, modulo));

      // constants before and after multiplication
      expect(cs.decrypt(cx.multiply(3).multiply(cy).multiply(k))).toBe(
        pmod(3n * x * y * k, modulo)
      );
      expect(cs.decrypt(cx.multiply(cy).multiply(-1))).toBe(
        pmod(-x * y, modulo)
      );
    }
  });

  it('supports only one multiplication', () => {
    const c1 = cs.encrypt(2);
    const c2 = cs.encrypt(3);
    const c3 = cs.encrypt(4);
    expect(() => c1.multiply(c2).multiply(c3)).toThrow(
      'only one multiplication'
    );
    expect(() => c1.multiply(c2.multiply(c3))).toThrow(
      'only one multiplication'
    );
  });

  it('respects the plaintext limit', () => {
    // rounded up to a power of 2
    expect(
      new LightPHE({
        algorithmName: ALGORITHM,
        keySize: 16,
        plaintextLimit: 1000,
      }).cs.plaintextModulo
    ).toBe(1024n);
    expect(cs.cs.plaintextModulo).toBe(2n ** 24n);

    const bigCs = new LightPHE({
      algorithmName: ALGORITHM,
      keySize: 16,
      plaintextLimit: 2 ** 32,
    });
    const x = 2n ** 32n - 7n;
    const y = 2n ** 31n + 5n;
    expect(bigCs.decrypt(bigCs.encrypt(x).multiply(bigCs.encrypt(y)))).toBe(
      pmod(x * y, 2n ** 32n)
    );

    // product of ciphertexts would not be decrypted correctly
    expect(
      () =>
        new LightPHE({
          algorithmName: ALGORITHM,
          keySize: 16,
          plaintextLimit: 2 ** 45,
        })
    ).toThrow('too large for Brakerski-Vaikuntanathan');

    for (const keySize of [4, 100]) {
      expect(() => new LightPHE({ algorithmName: ALGORITHM, keySize })).toThrow(
        'must be a power of 2'
      );
    }
  });

  it('does not support floats and tensors', () => {
    const c = cs.encrypt(5);
    const message = 'Brakerski-Vaikuntanathan does not support float';
    expect(() => cs.encrypt(1.5)).toThrow(message);
    expect(() => cs.encrypt([1, 2, 3])).toThrow(message);
    expect(() => c.multiply(1.5)).toThrow(message);
  });

  it('does not need Catalano-Fiore', () => {
    expect(
      () =>
        new LightPHE({
          algorithmName: ALGORITHM,
          keys: cs.cs.keys,
          boost: 'Catalano-Fiore',
        })
    ).toThrow('already supports one multiplication');
  });

  it('works with predefined keys', () => {
    const restoredCs = new LightPHE({
      algorithmName: ALGORITHM,
      keys: cs.cs.keys,
    });
    const c1 = cs.encrypt(11);
    const c2 = restoredCs.encrypt(7);
    expect(restoredCs.decrypt(c1.multiply(c2))).toBe(77n);
    expect(cs.decrypt(c1.add(c2))).toBe(18n);
    logger.info('✅ Brakerski-Vaikuntanathan predefined keys test succeeded');
  });

  it('works with exported keys', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-ts-'));
    const publicKeyFile = path.join(dir, 'public.txt');
    cs.exportKeys(publicKeyFile, true);

    // multiplication requires the public key only
    const publicCs = new LightPHE({
      algorithmName: ALGORITHM,
      keyFile: publicKeyFile,
    });
    const c = publicCs.encrypt(42).multiply(publicCs.encrypt(2));
    expect(cs.decrypt(c)).toBe(84n);

    expect(() => publicCs.decrypt(c)).toThrow('private key');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('works with 4096-degree keys', () => {
    const tic = Date.now();
    const large = getLargeCs();
    const modulo = large.cs.plaintextModulo;
    const xs = Array.from({ length: 5 }, () => randomInt(0, 1000));
    const ys = Array.from({ length: 5 }, () => randomInt(0, 1000));
    const encryptedXs = xs.map((x) => large.encrypt(x));
    const encryptedYs = ys.map((y) => large.encrypt(y));

    // dot product of encrypted vectors
    let encryptedDot = encryptedXs[0].multiply(encryptedYs[0]);
    for (let i = 1; i < 5; i++) {
      encryptedDot = encryptedDot.add(encryptedXs[i].multiply(encryptedYs[i]));
    }
    expect(large.decrypt(encryptedDot)).toBe(
      BigInt(xs.reduce((acc, x, i) => acc + x * ys[i], 0))
    );

    // full range plaintexts with constants after multiplication
    const x = randomBigInt(modulo);
    const y = randomBigInt(modulo);
    const product = large.encrypt(x).multiply(large.encrypt(y)).multiply(1000);
    expect(large.decrypt(product)).toBe(pmod(1000n * x * y, modulo));

    logger.info(
      `✅ Brakerski-Vaikuntanathan 4096-degree test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });

  it('runs the readme example', () => {
    const large = getLargeCs();
    const c1 = large.encrypt(15);
    const c2 = large.encrypt(25);
    const c3 = large.encrypt(100);

    // one multiplication, then additions and multiplications with constants
    expect(large.decrypt(c1.multiply(c2).add(c3))).toBe(475n);
    expect(
      large.decrypt(c1.multiply(c2).multiply(2).add(c1.multiply(c3)))
    ).toBe(2250n);
  });
});
