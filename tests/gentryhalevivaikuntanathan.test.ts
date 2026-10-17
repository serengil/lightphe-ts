import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { GHV_INSECURE_WARNING_MSG, LightPHE, Logger } from '../src';
import {
  bitLength,
  pmod,
  randomBigInt,
  randomInt,
  valuesEqual,
} from './helpers';

const logger = new Logger('tests/gentryhalevivaikuntanathan.test.ts');

const ALGORITHM = 'Gentry-Halevi-Vaikuntanathan';

// smallest lattice dimension keeps tests fast. it is for learning purposes only anyway.
const cs = new LightPHE({ algorithmName: ALGORITHM, keySize: 2 });

describe('Gentry-Halevi-Vaikuntanathan', () => {
  it('is additively homomorphic and supports one multiplication', () => {
    const tic = Date.now();
    const modulo = cs.cs.plaintextModulo;

    const m1 = 7;
    const m2 = 9;

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
    expect(cs.decrypt(c1.multiply(3))).toBe(BigInt(m1 * 3));
    expect(cs.decrypt(c1.multiplyByConstant(3))).toBe(BigInt(m1 * 3));

    // negative plaintexts and wrapping around the plaintext modulo
    const c3 = cs.encrypt(-5);
    expect(cs.decrypt(c3)).toBe(modulo - 5n);
    expect(cs.decrypt(c1.add(c3))).toBe(BigInt(m1 - 5));
    expect(cs.decrypt(c1.multiply(c3))).toBe(modulo - BigInt(5 * m1));

    // re-randomization
    const c1Prime = cs.regenerateCiphertext(c1);
    expect(valuesEqual(c1Prime.value, c1.value)).toBe(false);
    expect(cs.decrypt(c1Prime)).toBe(BigInt(m1));

    // unsupported homomorphic operations
    expect(() => c1.xor(c2)).toThrow();
    expect(() => c1.and(c2)).toThrow();

    logger.info(
      `✅ Gentry-Halevi-Vaikuntanathan api test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });

  it('warns that it is insecure', () => {
    const warnings: string[] = [];
    const spy = jest
      .spyOn(Logger.prototype, 'warn')
      .mockImplementation((message: string) => {
        warnings.push(message);
      });
    try {
      new LightPHE({ algorithmName: ALGORITHM, keys: cs.cs.keys });
      expect(warnings).toEqual([GHV_INSECURE_WARNING_MSG]);
      expect(warnings[0]).toContain('learning purposes only');

      // other algorithms do not warn
      new LightPHE({ algorithmName: 'Paillier', keySize: 64 });
      expect(warnings.length).toBe(1);
    } finally {
      spy.mockRestore();
    }
  });

  it('has well formed keys', () => {
    const a = cs.cs.keys.public_key!.A as bigint[][];
    const q = cs.cs.keys.public_key!.q as bigint;
    const p = cs.cs.keys.public_key!.p as bigint;
    const t = cs.cs.keys.private_key!.T as bigint[][];
    const u = cs.cs.keys.private_key!.u as bigint[];
    const m = a.length;

    // trapdoor T is square, short, and T A = 0 mod q
    expect(t.length).toBe(m);
    expect(t.every((row) => row.length === m)).toBe(true);
    const maxEntry = t
      .flat()
      .reduce(
        (acc, x) => (x < 0n ? (-x > acc ? -x : acc) : x > acc ? x : acc),
        0n
      );
    expect(maxEntry < BigInt(bitLength(q) * m)).toBe(true);
    for (const row of t) {
      for (let column = 0; column < a[0].length; column++) {
        const sum = row.reduce((acc, x, i) => acc + x * a[i][column], 0n);
        expect(pmod(sum, q)).toBe(0n);
      }
    }

    // u is the first row of T^-1 modulo p
    for (let j = 0; j < m; j++) {
      const expected = j === 0 ? 1n : 0n;
      const sum = u.reduce((acc, x, i) => acc + x * t[i][j], 0n);
      expect(pmod(sum, p)).toBe(expected);
    }

    expect(q & (q - 1n)).toBe(0n);
    expect(p % 2n).toBe(1n);
  });

  it('evaluates degree-2 functions', () => {
    const modulo = cs.cs.plaintextModulo;
    for (let round = 0; round < 10; round++) {
      const [x, y, z] = Array.from({ length: 3 }, () => randomBigInt(modulo));
      const half = Number(modulo / 2n);
      const k = BigInt(randomInt(-half, half));
      const cx = cs.encrypt(x);
      const cy = cs.encrypt(y);
      const cz = cs.encrypt(z);

      expect(cs.decrypt(cx.multiply(cx))).toBe(pmod(x * x, modulo));
      expect(cs.decrypt(cx.add(cy).multiply(cz))).toBe(
        pmod((x + y) * z, modulo)
      );

      // multiplied ciphertexts can be added with each other and with fresh ciphertexts
      expect(cs.decrypt(cx.multiply(cy).add(cz.multiply(cz)).add(cx))).toBe(
        pmod(x * y + z * z + x, modulo)
      );

      // constants before and after multiplication
      expect(cs.decrypt(cx.multiply(k).multiply(cy))).toBe(
        pmod(k * x * y, modulo)
      );
      expect(cs.decrypt(cx.multiply(cy).multiply(k))).toBe(
        pmod(k * x * y, modulo)
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

  it('validates key size and plaintext limit', () => {
    for (const keySize of [1, 9, 1024]) {
      expect(() => new LightPHE({ algorithmName: ALGORITHM, keySize })).toThrow(
        'for learning purposes only'
      );
    }

    expect(cs.cs.plaintextModulo).toBe(101n);

    // plaintext modulus is the smallest prime greater than or equal to the limit
    const bigCs = new LightPHE({
      algorithmName: ALGORITHM,
      keySize: 2,
      plaintextLimit: 1000,
    });
    expect(bigCs.cs.plaintextModulo).toBe(1009n);
    expect(
      bigCs.decrypt(bigCs.encrypt(1000).multiply(bigCs.encrypt(999)))
    ).toBe((1000n * 999n) % 1009n);
  });

  it('does not support floats and tensors', () => {
    const c = cs.encrypt(5);
    expect(() => cs.encrypt(1.5)).toThrow('does not support float');
    expect(() => cs.encrypt([1, 2, 3])).toThrow('does not support float');
    expect(() => c.multiply(1.5)).toThrow('does not support float');
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

  it('works with exported keys', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-ts-'));
    const publicKeyFile = path.join(dir, 'public.txt');
    cs.exportKeys(publicKeyFile, true);

    // multiplication requires the public key only
    const publicCs = new LightPHE({
      algorithmName: ALGORITHM,
      keyFile: publicKeyFile,
    });
    const c = publicCs
      .encrypt(4)
      .multiply(publicCs.encrypt(5))
      .add(publicCs.encrypt(1));
    expect(cs.decrypt(c)).toBe(21n);

    expect(() => publicCs.decrypt(c)).toThrow('private key');

    // private key restored from file
    const privateKeyFile = path.join(dir, 'private.txt');
    cs.exportKeys(privateKeyFile);
    const restoredCs = new LightPHE({
      algorithmName: ALGORITHM,
      keyFile: privateKeyFile,
    });
    expect(restoredCs.decrypt(c)).toBe(21n);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('works with the default key size', () => {
    const tic = Date.now();
    const defaultCs = new LightPHE({ algorithmName: ALGORITHM });
    expect((defaultCs.cs.keys.public_key!.A as bigint[][])[0].length).toBe(4);

    const c1 = defaultCs.encrypt(12);
    const c2 = defaultCs.encrypt(34);
    const c3 = defaultCs.encrypt(56);
    expect(defaultCs.decrypt(c1.multiply(c2).add(c3))).toBe(
      BigInt((12 * 34 + 56) % 101)
    );

    logger.info(
      `✅ Gentry-Halevi-Vaikuntanathan default key size test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });
});
