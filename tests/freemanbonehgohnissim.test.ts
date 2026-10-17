import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { FreemanBonehGohNissim, LightPHE, Logger } from '../src';
import { bitLength, pmod, randomInt, valuesEqual } from './helpers';

const logger = new Logger('tests/freemanbonehgohnissim.test.ts');

const ALGORITHM = 'Freeman-Boneh-Goh-Nissim';
const cs = new LightPHE({ algorithmName: ALGORITHM, keySize: 64 });

describe('Freeman-Boneh-Goh-Nissim', () => {
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

    // negative plaintexts
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
      `✅ Freeman-Boneh-Goh-Nissim api test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });

  it('has well formed keys', () => {
    const fbgn = cs.cs as FreemanBonehGohNissim;
    const publicKey = fbgn.keys.public_key!;
    const p = publicKey.p as bigint;
    const r = publicKey.r as bigint;
    const ec = fbgn.ec;

    // p + 1 points on y^2 = x^3 + x, and the generator has prime order r
    expect(p % 4n).toBe(3n);
    expect((p + 1n) % r).toBe(0n);
    expect(
      ec.G.multiply(r - 1n)
        .add(ec.G)
        .isIdentity()
    ).toBe(true);

    // projection v vanishes on h1 and h2, but not on g
    expect(fbgn.project(fbgn.publicPoints('h1')).isIdentity()).toBe(true);
    expect(fbgn.project(fbgn.publicPoints('h2')).isIdentity()).toBe(true);
    expect(fbgn.project(fbgn.publicPoints('g')).isIdentity()).toBe(false);
  });

  it('evaluates degree-2 functions', () => {
    const modulo = cs.cs.plaintextModulo;
    for (let round = 0; round < 20; round++) {
      const [x, y, z] = Array.from({ length: 3 }, () =>
        BigInt(randomInt(-100, 100))
      );
      const k = BigInt(randomInt(-20, 20));
      const cx = cs.encrypt(x);
      const cy = cs.encrypt(y);
      const cz = cs.encrypt(z);

      expect(cs.decrypt(cx.multiply(cx))).toBe(pmod(x * x, modulo));
      expect(cs.decrypt(cx.add(cy).multiply(cz))).toBe(
        pmod((x + y) * z, modulo)
      );

      // multiplied ciphertexts can be added with each other and with fresh ciphertexts
      expect(cs.decrypt(cx.multiply(cy).add(cz.multiply(cz)))).toBe(
        pmod(x * y + z * z, modulo)
      );
      expect(cs.decrypt(cx.multiply(cy).add(cz))).toBe(pmod(x * y + z, modulo));
      expect(cs.decrypt(cz.add(cx.multiply(cy)))).toBe(pmod(z + x * y, modulo));

      // constants before and after multiplication, including zero
      expect(cs.decrypt(cx.multiply(k).multiply(cy))).toBe(
        pmod(k * x * y, modulo)
      );
      expect(cs.decrypt(cx.multiply(cy).multiply(k))).toBe(
        pmod(k * x * y, modulo)
      );
      expect(cs.decrypt(cx.multiply(0))).toBe(0n);
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
    expect(() => cs.regenerateCiphertext(c1.multiply(c2))).toThrow(
      'non-multiplied ciphertexts only'
    );
  });

  it('respects the plaintext limit', () => {
    expect(cs.cs.keys.public_key!.limit).toBe(2n ** 20n);

    const smallCs = new LightPHE({
      algorithmName: ALGORITHM,
      keySize: 64,
      plaintextLimit: 100,
    });
    expect(smallCs.decrypt(smallCs.encrypt(100))).toBe(100n);
    expect(smallCs.decrypt(smallCs.encrypt(-100))).toBe(
      smallCs.cs.plaintextModulo - 100n
    );
    expect(
      smallCs.decrypt(smallCs.encrypt(10).multiply(smallCs.encrypt(10)))
    ).toBe(100n);

    // results out of the limit cannot be restored
    expect(() => smallCs.decrypt(smallCs.encrypt(101))).toThrow('out of');
    expect(() =>
      smallCs.decrypt(smallCs.encrypt(11).multiply(smallCs.encrypt(10)))
    ).toThrow('out of');

    expect(
      () =>
        new LightPHE({
          algorithmName: ALGORITHM,
          keySize: 64,
          plaintextLimit: 2 ** 40,
        })
    ).toThrow('too large');

    expect(
      () => new LightPHE({ algorithmName: ALGORITHM, keySize: 16 })
    ).toThrow('too small');
  });

  it('does not support floats and tensors', () => {
    const c = cs.encrypt(5);
    const message = 'Freeman-Boneh-Goh-Nissim does not support float';
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
    logger.info('✅ Freeman-Boneh-Goh-Nissim predefined keys test succeeded');
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
      .encrypt(42)
      .multiply(publicCs.encrypt(2))
      .add(publicCs.encrypt(1));
    expect(cs.decrypt(c)).toBe(85n);

    expect(() => publicCs.decrypt(c)).toThrow('private key');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('works with 1024-bit keys', () => {
    const tic = Date.now();
    const largeCs = new LightPHE({ algorithmName: ALGORITHM, keySize: 1024 });
    expect(bitLength(largeCs.cs.keys.public_key!.r as bigint)).toBe(256);

    const c1 = largeCs.encrypt(123);
    const c2 = largeCs.encrypt(-456);
    const modulo = largeCs.cs.plaintextModulo;
    expect(largeCs.decrypt(c1.add(c2))).toBe(modulo - 333n);
    expect(largeCs.decrypt(c1.multiply(c2).add(c1))).toBe(
      modulo - 123n * 456n + 123n
    );

    logger.info(
      `✅ Freeman-Boneh-Goh-Nissim 1024-bit key test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });
});
