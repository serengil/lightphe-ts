import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import {
  CATALANO_FIORE_SUPPORTED_ALGORITHMS,
  CatalanoFioreCiphertext,
  LightPHE,
  Logger,
} from '../src';
import { deepClone, pmod, randomBigInt, randomInt } from './helpers';

const logger = new Logger('tests/catalanofiore.test.ts');

// plain cryptosystem, and the one supporting multiplication with the same keys
const cs = new LightPHE({ algorithmName: 'Paillier', keySize: 128 });
const cf = new LightPHE({
  algorithmName: 'Paillier',
  keys: cs.cs.keys,
  boost: 'Catalano-Fiore',
});

function sum(ciphertexts: CatalanoFioreCiphertext[]): CatalanoFioreCiphertext {
  return ciphertexts.reduce((acc, c) => acc.add(c));
}

function randomBits(bits: number): bigint {
  return randomBigInt(1n << BigInt(bits));
}

describe('Catalano-Fiore', () => {
  it.each(CATALANO_FIORE_SUPPORTED_ALGORITHMS)(
    'evaluates degree-2 functions on %s',
    (algorithmName) => {
      const tic = Date.now();
      const transform = new LightPHE({
        algorithmName,
        keySize: 64,
        boost: 'Catalano-Fiore',
      });
      const modulo = transform.cs.plaintextModulo;

      for (let round = 0; round < 5; round++) {
        const [x, y, z, k] = Array.from({ length: 4 }, () =>
          randomBigInt(modulo)
        );
        const cx = transform.encrypt(x);
        const cy = transform.encrypt(y);
        const cz = transform.encrypt(z);

        expect(transform.decrypt(cx)).toBe(x);
        expect(transform.decrypt(cx.add(cy))).toBe(pmod(x + y, modulo));
        expect(transform.decrypt(cx.multiply(k))).toBe(pmod(x * k, modulo));
        expect(transform.decrypt(cx.multiply(cy))).toBe(pmod(x * y, modulo));
        expect(transform.decrypt(cx.multiply(cx))).toBe(pmod(x * x, modulo));

        // x * y + k * z * x - y + 7
        const result = cx
          .multiply(cy)
          .add(cz.multiply(cx).multiply(k))
          .subtract(cy)
          .add(7);
        expect(transform.decrypt(result)).toBe(
          pmod(x * y + k * z * x - y + 7n, modulo)
        );
      }

      logger.info(
        `✅ Catalano-Fiore on ${algorithmName} succeeded in ${(Date.now() - tic) / 1000} seconds`
      );
    }
  );

  it('supports homomorphic operations', () => {
    const modulo = cf.cs.plaintextModulo;
    const c3 = cf.encrypt(3);
    const c4 = cf.encrypt(4);
    const c5 = cf.encrypt(5);

    // one multiplication, then additions and scalar multiplications
    expect(cf.decrypt(c3.multiply(c4).add(c5))).toBe(17n);
    expect(cf.decrypt(c3.multiply(c4).multiply(2).add(c3.multiply(c5)))).toBe(
      39n
    );
    expect(cf.decrypt(c3.multiply(c4).multiply(2))).toBe(24n);

    // plain constants
    expect(cf.decrypt(c3.add(10))).toBe(13n);
    expect(cf.decrypt(c3.multiply(c4).add(10))).toBe(22n);
    expect(cf.decrypt(c3.multiply(c4).subtract(2))).toBe(10n);

    // subtraction, negation and wrapping around the plaintext modulo
    expect(cf.decrypt(c3.subtract(c4))).toBe(modulo - 1n);
    expect(cf.decrypt(c3.negate())).toBe(modulo - 3n);
    expect(cf.decrypt(c3.multiply(c4).subtract(c5.multiply(c5)))).toBe(
      modulo - 13n
    );
    expect(cf.decrypt(c3.multiply(c4).negate().add(20))).toBe(8n);

    // sums of products and non-multiplied ciphertexts
    expect(cf.decrypt(sum([c3.multiply(c4), c5, c3]))).toBe(20n);

    // negative and zero plaintexts, and multiplication with zero
    expect(cf.decrypt(cf.encrypt(-6))).toBe(modulo - 6n);
    expect(cf.decrypt(cf.encrypt(-6).multiply(c4))).toBe(modulo - 24n);
    expect(cf.decrypt(cf.encrypt(0).multiply(c4))).toBe(0n);
    expect(cf.decrypt(c3.multiply(c4).multiply(0))).toBe(0n);
  });

  it('randomizes ciphertexts', () => {
    const c1 = cf.encrypt(5);
    const c2 = cf.encrypt(5);
    expect(c1.a).not.toBe(c2.a);
    expect(c1.beta!.value).not.toBe(c2.beta!.value);
    expect(cf.decrypt(c1)).toBe(5n);
    expect(cf.decrypt(c2)).toBe(5n);
  });

  it('does not put the private key into ciphertexts', () => {
    const c = cf.encrypt(5).multiply(cf.encrypt(6)).add(cf.encrypt(7));
    expect(c.cf.cs.cs.keys.private_key).toBeUndefined();
    expect(c.alpha!.keys.private_key).toBeUndefined();

    // ciphertexts can be evaluated by another party, and still be decrypted by the key owner
    expect(cf.decrypt(c.add(cf.encrypt(1)))).toBe(38n);
  });

  it('computes dot products of encrypted vectors', () => {
    const xs = Array.from({ length: 10 }, () => randomInt(0, 1000));
    const ys = Array.from({ length: 10 }, () => randomInt(0, 1000));
    const encryptedXs = xs.map((x) => cf.encrypt(x));
    const encryptedYs = ys.map((y) => cf.encrypt(y));

    const result = sum(encryptedXs.map((ex, i) => ex.multiply(encryptedYs[i])));
    expect(cf.decrypt(result)).toBe(
      BigInt(xs.reduce((acc, x, i) => acc + x * ys[i], 0))
    );

    // a pair of ciphertexts is kept for every product
    expect(result.pairs.length).toBe(10);
  });

  it('supports only one multiplication', () => {
    const c1 = cf.encrypt(2);
    const c2 = cf.encrypt(3);
    const c3 = cf.encrypt(4);
    expect(() => c1.multiply(c2).multiply(c3)).toThrow(
      'only one multiplication'
    );
    expect(() => c1.multiply(c2.multiply(c3))).toThrow(
      'only one multiplication'
    );
  });

  it('encrypts and evaluates with the public key only', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-ts-'));
    const publicKeyFile = path.join(dir, 'public.txt');
    cs.exportKeys(publicKeyFile, true);

    // server encrypts and evaluates with the public key only
    const serverCf = new LightPHE({
      algorithmName: 'Paillier',
      keyFile: publicKeyFile,
      boost: 'Catalano-Fiore',
    });
    const c1 = cf.encrypt(6);
    const c2 = serverCf.encrypt(7);
    const result = c1.multiply(c2).add(serverCf.encrypt(8));

    expect(() => serverCf.decrypt(result)).toThrow('You must have private key');
    expect(cf.decrypt(result)).toBe(50n);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('rejects invalid inputs', () => {
    const c = cf.encrypt(5);

    for (const plaintext of [1.5, [1, 2], '5', true]) {
      expect(() => cf.encrypt(plaintext as unknown as number)).toThrow(
        'integers only'
      );
    }

    expect(() => c.multiply(1.5)).toThrow(
      'multiplied with a ciphertext or an integer'
    );
    expect(() => c.add(1.5)).toThrow('added to a ciphertext or an integer');
    expect(() => cf.regenerateCiphertext(c)).toThrow('cannot be regenerated');

    const otherCf = new LightPHE({
      algorithmName: 'Paillier',
      keySize: 128,
      boost: 'Catalano-Fiore',
    });
    expect(() => c.add(otherCf.encrypt(1))).toThrow('different cryptosystems');
  });

  it.each([
    ['Exponential-ElGamal', 'discrete logarithm'],
    ['EllipticCurve-ElGamal', 'discrete logarithm'],
    ['Okamoto-Uchiyama', 'plaintext modulus p is secret'],
    ['Regev', 'noise budget'],
    ['Lyubashevsky-Peikert-Regev', 'noise budget'],
    ['Goldwasser-Micali', 'xor only'],
    ['ML-KEM', 'xor only'],
    ['Gentry-Sahai-Waters', 'multiplications of bits'],
    ['Boneh-Goh-Nissim', 'already supports one multiplication'],
    ['RSA', 'not additively homomorphic'],
    ['ElGamal', 'not additively homomorphic'],
  ])('does not support %s', (algorithmName, reason) => {
    let keySize = ['Regev', 'Lyubashevsky-Peikert-Regev'].includes(
      algorithmName
    )
      ? 16
      : 64;
    if (algorithmName === 'ML-KEM') {
      keySize = 512;
    }
    if (algorithmName === 'Gentry-Sahai-Waters') {
      keySize = 16;
    }
    expect(
      () => new LightPHE({ algorithmName, keySize, boost: 'Catalano-Fiore' })
    ).toThrow(
      new RegExp(`does not support ${algorithmName} because .*${reason}`)
    );
  });

  it('rejects unknown boosts', () => {
    expect(
      () =>
        new LightPHE({
          algorithmName: 'Paillier',
          keySize: 64,
          boost: 'something',
        })
    ).toThrow('Unknown boost');
  });

  it('does not change the default behaviour', () => {
    // no boost by default, so ciphertexts are regular ones
    const keys = deepClone(cs.cs.keys);
    const c1 = cs.encrypt(5);
    cf.encrypt(5).multiply(cf.encrypt(6));
    expect(cs.cs.keys).toEqual(keys);
    expect(cs.decrypt(c1.add(cs.encrypt(3)))).toBe(8n);
    expect(cs.decrypt(cs.encrypt(1.5).multiply(2))).toBe(3n);
    expect(() => c1.multiply(cs.encrypt(3))).toThrow();

    // each one decrypts ciphertexts of the other, as they have the same keys
    expect(cf.decrypt(c1)).toBe(5n);
    expect(cs.decrypt(cf.encrypt(5).multiply(cf.encrypt(6)))).toBe(30n);
  });

  it('works with 1024-bit keys', () => {
    const tic = Date.now();
    const largeCf = new LightPHE({
      algorithmName: 'Paillier',
      keySize: 1024,
      boost: 'Catalano-Fiore',
    });
    const x = randomBits(400);
    const y = randomBits(400);
    expect(
      largeCf.decrypt(largeCf.encrypt(x).multiply(largeCf.encrypt(y)))
    ).toBe(x * y);
    logger.info(
      `✅ Catalano-Fiore 1024-bit key test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });

  it('runs the readme example', () => {
    // client builds a cryptosystem supporting multiplication, and encrypts its private vectors
    const clientCs = new LightPHE({
      algorithmName: 'Paillier',
      keySize: 256,
      boost: 'Catalano-Fiore',
    });

    const x = [3, 1, 4];
    const y = [1, 5, 9];
    const encryptedX = x.map((value) => clientCs.encrypt(value));
    const encryptedY = y.map((value) => clientCs.encrypt(value));

    // server computes dot product of encrypted vectors, ciphertexts carry the public key only
    const encryptedDot = sum(
      encryptedX.map((ex, i) => ex.multiply(encryptedY[i]))
    );

    // squared euclidean distance is also a degree-2 function
    const encryptedDistance = sum(
      encryptedX.map((ex, i) => {
        const difference = ex.subtract(encryptedY[i]);
        return difference.multiply(difference);
      })
    );

    // client decrypts the results
    expect(clientCs.decrypt(encryptedDot)).toBe(44n);
    expect(clientCs.decrypt(encryptedDistance)).toBe(45n);

    // multiplying again is not supported
    expect(() => encryptedDot.multiply(encryptedX[0])).toThrow(
      'only one multiplication'
    );
  });
});
