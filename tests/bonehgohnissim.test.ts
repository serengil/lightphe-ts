import { LightPHE, Logger, type BonehGohNissim } from '../src';
import { bitLength } from './helpers';

const logger = new Logger('tests/bonehgohnissim.test.ts');

const cs = new LightPHE({
  algorithmName: 'Boneh-Goh-Nissim',
  keySize: 50,
  maxTries: 10000,
});
const securityLevel = bitLength((cs.cs as BonehGohNissim).ec.n);

describe('Boneh-Goh-Nissim', () => {
  it('is additively homomorphic and multiplies once', () => {
    const started = Date.now();

    const m1 = 83;
    const m2 = 31;

    const c1 = cs.encrypt(m1);
    const c2 = cs.encrypt(m2);

    // proof of decryption
    expect(cs.decrypt(c1)).toBe(BigInt(m1));
    expect(cs.decrypt(c2)).toBe(BigInt(m2));

    // homomorphic addition
    expect(cs.decrypt(c1.add(c2))).toBe(
      BigInt(m1 + m2) % cs.cs.plaintextModulo
    );

    // homomorphic multiplication (once)
    const c1TimesC2 = c1.multiply(c2);
    expect(cs.decrypt(c1TimesC2)).toBe(BigInt(m1 * m2) % cs.cs.plaintextModulo);

    // scalar multiplication
    const k = 2;
    expect(cs.decrypt(c1.multiply(k))).toBe(
      BigInt(m1 * k) % cs.cs.plaintextModulo
    );

    // unsupported homomorphic operations
    expect(() => c1TimesC2.multiply(c2)).toThrow(
      'Boneh-Goh-Nissim only supports multiplication ciphertexts once!'
    );
    expect(() => c1.and(c2)).toThrow();
    expect(() => c1.xor(c2)).toThrow();

    // re-randomization
    const c1Prime = cs.cs.reencrypt(c1.value);
    const c2Prime = cs.cs.reencrypt(c2.value);
    expect(cs.cs.decrypt(c1Prime)).toBe(BigInt(m1));
    expect(cs.cs.decrypt(c2Prime)).toBe(BigInt(m2));

    logger.info(
      `✅ Boneh-Goh-Nissim test succeeded (${securityLevel} bit ECC security level)` +
        ` in ${(Date.now() - started) / 1000} seconds`
    );
  });

  it('evaluates an encrypted linear regression', () => {
    const started = Date.now();

    const x1 = 5;
    const w1 = 7;
    const x2 = 3;
    const w2 = 4;

    const x1Enc = cs.encrypt(x1);
    const w1Enc = cs.encrypt(w1);
    const x2Enc = cs.encrypt(x2);
    const w2Enc = cs.encrypt(w2);

    const x1w1Enc = x1Enc.multiply(w1Enc);
    const x2w2Enc = x2Enc.multiply(w2Enc);

    const sumEnc = x1w1Enc.add(x2w2Enc);

    expect(cs.decrypt(sumEnc)).toBe(BigInt(x1 * w1 + x2 * w2));

    // multiplication by constant
    expect(cs.decrypt(x1w1Enc.multiply(5))).toBe(BigInt(5 * x1 * w1));

    // unsupported homomorphic operations
    expect(() => x1w1Enc.multiply(w2Enc)).toThrow(
      'Boneh-Goh-Nissim only supports multiplication ciphertexts once!'
    );

    logger.info(
      '✅ Boneh-Goh-Nissim linear regression test succeeded ' +
        `(${securityLevel} bit ECC security level) in ${
          (Date.now() - started) / 1000
        } seconds`
    );
  });

  it('evaluates an encrypted cosine similarity', () => {
    const started = Date.now();

    // v1 = [5, 2, 8]
    const i1 = 5;
    const i2 = 2;
    const i3 = 8;

    // v2 = [1, 1, 2]
    const j1 = 1;
    const j2 = 1;
    const j3 = 2;

    const i1Enc = cs.encrypt(i1);
    const i2Enc = cs.encrypt(i2);
    const i3Enc = cs.encrypt(i3);

    const j1Enc = cs.encrypt(j1);
    const j2Enc = cs.encrypt(j2);
    const j3Enc = cs.encrypt(j3);

    // homomorphic operation
    const cosineSimEnc = i1Enc
      .multiply(j1Enc)
      .add(i2Enc.multiply(j2Enc))
      .add(i3Enc.multiply(j3Enc));

    // proof of work
    expect(cs.decrypt(cosineSimEnc)).toBe(BigInt(i1 * j1 + i2 * j2 + i3 * j3));

    logger.info(
      '✅ Boneh-Goh-Nissim cosine similarity test succeeded ' +
        `(${securityLevel} bit ECC security level) in ${
          (Date.now() - started) / 1000
        } seconds`
    );
  });

  it('evaluates an encrypted euclidean distance', () => {
    const started = Date.now();

    // v1 = [5, 2, 8]
    const i1 = 5;
    const i2 = 2;
    const i3 = 8;

    // v2 = [1, 1, 2]
    const j1 = 1;
    const j2 = 1;
    const j3 = 2;

    const i1Enc = cs.encrypt(i1);
    const i2Enc = cs.encrypt(i2);
    const i3Enc = cs.encrypt(i3);

    const j1Enc = cs.encrypt(-j1);
    const j2Enc = cs.encrypt(-j2);
    const j3Enc = cs.encrypt(-j3);

    const d1 = i1Enc.add(j1Enc);
    const d2 = i2Enc.add(j2Enc);
    const d3 = i3Enc.add(j3Enc);

    const euclideanSqrtEnc = d1
      .multiply(d1)
      .add(d2.multiply(d2))
      .add(d3.multiply(d3));

    expect(cs.decrypt(euclideanSqrtEnc)).toBe(
      BigInt((i1 - j1) ** 2 + (i2 - j2) ** 2 + (i3 - j3) ** 2)
    );

    logger.info(
      '✅ Boneh-Goh-Nissim euclidean distance test succeeded ' +
        `(${securityLevel} bit ECC security level) in ${
          (Date.now() - started) / 1000
        } seconds`
    );
  });

  it('works with pre-defined keys', () => {
    const keys = {
      private_key: { q1: 1260048562698661n, q2: 1495813357973021n },
      public_key: {
        curve: {
          a: 1n,
          b: 0n,
          p: 1477681217875020437035023206706703n,
          G: [
            404050258967758769169929337984186n,
            548422986186523785500578682099939n,
          ] as [bigint, bigint],
          n: 1884797471779362802340590824881n,
        },
        G: [
          404050258967758769169929337984186n,
          548422986186523785500578682099939n,
        ] as [bigint, bigint],
        u: [
          496699107331579016081758964967239n,
          1209427529257066171815901459972102n,
        ] as [bigint, bigint],
        h: [
          557434130026147587760748115479880n,
          109859910481881270030204038710204n,
        ] as [bigint, bigint],
        l: 784n,
      },
    };

    const bgnCs = new LightPHE({
      algorithmName: 'Boneh-Goh-Nissim',
      keys,
    });
    const level = bitLength((bgnCs.cs as BonehGohNissim).ec.n);

    const m1 = 3;
    const m2 = 2;

    const c1 = bgnCs.encrypt(m1);
    const c2 = bgnCs.encrypt(m2);

    // proof of decryption
    expect(bgnCs.decrypt(c1)).toBe(BigInt(m1));
    expect(bgnCs.decrypt(c2)).toBe(BigInt(m2));

    // homomorphic addition
    expect(bgnCs.decrypt(c1.add(c2))).toBe(
      BigInt(m1 + m2) % bgnCs.cs.plaintextModulo
    );

    // homomorphic multiplication
    const c1TimesC2 = c1.multiply(c2);
    expect(bgnCs.decrypt(c1TimesC2)).toBe(
      BigInt(m1 * m2) % bgnCs.cs.plaintextModulo
    );

    // scalar multiplication
    const k = 2;
    expect(bgnCs.decrypt(c1.multiply(k))).toBe(
      BigInt(m1 * k) % bgnCs.cs.plaintextModulo
    );

    // unsupported homomorphic operations
    expect(() => c1.and(c2)).toThrow();
    expect(() => c1.xor(c2)).toThrow();

    // re-randomization
    const c1Prime = bgnCs.cs.reencrypt(c1.value);
    const c2Prime = bgnCs.cs.reencrypt(c2.value);
    expect(bgnCs.cs.decrypt(c1Prime)).toBe(BigInt(m1));
    expect(bgnCs.cs.decrypt(c2Prime)).toBe(BigInt(m2));

    logger.info(
      `✅ Boneh-Goh-Nissim test succeeded (${level} bit ECC security level)`
    );
  });
});
