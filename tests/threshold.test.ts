import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { LightPHE, Logger, mathUtils } from '../src';
import { jsonRoundTrip } from './helpers';

const logger = new Logger('tests/threshold.test.ts');

const THRESHOLD = 3;
const PARTIES = 5;

const ADDITIVE_ALGORITHMS: Array<[string, number | null]> = [
  ['Exponential-ElGamal', 50],
  ['EllipticCurve-ElGamal', null],
  ['Paillier', 50],
  ['Damgard-Jurik', 50],
];

/** Builds a dealer, a public cryptosystem with threshold parameters and shareholders. */
function build(
  algorithmName: string,
  keySize: number | null = null
): [LightPHE, LightPHE[]] {
  const dealerCs = new LightPHE({
    algorithmName,
    keySize,
    primeOrder: ['ElGamal', 'Exponential-ElGamal'].includes(algorithmName),
  });
  const shareKeys = dealerCs.generateThresholdKeys(THRESHOLD, PARTIES);
  const shareholders = shareKeys.map(
    (keys) => new LightPHE({ algorithmName, keys })
  );
  return [dealerCs, shareholders];
}

/** Every subset of the given size, like Python's `itertools.combinations`. */
function combinations<T>(items: readonly T[], size: number): T[][] {
  if (size === 0) {
    return [[]];
  }
  return items.flatMap((item, i) =>
    combinations(items.slice(i + 1), size - 1).map((rest) => [item, ...rest])
  );
}

describe('threshold decryption', () => {
  it.each(ADDITIVE_ALGORITHMS)(
    'decrypts with any threshold many shareholders for %s',
    (algorithmName, keySize) => {
      const [dealerCs, shareholders] = build(algorithmName, keySize);

      const m1 = 17;
      const m2 = 21;
      const k = 3;
      const c1 = dealerCs.encrypt(m1);
      const c2 = dealerCs.encrypt(m2);

      // homomorphic operations before threshold decryption
      for (const [c, expected] of [
        [c1, m1],
        [c1.add(c2), m1 + m2],
        [c1.multiply(k), m1 * k],
      ] as const) {
        const partials = shareholders.map((shareholder) =>
          shareholder.partialDecrypt(c)
        );

        // any threshold many shareholders can decrypt
        for (const subset of combinations(partials, THRESHOLD)) {
          expect(dealerCs.combinePartialDecryptions(c, subset)).toBe(
            BigInt(expected)
          );
        }

        // more than threshold many partial decryptions are fine as well
        expect(dealerCs.combinePartialDecryptions(c, partials)).toBe(
          BigInt(expected)
        );

        // less than threshold many partial decryptions are rejected
        expect(() =>
          dealerCs.combinePartialDecryptions(
            c,
            partials.slice(0, THRESHOLD - 1)
          )
        ).toThrow('At least');
      }

      // regenerated ciphertexts are decrypted as well
      const c3 = dealerCs.regenerateCiphertext(c1);
      const partials = shareholders
        .slice(0, THRESHOLD)
        .map((shareholder) => shareholder.partialDecrypt(c3));
      expect(dealerCs.combinePartialDecryptions(c3, partials)).toBe(BigInt(m1));

      logger.info(
        `✅ Threshold decryption test succeeded for ${algorithmName}`
      );
    }
  );

  it('decrypts multiplicative ElGamal', () => {
    const [dealerCs, shareholders] = build('ElGamal', 50);

    const m1 = 17;
    const m2 = 21;
    const c = dealerCs.encrypt(m1).multiply(dealerCs.encrypt(m2));

    const partials = shareholders.map((shareholder) =>
      shareholder.partialDecrypt(c)
    );
    for (const subset of combinations(partials, THRESHOLD)) {
      expect(dealerCs.combinePartialDecryptions(c, subset)).toBe(
        BigInt(m1 * m2)
      );
    }
  });

  it.each(['Paillier', 'Damgard-Jurik'])(
    'decrypts negative and float values for %s',
    (algorithmName) => {
      const [dealerCs, shareholders] = build(algorithmName, 50);
      const modulo = dealerCs.cs.plaintextModulo;

      let c = dealerCs.encrypt(-5);
      let partials = shareholders
        .slice(0, THRESHOLD)
        .map((shareholder) => shareholder.partialDecrypt(c));
      expect(dealerCs.combinePartialDecryptions(c, partials)).toBe(modulo - 5n);

      // float is restored as dividend * divisor^-1 mod modulo, same as decrypt
      c = dealerCs.encrypt(1.5);
      partials = shareholders
        .slice(0, THRESHOLD)
        .map((shareholder) => shareholder.partialDecrypt(c));
      expect(dealerCs.combinePartialDecryptions(c, partials)).toBe(
        (15n * mathUtils.modInverse(10n, modulo)) % modulo
      );
    }
  );

  it('decrypts tensors', () => {
    const [dealerCs, shareholders] = build('Paillier', 128);

    const tensor = [1.005, 2.05, -3.5, 4, 0];
    const encrypted = dealerCs.encrypt(tensor, { silent: true });

    const partials = shareholders
      .slice(1, 4)
      .map((shareholder) => shareholder.partialDecrypt(encrypted));
    const restored = dealerCs.combinePartialDecryptions(encrypted, partials);
    restored.forEach((value, i) => expect(value).toBeCloseTo(tensor[i], 3));
  });

  it('drops the private key and shares the public key', () => {
    const [dealerCs, shareholders] = build('Paillier', 50);

    // dealer forgets the private key
    expect(dealerCs.cs.keys.private_key).toBeUndefined();
    expect(() => dealerCs.decrypt(dealerCs.encrypt(1))).toThrow('private key');

    // shareholders cannot decrypt alone, and do not have the private key
    const c = dealerCs.encrypt(42);
    for (const shareholder of shareholders) {
      expect(shareholder.cs.keys.private_key).toBeUndefined();
      expect(() => shareholder.decrypt(c)).toThrow('private key');
    }

    // dealer cannot generate threshold keys again
    expect(() => dealerCs.generateThresholdKeys(THRESHOLD, PARTIES)).toThrow(
      'private key'
    );

    // anyone having the exported public key can combine partial decryptions
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-threshold-'));
    const publicFile = path.join(dir, 'public.json');
    dealerCs.exportKeys(publicFile, true);
    const publicCs = new LightPHE({
      algorithmName: 'Paillier',
      keyFile: publicFile,
    });
    expect(() => publicCs.partialDecrypt(c)).toThrow('threshold key');

    // keys of shareholders and partial decryptions survive json round trip
    const shareFile = path.join(dir, 'share.json');
    shareholders[0].exportKeys(shareFile);
    const restoredShareholder = new LightPHE({
      algorithmName: 'Paillier',
      keyFile: shareFile,
    });
    const partials = jsonRoundTrip([
      restoredShareholder.partialDecrypt(c),
      ...shareholders
        .slice(1, THRESHOLD)
        .map((shareholder) => shareholder.partialDecrypt(c)),
    ]);
    expect(publicCs.combinePartialDecryptions(c, partials)).toBe(42n);
  });

  it('rejects invalid inputs', () => {
    const [dealerCs, shareholders] = build('Paillier', 50);
    const c = dealerCs.encrypt(7);
    const partials = shareholders.map((shareholder) =>
      shareholder.partialDecrypt(c)
    );

    // same party counted once
    expect(() =>
      dealerCs.combinePartialDecryptions(c, Array(THRESHOLD).fill(partials[0]))
    ).toThrow('distinct');

    // conflicting partial decryptions of same party
    const forged = {
      index: partials[0].index,
      value: (partials[0].value as bigint) + 1n,
    };
    expect(() =>
      dealerCs.combinePartialDecryptions(c, [partials[0], forged, partials[1]])
    ).toThrow('Conflicting');

    // unknown party
    expect(() =>
      dealerCs.combinePartialDecryptions(c, [
        ...partials.slice(0, 2),
        { index: PARTIES + 1, value: 1n },
      ])
    ).toThrow('Index');

    for (const [threshold, parties] of [
      [0, 5],
      [6, 5],
    ]) {
      const cs = new LightPHE({ algorithmName: 'Paillier', keySize: 50 });
      expect(() => cs.generateThresholdKeys(threshold, parties)).toThrow();
    }
  });

  it('supports a threshold of one and of all parties', () => {
    for (const [threshold, parties] of [
      [1, 3],
      [3, 3],
    ]) {
      const dealerCs = new LightPHE({
        algorithmName: 'Exponential-ElGamal',
        keySize: 50,
        primeOrder: true,
      });
      const shareKeys = dealerCs.generateThresholdKeys(threshold, parties);
      const shareholders = shareKeys.map(
        (keys) => new LightPHE({ algorithmName: 'Exponential-ElGamal', keys })
      );
      const c = dealerCs.encrypt(10);
      const partials = shareholders.map((shareholder) =>
        shareholder.partialDecrypt(c)
      );
      expect(
        dealerCs.combinePartialDecryptions(c, partials.slice(0, threshold))
      ).toBe(10n);
    }
  });

  it('rejects ElGamal keys without prime order', () => {
    for (const algorithmName of ['ElGamal', 'Exponential-ElGamal']) {
      // default key generation is unchanged and does not have q
      const cs = new LightPHE({ algorithmName, keySize: 50 });
      expect('q' in cs.cs.keys.public_key!).toBe(false);
      expect(() => cs.generateThresholdKeys(THRESHOLD, PARTIES)).toThrow(
        'prime_order=True'
      );

      // private key is kept if threshold keys cannot be generated
      const c = cs.encrypt(2);
      expect(cs.decrypt(c)).toBe(2n);
    }
  });

  it('generates prime order ElGamal keys', () => {
    for (const algorithmName of ['ElGamal', 'Exponential-ElGamal']) {
      const cs = new LightPHE({ algorithmName, keySize: 50, primeOrder: true });
      const publicKey = cs.cs.keys.public_key!;
      const p = publicKey.p as bigint;
      const g = publicKey.g as bigint;
      const q = publicKey.q as bigint;
      expect((p - 1n) % q).toBe(0n);
      expect(g).not.toBe(1n);
      expect(mathUtils.modPow(g, q, p)).toBe(1n);

      // classic usage works with prime order keys as well
      const c1 = cs.encrypt(17);
      const c2 = cs.encrypt(21);
      if (algorithmName === 'ElGamal') {
        expect(cs.decrypt(c1.multiply(c2))).toBe(17n * 21n);
      } else {
        expect(cs.decrypt(c1.add(c2))).toBe(17n + 21n);
        expect(cs.decrypt(c1.multiply(3))).toBe(17n * 3n);
      }
    }
  });

  it('rejects unsupported algorithms', () => {
    for (const algorithmName of [
      'RSA',
      'Okamoto-Uchiyama',
      'Goldwasser-Micali',
    ]) {
      const cs = new LightPHE({ algorithmName, keySize: 50 });
      expect(() => cs.generateThresholdKeys(THRESHOLD, PARTIES)).toThrow(
        'does not support threshold decryption'
      );
    }
  });
});
