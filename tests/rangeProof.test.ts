import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { Ciphertext, LightPHE, Logger, type RangeProof } from '../src';
import * as zkp from '../src/commons/zkp';
import { deepClone, jsonRoundTrip } from './helpers';

const logger = new Logger('tests/rangeProof.test.ts');

const ALGORITHMS: Array<[string, number | null, boolean]> = [
  ['Exponential-ElGamal', 128, true],
  ['EllipticCurve-ElGamal', null, false],
  ['Paillier', 128, false],
  ['Damgard-Jurik', 128, false],
];

function build(
  algorithmName: string,
  keySize: number | null,
  primeOrder: boolean
): LightPHE {
  return new LightPHE({ algorithmName, keySize, primeOrder });
}

describe('range proofs', () => {
  it.each(ALGORITHMS)(
    'proves a range for %s',
    (algorithmName, keySize, primeOrder) => {
      const cs = build(algorithmName, keySize, primeOrder);

      // prover and verifier have the public key only
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-range-'));
      const publicFile = path.join(dir, 'public.json');
      cs.exportKeys(publicFile, true);
      const publicCs = new LightPHE({ algorithmName, keyFile: publicFile });

      const low = 10;
      const high = 200;
      let c: Ciphertext | undefined;
      let proof: RangeProof | undefined;
      for (const plaintext of [low, 137, high]) {
        const [ciphertext, rawProof] = publicCs.encryptWithRangeProof(
          plaintext,
          low,
          high,
          {
            context: 'alice',
          }
        );
        c = ciphertext;
        proof = jsonRoundTrip(rawProof);
        expect(cs.decrypt(c)).toBe(BigInt(plaintext));
        expect(
          publicCs.verifyRange(c, proof, low, high, { context: 'alice' })
        ).toBe(true);
      }
      c = c!;
      proof = proof!;

      // proof is bound to its context, range and ciphertext
      expect(
        publicCs.verifyRange(c, proof, low, high, { context: 'bob' })
      ).toBe(false);
      expect(publicCs.verifyRange(c, proof, low, high)).toBe(false);
      expect(
        publicCs.verifyRange(c, proof, low - 1, high, { context: 'alice' })
      ).toBe(false);
      expect(
        publicCs.verifyRange(c, proof, low, high + 1, { context: 'alice' })
      ).toBe(false);
      expect(
        publicCs.verifyRange(c.add(c), proof, low, high, { context: 'alice' })
      ).toBe(false);
      const [otherC] = publicCs.encryptWithRangeProof(high, low, high, {
        context: 'alice',
      });
      expect(
        publicCs.verifyRange(otherC, proof, low, high, { context: 'alice' })
      ).toBe(false);

      // tampered, reordered, truncated and malformed proofs are rejected
      const reordered = deepClone(proof);
      [reordered.ciphertexts[1], reordered.ciphertexts[2]] = [
        reordered.ciphertexts[2],
        reordered.ciphertexts[1],
      ];
      [reordered.proofs[1], reordered.proofs[2]] = [
        reordered.proofs[2],
        reordered.proofs[1],
      ];
      expect(
        publicCs.verifyRange(c, reordered, low, high, { context: 'alice' })
      ).toBe(false);

      const truncated = {
        ciphertexts: proof.ciphertexts.slice(0, -1),
        proofs: proof.proofs.slice(0, -1),
      };
      expect(
        publicCs.verifyRange(c, truncated, low, high, { context: 'alice' })
      ).toBe(false);

      const tampered = deepClone(proof);
      tampered.proofs[1].challenges[0] += 1n;
      expect(
        publicCs.verifyRange(c, tampered, low, high, { context: 'alice' })
      ).toBe(false);

      expect(publicCs.verifyRange(c, {}, low, high, { context: 'alice' })).toBe(
        false
      );
      expect(
        publicCs.verifyRange(c, null, low, high, { context: 'alice' })
      ).toBe(false);

      logger.info(`✅ Range proof test succeeded for ${algorithmName}`);
    }
  );

  it.each(ALGORITHMS)(
    'rejects an out of range ciphertext for %s',
    (algorithmName, keySize, primeOrder) => {
      // a cheater runs the prover for a value out of the range, or presents the proof
      // of an in-range value next to the ciphertext of an out-of-range value
      const cs = build(algorithmName, keySize, primeOrder);
      const low = 0;
      const high = 100;
      const values: [bigint, bigint, bigint] = [0n, 0n, 1n];

      // decomposition cannot represent 150 with bits of [0, 100], so restored ciphertext
      // does not encrypt 150, and the ciphertext of 150 does not match it
      const outOfRange = cs.encrypt(150);
      let [, proof] = zkp.proveRange(cs.cs, 150n, 0n, 100n, values);
      expect(cs.verifyRange(outOfRange, proof, low, high)).toBe(false);

      [, proof] = cs.encryptWithRangeProof(50, low, high);
      expect(cs.verifyRange(outOfRange, proof, low, high)).toBe(false);
    }
  );

  it('handles edge ranges', () => {
    const cs = new LightPHE({ algorithmName: 'Paillier', keySize: 128 });
    const modulo = cs.cs.plaintextModulo;

    // single value range
    let [c, proof] = cs.encryptWithRangeProof(7, 7, 7);
    expect(cs.verifyRange(c, proof, 7, 7)).toBe(true);
    expect(cs.decrypt(c)).toBe(7n);

    // ranges with negative values decrypt to modulo - x as encrypt does
    [c, proof] = cs.encryptWithRangeProof(-30, -100, 100);
    expect(cs.verifyRange(c, proof, -100, 100)).toBe(true);
    expect(cs.decrypt(c)).toBe(modulo - 30n);

    // power of two widths
    for (const high of [1, 2, 255, 256]) {
      [c, proof] = cs.encryptWithRangeProof(high, 0, high);
      expect(cs.verifyRange(c, proof, 0, high)).toBe(true);
    }

    // invalid inputs
    expect(() => cs.encryptWithRangeProof(101, 0, 100)).toThrow('must be in');
    expect(() => cs.encryptWithRangeProof(-1, 0, 100)).toThrow('must be in');
    expect(() => cs.encryptWithRangeProof(5, 10, 0)).toThrow(
      'must not be greater'
    );
    expect(() => cs.encryptWithRangeProof(5, 0, 10.5)).toThrow(
      'must be integers'
    );
    expect(() => cs.encryptWithRangeProof(5, 0, modulo)).toThrow('narrower');
  });

  it('rejects unsupported algorithms', () => {
    let cs = new LightPHE({
      algorithmName: 'ElGamal',
      keySize: 128,
      primeOrder: true,
    });
    expect(() => cs.encryptWithRangeProof(5, 1, 10)).toThrow(
      'Use Exponential-ElGamal instead'
    );

    cs = new LightPHE({ algorithmName: 'Exponential-ElGamal', keySize: 50 });
    expect(() => cs.encryptWithRangeProof(5, 0, 10)).toThrow(
      'prime_order=True'
    );

    for (const algorithmName of ['RSA', 'Okamoto-Uchiyama']) {
      cs = new LightPHE({ algorithmName, keySize: 50 });
      expect(() => cs.encryptWithRangeProof(5, 0, 10)).toThrow(
        'does not support proving'
      );
    }
  });

  it('runs a salary survey', () => {
    // employees submit encrypted salaries with proofs that they are in [0, 500000].
    // invalid submissions are rejected, so nobody can skew the average, and the
    // authority decrypts only the total of valid salaries.
    const authorityCs = new LightPHE({
      algorithmName: 'Paillier',
      keySize: 128,
    });
    const publicCs = new LightPHE({
      algorithmName: 'Paillier',
      keys: { public_key: authorityCs.cs.keys.public_key },
    });
    const low = 0;
    const high = 500000;

    const salaries: Record<string, number> = {
      alice: 85000,
      bob: 62000,
      carol: 120000,
      dave: 47000,
    };
    const submissions: Record<string, [Ciphertext, RangeProof]> = {};
    for (const [employee, salary] of Object.entries(salaries)) {
      submissions[employee] = publicCs.encryptWithRangeProof(
        salary,
        low,
        high,
        {
          context: employee,
        }
      );
    }

    // mallory copies alice's submission
    submissions.mallory = submissions.alice;

    // oscar cannot prove a huge salary, and cannot reuse a proof of a valid salary
    expect(() =>
      publicCs.encryptWithRangeProof(10 ** 9, low, high, { context: 'oscar' })
    ).toThrow('must be in');
    const [, oscarProof] = publicCs.encryptWithRangeProof(50000, low, high, {
      context: 'oscar',
    });
    submissions.oscar = [publicCs.encrypt(10 ** 9), oscarProof];

    // trent cannot submit a negative salary either
    const [, trentProof] = publicCs.encryptWithRangeProof(0, low, high, {
      context: 'trent',
    });
    submissions.trent = [publicCs.encrypt(-(10 ** 6)), trentProof];

    const valid = Object.entries(submissions)
      .filter(([employee, [c, proof]]) =>
        publicCs.verifyRange(c, proof, low, high, { context: employee })
      )
      .map(([, [c]]) => c);
    expect(valid.length).toBe(Object.keys(salaries).length);

    const total = valid.slice(1).reduce((sum, c) => sum.add(c), valid[0]);

    // authority decrypts the total only with a proof, and anyone verifies it
    const [result, proof] = authorityCs.decryptWithProof(total);
    expect(publicCs.verifyDecryption(total, result, proof)).toBe(true);
    const expected = Object.values(salaries).reduce((a, b) => a + b, 0);
    expect(result).toBe(BigInt(expected));
    expect(Number(result) / valid.length).toBe(78500);

    logger.info('✅ Salary survey test succeeded');
  });
});
