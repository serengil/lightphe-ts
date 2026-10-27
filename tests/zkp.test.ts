import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import {
  Ciphertext,
  EllipticCurveElGamal,
  EllipticCurvePoint,
  LightPHE,
  Logger,
  type Keys,
} from '../src';
import { modPow } from '../src/commons/mathUtils';
import * as zkp from '../src/commons/zkp';
import { jsonRoundTrip, tamper } from './helpers';

const logger = new Logger('tests/zkp.test.ts');

const ALGORITHMS: Array<[string, number | null, boolean]> = [
  ['ElGamal', 128, true],
  ['Exponential-ElGamal', 128, true],
  ['EllipticCurve-ElGamal', null, false],
  ['Paillier', 128, false],
  ['Damgard-Jurik', 128, false],
];

const ELGAMAL_FAMILY = [
  'ElGamal',
  'Exponential-ElGamal',
  'EllipticCurve-ElGamal',
];

const MEMBERSHIP_ALGORITHMS = ALGORITHMS.filter(([name]) => name !== 'ElGamal');

function build(
  algorithmName: string,
  keySize: number | null,
  primeOrder: boolean
): LightPHE {
  return new LightPHE({ algorithmName, keySize, primeOrder });
}

/** Combines two encrypted values homomorphically, and returns the expected plaintext. */
function compute(
  cs: LightPHE,
  algorithmName: string,
  m1: number,
  m2: number
): [Ciphertext, bigint] {
  if (algorithmName === 'ElGamal') {
    return [cs.encrypt(m1).multiply(cs.encrypt(m2)), BigInt(m1 * m2)];
  }
  return [cs.encrypt(m1).add(cs.encrypt(m2)), BigInt(m1 + m2)];
}

/** Builds a verifier having the public key only, restored from an exported file. */
function publicCopy(cs: LightPHE): LightPHE {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-zkp-'));
  const publicFile = path.join(dir, 'public.json');
  cs.exportKeys(publicFile, true);
  return new LightPHE({ algorithmName: cs.algorithmName, keyFile: publicFile });
}

describe('Fiat-Shamir transcripts', () => {
  it('hash exactly as the Python library does', () => {
    // computed with challenge() of lightphe/commons/zkp.py
    const items = [
      [[0n, 1n], 'voter-ğ42\n'],
      2n ** 200n + 7n,
      [3, 4],
      null,
      { a: [1, null] },
      1.5,
      true,
    ];
    expect(
      zkp.toJson(['lightphe/paillier/membership', zkp.canonicalize(items)])
    ).toBe(
      '["lightphe/paillier/membership",[[[0,1],"voter-\\u011f42\\n"],' +
        '1606938044258990275541962092341162602522202993782792835301383,' +
        '[3,4],null,{"a":[1,null]},"1.5",true]]'
    );
    expect(
      zkp.challenge('lightphe/paillier/membership', 2n ** 128n, ...items)
    ).toBe(87132113241011999213195950651237695788n);
    expect(
      zkp.challenge(
        'd',
        2n ** 521n - 1n,
        zkp.oneHotContext(undefined, 3, 'sum')
      )
    ).toBe(
      749409431310395357364459281640419028595539485987469949943066188208662836773689386052853474741180323524999708524226312649737155526317250889927481356836150n
    );
  });
});

describe('zero-knowledge proofs', () => {
  it.each(ALGORITHMS)(
    'proves correct decryption for %s',
    (algorithmName, keySize, primeOrder) => {
      const cs = build(algorithmName, keySize, primeOrder);
      const [c, expected] = compute(cs, algorithmName, 17, 3);

      const [plaintext, proof] = cs.decryptWithProof(c);
      expect(plaintext).toBe(expected);
      expect(cs.decrypt(c)).toBe(expected);
      expect(cs.verifyDecryption(c, plaintext, proof)).toBe(true);

      // verifier has the public key only, and proof survives json round trip
      const verifierCs = publicCopy(cs);
      const restored = jsonRoundTrip(proof);
      expect(verifierCs.verifyDecryption(c, plaintext, restored)).toBe(true);

      // wrong plaintext, tampered proof and malformed proof are rejected
      expect(verifierCs.verifyDecryption(c, plaintext + 1n, restored)).toBe(
        false
      );
      expect(verifierCs.verifyDecryption(c, plaintext, tamper(restored))).toBe(
        false
      );
      expect(verifierCs.verifyDecryption(c, plaintext, {})).toBe(false);
      expect(verifierCs.verifyDecryption(c, plaintext, null)).toBe(false);
      expect(
        verifierCs.verifyDecryption(c, String(plaintext) as never, restored)
      ).toBe(false);

      // proof of a ciphertext does not prove another ciphertext of same plaintext
      const cPrime = cs.regenerateCiphertext(c);
      expect(verifierCs.verifyDecryption(cPrime, plaintext, restored)).toBe(
        false
      );
      const [plaintextPrime, proofPrime] = cs.decryptWithProof(cPrime);
      expect(plaintextPrime).toBe(plaintext);
      expect(verifierCs.verifyDecryption(cPrime, plaintext, proofPrime)).toBe(
        true
      );

      logger.info(
        `✅ Proof of correct decryption test succeeded for ${algorithmName}`
      );
    }
  );

  it.each(['ElGamal', 'Exponential-ElGamal'])(
    'requires prime order keys for %s',
    (algorithmName) => {
      const cs = new LightPHE({ algorithmName, keySize: 50 });
      const c = cs.encrypt(5);
      expect(() => cs.decryptWithProof(c)).toThrow('prime_order=True');
      expect(() =>
        cs.verifyDecryption(c, 5, { challenge: 1n, response: 1n })
      ).toThrow('prime_order=True');
    }
  );

  it('rejects a ciphertext out of the group', () => {
    const cs = new LightPHE({
      algorithmName: 'Exponential-ElGamal',
      keySize: 128,
      primeOrder: true,
    });
    const c = cs.encrypt(5);
    const [plaintext, proof] = cs.decryptWithProof(c);

    // -c1 is not in the subgroup of prime order q
    const p = cs.cs.keys.public_key!.p as bigint;
    const [c1, c2] = c.value as bigint[];
    const forged = cs.createCiphertextObj([p - c1, c2]);
    expect(cs.verifyDecryption(forged, plaintext, proof)).toBe(false);
  });

  it('rejects unsupported algorithms', () => {
    for (const algorithmName of ['RSA', 'Okamoto-Uchiyama']) {
      const cs = new LightPHE({ algorithmName, keySize: 50 });
      const c = cs.encrypt(5);
      expect(() => cs.decryptWithProof(c)).toThrow(
        'does not support proofs of correct decryption'
      );
      expect(() => cs.verifyDecryption(c, 5, {})).toThrow(
        'does not support proofs of correct decryption'
      );
    }
  });

  it.each(ELGAMAL_FAMILY)(
    'verifies partial decryptions of %s',
    (algorithmName) => {
      const threshold = 3;
      const parties = 5;
      const dealerCs = new LightPHE({
        algorithmName,
        keySize: algorithmName === 'EllipticCurve-ElGamal' ? null : 128,
        primeOrder: algorithmName !== 'EllipticCurve-ElGamal',
      });
      const shareKeys = dealerCs.generateThresholdKeys(threshold, parties);
      const shareholders = shareKeys.map(
        (keys) => new LightPHE({ algorithmName, keys })
      );

      const [c, expected] = compute(dealerCs, algorithmName, 17, 3);
      const partials = jsonRoundTrip(
        shareholders.map((s) => s.partialDecrypt(c, { prove: true }))
      );

      for (const partial of partials) {
        expect(dealerCs.verifyPartialDecryption(c, partial)).toBe(true);
      }

      // a cheating shareholder sends a wrong value with its old proof
      const honest = partials[0];
      let forgedValue: unknown;
      if (algorithmName === 'EllipticCurve-ElGamal') {
        forgedValue = shareholders[1].partialDecrypt(c, { prove: true }).value;
      } else {
        const p = dealerCs.cs.keys.public_key!.p as bigint;
        const g = dealerCs.cs.keys.public_key!.g as bigint;
        forgedValue = ((honest.value as bigint) * g) % p;
      }
      const forged = { ...honest, value: forgedValue };
      expect(dealerCs.verifyPartialDecryption(c, forged)).toBe(false);

      // a proof cannot be reused under another index or for another ciphertext
      expect(dealerCs.verifyPartialDecryption(c, { ...honest, index: 2 })).toBe(
        false
      );
      expect(
        dealerCs.verifyPartialDecryption(c, { ...honest, index: parties + 1 })
      ).toBe(false);
      const otherC = dealerCs.regenerateCiphertext(c);
      expect(dealerCs.verifyPartialDecryption(otherC, honest)).toBe(false);
      expect(
        dealerCs.verifyPartialDecryption(c, { ...honest, proof: null })
      ).toBe(false);

      // invalid partial decryptions are discarded if enough valid ones remain
      expect(
        dealerCs.combinePartialDecryptions(
          c,
          [forged, ...partials.slice(1, 4)],
          {
            verify: true,
          }
        )
      ).toBe(expected);

      // otherwise combination fails instead of returning a wrong plaintext
      expect(() =>
        dealerCs.combinePartialDecryptions(
          c,
          [forged, ...partials.slice(1, 3)],
          {
            verify: true,
          }
        )
      ).toThrow('valid partial decryptions');

      // partial decryptions without proofs are discarded if verification is on
      const unproven = shareholders.map((s) => s.partialDecrypt(c));
      expect(() =>
        dealerCs.combinePartialDecryptions(c, unproven, { verify: true })
      ).toThrow('valid partial decryptions');

      logger.info(
        `✅ Verifiable partial decryption test succeeded for ${algorithmName}`
      );
    }
  );

  it.each(ELGAMAL_FAMILY)(
    'keeps partial decryption proofs opt-in for %s',
    (algorithmName) => {
      const dealerCs = new LightPHE({
        algorithmName,
        keySize: algorithmName === 'EllipticCurve-ElGamal' ? null : 128,
        primeOrder: algorithmName !== 'EllipticCurve-ElGamal',
      });
      const shareKeys = dealerCs.generateThresholdKeys(2, 3);
      const shareholders = shareKeys.map(
        (keys) => new LightPHE({ algorithmName, keys })
      );
      const [c, expected] = compute(dealerCs, algorithmName, 17, 3);

      // no proofs by default, and combination does not check them by default
      const partials = shareholders.map((s) => s.partialDecrypt(c));
      expect(partials.every((partial) => !('proof' in partial))).toBe(true);
      expect(dealerCs.combinePartialDecryptions(c, partials)).toBe(expected);

      // proven partial decryptions are combined with or without verification
      const proven = shareholders.map((s) =>
        s.partialDecrypt(c, { prove: true })
      );
      expect(dealerCs.combinePartialDecryptions(c, proven)).toBe(expected);
      expect(
        dealerCs.combinePartialDecryptions(c, proven, { verify: true })
      ).toBe(expected);

      // without verification, a cheating shareholder causes a wrong plaintext silently.
      // additive variants would brute force a huge discrete logarithm, so check ElGamal only.
      if (algorithmName === 'ElGamal') {
        const p = dealerCs.cs.keys.public_key!.p as bigint;
        const forged = {
          ...partials[0],
          value: ((partials[0].value as bigint) * 2n) % p,
        };
        expect(
          dealerCs.combinePartialDecryptions(c, [forged, partials[1]])
        ).not.toBe(expected);
      }
    }
  );

  it.each(['Paillier', 'Damgard-Jurik'])(
    'requires safe primes to prove partial decryptions of %s',
    (algorithmName) => {
      const dealerCs = new LightPHE({ algorithmName, keySize: 50 });
      const shareKeys = dealerCs.generateThresholdKeys(2, 3);
      const shareholder = new LightPHE({ algorithmName, keys: shareKeys[0] });
      const c = dealerCs.encrypt(5);

      // regular keys still decrypt without proofs
      const partials = shareKeys.map((keys) =>
        new LightPHE({ algorithmName, keys }).partialDecrypt(c)
      );
      expect(dealerCs.combinePartialDecryptions(c, partials)).toBe(5n);

      expect(() => shareholder.partialDecrypt(c, { prove: true })).toThrow(
        'safe_primes=True'
      );
      expect(() =>
        dealerCs.verifyPartialDecryption(c, shareholder.partialDecrypt(c))
      ).toThrow('safe_primes=True');
      expect(() =>
        dealerCs.combinePartialDecryptions(c, partials, { verify: true })
      ).toThrow('safe_primes=True');
    }
  );

  it.each(['Paillier', 'Damgard-Jurik'])(
    'verifies partial decryptions of %s',
    (algorithmName) => {
      const threshold = 3;
      const parties = 5;
      const dealerCs = new LightPHE({
        algorithmName,
        keySize: 128,
        safePrimes: true,
      });

      // safe prime keys work as regular keys
      const c = dealerCs.encrypt(100).add(dealerCs.encrypt(50));
      expect(dealerCs.decrypt(c)).toBe(150n);
      expect(dealerCs.decrypt(c.multiply(3))).toBe(450n);

      const shareKeys = dealerCs.generateThresholdKeys(threshold, parties);

      // keys of shareholders survive exporting and restoring
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-zkp-'));
      const shareholders = shareKeys.map((keys: Keys, k: number) => {
        const keyFile = path.join(dir, `share_${k}.json`);
        new LightPHE({ algorithmName, keys }).exportKeys(keyFile);
        return new LightPHE({ algorithmName, keyFile });
      });

      const partials = jsonRoundTrip(
        shareholders.map((s) => s.partialDecrypt(c, { prove: true }))
      );
      for (const partial of partials) {
        expect(dealerCs.verifyPartialDecryption(c, partial)).toBe(true);
      }
      expect(
        dealerCs.combinePartialDecryptions(c, partials, { verify: true })
      ).toBe(150n);

      // partial decryptions without proofs are combined if verification is off
      const unproven = shareholders.map((s) => s.partialDecrypt(c));
      expect(unproven.every((partial) => !('proof' in partial))).toBe(true);
      expect(dealerCs.combinePartialDecryptions(c, unproven)).toBe(150n);
      expect(() =>
        dealerCs.combinePartialDecryptions(c, unproven, { verify: true })
      ).toThrow('valid partial decryptions');

      // a cheating shareholder multiplies its partial decryption with (1 + n)^shift
      const n = dealerCs.cs.keys.public_key!.n as bigint;
      const modulo = dealerCs.cs.ciphertextModulo;
      const honest = partials[0];
      const forged = {
        ...honest,
        value: ((honest.value as bigint) * (1n + n)) % modulo,
      };
      expect(dealerCs.verifyPartialDecryption(c, forged)).toBe(false);

      // a proof cannot be reused under another index or for another ciphertext
      expect(dealerCs.verifyPartialDecryption(c, { ...honest, index: 2 })).toBe(
        false
      );
      expect(
        dealerCs.verifyPartialDecryption(c, { ...honest, index: parties + 1 })
      ).toBe(false);
      expect(
        dealerCs.verifyPartialDecryption(
          dealerCs.regenerateCiphertext(c),
          honest
        )
      ).toBe(false);
      expect(
        dealerCs.verifyPartialDecryption(c, { ...honest, proof: null })
      ).toBe(false);
      expect(
        dealerCs.verifyPartialDecryption(c, {
          ...honest,
          proof: tamper(honest.proof),
        })
      ).toBe(false);

      // invalid partial decryptions are discarded if enough valid ones remain
      expect(
        dealerCs.combinePartialDecryptions(
          c,
          [forged, ...partials.slice(1, 4)],
          {
            verify: true,
          }
        )
      ).toBe(150n);
      expect(() =>
        dealerCs.combinePartialDecryptions(
          c,
          [forged, ...partials.slice(1, 3)],
          {
            verify: true,
          }
        )
      ).toThrow('valid partial decryptions');

      logger.info(
        `✅ Verifiable partial decryption test succeeded for ${algorithmName}`
      );
    }
  );

  it.each(MEMBERSHIP_ALGORITHMS)(
    'proves membership for %s',
    (algorithmName, keySize, primeOrder) => {
      const cs = build(algorithmName, keySize, primeOrder);

      // voter has the public key only
      const voterCs = publicCopy(cs);

      for (const vote of [0, 1]) {
        const [ballot, rawProof] = voterCs.encryptWithProof(vote, {
          context: 'voter-42',
        });
        const proof = jsonRoundTrip(rawProof);
        expect(cs.decrypt(ballot)).toBe(BigInt(vote));
        expect(
          voterCs.verifyCiphertext(ballot, proof, { context: 'voter-42' })
        ).toBe(true);
        expect(
          voterCs.verifyCiphertext(ballot, proof, {
            values: [0, 1],
            context: 'voter-42',
          })
        ).toBe(true);

        // proof is bound to its context, values and ciphertext
        expect(
          voterCs.verifyCiphertext(ballot, proof, { context: 'voter-43' })
        ).toBe(false);
        expect(voterCs.verifyCiphertext(ballot, proof)).toBe(false);
        expect(
          voterCs.verifyCiphertext(ballot, proof, {
            values: [1, 0],
            context: 'voter-42',
          })
        ).toBe(false);
        expect(
          voterCs.verifyCiphertext(ballot.add(ballot), proof, {
            context: 'voter-42',
          })
        ).toBe(false);
        expect(
          voterCs.verifyCiphertext(ballot, tamper(proof), {
            context: 'voter-42',
          })
        ).toBe(false);
        expect(
          voterCs.verifyCiphertext(ballot, {}, { context: 'voter-42' })
        ).toBe(false);
        expect(
          voterCs.verifyCiphertext(ballot, null, { context: 'voter-42' })
        ).toBe(false);
      }

      // larger sets of values, e.g. a rating in [1, 5]
      const [rating, proof] = voterCs.encryptWithProof(4, {
        values: [1, 2, 3, 4, 5],
      });
      expect(
        voterCs.verifyCiphertext(rating, proof, { values: [1, 2, 3, 4, 5] })
      ).toBe(true);
      expect(
        voterCs.verifyCiphertext(rating, proof, { values: [1, 2, 3, 5, 6] })
      ).toBe(false);
      expect(cs.decrypt(rating)).toBe(4n);

      // single allowed value
      const [c, singleProof] = voterCs.encryptWithProof(7, { values: [7] });
      expect(voterCs.verifyCiphertext(c, singleProof, { values: [7] })).toBe(
        true
      );

      // invalid inputs
      expect(() => voterCs.encryptWithProof(2)).toThrow(
        'one of the allowed values'
      );
      expect(() => voterCs.encryptWithProof(1, { values: [0, 1, 1] })).toThrow(
        'distinct'
      );
      expect(() => voterCs.encryptWithProof(1, { values: [] })).toThrow(
        'non-empty'
      );
      expect(() => voterCs.encryptWithProof(1, { values: [0, 1.5] })).toThrow(
        'non-empty'
      );

      logger.info(`✅ Proof of membership test succeeded for ${algorithmName}`);
    }
  );

  it.each(MEMBERSHIP_ALGORITHMS)(
    'rejects a cheating voter for %s',
    (algorithmName, keySize, primeOrder) => {
      // a voter encrypts 2 and runs the prover pretending that it encrypts 1
      const cs = build(algorithmName, keySize, primeOrder);
      const keys = cs.cs.keys.public_key!;
      const values = [0n, 1n];
      const r = cs.cs.generateRandomKey() as bigint;
      const value = cs.cs.encrypt(2n, r);

      let proof: unknown;
      if (algorithmName === 'Paillier' || algorithmName === 'Damgard-Jurik') {
        const n = keys.n as bigint;
        const modulo =
          algorithmName === 'Paillier' ? n * n : n ** ((keys.s as bigint) + 1n);
        const domain =
          algorithmName === 'Paillier'
            ? 'lightphe/paillier/membership'
            : 'lightphe/damgard-jurik/membership';
        proof = zkp.proveNthPowerOr({
          n,
          modulo,
          us: zkp.paillierMembershipCandidates(
            value as bigint,
            values,
            n,
            modulo
          ),
          r,
          index: 1,
          domain,
          context: [values, null],
        });
      } else if (algorithmName === 'Exponential-ElGamal') {
        const p = keys.p as bigint;
        const g = keys.g as bigint;
        const [c1, c2] = value as bigint[];
        proof = zkp.proveDleqOr({
          group: new zkp.ModularGroup(p, keys.q as bigint),
          g1: g,
          h1: c1,
          g2: keys.y as bigint,
          h2s: values.map((v) => (c2 * modPow(g, -v, p)) % p),
          x: r,
          index: 1,
          domain: 'lightphe/exponential-elgamal/membership',
          context: [p, c2, values, null],
        });
      } else {
        const ecc = (cs.cs as EllipticCurveElGamal).ecc;
        const toPoint = (point: unknown): EllipticCurvePoint => {
          const [x, y] = point as [bigint, bigint];
          return EllipticCurvePoint.restore(x, y, ecc.curve);
        };
        const [c1, c2] = value as [[bigint, bigint], [bigint, bigint]];
        const c2Point = toPoint(c2);
        proof = zkp.proveDleqOr({
          group: new zkp.EllipticCurveGroup(ecc),
          g1: ecc.G,
          h1: toPoint(c1),
          g2: toPoint(keys.Qa),
          h2s: values.map((v) =>
            v === 0n ? c2Point : c2Point.sub(ecc.G.multiply(v))
          ),
          x: r,
          index: 1,
          domain: 'lightphe/elliptic-curve-elgamal/membership',
          context: [ecc.n, c2, values, null],
        });
      }

      const ballot = cs.createCiphertextObj(value);
      expect(cs.decrypt(ballot)).toBe(2n);
      expect(cs.verifyCiphertext(ballot, proof as never)).toBe(false);
    }
  );

  it('rejects membership proofs of unsupported algorithms', () => {
    let cs = new LightPHE({
      algorithmName: 'ElGamal',
      keySize: 128,
      primeOrder: true,
    });
    expect(() => cs.encryptWithProof(1, { values: [1, 2] })).toThrow(
      'Use Exponential-ElGamal instead'
    );

    cs = new LightPHE({ algorithmName: 'Exponential-ElGamal', keySize: 50 });
    expect(() => cs.encryptWithProof(1)).toThrow('prime_order=True');

    for (const algorithmName of ['RSA', 'Okamoto-Uchiyama']) {
      cs = new LightPHE({ algorithmName, keySize: 50 });
      expect(() => cs.encryptWithProof(1)).toThrow('does not support proving');
    }
  });

  it.each(ALGORITHMS)(
    'proves knowledge of plaintext for %s',
    (algorithmName, keySize, primeOrder) => {
      const cs = build(algorithmName, keySize, primeOrder);

      // prover and verifier have the public key only
      const publicCs = publicCopy(cs);

      const [c, rawProof] = publicCs.encryptWithProofOfKnowledge(17, {
        context: 'alice',
      });
      const proof = jsonRoundTrip(rawProof);
      expect(cs.decrypt(c)).toBe(17n);
      expect(publicCs.verifyKnowledge(c, proof, { context: 'alice' })).toBe(
        true
      );

      // proof is bound to its context and ciphertext
      expect(publicCs.verifyKnowledge(c, proof, { context: 'bob' })).toBe(
        false
      );
      expect(publicCs.verifyKnowledge(c, proof)).toBe(false);

      // a copied ciphertext cannot be re-randomized or modified with the same proof
      expect(
        publicCs.verifyKnowledge(publicCs.regenerateCiphertext(c), proof, {
          context: 'alice',
        })
      ).toBe(false);
      const modified =
        algorithmName === 'ElGamal'
          ? c.multiply(publicCs.encrypt(2))
          : c.add(publicCs.encrypt(1));
      expect(
        publicCs.verifyKnowledge(modified, proof, { context: 'alice' })
      ).toBe(false);
      if (algorithmName !== 'ElGamal') {
        expect(
          publicCs.verifyKnowledge(c.multiply(3), proof, { context: 'alice' })
        ).toBe(false);
      }

      // tampered and malformed proofs are rejected
      expect(
        publicCs.verifyKnowledge(c, tamper(proof), { context: 'alice' })
      ).toBe(false);
      expect(publicCs.verifyKnowledge(c, {}, { context: 'alice' })).toBe(false);
      expect(publicCs.verifyKnowledge(c, null, { context: 'alice' })).toBe(
        false
      );

      // a proof of another ciphertext does not prove this one
      const [otherC, otherProof] = publicCs.encryptWithProofOfKnowledge(17, {
        context: 'alice',
      });
      expect(
        publicCs.verifyKnowledge(c, otherProof, { context: 'alice' })
      ).toBe(false);
      expect(
        publicCs.verifyKnowledge(otherC, otherProof, { context: 'alice' })
      ).toBe(true);

      logger.info(`✅ Proof of knowledge test succeeded for ${algorithmName}`);
    }
  );

  it('rejects proofs of knowledge of unsupported algorithms', () => {
    for (const algorithmName of ['ElGamal', 'Exponential-ElGamal']) {
      const cs = new LightPHE({ algorithmName, keySize: 50 });
      expect(() => cs.encryptWithProofOfKnowledge(5)).toThrow(
        'prime_order=True'
      );
    }

    for (const algorithmName of ['RSA', 'Okamoto-Uchiyama']) {
      const cs = new LightPHE({ algorithmName, keySize: 50 });
      expect(() => cs.encryptWithProofOfKnowledge(5)).toThrow(
        'does not support proofs of knowledge'
      );
    }
  });
});
