import {
  Ciphertext,
  LightPHE,
  Logger,
  type MembershipProof,
  type OneHotProof,
  type RandomKey,
} from '../src';
import { modPow } from '../src/commons/mathUtils';
import { scaledLagrangeCoefficient } from '../src/commons/threshold';
import { oneHotContext } from '../src/commons/zkp';

const logger = new Logger('tests/evoting.test.ts');

describe('e-voting', () => {
  it('runs an encrypted referendum', () => {
    // voters cast 0/1 ballots with proofs, invalid ballots are rejected, valid ones
    // are tallied homomorphically, and trustees threshold-decrypt the tally with proofs
    const authorityCs = new LightPHE({
      algorithmName: 'Exponential-ElGamal',
      keySize: 128,
      primeOrder: true,
    });
    const shareKeys = authorityCs.generateThresholdKeys(2, 3);
    const trustees = shareKeys.map(
      (keys) => new LightPHE({ algorithmName: 'Exponential-ElGamal', keys })
    );

    const votes: Record<string, number> = {
      alice: 1,
      bob: 0,
      carol: 1,
      dave: 1,
    };
    const ballots: Record<string, [Ciphertext, MembershipProof]> = {};
    for (const [voter, vote] of Object.entries(votes)) {
      ballots[voter] = authorityCs.encryptWithProof(vote, { context: voter });
    }

    // mallory copies alice's ballot
    ballots.mallory = ballots.alice;

    const valid = Object.entries(ballots)
      .filter(([voter, [ballot, proof]]) =>
        authorityCs.verifyCiphertext(ballot, proof, { context: voter })
      )
      .map(([, [ballot]]) => ballot);
    expect(valid.length).toBe(Object.keys(votes).length);

    const tally = valid
      .slice(1)
      .reduce((sum, ballot) => sum.add(ballot), valid[0]);

    const partials = trustees
      .slice(0, 2)
      .map((trustee) => trustee.partialDecrypt(tally, { prove: true }));
    expect(
      authorityCs.combinePartialDecryptions(tally, partials, { verify: true })
    ).toBe(3n);

    logger.info('✅ Encrypted voting test succeeded');
  });

  it('runs an encrypted election of parties', () => {
    // voters cast a ballot for one of many parties with proofs. A vote for party k is
    // encrypted as base^k, so the tally keeps the count of each party in a digit.
    const authorityCs = new LightPHE({
      algorithmName: 'Paillier',
      keySize: 128,
    });
    const publicCs = new LightPHE({
      algorithmName: 'Paillier',
      keys: { public_key: authorityCs.cs.keys.public_key },
    });

    // a vote for party k is encrypted as base^k, i.e. 1 for red, 100 for green and
    // 10000 for blue. base must be greater than the votes a party can get, and
    // base^parties must be less than the modulus n.
    const parties = ['red', 'green', 'blue'];
    const base = 100n;
    const values = parties.map((_, k) => base ** BigInt(k));

    const votes: Record<string, string> = {
      alice: 'red',
      bob: 'blue',
      carol: 'red',
      dave: 'red',
      erin: 'blue',
    };
    const ballots: Record<string, [Ciphertext, MembershipProof]> = {};
    for (const [voter, party] of Object.entries(votes)) {
      ballots[voter] = publicCs.encryptWithProof(
        values[parties.indexOf(party)],
        {
          values,
          context: voter,
        }
      );
    }

    // mallory copies alice's ballot
    ballots.mallory = ballots.alice;

    // oscar cannot vote twice for a party, as 2 * base^k is not an allowed value
    expect(() =>
      publicCs.encryptWithProof(2n * values[1], { values, context: 'oscar' })
    ).toThrow('one of the allowed values');

    // oscar cannot reuse a proof of a single vote for a doubled ballot
    const [oscarBallot, oscarProof] = publicCs.encryptWithProof(values[1], {
      values,
      context: 'oscar',
    });
    ballots.oscar = [oscarBallot.add(oscarBallot), oscarProof];

    const valid = Object.entries(ballots)
      .filter(([voter, [ballot, proof]]) =>
        publicCs.verifyCiphertext(ballot, proof, { values, context: voter })
      )
      .map(([, [ballot]]) => ballot);
    expect(valid.length).toBe(Object.keys(votes).length);

    const tally = valid
      .slice(1)
      .reduce((sum, ballot) => sum.add(ballot), valid[0]);

    // authority decrypts the tally with a proof, and anyone verifies it
    const [result, proof] = authorityCs.decryptWithProof(tally);
    expect(publicCs.verifyDecryption(tally, result, proof)).toBe(true);

    // 3 x 1 + 0 x 100 + 2 x 10000 = 20003, which is read 2 digits at a time from right
    const counts = Object.fromEntries(
      parties.map((party, k) => [party, (result / base ** BigInt(k)) % base])
    );
    expect(counts).toEqual({ red: 3n, green: 0n, blue: 2n });

    logger.info('✅ Encrypted election of parties test succeeded');
  });

  it('discards a cheating trustee of an election of parties', () => {
    // trustees from competing parties hold shares of the key of a party election. A
    // cheating trustee shifts its partial decryption to add 50 votes to its own party.
    // Without proofs, the forged tally is accepted silently. With proofs, it is discarded.
    const authorityCs = new LightPHE({
      algorithmName: 'Paillier',
      keySize: 128,
      safePrimes: true,
    });
    const shareKeys = authorityCs.generateThresholdKeys(2, 3);
    const trustees = shareKeys.map(
      (keys) => new LightPHE({ algorithmName: 'Paillier', keys })
    );

    const parties = ['red', 'green', 'blue'];
    const base = 100n;
    const values = parties.map((_, k) => base ** BigInt(k));

    const votes: Record<string, string> = {
      alice: 'red',
      bob: 'blue',
      carol: 'red',
      dave: 'green',
      erin: 'red',
    };
    const valid = Object.entries(votes)
      .map(([voter, party]): [string, [Ciphertext, MembershipProof]] => [
        voter,
        authorityCs.encryptWithProof(values[parties.indexOf(party)], {
          values,
          context: voter,
        }),
      ])
      .filter(([voter, [ballot, proof]]) =>
        authorityCs.verifyCiphertext(ballot, proof, { values, context: voter })
      )
      .map(([, [ballot]]) => ballot);
    const tally = valid
      .slice(1)
      .reduce((sum, ballot) => sum.add(ballot), valid[0]);

    const count = (result: bigint): Record<string, bigint> =>
      Object.fromEntries(
        parties.map((party, k) => [party, (result / base ** BigInt(k)) % base])
      );

    const partials = trustees.map((trustee) =>
      trustee.partialDecrypt(tally, { prove: true })
    );
    expect(
      count(
        authorityCs.combinePartialDecryptions(tally, partials.slice(0, 2), {
          verify: true,
        })
      )
    ).toEqual({ red: 3n, green: 1n, blue: 1n });

    // trustee 1 of blue party knows that trustee 2 joins the decryption, so it finds the
    // shift adding 50 votes to blue from public lagrange coefficients
    const n = authorityCs.cs.keys.public_key!.n as bigint;
    const modulo = authorityCs.cs.ciphertextModulo;
    const delta = 6n; // factorial of the number of trustees
    const coefficient = scaledLagrangeCoefficient(1, [1, 2], delta);
    const target = 50n * values[parties.indexOf('blue')];
    const shift =
      (target * 4n * delta * delta * modPow(2n * coefficient, -1n, n)) % n;
    const forged = {
      ...partials[0],
      value:
        ((partials[0].value as bigint) * modPow(1n + n, shift, modulo)) %
        modulo,
    };

    // without proofs, blue gets 50 more votes silently
    const forgedResult = authorityCs.combinePartialDecryptions(tally, [
      forged,
      partials[1],
    ]);
    expect(count(forgedResult)).toEqual({ red: 3n, green: 1n, blue: 51n });

    // with proofs, the forged partial decryption is discarded and the honest trustees decrypt
    const result = authorityCs.combinePartialDecryptions(
      tally,
      [forged, ...partials.slice(1)],
      { verify: true }
    );
    expect(count(result)).toEqual({ red: 3n, green: 1n, blue: 1n });

    logger.info('✅ Trustees tally election of parties test succeeded');
  });

  it('runs a one-hot election', () => {
    // voters cast one-hot ballots, i.e. one 0/1 ciphertext per party with a proof that
    // exactly one of them is 1. Slots are summed homomorphically, so each party's votes
    // are counted separately, and the number of parties is not limited.
    const authorityCs = new LightPHE({
      algorithmName: 'Exponential-ElGamal',
      keySize: 128,
      primeOrder: true,
    });
    const shareKeys = authorityCs.generateThresholdKeys(2, 3);
    const trustees = shareKeys.map(
      (keys) => new LightPHE({ algorithmName: 'Exponential-ElGamal', keys })
    );

    const parties = [
      'red',
      'green',
      'blue',
      'yellow',
      'purple',
      'orange',
      'black',
      'white',
    ];
    const votes: Record<string, string> = {
      alice: 'red',
      bob: 'blue',
      carol: 'red',
      dave: 'white',
      erin: 'blue',
      frank: 'red',
    };
    const ballots: Record<string, [Ciphertext[], OneHotProof]> = {};
    for (const [voter, party] of Object.entries(votes)) {
      ballots[voter] = authorityCs.encryptOneHot(
        parties.indexOf(party),
        parties.length,
        {
          context: voter,
        }
      );
    }

    // mallory copies alice's ballot, and oscar reorders bob's slots to vote for another party
    ballots.mallory = ballots.alice;
    const [bobBallot, bobProof] = ballots.bob;
    ballots.oscar = [
      [...bobBallot.slice(1), ...bobBallot.slice(0, 1)],
      bobProof,
    ];

    const valid = Object.entries(ballots)
      .filter(([voter, [ballot, proof]]) =>
        authorityCs.verifyOneHot(ballot, proof, { context: voter })
      )
      .map(([, [ballot]]) => ballot);
    expect(valid.length).toBe(Object.keys(votes).length);

    // sum each slot over all ballots
    const tally = valid
      .slice(1)
      .reduce(
        (totals, ballot) => totals.map((total, i) => total.add(ballot[i])),
        valid[0]
      );

    const counts: Record<string, bigint> = {};
    parties.forEach((party, i) => {
      const partials = trustees
        .slice(0, 2)
        .map((trustee) => trustee.partialDecrypt(tally[i], { prove: true }));
      counts[party] = authorityCs.combinePartialDecryptions(
        tally[i],
        partials,
        {
          verify: true,
        }
      );
    });

    expect(counts).toEqual({
      red: 3n,
      green: 0n,
      blue: 2n,
      yellow: 0n,
      purple: 0n,
      orange: 0n,
      black: 0n,
      white: 1n,
    });

    logger.info('✅ One-hot election test succeeded');
  });

  it.each([
    ['Exponential-ElGamal', 128, true],
    ['EllipticCurve-ElGamal', null, false],
    ['Paillier', 128, false],
    ['Damgard-Jurik', 128, false],
  ] as Array<[string, number | null, boolean]>)(
    'rejects cheating one-hot ballots for %s',
    (algorithmName, keySize, primeOrder) => {
      // a cheating voter builds its ballot slot by slot, proving whatever it can
      const cs = new LightPHE({ algorithmName, keySize, primeOrder });
      const options = 3;

      const cheat = (
        slots: number[],
        claimedSum: bigint
      ): [Ciphertext[], OneHotProof] => {
        const ciphertexts = [];
        const randomKeys: RandomKey[] = [];
        const slotProofs: MembershipProof[] = [];
        for (const [slot, plaintext] of slots.entries()) {
          const randomKey = cs.cs.generateRandomKey();
          const ciphertext = cs.cs.encrypt(BigInt(plaintext), randomKey);
          // a slot of 2 cannot be proven to be 0 or 1, so prove it as 1
          slotProofs.push(
            cs.cs.proveMembership(
              ciphertext,
              BigInt(Math.min(plaintext, 1)),
              randomKey,
              [0n, 1n],
              oneHotContext(null, options, slot)
            )
          );
          ciphertexts.push(ciphertext);
          randomKeys.push(randomKey);
        }
        const total = ciphertexts
          .slice(1)
          .reduce((sum, c) => cs.cs.add(sum, c), ciphertexts[0]);
        // claim that the sum is 1 although it is not
        const sumProof = cs.cs.proveMembership(
          total,
          claimedSum,
          cs.cs.combineRandomKeys(randomKeys),
          [claimedSum],
          oneHotContext(null, options, 'sum')
        );
        return [
          ciphertexts.map((c) => cs.createCiphertextObj(c)),
          { slots: slotProofs, sum: sumProof },
        ];
      };

      // an honest ballot built in the same way is valid
      let [ballot, proof] = cheat([0, 1, 0], 1n);
      expect(cs.verifyOneHot(ballot, proof)).toBe(true);

      // voting for two parties, voting twice for a party, or abstaining is rejected
      for (const slots of [
        [1, 1, 0],
        [2, 0, 0],
        [0, 0, 0],
      ]) {
        [ballot, proof] = cheat(slots, 1n);
        expect(cs.verifyOneHot(ballot, proof)).toBe(false);
      }
    }
  );

  it('rejects invalid one-hot inputs', () => {
    const cs = new LightPHE({ algorithmName: 'Paillier', keySize: 128 });
    expect(() => cs.encryptOneHot(3, 3)).toThrow('Choice must be in');
    expect(() => cs.encryptOneHot(0, 0)).toThrow('at least 1');
    expect(() => cs.encryptOneHot(1.5, 3)).toThrow('must be integers');

    const [ballot, proof] = cs.encryptOneHot(0, 1);
    expect(cs.verifyOneHot(ballot, proof)).toBe(true);
    expect(cs.verifyOneHot([], proof)).toBe(false);
    expect(cs.verifyOneHot(ballot, {})).toBe(false);
    expect(cs.verifyOneHot(ballot, null)).toBe(false);

    expect(() =>
      new LightPHE({ algorithmName: 'RSA', keySize: 50 }).encryptOneHot(0, 2)
    ).toThrow('does not support proving');
  });
});
