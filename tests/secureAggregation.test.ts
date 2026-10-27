import { LightPHE, Logger } from '../src';
import * as secureAggregation from '../src/commons/secureAggregation';

const logger = new Logger('tests/secureAggregation.test.ts');

// quantization error of a value is at most half of 10^-precision
const PRECISION = 5;
const TOLERANCE = 10 ** -PRECISION;

/** A seeded random source, so that random updates are reproducible like `random.seed`. */
function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    // mulberry32
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function uniform(random: () => number, low: number, high: number): number {
  return low + (high - low) * random();
}

function gauss(random: () => number, mu: number, sigma: number): number {
  // box-muller transform
  const u = 1 - random();
  const v = random();
  return mu + sigma * Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
}

function expectClose(
  actual: number[],
  expected: number[],
  tolerance: number
): void {
  expect(actual.length).toBe(expected.length);
  actual.forEach((x, i) =>
    expect(Math.abs(x - expected[i])).toBeLessThanOrEqual(tolerance)
  );
}

function isClose(
  actual: number[],
  expected: number[],
  tolerance: number
): boolean {
  return actual.every((x, i) => Math.abs(x - expected[i]) <= tolerance);
}

/** Dealer splits the key among a committee, and the server has the public key only. */
function buildCommittee(
  algorithmName = 'Paillier',
  threshold = 3,
  parties = 5
): [LightPHE, LightPHE[]] {
  const dealer = new LightPHE({
    algorithmName,
    keySize: 256,
    safePrimes: true,
  });
  const shareKeys = dealer.generateThresholdKeys(threshold, parties);
  const committee = shareKeys.map(
    (keys) => new LightPHE({ algorithmName, keys })
  );
  const server = new LightPHE({
    algorithmName,
    keys: { public_key: dealer.cs.keys.public_key },
  });
  return [server, committee];
}

/** Sum of updates value by value. */
function sumOf(updates: number[][]): number[] {
  return updates[0].map((_, i) =>
    updates.reduce((total, update) => total + update[i], 0)
  );
}

describe('secure aggregation', () => {
  it('packs and unpacks updates', () => {
    const random = seededRandom(0);
    const modulo = 2n ** 1024n;
    const layout = secureAggregation.buildLayout(100, 3, 2.5, 7, modulo);
    expect(layout.bound).toBe(2500n);
    expect(layout.slot_bits).toBe((7 * 2 * 2500).toString(2).length);
    expect(layout.slots).toBe(Math.floor(1024 / layout.slot_bits));

    const updates = Array.from({ length: 7 }, () =>
      Array.from(
        { length: 100 },
        () => Math.round(uniform(random, -2.5, 2.5) * 1000) / 1000
      )
    );
    updates[0].splice(0, 3, 2.5, -2.5, 0);

    // sum of packed plaintexts unpacks to the sum of updates, as slots never overflow
    const total = new Array<bigint>(secureAggregation.chunksOf(layout)).fill(
      0n
    );
    for (const update of updates) {
      secureAggregation.pack(update, layout).forEach((plaintext, i) => {
        expect(plaintext < modulo).toBe(true);
        total[i] += plaintext;
      });
    }
    const restored = secureAggregation.unpack(total, layout, 7);
    expectClose(restored, sumOf(updates), 1e-9);
  });

  it('aggregates with a threshold committee', () => {
    const random = seededRandom(1);
    const [server, committee] = buildCommittee();
    const length = 120;
    const updates = Array.from({ length: 6 }, () =>
      Array.from({ length }, () => uniform(random, -1, 1))
    );

    const encrypted = updates.map((update) =>
      server.encryptUpdate(update, 1, 50)
    );
    const layout = encrypted[0].layout;
    expect(encrypted[0].chunks.length).toBe(secureAggregation.chunksOf(layout));
    expect(encrypted[0].chunks.length).toBeLessThan(length);

    const encryptedSum = server.aggregateUpdates(encrypted);
    expect(encryptedSum.count).toBe(6);

    // any 3 of 5 members decrypt the sum, e.g. if 2 members drop out
    const partials = committee.map((member) =>
      member.partialDecryptAggregate(encryptedSum, { prove: true })
    );
    const expectedSum = sumOf(updates);
    for (const subset of [partials.slice(0, 3), partials.slice(2)]) {
      const result = server.combineAggregate(encryptedSum, subset, {
        verify: true,
      });
      expect(result.count).toBe(6);
      expectClose(result.sum, expectedSum, 6 * TOLERANCE);
      expectClose(
        result.mean,
        expectedSum.map((x) => x / 6),
        TOLERANCE
      );
    }

    // 2 members cannot decrypt the sum
    expect(() =>
      server.combineAggregate(encryptedSum, partials.slice(0, 2))
    ).toThrow('At least 3');

    logger.info('✅ Threshold secure aggregation test succeeded');
  });

  it('discards a cheating committee member', () => {
    const random = seededRandom(2);
    const [server, committee] = buildCommittee();
    const updates = Array.from({ length: 3 }, () =>
      Array.from({ length: 10 }, () => uniform(random, -1, 1))
    );
    const encryptedSum = server.aggregateUpdates(
      updates.map((update) => server.encryptUpdate(update, 1, 10))
    );
    const partials = committee
      .slice(0, 4)
      .map((member) =>
        member.partialDecryptAggregate(encryptedSum, { prove: true })
      );

    // member 1 shifts its partial decryption of the first chunk to bias the sum
    const n = server.cs.keys.public_key!.n as bigint;
    const modulo = server.cs.ciphertextModulo;
    const forged = {
      ...partials[0][0],
      value: ((partials[0][0].value as bigint) * (1n + n)) % modulo,
    };
    partials[0] = [forged, ...partials[0].slice(1)];

    // without verification, the sum is wrong
    const expectedSum = sumOf(updates);
    const biased = server.combineAggregate(encryptedSum, partials.slice(0, 3));
    expect(isClose(biased.sum, expectedSum, 3 * TOLERANCE)).toBe(false);

    // with verification, the forged partial decryption is discarded
    const result = server.combineAggregate(encryptedSum, partials, {
      verify: true,
    });
    expectClose(result.sum, expectedSum, 3 * TOLERANCE);
  });

  it('trains a model with federated averaging', () => {
    // clients train a linear model y = w x + b on their private data. In each round,
    // each client sends its encrypted weights, and the committee decrypts only their average.
    const random = seededRandom(3);
    const [server, committee] = buildCommittee('Paillier', 2, 3);

    const trueW = 2.0;
    const trueB = -1.0;
    const clients = Array.from({ length: 4 }, () => {
      const xs = Array.from({ length: 30 }, () => uniform(random, -1, 1));
      const ys = xs.map((x) => trueW * x + trueB + gauss(random, 0, 0.01));
      return [xs, ys];
    });

    let weights = [0.0, 0.0];
    for (let round = 0; round < 30; round++) {
      const updates = clients.map(([xs, ys]) => {
        // one local step of gradient descent on mean squared error
        const [w, b] = weights;
        const gradW =
          xs.reduce((total, x, i) => total + 2 * (w * x + b - ys[i]) * x, 0) /
          xs.length;
        const gradB =
          xs.reduce((total, x, i) => total + 2 * (w * x + b - ys[i]), 0) /
          xs.length;
        return [w - 0.5 * gradW, b - 0.5 * gradB];
      });

      const encryptedSum = server.aggregateUpdates(
        updates.map((update) => server.encryptUpdate(update, 10, 4))
      );
      const partials = committee
        .slice(0, 2)
        .map((member) => member.partialDecryptAggregate(encryptedSum));
      weights = server.combineAggregate(encryptedSum, partials).mean;
    }

    expectClose(weights, [trueW, trueB], 0.05);
  });

  it('decrypts with a single key owner, and supports Damgard-Jurik', () => {
    for (const algorithmName of ['Paillier', 'Damgard-Jurik']) {
      const cs = new LightPHE({ algorithmName, keySize: 256 });
      const updates = [
        [0.5, -0.25, 1.0],
        [-1.0, 0.75, 0.0],
      ];
      const encryptedSum = cs.aggregateUpdates(
        updates.map((update) => cs.encryptUpdate(update, 1, 2))
      );
      const result = cs.decryptAggregate(encryptedSum);
      expectClose(result.sum, [-0.5, 0.5, 1.0], 1e-9);
      expectClose(result.mean, [-0.25, 0.25, 0.5], 1e-9);
    }
  });

  it('rejects invalid inputs', () => {
    const cs = new LightPHE({ algorithmName: 'Paillier', keySize: 256 });

    expect(() => cs.encryptUpdate([0.5, 1.5], 1, 2)).toThrow(
      'exceeds the maximum value'
    );
    expect(() => cs.encryptUpdate([0.5, 'a' as never], 1, 2)).toThrow(
      'list of numbers'
    );
    expect(() => cs.encryptUpdate([], 1, 2)).toThrow('at least one value');
    // a single slot needs more bits than the plaintext space of a 256-bit key has
    expect(() => cs.encryptUpdate([0.5], 10 ** 80, 2)).toThrow('too small');

    const a = cs.encryptUpdate([0.5, 0.5], 1, 2);
    const b = cs.encryptUpdate([0.5], 1, 2);
    expect(() => cs.aggregateUpdates([a, b])).toThrow('same layout');

    // summing more updates than the slots are packed for would overflow
    expect(() => cs.aggregateUpdates([a, a, a])).toThrow('overflow');

    expect(() =>
      new LightPHE({
        algorithmName: 'Exponential-ElGamal',
        keySize: 50,
      }).encryptUpdate([0.5], 1, 2)
    ).toThrow('does not support secure aggregation');
  });
});
