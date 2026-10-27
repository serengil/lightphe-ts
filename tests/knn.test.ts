import {
  CatalanoFioreCiphertext,
  LightPHE,
  Logger,
  type ArgmaxMessage,
  type DamgardGeislerKroigaard,
} from '../src';
import { randomInt } from './helpers';

const logger = new Logger('tests/knn.test.ts');

// 512-bit keys have the same 32-bit plaintext space as 1024-bit keys, but are faster.
// they are not secure, and are for testing only.
const clientCs = new LightPHE({
  algorithmName: 'Damgard-Geisler-Kroigaard',
  keySize: 512,
});
const serverCs = new LightPHE({
  algorithmName: 'Damgard-Geisler-Kroigaard',
  keys: { public_key: clientCs.cs.keys.public_key },
});

function squaredDistance(a: readonly number[], b: readonly number[]): number {
  return a.reduce((total, x, i) => total + (x - b[i]) ** 2, 0);
}

function plainKnn(query: number[], database: number[][], k: number): number[] {
  const distances = database.map((vector) => squaredDistance(query, vector));
  // earlier index first on ties
  return distances
    .map((_, i) => i)
    .sort((i, j) => distances[i] - distances[j] || i - j)
    .slice(0, k);
}

async function search(
  query: number[],
  database: number[][],
  k: number,
  bitLength: number,
  labels?: number[],
  client?: (message: ArgmaxMessage) => bigint[]
): Promise<[number[], number[]]> {
  const encryptedQuery = clientCs.encryptKnnQuery(query);
  const result = await serverCs.evaluateKnn(
    encryptedQuery,
    database,
    k,
    bitLength,
    client ?? clientCs.answerKnn,
    { labels }
  );
  const indices = result.indices.map((c) => Number(clientCs.decrypt(c)));
  const decryptedLabels = (result.labels ?? []).map((c) =>
    Number(clientCs.decrypt(c))
  );
  return [indices, decryptedLabels];
}

describe('encrypted k nearest neighbors', () => {
  it('matches plain k-NN', async () => {
    for (let round = 0; round < 2; round++) {
      const database = Array.from({ length: 10 }, () =>
        Array.from({ length: 8 }, () => randomInt(-50, 50))
      );
      const labels = database.map(() => randomInt(1, 10 ** 6));
      const query = Array.from({ length: 8 }, () => randomInt(-50, 50));

      const [indices, foundLabels] = await search(
        query,
        database,
        3,
        17,
        labels
      );
      const expected = plainKnn(query, database, 3);
      expect(indices).toEqual(expected);
      expect(foundLabels).toEqual(expected.map((i) => labels[i]));
    }

    logger.info('✅ Encrypted k-NN matches plain k-NN');
  });

  it('finds the nearest one and the full ranking', async () => {
    const database = Array.from({ length: 5 }, () =>
      Array.from({ length: 4 }, () => randomInt(0, 20))
    );
    const query = Array.from({ length: 4 }, () => randomInt(0, 20));

    const [nearest, labels] = await search(query, database, 1, 12);
    expect(nearest).toEqual(plainKnn(query, database, 1));
    expect(labels).toEqual([]);

    const [ranking] = await search(query, database, 5, 12);
    expect(ranking).toEqual(plainKnn(query, database, 5));
  });

  it('returns earlier index first on ties', async () => {
    const database = [
      [3, 4],
      [0, 0],
      [3, 4],
      [0, 0],
      [9, 9],
    ];
    const [indices] = await search([0, 0], database, 4, 8);
    expect(indices).toEqual([1, 3, 0, 2]);
  });

  it('shows the client a single zero in shuffled positions', async () => {
    const database = Array.from({ length: 6 }, (_, i) => [i, 2 * i]);
    const seen: boolean[][] = [];

    const recordingClient = (message: ArgmaxMessage): bigint[] => {
      if (message.type === 'equality') {
        const dgk = clientCs.cs as DamgardGeislerKroigaard;
        seen.push((message.payload as bigint[]).map((c) => dgk.isZero(c)));
      }
      return clientCs.answerKnn(message);
    };

    const [indices] = await search(
      [0, 0],
      database,
      3,
      8,
      undefined,
      recordingClient
    );
    expect(indices).toEqual([0, 1, 2]);

    // one equality round per found vector except the last one, each having a single zero
    expect(seen.length).toBe(2);
    for (const round of seen) {
      expect(round.filter(Boolean).length).toBe(1);
      expect(round.length).toBe(database.length);
    }
  });

  it('searches faces with quantized embeddings', async () => {
    // gallery of 8 people with 32-dimensional embeddings in [-1, 1]
    const gallery = Array.from({ length: 8 }, () =>
      Array.from({ length: 32 }, () => 2 * Math.random() - 1)
    );
    const people = [101, 102, 103, 104, 105, 106, 107, 108];

    // query is a noisy capture of person 105
    const query = gallery[4].map((x) => x + 0.05 * (2 * Math.random() - 1));

    // embeddings are quantized to 8-bit integers, so squared distances are less than 2^21
    const quantize = (vector: number[]): number[] =>
      vector.map((x) => Math.max(-127, Math.min(127, Math.round(x * 127))));

    const [, labels] = await search(
      quantize(query),
      gallery.map(quantize),
      1,
      21,
      people
    );
    expect(labels).toEqual([105]);
  });

  it('rejects invalid inputs', async () => {
    const encryptedQuery = clientCs.encryptKnnQuery([1, 2]);
    const database = [
      [1, 2],
      [3, 4],
    ];
    const client = clientCs.answerKnn;

    await expect(
      serverCs.evaluateKnn(encryptedQuery, [[1, 2, 3]], 1, 8, client)
    ).rejects.toThrow('list of 2 integers');
    await expect(
      serverCs.evaluateKnn(encryptedQuery, [[1, 2.5]], 1, 8, client)
    ).rejects.toThrow('list of 2 integers');
    for (const k of [0, 3]) {
      await expect(
        serverCs.evaluateKnn(encryptedQuery, database, k, 8, client)
      ).rejects.toThrow('k must be in');
    }
    await expect(
      serverCs.evaluateKnn(encryptedQuery, database, 1, 8, client, {
        labels: [1],
      })
    ).rejects.toThrow('one for each vector');
    await expect(
      serverCs.evaluateKnn(encryptedQuery, database, 1, 4, client)
    ).rejects.toThrow('does not fit');
    await expect(
      serverCs.evaluateKnn(encryptedQuery, database, 1, 40, client)
    ).rejects.toThrow('too small for argmax');
    await expect(
      serverCs.evaluateKnn({} as never, database, 1, 8, client)
    ).rejects.toThrow('output of encryptKnnQuery');
    expect(() => clientCs.encryptKnnQuery([1.5, 2])).toThrow(
      'non-empty list of integers'
    );
    expect(() => serverCs.answerKnn({ type: 'equality', payload: [] })).toThrow(
      'private key'
    );

    const paillier = new LightPHE({ algorithmName: 'Paillier', keySize: 64 });
    expect(() => paillier.encryptKnnQuery([1, 2])).toThrow(
      'does not support encrypted nearest neighbor search'
    );
  });
});

describe('encrypted database in an untrusted cloud', () => {
  // owner stores its encrypted database in an untrusted cloud
  const ownerCs = new LightPHE({
    algorithmName: 'Paillier',
    keySize: 256,
    boost: 'Catalano-Fiore',
  });
  const cloudCs = new LightPHE({
    algorithmName: 'Paillier',
    keys: { public_key: ownerCs.cs.keys.public_key },
    boost: 'Catalano-Fiore',
  });

  it('finds the nearest vectors', () => {
    const database = Array.from({ length: 8 }, () =>
      Array.from({ length: 6 }, () => randomInt(-100, 100))
    );
    const query = Array.from({ length: 6 }, () => randomInt(-100, 100));

    // owner encrypts its database once and uploads it, then encrypts queries
    const encryptedDatabase = database.map((vector) =>
      vector.map((x) => ownerCs.encrypt(x))
    );
    const encryptedQuery = query.map((x) => ownerCs.encrypt(x));

    // cloud computes encrypted distances with the public key only
    const encryptedDistances = cloudCs.evaluateKnnDistances(
      encryptedQuery,
      encryptedDatabase
    );
    expect(encryptedDistances.length).toBe(database.length);
    expect(() => cloudCs.decryptKnn(encryptedDistances, 3)).toThrow(
      'private key'
    );

    // owner decrypts them and finds the nearest vectors locally
    const result = ownerCs.decryptKnn(encryptedDistances, 3);
    const expected = plainKnn(query, database, 3);
    expect(result.indices).toEqual(expected);
    expect(result.distances).toEqual(
      expected.map((i) => BigInt(squaredDistance(query, database[i])))
    );

    logger.info('✅ Encrypted database in cloud test succeeded');
  });

  it('rejects invalid inputs', () => {
    const encryptedQuery = [1, 2].map((x) => ownerCs.encrypt(x));
    const encryptedDatabase = [[3, 4].map((x) => ownerCs.encrypt(x))];

    expect(() =>
      cloudCs.evaluateKnnDistances(encryptedQuery, [[ownerCs.encrypt(1)]])
    ).toThrow('list of 2 encrypted integers');
    expect(() =>
      cloudCs.evaluateKnnDistances(
        [1, 2] as unknown as CatalanoFioreCiphertext[],
        encryptedDatabase
      )
    ).toThrow('non-empty list of encrypted integers');

    // products cannot be multiplied again
    const product = encryptedQuery[0].multiply(encryptedQuery[1]);
    expect(() =>
      cloudCs.evaluateKnnDistances(
        [product, encryptedQuery[1]],
        encryptedDatabase
      )
    ).toThrow('non-empty list of encrypted integers');

    const distances = cloudCs.evaluateKnnDistances(
      encryptedQuery,
      encryptedDatabase
    );
    for (const k of [0, 2]) {
      expect(() => ownerCs.decryptKnn(distances, k)).toThrow('k must be in');
    }

    expect(() =>
      new LightPHE({
        algorithmName: 'Paillier',
        keySize: 64,
      }).evaluateKnnDistances(encryptedQuery, encryptedDatabase)
    ).toThrow("boost='Catalano-Fiore'");
  });
});
