import {
  CatalanoFioreCiphertext,
  Ciphertext,
  EncryptedTensor,
  LightPHE,
  Logger,
  serialization,
  type ArgmaxMessage,
  type CiphertextValue,
  type DecryptionProof,
  type OneHotProof,
  type PartialDecryption,
  type RangeProof,
} from '../src';
import { valuesEqual } from './helpers';

const logger = new Logger('tests/serialization.test.ts');

// small keys are not secure, and are for testing only
const ALGORITHMS: [string, { keySize?: number }, string][] = [
  ['RSA', { keySize: 128 }, 'mul'],
  ['ElGamal', { keySize: 128 }, 'mul'],
  ['Exponential-ElGamal', { keySize: 128 }, 'add'],
  ['EllipticCurve-ElGamal', {}, 'add'],
  ['Paillier', { keySize: 128 }, 'add'],
  ['Damgard-Jurik', { keySize: 128 }, 'add'],
  ['Okamoto-Uchiyama', { keySize: 128 }, 'add'],
  ['Benaloh', { keySize: 64 }, 'add'],
  ['Naccache-Stern', { keySize: 64 }, 'add'],
  ['Goldwasser-Micali', { keySize: 64 }, 'xor'],
  ['Sander-Young-Yung', { keySize: 64 }, 'and'],
  ['Boneh-Goh-Nissim', { keySize: 64 }, 'add'],
  ['Joye-Libert', { keySize: 128 }, 'add'],
  ['Castagnos-Laguillaumie', { keySize: 128 }, 'add'],
  ['Ishai-Paskin', { keySize: 128 }, 'add'],
  ['Damgard-Geisler-Kroigaard', { keySize: 128 }, 'add'],
  ['Bresson-Catalano-Pointcheval', { keySize: 128 }, 'add'],
  ['Camenisch-Shoup', { keySize: 128 }, 'add'],
  ['EllipticCurve-Paillier', { keySize: 128 }, 'add'],
  ['Regev', {}, 'add'],
  ['Brakerski-Vaikuntanathan', { keySize: 64 }, 'add'],
  ['Freeman-Boneh-Goh-Nissim', {}, 'add'],
  ['Gentry-Halevi-Vaikuntanathan', {}, 'add'],
  ['Lyubashevsky-Peikert-Regev', { keySize: 64 }, 'add'],
  ['ML-KEM', { keySize: 512 }, 'xor'],
  ['Gentry-Sahai-Waters', { keySize: 64 }, 'xor'],
];

function publicParty(cs: LightPHE<string | null | undefined>): LightPHE {
  return new LightPHE({
    algorithmName: cs.algorithmName,
    keys: { public_key: cs.cs.keys.public_key },
    form: cs.form,
    curve: cs.curve,
  });
}

/** Name of the constructor of a ciphertext payload, to compare shapes. */
function shapeOf(value: CiphertextValue): string {
  if (Array.isArray(value)) {
    return `[${value.map(shapeOf).join(',')}]`;
  }
  return typeof value === 'bigint' ? 'bigint' : value.constructor.name;
}

describe('serialization', () => {
  it.each(ALGORITHMS)(
    'round trips %s ciphertexts through an untrusted party',
    (algorithmName, options, operation) => {
      const owner = new LightPHE({ algorithmName, ...options });
      const cloud = publicParty(owner);

      const m1 = 1n;
      const m2 = 1n;
      const c1 = owner.encrypt(m1);
      const c2 = owner.encrypt(m2);

      // owner sends ciphertexts, and cloud computes on them with the public key only
      const data = owner.serialize(c1);
      expect(data).not.toContain('private_key');
      const restored1 = cloud.deserialize<Ciphertext>(data);
      const restored2 = cloud.fromDict<Ciphertext>(
        serialization.parse(serialization.stringify(c2.toDict()))
      );
      expect(restored1).toBeInstanceOf(Ciphertext);
      expect(valuesEqual(restored1.value, c1.value)).toBe(true);
      expect(shapeOf(restored1.value)).toBe(shapeOf(c1.value));
      expect(restored1.cs.keys.private_key).toBeUndefined();

      let result: Ciphertext;
      let expected: bigint;
      if (operation === 'mul') {
        [result, expected] = [restored1.multiply(restored2), m1 * m2];
      } else if (operation === 'xor') {
        [result, expected] = [restored1.xor(restored2), m1 ^ m2];
      } else if (operation === 'and') {
        [result, expected] = [restored1.and(restored2), m1 & m2];
      } else {
        [result, expected] = [restored1.add(restored2), m1 + m2];
      }

      // cloud sends the result back to the owner
      const decrypted: unknown = owner.decrypt(
        owner.deserialize<Ciphertext>(cloud.serialize(result))
      );
      expect([expected, [expected]]).toContainEqual(decrypted);

      logger.info(
        `✅ Serialization round trip test succeeded for ${algorithmName}`
      );
    }
  );

  it.each([
    ['Boneh-Goh-Nissim', { keySize: 64 }],
    ['Freeman-Boneh-Goh-Nissim', {}],
    ['Brakerski-Vaikuntanathan', { keySize: 64 }],
  ])('restores multiplied ciphertexts of %s', (algorithmName, options) => {
    // multiplied ciphertexts of these algorithms are told apart by their types,
    // e.g. a point on the curve for Boneh-Goh-Nissim becomes an F_p^2 element
    const owner = new LightPHE({ algorithmName, ...options });
    const cloud = publicParty(owner);

    const c1 = cloud.deserialize<Ciphertext>(owner.serialize(owner.encrypt(3)));
    const c2 = owner.encrypt(4);
    const product = c1.multiply(cloud.fromDict<Ciphertext>(c2.toDict()));
    const restored = owner.deserialize<Ciphertext>(cloud.serialize(product));
    expect(shapeOf(restored.value)).toBe(shapeOf(product.value));
    expect(owner.decrypt(restored)).toBe(12n);

    logger.info(
      `✅ Multiplied ciphertext serialization test succeeded for ${algorithmName}`
    );
  });

  it('preserves structures and number types', () => {
    const cs = new LightPHE({ algorithmName: 'Paillier', keySize: 128 });
    const c = cs.encrypt(5);
    const item = {
      nested: [1n, [2n, 3n], 4],
      list: [c, null, true, 'text', 1.5],
      int_keys: new Map<unknown, unknown>([
        [1n, c],
        [2n, [c, c]],
      ]),
      inf: [Infinity, -Infinity],
      big: 2n ** 200n,
      skipped: undefined,
      [serialization.TAG]: 'not an encoded object',
    };
    const restored = cs.deserialize<Record<string, unknown>>(
      cs.serialize(item)
    );

    expect(restored.nested).toEqual([1n, [2n, 3n], 4]);
    const list = restored.list as unknown[];
    expect(list.slice(1)).toEqual([null, true, 'text', 1.5]);
    expect(cs.decrypt(list[0] as Ciphertext)).toBe(5n);
    const intKeys = restored.int_keys as Map<unknown, unknown>;
    expect([...intKeys.keys()]).toEqual([1n, 2n]);
    expect(cs.decrypt((intKeys.get(2n) as Ciphertext[])[1])).toBe(5n);
    expect(restored.inf).toEqual([Infinity, -Infinity]);
    expect(restored.big).toBe(2n ** 200n);
    expect('skipped' in restored).toBe(false);
    expect(restored[serialization.TAG]).toBe('not an encoded object');

    // a __proto__ key is restored as an own property, not as the prototype
    const polluted = cs.deserialize<Record<string, unknown>>(
      '{"__proto__": {"polluted": 1}}'
    );
    expect(Object.getPrototypeOf(polluted)).toBe(Object.prototype);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();

    logger.info('✅ Serialization preserves structures and number types');
  });

  it('restores the json layout of the Python library', () => {
    const cs = new LightPHE({ algorithmName: 'Paillier', keySize: 128 });
    const value = cs.encrypt(17).value as bigint;

    // json.dumps of a ciphertext, a tuple and a float in Python
    const data =
      `{"c": {"__lightphe__": "ciphertext", "version": 1, "algorithm_name": "Paillier",` +
      ` "value": ${value}}, "pair": {"__lightphe__": "tuple", "items": [3, 1.0]}}`;
    const restored = cs.deserialize<{ c: Ciphertext; pair: unknown[] }>(data);
    expect(cs.decrypt(restored.c)).toBe(17n);
    expect(restored.pair).toEqual([3n, 1]);

    // and the same layout is written back
    expect(cs.serialize(restored.c)).toBe(
      `{"__lightphe__": "ciphertext", "version": 1, "algorithm_name": "Paillier", "value": ${value}}`
    );

    logger.info('✅ Python json layout is restored');
  });

  it('restores encrypted tensors', () => {
    const cs = new LightPHE({
      algorithmName: 'Paillier',
      keySize: 128,
      precision: 3,
    });
    const cloud = publicParty(cs);
    const signed = cs.deserialize<EncryptedTensor>(
      cs.serialize(cs.encrypt([1.5, -2.25, 3], { silent: true }))
    );
    const decrypted = cs.decrypt(signed);
    [1.5, -2.25, 3].forEach((x, i) => expect(decrypted[i]).toBeCloseTo(x));

    const restored = cloud.deserialize<EncryptedTensor>(
      cs.serialize(cs.encrypt([1.5, 2.25, 3], { silent: true }))
    );
    expect(restored).toBeInstanceOf(EncryptedTensor);
    expect(restored.cs.keys.private_key).toBeUndefined();
    expect(restored.precision).toBe(3);

    // cloud multiplies the encrypted tensor with a plain tensor and sends it back
    const result = cs.deserialize<EncryptedTensor>(
      cloud.serialize(restored.multiply([2, 2, 2]))
    );
    const product = cs.decrypt(result);
    [3, 4.5, 6].forEach((x, i) => expect(product[i]).toBeCloseTo(x));

    logger.info('✅ Encrypted tensor serialization test succeeded');
  });

  it('sends proofs to a verifier', () => {
    const prover = new LightPHE({ algorithmName: 'Paillier', keySize: 128 });
    const verifier = publicParty(prover);

    const [ciphertext, rangeProof] = prover.encryptWithRangeProof(17, 0, 100);
    const [receivedCiphertext, receivedRangeProof] = verifier.deserialize<
      [Ciphertext, RangeProof]
    >(prover.serialize([ciphertext, rangeProof]));
    expect(
      verifier.verifyRange(receivedCiphertext, receivedRangeProof, 0, 100)
    ).toBe(true);

    const [ciphertexts, oneHotProof] = prover.encryptOneHot(1, 3);
    const [receivedCiphertexts, receivedOneHotProof] = verifier.deserialize<
      [Ciphertext[], OneHotProof]
    >(prover.serialize([ciphertexts, oneHotProof]));
    expect(
      verifier.verifyOneHot(receivedCiphertexts, receivedOneHotProof)
    ).toBe(true);

    const [plaintext, proof] = prover.decryptWithProof(ciphertext);
    const message = verifier.deserialize<{
      ciphertext: Ciphertext;
      plaintext: bigint;
      proof: DecryptionProof;
    }>(prover.serialize({ ciphertext, plaintext, proof }));
    expect(
      verifier.verifyDecryption(
        message.ciphertext,
        message.plaintext,
        message.proof
      )
    ).toBe(true);

    logger.info('✅ Proof serialization test succeeded');
  });

  it('sends elliptic curve proofs to a verifier', () => {
    const prover = new LightPHE({ algorithmName: 'EllipticCurve-ElGamal' });
    const verifier = publicParty(prover);

    const ciphertext = prover.encrypt(7);
    const [plaintext, proof] = prover.decryptWithProof(ciphertext);
    const [c, m, p] = verifier.deserialize<
      [Ciphertext, bigint, DecryptionProof]
    >(prover.serialize([ciphertext, plaintext, proof]));
    expect(verifier.verifyDecryption(c, m, p)).toBe(true);

    logger.info('✅ Elliptic curve proof serialization test succeeded');
  });

  it('runs threshold decryption over network', () => {
    const dealer = new LightPHE({
      algorithmName: 'Paillier',
      keySize: 256,
      safePrimes: true,
    });
    const shareKeys = dealer.generateThresholdKeys(2, 3);
    const shareholders = shareKeys.map(
      (keys) => new LightPHE({ algorithmName: 'Paillier', keys })
    );
    const combiner = publicParty(dealer);

    const ciphertext = combiner.encrypt(42);
    const data = combiner.serialize(ciphertext);

    // every shareholder receives the ciphertext, and sends its partial decryption back
    const partials = shareholders
      .slice(0, 2)
      .map((shareholder) =>
        combiner.deserialize<PartialDecryption>(
          shareholder.serialize(
            shareholder.partialDecrypt(
              shareholder.deserialize<Ciphertext>(data),
              { prove: true }
            )
          )
        )
      );
    expect(partials[0].index).toBe(1);
    expect(
      combiner.combinePartialDecryptions(ciphertext, partials, {
        verify: true,
      })
    ).toBe(42n);

    logger.info('✅ Threshold decryption over network test succeeded');
  });

  it('runs secure aggregation over network', () => {
    const owner = new LightPHE({ algorithmName: 'Paillier', keySize: 256 });
    const server = publicParty(owner);
    const clients = [0, 1, 2].map(() => publicParty(owner));
    const updates = clients.map(() =>
      Array.from({ length: 20 }, () => Math.random() * 2 - 1)
    );

    const messages = clients.map((client, i) =>
      client.serialize(client.encryptUpdate(updates[i], 1, 10))
    );
    const encryptedSum = server.aggregateUpdates(
      messages.map((m) => server.deserialize(m))
    );
    const result = owner.decryptAggregate(
      owner.deserialize(server.serialize(encryptedSum))
    );

    expect(result.count).toBe(3);
    result.sum.forEach((x, i) =>
      expect(x).toBeCloseTo(
        updates.reduce((total, update) => total + update[i], 0),
        4
      )
    );

    logger.info('✅ Secure aggregation over network test succeeded');
  });

  it('runs k-NN over network', async () => {
    const client = new LightPHE({
      algorithmName: 'Damgard-Geisler-Kroigaard',
      keySize: 512,
    });
    const server = publicParty(client);

    const network = (message: ArgmaxMessage): bigint[] => {
      // server serializes its message, client answers it, and server restores the answer
      const answer = client.answerKnn(
        client.deserialize<ArgmaxMessage>(server.serialize(message))
      );
      return server.deserialize<bigint[]>(client.serialize(answer));
    };

    const database = [
      [1, 2],
      [5, 5],
      [0, 0],
      [9, 1],
    ];
    const query = server.deserialize<ReturnType<LightPHE['encryptKnnQuery']>>(
      client.serialize(client.encryptKnnQuery([1, 1]))
    );
    const result = await server.evaluateKnn(query, database, 2, 8, network);
    const received = client.deserialize<{ indices: Ciphertext[] }>(
      server.serialize(result)
    );

    expect(received.indices.map((c) => client.decrypt(c))).toEqual([0n, 2n]);

    logger.info('✅ k-NN over network test succeeded');
  });

  it('restores Catalano-Fiore ciphertexts', () => {
    const owner = new LightPHE({
      algorithmName: 'Paillier',
      keySize: 128,
      boost: 'Catalano-Fiore',
    });
    const cloud = new LightPHE({
      algorithmName: 'Paillier',
      keys: { public_key: owner.cs.keys.public_key },
      boost: 'Catalano-Fiore',
    });

    const database = [
      [1, 2, 3],
      [4, 4, 4],
      [0, 1, 2],
    ];
    const query = [1, 1, 1];
    const encryptedDatabase = cloud.deserialize<CatalanoFioreCiphertext[][]>(
      owner.serialize(
        database.map((vector) => vector.map((x) => owner.encrypt(x)))
      )
    );
    const encryptedQuery = cloud.fromDict<CatalanoFioreCiphertext[]>(
      serialization.parse(owner.serialize(query.map((x) => owner.encrypt(x))))
    );
    expect(
      encryptedQuery.every((c) => c instanceof CatalanoFioreCiphertext)
    ).toBe(true);

    const distances = cloud.evaluateKnnDistances(
      encryptedQuery,
      encryptedDatabase
    );
    const received = owner.deserialize<CatalanoFioreCiphertext[]>(
      cloud.serialize(distances)
    );
    expect(received.every((c) => c.isMultiplied)).toBe(true);
    expect(owner.decryptKnn(received, 2)).toEqual({
      indices: [2, 0],
      distances: [2n, 5n],
    });

    // a party without the boost restores Catalano-Fiore ciphertexts as well
    const product = publicParty(owner).fromDict<CatalanoFioreCiphertext>(
      owner.encrypt(6).multiply(owner.encrypt(7)).toDict()
    );
    expect(product).toBeInstanceOf(CatalanoFioreCiphertext);
    expect(product.isMultiplied).toBe(true);
    expect(owner.decrypt(product)).toBe(42n);

    logger.info('✅ Catalano-Fiore serialization test succeeded');
  });

  it('rejects invalid inputs', () => {
    const cs = new LightPHE({ algorithmName: 'Paillier', keySize: 128 });
    const data = cs.encrypt(5).toDict();

    const other = new LightPHE({
      algorithmName: 'Damgard-Jurik',
      keySize: 128,
    });
    expect(() => other.fromDict(data)).toThrow('belongs to Paillier');

    expect(() => cs.deserialize('{not json')).toThrow('not a valid json');
    expect(() => cs.deserialize('[1, 2] 3')).toThrow('not a valid json');

    for (const value of ['123', true, null, { x: 1n }, [1n, '2'], 1.5, 1]) {
      expect(() => cs.fromDict({ ...data, value })).toThrow(
        'must consist of integers'
      );
    }

    expect(() => cs.fromDict({ ...data, version: 999n })).toThrow('version');
    expect(() => cs.fromDict({ [serialization.TAG]: 'something' })).toThrow(
      'Unknown serialized object'
    );
    expect(() =>
      cs.fromDict({ [serialization.TAG]: 'float', value: '1e3' })
    ).toThrow('Invalid encoded float');
    expect(() => cs.serialize(new Date())).toThrow('cannot be serialized');
    expect(() => cs.serialize(cs)).toThrow('cannot be serialized');

    // points must be on the curve
    const bgn = new LightPHE({
      algorithmName: 'Boneh-Goh-Nissim',
      keySize: 64,
    });
    const pointData = bgn.encrypt(1).toDict();
    const point = pointData.value as Record<string, unknown>;
    point.y = (point.y as bigint) + 1n;
    expect(() => bgn.fromDict(pointData)).toThrow('not on the curve');
    expect(() => cs.fromDict({ ...data, value: point })).toThrow(
      'not elliptic curve points'
    );

    // Catalano-Fiore ciphertexts must be well formed
    const cf = new LightPHE({
      algorithmName: 'Paillier',
      keys: cs.cs.keys,
      boost: 'Catalano-Fiore',
    });
    const cfData = cf.encrypt(5).toDict();
    const modulo = cs.cs.plaintextModulo;
    expect(() => cs.fromDict({ ...cfData, a: modulo })).toThrow('must be in');
    expect(() => cs.fromDict({ ...cfData, pairs: [[data, data]] })).toThrow(
      'a and beta only'
    );
    expect(() => cs.fromDict({ ...cfData, alpha: data })).toThrow(
      'alpha and pairs only'
    );
    expect(() => other.fromDict(cfData)).toThrow('belongs to Paillier');

    logger.info('✅ Invalid serialized inputs are rejected');
  });
});
