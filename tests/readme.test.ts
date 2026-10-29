/**
 * The examples from README.md, executed.
 *
 * Documentation that has never been run tends to drift; this keeps every
 * snippet in the README honest. The only change from the published text is a
 * smaller key size, so the suite stays quick.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import LightPHEDefault, {
  FORMS,
  LightPHE,
  getDefaultCurve,
  listCurveNames,
  type DecisionTree,
} from '../src';

describe('README examples', () => {
  it('builds a cryptosystem for every listed algorithm name', () => {
    const algorithms = [
      'RSA',
      'ElGamal',
      'Exponential-ElGamal',
      'Paillier',
      'Damgard-Jurik',
      'Okamoto-Uchiyama',
      'Benaloh',
      'Naccache-Stern',
      'Goldwasser-Micali',
      'EllipticCurve-ElGamal',
      'Sander-Young-Yung',
      'Boneh-Goh-Nissim',
      'Joye-Libert',
      'Castagnos-Laguillaumie',
      'Ishai-Paskin',
      'Damgard-Geisler-Kroigaard',
      'Bresson-Catalano-Pointcheval',
      'Camenisch-Shoup',
      'EllipticCurve-Paillier',
      'Regev',
      'Lyubashevsky-Peikert-Regev',
      'ML-KEM',
      'Brakerski-Vaikuntanathan',
      'Freeman-Boneh-Goh-Nissim',
      'Gentry-Halevi-Vaikuntanathan',
      'Gentry-Sahai-Waters',
    ];

    // lattice based ones take dimensions instead of bit lengths
    const keySizes: Record<string, number> = {
      'Lyubashevsky-Peikert-Regev': 64,
      'ML-KEM': 512,
      'Brakerski-Vaikuntanathan': 64,
      'Freeman-Boneh-Goh-Nissim': 64,
      'Gentry-Halevi-Vaikuntanathan': 2,
      'Gentry-Sahai-Waters': 16,
    };

    for (const algorithmName of algorithms) {
      const keySize = keySizes[algorithmName] ?? 50;
      const cs = new LightPHE({ algorithmName, keySize });
      expect(cs.cs.keys.public_key).toBeDefined();
    }
  });

  it('exposes LightPHE as the default export too', () => {
    expect(LightPHEDefault).toBe(LightPHE);
  });

  it('runs the additively homomorphic walkthrough', () => {
    const cs = new LightPHE({ algorithmName: 'Paillier', keySize: 50 });

    const m1 = 10000; // base salary in usd
    const m2 = 500; // wage increase in usd

    const c1 = cs.encrypt(m1);
    const c2 = cs.encrypt(m2);

    const c3 = c1.add(c2);

    const k = 1.05; // increase something 5%
    const c4 = c1.multiply(k);

    expect(cs.decrypt(c3)).toBe(BigInt(m1 + m2));
    expect(cs.decrypt(c4)).toBe(BigInt(m1 * k));
  });

  it('runs the multiplicatively homomorphic walkthrough', () => {
    const cs = new LightPHE({ algorithmName: 'RSA', keySize: 50 });

    const m1 = 17;
    const m2 = 21;

    const c1 = cs.encrypt(m1);
    const c2 = cs.encrypt(m2);

    expect(cs.decrypt(c1.multiply(c2))).toBe(BigInt(m1 * m2));
  });

  it('throws on an operation the scheme does not support', () => {
    const cs = new LightPHE({ algorithmName: 'RSA', keySize: 50 });
    const c1 = cs.encrypt(17);
    const c2 = cs.encrypt(21);

    expect(() => c1.add(c2)).toThrow(
      'RSA is not homomorphic with respect to the addition'
    );
  });

  it('regenerates a ciphertext', () => {
    const cs = new LightPHE({ algorithmName: 'Paillier', keySize: 50 });
    const c1 = cs.encrypt(17);

    const c1Prime = cs.regenerateCiphertext(c1);
    expect(cs.decrypt(c1Prime)).toBe(cs.decrypt(c1));
  });

  it('builds an elliptic curve cryptosystem and lists the inventory', () => {
    const cs = new LightPHE({
      algorithmName: 'EllipticCurve-ElGamal',
      form: 'edwards',
    });
    expect(cs.decrypt(cs.encrypt(10))).toBe(10n);

    expect([...FORMS]).toEqual(['weierstrass', 'edwards', 'koblitz']);
    expect(getDefaultCurve('weierstrass')).toBe('secp256k1');
    expect(listCurveNames('edwards')).toContain('ed25519');
  });

  it('runs the vector embedding walkthrough', () => {
    const cs = new LightPHE({ algorithmName: 'Paillier', keySize: 50 });

    const t1 = [1.005, 2.05, 3.6, 4, 4.02, 3.5];
    const t2 = [5, 6.2, 7.5, 8.02, 8.02, 4.5];
    const t3 = [1.03, 2.04, 3.05, 7.02, 2.01, 1.06];

    const c1 = cs.encrypt(t1);
    const c2 = cs.encrypt(t2);

    const c4 = c1.add(c2);
    const c5 = c1.multiply(3);
    const c6 = c1.multiply(t3);
    const c7 = c1.dot(t3);

    const close = (a: number[], b: number[]): boolean =>
      a.every((x, i) => Math.abs(x - b[i]) < 0.1);

    expect(
      close(
        cs.decrypt(c4),
        t1.map((a, i) => a + t2[i])
      )
    ).toBe(true);
    expect(
      close(
        cs.decrypt(c5),
        t1.map((a) => a * 3)
      )
    ).toBe(true);
    expect(
      close(
        cs.decrypt(c6),
        t1.map((a, i) => a * t3[i])
      )
    ).toBe(true);
    expect(
      Math.abs(cs.decrypt(c7)[0] - t1.reduce((s, a, i) => s + a * t3[i], 0))
    ).toBeLessThan(0.1);
  });

  it('runs the decision tree walkthrough', () => {
    const creditLimitTree: DecisionTree = [0, [2, 0, 5], [1, 20, [2, 5, 10]]];

    const customerCs = new LightPHE({
      algorithmName: 'Ishai-Paskin',
      keySize: 50,
    });

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-ts-'));
    const publicKeyFile = path.join(dir, 'public.txt');
    customerCs.exportKeys(publicKeyFile, true);

    const answers = [1, 1, 0];
    const encryptedAnswers = customerCs.encryptDecisionTreeInput(answers, 3);

    const bankCs = new LightPHE({
      algorithmName: 'Ishai-Paskin',
      keyFile: publicKeyFile,
    });

    const encryptedLimit = bankCs.evaluateDecisionTree(
      creditLimitTree,
      encryptedAnswers
    );

    expect(customerCs.decrypt(encryptedLimit)).toBe(5n);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('hands a public key to a cloud that cannot decrypt', () => {
    const cs = new LightPHE({ algorithmName: 'Paillier', keySize: 50 });

    const cloud = new LightPHE({
      algorithmName: 'Paillier',
      keys: { public_key: cs.cs.keys.public_key },
    });
    const c1 = cloud.encrypt(17);

    expect(() => cloud.decrypt(c1)).toThrow(
      'You must have private key to perform decryption'
    );
    // but the owner of the private key can
    expect(cs.decrypt(c1)).toBe(17n);
  });

  it('accepts a key pair passed in directly', () => {
    const cs = new LightPHE({
      algorithmName: 'RSA',
      keys: { public_key: { n: 175501n, e: 101753n } },
    });
    expect(cs.cs.plaintextModulo).toBe(175501n);
  });

  it('round-trips a raw payload through createCiphertextObj', () => {
    const cs = new LightPHE({ algorithmName: 'Paillier', keySize: 50 });
    const c1 = cs.encrypt(17);

    const payload = c1.value;
    const rebuilt = cs.createCiphertextObj(payload);

    expect(cs.decrypt(rebuilt)).toBe(17n);
  });

  it('runs the encrypted argmax walkthrough', async () => {
    const clientCs = new LightPHE({
      algorithmName: 'Damgard-Geisler-Kroigaard',
      keySize: 256,
    });
    const encryptedFeatures = [3, 1, 4].map((feature) =>
      clientCs.encrypt(feature)
    );

    const serverCs = new LightPHE({
      algorithmName: 'Damgard-Geisler-Kroigaard',
      keys: { public_key: clientCs.cs.keys.public_key },
    });
    const weights = [
      [1, 2, 0],
      [0, 1, 3],
      [2, 0, 1],
    ];
    const encryptedScores = weights.map((classWeights) =>
      classWeights
        .slice(1)
        .reduce(
          (score, weight, i) =>
            score.add(encryptedFeatures[i + 1].multiply(weight)),
          encryptedFeatures[0].multiply(classWeights[0])
        )
    );

    const encryptedClass = await serverCs.evaluateArgmax(
      encryptedScores,
      8,
      clientCs.answerArgmax
    );
    expect(clientCs.decrypt(encryptedClass)).toBe(1n);
  });

  it('runs the Catalano-Fiore walkthrough', () => {
    const clientCs = new LightPHE({
      algorithmName: 'Paillier',
      keySize: 256,
      boost: 'Catalano-Fiore',
    });

    const x = [3, 1, 4];
    const y = [1, 5, 9];
    const encryptedX = x.map((value) => clientCs.encrypt(value));
    const encryptedY = y.map((value) => clientCs.encrypt(value));

    const encryptedDot = encryptedX
      .map((ex, i) => ex.multiply(encryptedY[i]))
      .reduce((acc, product) => acc.add(product));

    const encryptedDistance = encryptedX
      .map((ex, i) => {
        const difference = ex.subtract(encryptedY[i]);
        return difference.multiply(difference);
      })
      .reduce((acc, square) => acc.add(square));

    expect(clientCs.decrypt(encryptedDot)).toBe(44n);
    expect(clientCs.decrypt(encryptedDistance)).toBe(45n);
  });

  it('runs the hyperplane and naive bayes walkthroughs', async () => {
    const clientCs = new LightPHE({
      algorithmName: 'Damgard-Geisler-Kroigaard',
      keySize: 512,
    });
    const encryptedFeatures = [85, 20, 6, 0].map((x) => clientCs.encrypt(x));

    const serverCs = new LightPHE({
      algorithmName: 'Damgard-Geisler-Kroigaard',
      keys: { public_key: clientCs.cs.keys.public_key },
    });
    const weights = [
      [0, 0, 0, 0],
      [42, -65, 310, -900],
    ];
    const biases = [0, -1200];

    const encryptedClass = await serverCs.evaluateHyperplane(
      encryptedFeatures,
      weights,
      16,
      clientCs.answerArgmax,
      { biases }
    );
    expect(clientCs.decrypt(encryptedClass)).toBe(1n);

    const encryptedSymptoms = clientCs.encryptNaiveBayesInput(
      [1, 1, 1],
      [2, 3, 2]
    );
    const priors = [0.36, 0.36, 0.28];
    const likelihoods = [
      [
        [0.71, 0.29],
        [0.12, 0.25, 0.63],
        [0.71, 0.29],
      ],
      [
        [0.29, 0.71],
        [0.12, 0.63, 0.25],
        [0.29, 0.71],
      ],
      [
        [0.83, 0.17],
        [0.57, 0.29, 0.14],
        [0.67, 0.33],
      ],
    ];
    const encryptedDiagnosis = await serverCs.evaluateNaiveBayes(
      encryptedSymptoms,
      priors,
      likelihoods,
      clientCs.answerArgmax
    );
    expect(clientCs.decrypt(encryptedDiagnosis)).toBe(1n);
  });

  it('runs the encrypted nearest neighbor walkthroughs', async () => {
    const gallery = [
      [10, -5, 30, 4],
      [-40, 22, 1, 9],
      [13, -8, 35, 6],
    ];

    const clientCs = new LightPHE({
      algorithmName: 'Damgard-Geisler-Kroigaard',
      keySize: 512,
    });
    const encryptedQuery = clientCs.encryptKnnQuery([12, -7, 33, 5]);
    const serverCs = new LightPHE({
      algorithmName: 'Damgard-Geisler-Kroigaard',
      keys: { public_key: clientCs.cs.keys.public_key },
    });
    const people = [101, 102, 103];
    const result = await serverCs.evaluateKnn(
      encryptedQuery,
      gallery,
      2,
      16,
      clientCs.answerKnn,
      { labels: people }
    );
    const nearest = result.labels!.map((label) => clientCs.decrypt(label));
    expect(nearest.join()).toBe('103,101');

    const ownerCs = new LightPHE({
      algorithmName: 'Paillier',
      keySize: 256,
      boost: 'Catalano-Fiore',
    });
    const encryptedGallery = gallery.map((vector) =>
      vector.map((x) => ownerCs.encrypt(x))
    );
    const encryptedOwnerQuery = [12, -7, 33, 5].map((x) => ownerCs.encrypt(x));
    const cloudCs = new LightPHE({
      algorithmName: 'Paillier',
      keys: { public_key: ownerCs.cs.keys.public_key },
      boost: 'Catalano-Fiore',
    });
    const encryptedDistances = cloudCs.evaluateKnnDistances(
      encryptedOwnerQuery,
      encryptedGallery
    );
    expect(ownerCs.decryptKnn(encryptedDistances, 2).indices.join()).toBe(
      '2,0'
    );
  });

  it('runs the threshold decryption walkthrough', () => {
    const dealerCs = new LightPHE({ algorithmName: 'Paillier', keySize: 128 });
    const shareKeys = dealerCs.generateThresholdKeys(3, 5);

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-ts-'));
    const publicKeyFile = path.join(dir, 'public.txt');
    dealerCs.exportKeys(publicKeyFile, true);

    const shareholders = shareKeys.map(
      (keys) => new LightPHE({ algorithmName: 'Paillier', keys })
    );
    const publicCs = new LightPHE({
      algorithmName: 'Paillier',
      keyFile: publicKeyFile,
    });
    const c = publicCs.encrypt(100).add(publicCs.encrypt(50));

    const partials = [0, 2, 4].map((i) => shareholders[i].partialDecrypt(c));
    expect(publicCs.combinePartialDecryptions(c, partials)).toBe(150n);
  });

  it('runs the secure aggregation walkthrough', () => {
    const dealerCs = new LightPHE({
      algorithmName: 'Paillier',
      keySize: 256,
      safePrimes: true,
    });
    const shareKeys = dealerCs.generateThresholdKeys(3, 5);
    const committee = shareKeys.map(
      (keys) => new LightPHE({ algorithmName: 'Paillier', keys })
    );
    const publicKey = { public_key: dealerCs.cs.keys.public_key };

    const clientCs = new LightPHE({
      algorithmName: 'Paillier',
      keys: publicKey,
    });
    const updates = [
      [0.12, -0.53, 0.98],
      [0.33, 0.21, -0.47],
      [-0.25, 0.08, 0.61],
    ];
    const encryptedUpdates = updates.map((update) =>
      clientCs.encryptUpdate(update, 1, 100)
    );

    const serverCs = new LightPHE({
      algorithmName: 'Paillier',
      keys: publicKey,
    });
    const encryptedSum = serverCs.aggregateUpdates(encryptedUpdates);

    const partials = committee
      .slice(0, 3)
      .map((member) =>
        member.partialDecryptAggregate(encryptedSum, { prove: true })
      );
    const result = serverCs.combineAggregate(encryptedSum, partials, {
      verify: true,
    });
    expect(result.mean.map((x) => x.toFixed(2)).join()).toBe('0.07,-0.08,0.37');
  });

  it('runs the zero-knowledge proof walkthroughs', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-ts-'));
    const publicKeyFile = path.join(dir, 'public.txt');

    // proof of decryption
    const cs = new LightPHE({
      algorithmName: 'Exponential-ElGamal',
      keySize: 128,
      primeOrder: true,
    });
    cs.exportKeys(publicKeyFile, true);
    const publicCs = new LightPHE({
      algorithmName: 'Exponential-ElGamal',
      keyFile: publicKeyFile,
    });
    const c = publicCs.encrypt(17).add(publicCs.encrypt(25));
    const [plaintext, proof] = cs.decryptWithProof(c);
    expect(publicCs.verifyDecryption(c, plaintext, proof)).toBe(true);
    expect(publicCs.verifyDecryption(c, plaintext + 1n, proof)).toBe(false);

    // proof of partial decryption
    const dealerCs = new LightPHE({
      algorithmName: 'Exponential-ElGamal',
      keySize: 128,
      primeOrder: true,
    });
    const shareKeys = dealerCs.generateThresholdKeys(2, 3);
    const shareholders = shareKeys.map(
      (keys) => new LightPHE({ algorithmName: 'Exponential-ElGamal', keys })
    );
    const c42 = dealerCs.encrypt(42);
    const partials = shareholders.map((shareholder) =>
      shareholder.partialDecrypt(c42, { prove: true })
    );
    expect(dealerCs.verifyPartialDecryption(c42, partials[0])).toBe(true);
    expect(
      dealerCs.combinePartialDecryptions(c42, partials, { verify: true })
    ).toBe(42n);

    const paillierCs = new LightPHE({
      algorithmName: 'Paillier',
      keySize: 128,
    });

    // proof of knowledge
    const [aliceBid, aliceProof] = paillierCs.encryptWithProofOfKnowledge(950, {
      context: 'alice',
    });
    expect(
      paillierCs.verifyKnowledge(aliceBid, aliceProof, { context: 'alice' })
    ).toBe(true);
    const malloryBid = aliceBid.add(paillierCs.encrypt(1));
    expect(
      paillierCs.verifyKnowledge(malloryBid, aliceProof, { context: 'mallory' })
    ).toBe(false);

    // proof of allowed values
    const values = [1, 2, 3, 4, 5];
    const [rating, ratingProof] = paillierCs.encryptWithProof(4, {
      values,
      context: 'customer-42',
    });
    expect(
      paillierCs.verifyCiphertext(rating, ratingProof, {
        values,
        context: 'customer-42',
      })
    ).toBe(true);
    expect(
      paillierCs.verifyCiphertext(rating, ratingProof, {
        values,
        context: 'customer-43',
      })
    ).toBe(false);

    // proof of range
    const [salary, salaryProof] = paillierCs.encryptWithRangeProof(
      85000,
      0,
      500000,
      { context: 'alice' }
    );
    expect(
      paillierCs.verifyRange(salary, salaryProof, 0, 500000, {
        context: 'alice',
      })
    ).toBe(true);
    expect(
      paillierCs.verifyRange(salary, salaryProof, 0, 50000, {
        context: 'alice',
      })
    ).toBe(false);
  });

  it('runs the e-voting walkthroughs', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-ts-'));
    const publicKeyFile = path.join(dir, 'public.txt');

    // yes or no
    let authorityCs = new LightPHE({
      algorithmName: 'Exponential-ElGamal',
      keySize: 128,
      primeOrder: true,
    });
    authorityCs.exportKeys(publicKeyFile, true);
    let publicCs = new LightPHE({
      algorithmName: 'Exponential-ElGamal',
      keyFile: publicKeyFile,
    });
    const [aliceBallot, aliceProof] = publicCs.encryptWithProof(1, {
      context: 'alice',
    });
    const [bobBallot, bobProof] = publicCs.encryptWithProof(0, {
      context: 'bob',
    });
    expect(
      publicCs.verifyCiphertext(aliceBallot, aliceProof, { context: 'alice' })
    ).toBe(true);
    expect(
      publicCs.verifyCiphertext(bobBallot, bobProof, { context: 'bob' })
    ).toBe(true);
    expect(
      publicCs.verifyCiphertext(aliceBallot, aliceProof, { context: 'mallory' })
    ).toBe(false);
    const tally = aliceBallot.add(bobBallot);
    const [result, proof] = authorityCs.decryptWithProof(tally);
    expect(publicCs.verifyDecryption(tally, result, proof)).toBe(true);
    expect(result).toBe(1n);

    // a vote for party k is encrypted as 100^k
    authorityCs = new LightPHE({ algorithmName: 'Paillier', keySize: 128 });
    authorityCs.exportKeys(publicKeyFile, true);
    publicCs = new LightPHE({
      algorithmName: 'Paillier',
      keyFile: publicKeyFile,
    });
    let parties = ['red', 'green', 'blue'];
    const values = parties.map((_, k) => 100n ** BigInt(k));
    const ballots = [
      ['alice', 'red'],
      ['bob', 'blue'],
      ['carol', 'red'],
    ].map(([voter, party]) => {
      const [ballot, ballotProof] = publicCs.encryptWithProof(
        values[parties.indexOf(party)],
        { values, context: voter }
      );
      expect(
        publicCs.verifyCiphertext(ballot, ballotProof, {
          values,
          context: voter,
        })
      ).toBe(true);
      return ballot;
    });
    const partyTally = ballots.reduce((sum, ballot) => sum.add(ballot));
    const [partyResult, partyProof] = authorityCs.decryptWithProof(partyTally);
    expect(publicCs.verifyDecryption(partyTally, partyResult, partyProof)).toBe(
      true
    );
    const votes = parties.map(
      (_, k) => (partyResult / 100n ** BigInt(k)) % 100n
    );
    expect(votes.join()).toBe('2,0,1');

    // one-hot ballots
    authorityCs = new LightPHE({
      algorithmName: 'Exponential-ElGamal',
      keySize: 128,
      primeOrder: true,
    });
    authorityCs.exportKeys(publicKeyFile, true);
    publicCs = new LightPHE({
      algorithmName: 'Exponential-ElGamal',
      keyFile: publicKeyFile,
    });
    parties = ['red', 'green', 'blue', 'yellow'];
    const oneHotBallots = [
      ['alice', 'red'],
      ['bob', 'blue'],
      ['carol', 'red'],
    ].map(([voter, party]) => {
      const [ballot, ballotProof] = publicCs.encryptOneHot(
        parties.indexOf(party),
        parties.length,
        { context: voter }
      );
      expect(
        publicCs.verifyOneHot(ballot, ballotProof, { context: voter })
      ).toBe(true);
      return ballot;
    });
    const oneHotTally = oneHotBallots.reduce((sums, ballot) =>
      sums.map((sum, i) => sum.add(ballot[i]))
    );
    const counts = oneHotTally.map((count) => {
      const [countResult, countProof] = authorityCs.decryptWithProof(count);
      expect(publicCs.verifyDecryption(count, countResult, countProof)).toBe(
        true
      );
      return countResult;
    });
    expect(counts.join()).toBe('2,0,1,0');
  });

  it('runs the post-quantum walkthroughs', () => {
    const lpr = new LightPHE({
      algorithmName: 'Lyubashevsky-Peikert-Regev',
      keySize: 64,
    });
    const c1 = lpr.encrypt(1500);
    const c2 = lpr.encrypt(2500);
    expect(lpr.decrypt(c1.add(c2))).toBe(4000n);
    expect(lpr.decrypt(c1.multiply(3))).toBe(4500n);

    const mlkem = new LightPHE({ algorithmName: 'ML-KEM', keySize: 512 });
    const m1 =
      0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefn;
    const m2 =
      0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321n;
    expect(mlkem.decrypt(mlkem.encrypt(m1).xor(mlkem.encrypt(m2)))).toBe(
      m1 ^ m2
    );

    const gsw = new LightPHE({
      algorithmName: 'Gentry-Sahai-Waters',
      keySize: 64,
    });
    const [a, b, c, d] = [1, 1, 0, 1].map((bit) => gsw.encrypt(bit));
    expect(gsw.decrypt(a.and(b).xor(a.and(c)).xor(b.and(c)))).toBe(1n);
    expect(gsw.decrypt(a.and(b).and(c.and(d)))).toBe(0n);
  });
});
