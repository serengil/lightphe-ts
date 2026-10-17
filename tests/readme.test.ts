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
      'Brakerski-Vaikuntanathan',
      'Freeman-Boneh-Goh-Nissim',
      'Gentry-Halevi-Vaikuntanathan',
    ];

    // lattice based ones take dimensions instead of bit lengths
    const keySizes: Record<string, number> = {
      'Brakerski-Vaikuntanathan': 64,
      'Freeman-Boneh-Goh-Nissim': 64,
      'Gentry-Halevi-Vaikuntanathan': 2,
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
});
