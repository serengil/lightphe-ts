# lightphe-ts

<div align="center">

[![Stars](https://img.shields.io/github/stars/serengil/lightphe-ts?color=yellow&style=flat&label=%E2%AD%90%20stars)](https://github.com/serengil/lightphe-ts/stargazers)
[![License](http://img.shields.io/:license-MIT-green.svg?style=flat)](https://github.com/serengil/lightphe-ts/blob/main/LICENSE)
[![DOI](http://img.shields.io/:DOI-10.3390/sym18050832-blue.svg?style=flat)](https://www.mdpi.com/2073-8994/18/5/832)

</div>

`lightphe-ts` is a lightweight homomorphic encryption library for TypeScript and JavaScript supporting various partially and somewhat homomorphic encryption schemes such as
[`RSA`](https://sefiks.com/2023/03/06/a-step-by-step-partially-homomorphic-encryption-example-with-rsa-in-python/),
[`ElGamal`](https://sefiks.com/2023/03/27/a-step-by-step-partially-homomorphic-encryption-example-with-elgamal-in-python/),
[`Exponential ElGamal`](https://sefiks.com/2023/03/27/a-step-by-step-partially-homomorphic-encryption-example-with-elgamal-in-python/),
[`Elliptic Curve ElGamal`](https://sefiks.com/2018/08/21/elliptic-curve-elgamal-encryption/)
([`Weierstrass`](https://sefiks.com/2016/03/13/the-math-behind-elliptic-curve-cryptography/),
[`Koblitz`](https://sefiks.com/2016/03/13/the-math-behind-elliptic-curves-over-binary-field/) and
[`Edwards`](https://sefiks.com/2018/12/19/a-gentle-introduction-to-edwards-curves/) forms),
[`Paillier`](https://sefiks.com/2023/04/03/a-step-by-step-partially-homomorphic-encryption-example-with-paillier-in-python/),
[`Damgard-Jurik`](https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-damgard-jurik-in-python/),
[`Okamoto–Uchiyama`](https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-okamoto-uchiyama-in-python/),
[`Benaloh`](https://sefiks.com/2023/10/06/a-step-by-step-partially-homomorphic-encryption-example-with-benaloh-in-python-from-scratch/),
[`Naccache–Stern`](https://sefiks.com/2023/10/26/a-step-by-step-partially-homomorphic-encryption-example-with-naccache-stern-in-python/),
[`Goldwasser–Micali`](https://sefiks.com/2023/10/27/a-step-by-step-partially-homomorphic-encryption-example-with-goldwasser-micali-in-python/),
[`Sander-Young-Yung`](https://sefiks.com/2026/04/02/a-step-by-step-partially-homomorphic-sander-young-yung-example-in-python/),
[`Boneh-Goh-Nissim`](https://sefiks.com/2026/04/02/a-step-by-step-somewhat-homomorphic-encryption-example-with-boneh-goh-nissim-in-python/),
`Joye-Libert`, `Castagnos-Laguillaumie`, `Ishai-Paskin`, `Damgard-Geisler-Kroigaard`,
`Bresson-Catalano-Pointcheval`, `Camenisch-Shoup`, `Elliptic Curve Paillier`, `Regev`,
`Brakerski-Vaikuntanathan`, `Freeman-Boneh-Goh-Nissim`, `Gentry-Halevi-Vaikuntanathan`.

It is a TypeScript port of [LightPHE](https://github.com/serengil/LightPHE), with the elliptic curve arithmetic of [LightECC](https://github.com/serengil/LightECC) folded in. It has **no runtime dependencies** — every large integer is a native `bigint`, and randomness comes from the platform CSPRNG.

# Partially vs Fully Homomorphic Encryption

Even though fully homomorphic encryption (FHE) has become available in recent times, when considering the trade-offs `lightphe-ts` emerges as a more efficient and practical choice. If your specific task doesn't demand the full homomorphic capabilities, opting for partial homomorphism is the logical decision.

- 🏎️ Notably faster
- 💻 Demands fewer computational resources
- 📏 Generating much smaller ciphertexts
- 🔑 Distributing much smaller keys
- 🧠 Well-suited for memory-constrained environments
- ⚖️ Strikes a favorable balance for practical use cases

# Installation [![npm](https://img.shields.io/npm/v/lightphe-ts.svg)](https://www.npmjs.com/package/lightphe-ts)

The easiest way to install `lightphe-ts` is through [npm](https://www.npmjs.com/package/lightphe-ts).

```shell
npm install lightphe-ts
```

The package ships both an ES module and a CommonJS build alongside TypeScript declarations, so it works from either module system with no configuration.

**TypeScript / ES modules**

```typescript
import { LightPHE } from 'lightphe-ts';
```

**JavaScript / CommonJS**

```javascript
const { LightPHE } = require('lightphe-ts');
```

`LightPHE` is also the default export, so `import LightPHE from 'lightphe-ts'` works too.

Node 18 or newer is required. In a browser or edge runtime the library works as-is, provided `crypto.getRandomValues` is available — it is, in every modern browser and in Deno, Bun, Cloudflare Workers and Vercel Edge.

### A note on numbers

Ciphertexts and plaintexts are `bigint`, not `number`, because the values involved routinely exceed what a double can hold. So `decrypt` hands back a `bigint`:

```typescript
const restored = cs.decrypt(c3); // 38n, not 38
```

Plaintexts and constants can be passed as either a `number` or a `bigint` — whichever reads better at the call site.

# Summary of Homomorphic Features of Different Cryptosystems

In summary, `lightphe-ts` covers the following algorithms, and these are partially homomorphic and somewhat homomorphic with respect to the operations mentioned in the following table.

| Algorithm                    | Multiplicatively<br>Homomorphic | Additively<br>Homomorphic | Scalar Multiplication | Bitwise-XOR Homomorphic | Bitwise-AND Homomorphic | Regeneration<br>of Ciphertext | Decision Tree<br>Evaluation | Secure<br>Comparison | Encrypted<br>Argmax |
| ---------------------------- | ------------------------------- | ------------------------- | --------------------- | ----------------------- | ----------------------- | ----------------------------- | --------------------------- | -------------------- | ------------------- |
| RSA                          | ✅                              | ❌                        | ❌                    | ❌                      | ❌                      | ❌                            | ❌                          | ❌                   | ❌                  |
| ElGamal                      | ✅                              | ❌                        | ❌                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  |
| Exponential ElGamal          | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  |
| Elliptic Curve ElGamal       | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  |
| Paillier                     | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  |
| Elliptic Curve Paillier      | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  |
| Damgard-Jurik                | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  |
| Benaloh                      | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  |
| Naccache-Stern               | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  |
| Okamoto-Uchiyama             | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  |
| Joye-Libert                  | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  |
| Castagnos-Laguillaumie       | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  |
| Damgard-Geisler-Kroigaard    | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ✅                          | ✅                   | ✅                  |
| Bresson-Catalano-Pointcheval | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  |
| Camenisch-Shoup              | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  |
| Ishai-Paskin                 | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ✅                          | ❌                   | ❌                  |
| Regev                        | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  |
| Goldwasser-Micali            | ❌                              | ❌                        | ❌                    | ✅                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  |
| Sander-Young-Yung            | ❌                              | ❌                        | ❌                    | ❌                      | ✅                      | ✅                            | ❌                          | ❌                   | ❌                  |
| Boneh-Goh-Nissim             | 1️⃣                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  |
| Freeman-Boneh-Goh-Nissim     | 1️⃣                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  |
| Brakerski-Vaikuntanathan     | 1️⃣                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  |
| Gentry-Halevi-Vaikuntanathan | 1️⃣                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  |

1️⃣ Boneh-Goh-Nissim, Freeman-Boneh-Goh-Nissim, Brakerski-Vaikuntanathan and Gentry-Halevi-Vaikuntanathan support one multiplication natively. Most additively homomorphic algorithms can support one multiplication with [Catalano-Fiore transform](#adding-multiplication-support-to-additive-algorithms) as well.

# Building a cryptosystem

Once you have imported the library, you can build a cryptosystem for any of the algorithms. This generates a private and public key pair.

```typescript
import { LightPHE } from 'lightphe-ts';

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

const cs = new LightPHE({ algorithmName: algorithms[0] });
```

# Homomorphic Operations

The following example demonstrates a simple workflow with an additively homomorphic cryptosystem (e.g. Paillier). First, the cryptosystem is built on-premises and two plaintext values are defined. Next, the plaintexts are encrypted — this can be done either on-premises or in the cloud, and does not require the private key. Homomorphic operations such as addition and scalar multiplication can then be performed on the ciphertexts, and those can be offloaded to the cloud, leveraging its computational power without revealing the private key or the plaintext. Finally, the results are decrypted on-premises using the private key.

```typescript
// build an additively homomorphic cryptosystem
const cs = new LightPHE({ algorithmName: 'Paillier' });

// define plaintexts
const m1 = 10000; // base salary in usd
const m2 = 500; // wage increase in usd

// encrypt plaintexts - private key is not required
const c1 = cs.encrypt(m1);
const c2 = cs.encrypt(m2);

// homomorphic addition - private key is not required
const c3 = c1.add(c2);

// homomorphic scalar multiplication - private key is not required
const k = 1.05; // increase something 5%
const c4 = c1.multiply(k);

// decryption - private key is required
console.assert(cs.decrypt(c3) === BigInt(m1 + m2));
console.assert(cs.decrypt(c4) === BigInt(m1 * k));
```

The same thing in JavaScript with CommonJS:

```javascript
const { LightPHE } = require('lightphe-ts');

const cs = new LightPHE({ algorithmName: 'Paillier' });

const m1 = 10000;
const m2 = 500;

const c1 = cs.encrypt(m1);
const c2 = cs.encrypt(m2);

console.log(cs.decrypt(c1.add(c2))); // 10500n
console.log(cs.decrypt(c1.multiply(1.05))); // 10500n
```

On the other hand, if you adopt a multiplicatively homomorphic cryptosystem (e.g. RSA or ElGamal), you can multiply ciphertexts without revealing the private key or the plaintext.

```typescript
// build a multiplicatively homomorphic cryptosystem
const cs = new LightPHE({ algorithmName: 'RSA' });

// define plaintexts
const m1 = 17;
const m2 = 21;

// encrypt plaintexts - private key is not required
const c1 = cs.encrypt(m1);
const c2 = cs.encrypt(m2);

// homomorphic multiplication
const c3 = c1.multiply(c2);

// decryption - private key is required
console.assert(cs.decrypt(c3) === BigInt(m1 * m2));
```

An operation a scheme does not support throws rather than returning a wrong answer:

```typescript
const cs = new LightPHE({ algorithmName: 'RSA' });
const c1 = cs.encrypt(17);
const c2 = cs.encrypt(21);

c1.add(c2); // throws: RSA is not homomorphic with respect to the addition
```

### Ciphertext Regeneration

Most of the homomorphic algorithms let you regenerate a ciphertext without breaking its plaintext restoration. You may consider doing this many times to have stronger ciphertexts.

```typescript
const c1Prime = cs.regenerateCiphertext(c1);
console.assert(cs.decrypt(c1Prime) === cs.decrypt(c1));
```

### Elliptic Curve Cryptography

ECC is a powerful public-key cryptosystem based on the algebraic structure of elliptic curves over finite fields. The library supports 3 elliptic curve forms (`weierstrass` (default), `edwards` and `koblitz`) and 140+ standard elliptic curve configurations, all bundled in — there is nothing extra to install.

The [Elliptic Curve ElGamal](https://sefiks.com/2018/08/21/elliptic-curve-elgamal-encryption/) scheme is implemented, offering a secure and efficient homomorphic encryption option.

```typescript
const cs = new LightPHE({
  algorithmName: 'EllipticCurve-ElGamal',
  form: 'edwards',
  // curve: 'ed448', // optionally you can specify the curve for the given form
});
```

One of the crucial factors that define the security level of an elliptic curve cryptosystem is the order of the curve. The order of a curve is the number of points on the curve, and it directly influences the strength of the encryption. A higher order typically corresponds to a stronger cryptosystem, making it more resistant to cryptographic attacks.

Each curve has a specific order, chosen to balance performance and security. Selecting a curve with a larger order increases security, but may come with a trade-off in computational efficiency, so choosing the appropriate curve order is a decision based on your application's security and performance requirements.

You can enumerate the bundled curves at runtime:

```typescript
import { listCurveNames, getDefaultCurve, FORMS } from 'lightphe-ts';

console.log(FORMS); // ['weierstrass', 'edwards', 'koblitz']
console.log(getDefaultCurve('weierstrass')); // 'secp256k1'
console.log(listCurveNames('edwards')); // ['curve41417', 'e222', ...]
```

See the [`curves`](https://github.com/serengil/LightECC#supported-curves) page for details on all supported forms and curves.

### Decision Trees

`lightphe-ts` can evaluate decision trees privately. Suppose a bank has a secret decision tree that decides a customer's credit limit, and a customer has private data. The bank does not want to reveal its tree, and the customer does not want to reveal their data. The customer sends encrypted data, the bank runs its tree on it without seeing it, and only the customer can decrypt the result. The customer learns the credit limit but not the rest of the tree. Two cryptosystems support this: Ishai-Paskin for trees on yes / no answers, and Damgard-Geisler-Kroigaard for trees on numeric features.

#### Decision Trees with Nominal Decisions

Ishai-Paskin evaluates trees whose questions have yes / no answers, in a single round: the customer sends encrypted answers, and the bank sends back the encrypted result.

Let the bank's tree be the following, where questions are numbered 0, 1 and 2 and leaves are credit limits in thousand dollars.

```
                  Q0: has stable income?
                 /no                    \yes
     Q2: owns a house?              Q1: has existing debt?
       /no        \yes               /no           \yes
      0            5               20         Q2: owns a house?
                                                /no       \yes
                                               5          10
```

Each question is written as an array of `[question number, what to do if no, what to do if yes]`, and leaves are plain integers. So, the tree above becomes:

```typescript
import { LightPHE, type DecisionTree } from 'lightphe-ts';

const creditLimitTree: DecisionTree = [0, [2, 0, 5], [1, 20, [2, 5, 10]]];
```

Then, the customer and the bank run the following steps.

```typescript
// customer builds the cryptosystem and keeps the private key
const customerCs = new LightPHE({ algorithmName: 'Ishai-Paskin' });

// customer shares only the public key with the bank
customerCs.exportKeys('public.txt', true);

// customer's answers: stable income = yes, existing debt = yes, owns a house = no
const answers = [1, 1, 0];

// customer encrypts the answers and sends them to the bank. depth is the maximum
// number of questions on a path of the tree, the bank should share this value
const encryptedAnswers = customerCs.encryptDecisionTreeInput(answers, 3);

// bank builds its own cryptosystem with the customer's public key
const bankCs = new LightPHE({
  algorithmName: 'Ishai-Paskin',
  keyFile: 'public.txt',
});

// bank runs its tree on encrypted answers and sends the result back to the customer
const encryptedLimit = bankCs.evaluateDecisionTree(
  creditLimitTree,
  encryptedAnswers
);

// customer decrypts the result - only the customer has the private key
console.assert(customerCs.decrypt(encryptedLimit) === 5n);
```

The size of the result grows with the depth of the tree, not with the number of its nodes. Still, each extra level makes the computation noticeably slower, so this is practical for shallow trees.

#### Decision Trees with Numeric Decisions

Damgard-Geisler-Kroigaard evaluates decision trees with numeric thresholds instead of yes / no answers, using the secure comparison protocol below at each node. It requires a few rounds of interaction between the customer and the bank, but its cost grows linearly with the number of nodes.

Let the bank's tree be the following, where features are numbered 0 (age), 1 (income in thousand dollars) and 2 (number of open loans), and leaves are credit limits in thousand dollars.

```
                  F1: income <= 40?
                 /yes                \no
       F0: age <= 25?          F2: open loans <= 2?
        /yes      \no            /yes           \no
       0           5            20              10
```

Each decision node is written as an array of `[feature index, threshold, what to do if feature <= threshold, what to do otherwise]`, and leaves are plain integers. So, the tree above becomes:

```typescript
import { LightPHE, type NumericDecisionTree } from 'lightphe-ts';

const creditLimitTree: NumericDecisionTree = [
  1,
  40,
  [0, 25, 0, 5],
  [2, 2, 20, 10],
];
```

Then, the customer and the bank run the following steps.

```typescript
// customer: age = 30, income = 75 and open loans = 1
// so, the expected path is income > 40 -> open loans <= 2 -> credit limit of 20
const customerCs = new LightPHE({ algorithmName: 'Damgard-Geisler-Kroigaard' });
const encryptedFeatures = customerCs.encryptDecisionTreeInput({
  features: [30, 75, 1],
  bitLength: 8,
});

// bank, having the customer's public key only
const bankCs = new LightPHE({
  algorithmName: 'Damgard-Geisler-Kroigaard',
  keyFile: 'public.txt',
});
const [encryptedComparisons, bankState] =
  bankCs.evaluateDecisionTreeComparisons(creditLimitTree, encryptedFeatures);

// customer answers randomly flipped comparisons, so cannot follow the path in the tree
const encryptedAnswers =
  customerCs.answerDecisionTreeComparisons(encryptedComparisons);

// bank keeps bankState secret and finds the reached leaf in encrypted form
const encryptedLeaves = bankCs.evaluateDecisionTreeLeaves(
  bankState,
  encryptedAnswers
);

// customer learns only the credit limit
console.assert(customerCs.decryptDecisionTreeOutput(encryptedLeaves) === 20n);
```

### Secure Comparison

Damgard-Geisler-Kroigaard lets a client and a server find out whether the client's private value is less than or equal to the server's private value, without revealing the values to each other. For instance, a bidder can check whether their bid beats the reserve price of an auction.

```typescript
// client encrypts its value bit by bit
const clientCs = new LightPHE({ algorithmName: 'Damgard-Geisler-Kroigaard' });
const encryptedBid = clientCs.encryptComparisonInput(120, 16);

// server compares it with its own value having the client's public key only
const serverCs = new LightPHE({
  algorithmName: 'Damgard-Geisler-Kroigaard',
  keyFile: 'public.txt',
});
const encryptedResult = serverCs.evaluateComparison(encryptedBid, 150);

// client learns only whether bid <= reserve price
console.assert(clientCs.decryptComparison(encryptedResult) === true);
```

### Encrypted Argmax

Damgard-Geisler-Kroigaard can also find the index of the maximum among encrypted values. For instance, a server can compute encrypted class scores of a linear classifier on a client's encrypted features, and then find the predicted class. The client learns only the index, neither the scores nor the intermediate comparisons, and the server learns nothing. The protocol needs a few round trips per value, so the server talks to the client through a callable, and `evaluateArgmax` returns a promise. Locally, the callable can be the client's `answerArgmax` directly. Otherwise, wrap your network call with it — it may return a promise as well.

```typescript
// client encrypts its features
const clientCs = new LightPHE({ algorithmName: 'Damgard-Geisler-Kroigaard' });
const encryptedFeatures = [3, 1, 4].map((feature) => clientCs.encrypt(feature));

// server computes class scores with its private weights homomorphically
const serverCs = new LightPHE({
  algorithmName: 'Damgard-Geisler-Kroigaard',
  keyFile: 'public.txt',
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

// server finds the argmax with the client's help - scores must fit into bitLength bits
const encryptedClass = await serverCs.evaluateArgmax(
  encryptedScores,
  8,
  clientCs.answerArgmax
);

// client learns only the predicted class
console.assert(clientCs.decrypt(encryptedClass) === 1n);
```

### Master Key Decryption

Bresson-Catalano-Pointcheval has two ways to decrypt a ciphertext. Each user decrypts with its own private key, while an authority holding the master key decrypts ciphertexts of all users. For instance, a company can let every employee encrypt with their own key, and still recover the data if an employee leaves. Keep in mind that the master key holder can read everything by design.

```typescript
// authority generates the master key and publishes its public key
const authorityCs = new LightPHE({
  algorithmName: 'Bresson-Catalano-Pointcheval',
});
authorityCs.exportKeys('public.txt', true);

// each user generates its own key pair with the public key of the authority
const publicCs = new LightPHE({
  algorithmName: 'Bresson-Catalano-Pointcheval',
  keyFile: 'public.txt',
});
const aliceCs = new LightPHE({
  algorithmName: 'Bresson-Catalano-Pointcheval',
  keys: publicCs.generateUserKeys(),
});
const bobCs = new LightPHE({
  algorithmName: 'Bresson-Catalano-Pointcheval',
  keys: publicCs.generateUserKeys(),
});

const aliceCiphertext = aliceCs.encrypt(100).add(aliceCs.encrypt(50));
const bobCiphertext = bobCs.encrypt(200);

// users decrypt their own ciphertexts only
console.assert(aliceCs.decrypt(aliceCiphertext) === 150n);
console.assert(aliceCs.decrypt(bobCiphertext) !== 200n);

// authority decrypts ciphertexts of all users
console.assert(authorityCs.decryptWithMasterKey(aliceCiphertext) === 150n);
console.assert(authorityCs.decryptWithMasterKey(bobCiphertext) === 200n);
```

### Verifiable Encryption

Camenisch-Shoup lets you encrypt a secret for someone else and prove that the ciphertext really contains it, without revealing the secret. For instance, Alice can escrow the private key of her crypto wallet with a trusted third party. A bank, which knows only her public key, verifies that the escrowed ciphertext contains its private key, and the trusted third party can recover it only under the conditions written in the label.

```typescript
import { LightECC, LightPHE } from 'lightphe-ts';

// trusted third party builds the cryptosystem and publishes its public key
const ttpCs = new LightPHE({ algorithmName: 'Camenisch-Shoup' });
ttpCs.exportKeys('public.txt', true);

// alice's wallet key pair on secp256k1
const ecc = new LightECC({ curveName: 'secp256k1' });
const privateKey = 123456789n;
const publicKey = ecc.G.multiply(privateKey);

// alice encrypts her private key for the trusted third party with a proof
const label = 'release only if alice loses access to her wallet';
const aliceCs = new LightPHE({
  algorithmName: 'Camenisch-Shoup',
  keyFile: 'public.txt',
});
const escrow = aliceCs.encryptVerifiably(privateKey, label);

// bank verifies it with public keys only, without learning alice's private key
const bankCs = new LightPHE({
  algorithmName: 'Camenisch-Shoup',
  keyFile: 'public.txt',
});
console.assert(bankCs.verifyEncryption(escrow, publicKey, label) === true);

// trusted third party recovers the private key under the same label only
console.assert(ttpCs.decryptVerifiableCiphertext(escrow, label) === privateKey);
```

Private keys of other curves can be escrowed by passing `form` and `curve` options while building the cryptosystem. Verifiable ciphertexts reject any modification, so homomorphic operations are applied to regular ciphertexts created with `encrypt`. Proofs are interoperable with the Python library.

### Adding Multiplication Support to Additive Algorithms

Additively homomorphic algorithms cannot multiply two ciphertexts. Boosting them with Catalano-Fiore transform adds one multiplication on top of them, without changing the algorithms themselves. This lets you evaluate degree-2 functions on encrypted data, such as dot products of two encrypted vectors, variances or squared distances. It supports Paillier, Damgard-Jurik, Bresson-Catalano-Pointcheval, Camenisch-Shoup, Elliptic Curve Paillier, Joye-Libert, Castagnos-Laguillaumie, Naccache-Stern, Benaloh and Damgard-Geisler-Kroigaard.

```typescript
// client builds a boosted cryptosystem, and encrypts its private vectors
const clientCs = new LightPHE({
  algorithmName: 'Paillier',
  boost: 'Catalano-Fiore',
});

const x = [3, 1, 4];
const y = [1, 5, 9];
const encryptedX = x.map((value) => clientCs.encrypt(value));
const encryptedY = y.map((value) => clientCs.encrypt(value));

// server computes dot product of encrypted vectors - ciphertexts carry the public key only
const encryptedDot = encryptedX
  .map((ex, i) => ex.multiply(encryptedY[i]))
  .reduce((acc, product) => acc.add(product));

// squared euclidean distance is also a degree-2 function
const encryptedDistance = encryptedX
  .map((ex, i) => {
    const difference = ex.subtract(encryptedY[i]);
    return difference.multiply(difference);
  })
  .reduce((acc, square) => acc.add(square));

// client decrypts the results
console.assert(clientCs.decrypt(encryptedDot) === 44n);
console.assert(clientCs.decrypt(encryptedDistance) === 45n);
```

Boosted ciphertexts are `CatalanoFioreCiphertext` objects supporting `add`, `subtract`, `negate` and `multiply` with ciphertexts or plain integers. Multiplied ciphertexts can be added and multiplied with constants, but not multiplied with ciphertexts again. They keep a pair of ciphertexts for every product, so a dot product of length d grows d times. Only integers are supported.

### Post-Quantum Security

Most algorithms in `lightphe-ts` rely on factoring or discrete logarithm problems, which a large enough quantum computer could solve with Shor's algorithm. Regev and Brakerski-Vaikuntanathan rely on learning with errors problems instead, which are believed to be hard for quantum computers too. Their default key sizes give about 128-bit security against quantum attacks.

Regev is additively homomorphic. Its key size is the lattice dimension, and its default is 2048.

```typescript
const cs = new LightPHE({ algorithmName: 'Regev' });

const c1 = cs.encrypt(1500);
const c2 = cs.encrypt(2500);

console.assert(cs.decrypt(c1.add(c2)) === 4000n);
console.assert(cs.decrypt(c1.multiply(3)) === 4500n);
```

Brakerski-Vaikuntanathan additionally supports one multiplication of ciphertexts like Boneh-Goh-Nissim, but without pairings. Its key size is the degree of its polynomial ring, and its default is 4096.

```typescript
const cs = new LightPHE({ algorithmName: 'Brakerski-Vaikuntanathan' });

const c1 = cs.encrypt(15);
const c2 = cs.encrypt(25);
const c3 = cs.encrypt(100);

// one multiplication, then additions and multiplications with constants
console.assert(cs.decrypt(c1.multiply(c2).add(c3)) === 475n);
console.assert(
  cs.decrypt(c1.multiply(c2).multiply(2).add(c1.multiply(c3))) === 2250n
);
```

Every ciphertext of these algorithms carries a small noise, which grows with each homomorphic operation, and decryption silently fails once it grows too much. With default settings, plaintexts must be less than 2^24. Regev has room for thousands of additions or multiplications with constants up to a few thousands, and a product of Brakerski-Vaikuntanathan has room for millions of times more noise. You can increase the plaintext space with the `plaintextLimit` option in exchange of less room for noise. Floats and tensors are not supported.

### Vector Embeddings

Homomorphic encryption is supported on vector embeddings too. This is useful in privacy-preserving machine learning, secure aggregation, and confidential data processing.

```typescript
// build an additively homomorphic cryptosystem (e.g. Paillier)
const cs = new LightPHE({ algorithmName: 'Paillier' });

// define plain embeddings
const t1 = [1.005, 2.05, 3.6, 4, 4.02, 3.5];
const t2 = [5, 6.2, 7.5, 8.02, 8.02, 4.5];
const t3 = [1.03, 2.04, 3.05, 7.02, 2.01, 1.06];

// encrypt embeddings
const c1 = cs.encrypt(t1);
const c2 = cs.encrypt(t2);

// perform addition of two encrypted embeddings
const c4 = c1.add(c2);

// perform scalar multiplication on an embedding
const c5 = c1.multiply(3);

// perform element-wise multiplication between an encrypted and a plain embedding
const c6 = c1.multiply(t3);

// encrypted dot product (likewise cosine similarity)
const c7 = c1.dot(t3);

// proof of work — decrypting a tensor gives back plain numbers
const close = (a: number[], b: number[]) =>
  a.every((x, i) => Math.abs(x - b[i]) < 0.1);

console.assert(
  close(
    cs.decrypt(c4),
    t1.map((a, i) => a + t2[i])
  )
);
console.assert(
  close(
    cs.decrypt(c5),
    t1.map((a) => a * 3)
  )
);
console.assert(
  close(
    cs.decrypt(c6),
    t1.map((a, i) => a * t3[i])
  )
);
console.assert(
  Math.abs(cs.decrypt(c7)[0] - t1.reduce((s, a, i) => s + a * t3[i], 0)) < 0.1
);
```

Unlike scalars, decrypting an encrypted tensor gives back `number[]` rather than `bigint[]`, because a tensor carries fixed-point reals.

### Working with keys

Keys can be exported to a file and restored later, which is how you hand a public key to whoever will do the encrypting.

```typescript
const cs = new LightPHE({ algorithmName: 'Paillier' });

// write both keys - keep this file secret
cs.exportKeys('secret.json');

// write only the public key - this one is safe to publish
cs.exportKeys('public.json', true);

// a cloud that only holds the public key can encrypt and evaluate
const cloud = new LightPHE({
  algorithmName: 'Paillier',
  keyFile: 'public.json',
});
const c1 = cloud.encrypt(17);

// but it cannot decrypt
cloud.decrypt(c1); // throws: You must have private key to perform decryption
```

You can also pass a key pair directly, which is useful when the keys live somewhere other than the filesystem:

```typescript
const cs = new LightPHE({
  algorithmName: 'RSA',
  keys: { public_key: { n: 175501n, e: 101753n } },
});
```

Keys are serialised as JSON with every big integer written as a decimal string, so a key file is portable and human-readable.

### Sending a ciphertext over the wire

A `Ciphertext` carries the public cryptosystem along with the payload. To send just the payload and rebuild it on the other side, use `.value` and `createCiphertextObj`:

```typescript
const payload = c1.value; // the raw ciphertext
const rebuilt = cs.createCiphertextObj(payload);
```

## LightPHE Ecosystem

`LightPHE` is available across multiple programming languages with consistent APIs and native performance for each ecosystem. Choose the port that fits your stack:

| Language       | Repository                                               | Ecosystem Focus                              |
| :------------- | :------------------------------------------------------- | :------------------------------------------- |
| **Python**     | [`lightphe`](https://github.com/serengil/lightphe)       | AI, Research & Prototyping                   |
| **Go**         | [`lightphe-go`](https://github.com/serengil/lightphe-go) | Cloud-Native & High-Throughput Microservices |
| **Java**       | [`lightphe4j`](https://github.com/serengil/lightphe4j)   | Enterprise, Banking & Legacy Systems         |
| **TypeScript** | [`lightphe-ts`](https://github.com/serengil/lightphe-ts) | Client-Side Privacy & Node.js Backend        |

# Support

There are many ways to support a project - starring⭐️ the GitHub repo is just one 🙏

You can also support this work on [Patreon](https://www.patreon.com/serengil?repo=lightphe), [GitHub Sponsors](https://github.com/sponsors/serengil) or [Buy Me a Coffee](https://buymeacoffee.com/serengil).

<a href="https://www.patreon.com/serengil?repo=lightphe">
<img src="https://raw.githubusercontent.com/serengil/LightPHE/master/icons/patreon.png" width="30%">
</a>

# Citation

Please cite LightPHE in your publications if it helps your research. Here is its BibTeX entry:

```BibTeX
@article{lightphets,
  title          = {Sustainable Cryptography: Carbon Asymmetry in Partially Homomorphic Encryption in the Cloud},
  author         = {Ozpinar, Alper and Serengil, Sefik Ilkin},
  journal        = {Symmetry},
  volume         = {18},
  number         = {5},
  pages          = {832},
  url            = {https://www.mdpi.com/2073-8994/18/5/832},
  doi            = {10.3390/sym18050832},
  note           = {Special Issue: Symmetry in Cryptography and Cybersecurity},
  year           = {2026}
}
```

Also, if you use `lightphe-ts` in your projects, please add `lightphe-ts` to your `package.json` dependencies.

# License

`lightphe-ts` is licensed under the MIT License - see [`LICENSE`](https://github.com/serengil/lightphe-ts/blob/main/LICENSE) for more details.
