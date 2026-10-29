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
`Lyubashevsky-Peikert-Regev`, `ML-KEM`, `Brakerski-Vaikuntanathan`, `Freeman-Boneh-Goh-Nissim`,
`Gentry-Halevi-Vaikuntanathan`, `Gentry-Sahai-Waters`. It also
supports [`Catalano-Fiore`](#adding-multiplication-support-to-additive-algorithms) transform to add
one multiplication to additively homomorphic ones.

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

| Algorithm                    | Multiplicatively<br>Homomorphic | Additively<br>Homomorphic | Scalar Multiplication | Bitwise-XOR Homomorphic | Bitwise-AND Homomorphic | Regeneration<br>of Ciphertext | Decision Tree<br>Evaluation | Secure<br>Comparison | Encrypted<br>Argmax | Threshold<br>Decryption | Zero-Knowledge<br>Proofs |
| ---------------------------- | ------------------------------- | ------------------------- | --------------------- | ----------------------- | ----------------------- | ----------------------------- | --------------------------- | -------------------- | ------------------- | ----------------------- | ------------------------ |
| RSA                          | ✅                              | ❌                        | ❌                    | ❌                      | ❌                      | ❌                            | ❌                          | ❌                   | ❌                  | ❌                      | ❌                       |
| ElGamal                      | ✅                              | ❌                        | ❌                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  | ✅                      | ✅                       |
| Exponential ElGamal          | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  | ✅                      | ✅                       |
| Elliptic Curve ElGamal       | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  | ✅                      | ✅                       |
| Paillier                     | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  | ✅                      | ✅                       |
| Elliptic Curve Paillier      | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  | ❌                      | ❌                       |
| Damgard-Jurik                | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  | ✅                      | ✅                       |
| Benaloh                      | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  | ❌                      | ❌                       |
| Naccache-Stern               | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  | ❌                      | ❌                       |
| Okamoto-Uchiyama             | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  | ❌                      | ❌                       |
| Joye-Libert                  | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  | ❌                      | ❌                       |
| Castagnos-Laguillaumie       | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  | ❌                      | ❌                       |
| Damgard-Geisler-Kroigaard    | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ✅                          | ✅                   | ✅                  | ❌                      | ❌                       |
| Bresson-Catalano-Pointcheval | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  | ❌                      | ❌                       |
| Camenisch-Shoup              | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  | ❌                      | ✅                       |
| Ishai-Paskin                 | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ✅                          | ❌                   | ❌                  | ❌                      | ❌                       |
| Regev                        | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  | ❌                      | ❌                       |
| Lyubashevsky-Peikert-Regev   | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  | ❌                      | ❌                       |
| ML-KEM                       | ❌                              | ❌                        | ❌                    | ✅                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  | ❌                      | ❌                       |
| Goldwasser-Micali            | ❌                              | ❌                        | ❌                    | ✅                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  | ❌                      | ❌                       |
| Sander-Young-Yung            | ❌                              | ❌                        | ❌                    | ❌                      | ✅                      | ✅                            | ❌                          | ❌                   | ❌                  | ❌                      | ❌                       |
| Boneh-Goh-Nissim             | 1️⃣                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  | ❌                      | ❌                       |
| Freeman-Boneh-Goh-Nissim     | 1️⃣                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  | ❌                      | ❌                       |
| Brakerski-Vaikuntanathan     | 1️⃣                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  | ❌                      | ❌                       |
| Gentry-Halevi-Vaikuntanathan | 1️⃣                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            | ❌                          | ❌                   | ❌                  | ❌                      | ❌                       |
| Gentry-Sahai-Waters          | ✅                              | ❌                        | ❌                    | ✅                      | ✅                      | ✅                            | ❌                          | ❌                   | ❌                  | ❌                      | ❌                       |

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
  'Lyubashevsky-Peikert-Regev',
  'ML-KEM',
  'Brakerski-Vaikuntanathan',
  'Freeman-Boneh-Goh-Nissim',
  'Gentry-Halevi-Vaikuntanathan',
  'Gentry-Sahai-Waters',
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

### Sending Ciphertexts over Network

Ciphertexts, proofs and messages of interactive protocols can be serialized into json to be sent to another party. Keys are never serialized, the receiver restores ciphertexts with its own public key. `serialize` handles ciphertexts nested in arrays, plain objects and maps, e.g. a ciphertext with its proof, an encrypted update for secure aggregation, or a message sent to the `client` callable of encrypted argmax and nearest neighbor search. A `bigint` comes back as a `bigint` and a `number` as a `number`, and the json layout matches the Python library's.

```typescript
// client encrypts its value and sends it to the server
const clientCs = new LightPHE({ algorithmName: 'Paillier' });
const data = clientCs.serialize(clientCs.encrypt(17));

// server restores the ciphertext with the client's public key only, and computes on it
const serverCs = new LightPHE({
  algorithmName: 'Paillier',
  keys: { public_key: clientCs.cs.keys.public_key },
});
const c = serverCs.deserialize<Ciphertext>(data);
const response = serverCs.serialize(c.add(serverCs.encrypt(25)));

// client decrypts the response
console.assert(
  clientCs.decrypt(clientCs.deserialize<Ciphertext>(response)) === 42n
);

// a single ciphertext can be converted into a dict as well
console.assert(
  clientCs.decrypt(clientCs.fromDict<Ciphertext>(c.toDict())) === 17n
);
```

To run an interactive protocol across machines, wrap the network call with the `client` callable:

```typescript
const client = async (message: ArgmaxMessage): Promise<bigint[]> => {
  // e.g. an http request to the client, which answers with
  // clientCs.serialize(clientCs.answerKnn(clientCs.deserialize(body)))
  const response = await fetch(CLIENT_URL, {
    method: 'POST',
    body: serverCs.serialize(message),
  });
  return serverCs.deserialize<bigint[]>(await response.text());
};

const result = await serverCs.evaluateKnn(
  encryptedQuery,
  gallery,
  2,
  16,
  client
);
```

To send just the raw payload of a single ciphertext instead, use `.value` and rebuild it on the other side with `createCiphertextObj`:

```typescript
const payload = c.value; // the raw ciphertext
const rebuilt = serverCs.createCiphertextObj(payload);
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

### Hyperplane and Naive Bayes Classifiers

Together with [decision trees](#decision-trees), Damgard-Geisler-Kroigaard supports the classifiers of Bost et al. over encrypted data: hyperplane classifiers, e.g. logistic regression or linear SVM, and naive Bayes. The client encrypts its features, the server evaluates its private model on them, and finds the predicted class with [encrypted argmax](#encrypted-argmax). The client learns only the predicted class, and the server learns nothing about the features. Scores of classes must fit into about 30 bits, so floats must be quantized to integers.

```typescript
// client encrypts its features: income and debt in thousands, years of employment, late payments
const clientCs = new LightPHE({ algorithmName: 'Damgard-Geisler-Kroigaard' });
const encryptedFeatures = [85, 20, 6, 0].map((x) => clientCs.encrypt(x));

// bank's logistic regression model, quantized by 1000: class 1 approves the loan
const serverCs = new LightPHE({
  algorithmName: 'Damgard-Geisler-Kroigaard',
  keys: { public_key: clientCs.cs.keys.public_key },
});
const weights = [
  [0, 0, 0, 0],
  [42, -65, 310, -900],
];
const biases = [0, -1200];

// absolute values of scores must be less than 2^bitLength
const encryptedClass = await serverCs.evaluateHyperplane(
  encryptedFeatures,
  weights,
  16,
  clientCs.answerArgmax,
  { biases }
);
console.assert(clientCs.decrypt(encryptedClass) === 1n);
```

Naive Bayes works with categorical features, which the client encrypts as one-hot vectors. The server quantizes the logarithms of its probabilities, which must be positive, e.g. smoothed with Laplace smoothing.

```typescript
// continuing with clientCs and serverCs above
// patient encrypts symptoms: fever (no, yes), cough (none, dry, wet), fatigue (no, yes)
const encryptedSymptoms = clientCs.encryptNaiveBayesInput([1, 1, 1], [2, 3, 2]);

// clinic's model: P(diagnosis) and P(symptom | diagnosis) for cold, flu and allergy
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

// patient learns only the most likely diagnosis: flu
console.assert(clientCs.decrypt(encryptedDiagnosis) === 1n);
```

Scenarios:

- A customer applies for a loan from a mobile app, and the bank runs its credit scoring model on the encrypted income and debts, so the customer learns only whether the loan is approved, and the bank neither reveals its model nor sees the financial details before the customer agrees to share them.
- A patient checks symptoms with an online clinic, whose diagnosis model was trained on years of patient records, so the patient learns the most likely diagnosis without revealing the symptoms, and the clinic does not give away its model.
- An email client asks a spam filtering service whether a message is spam, and the service classifies the encrypted word counts of the message, so it never reads the email.

### Encrypted Nearest Neighbor Search

`lightphe-ts` can find the k nearest vectors to an encrypted query, e.g. searching a face embedding in a gallery, without revealing the query. Embeddings must be quantized to integers first, e.g. by scaling and rounding. There are two settings.

If the server owns the gallery in plain, the client encrypts its query with Damgard-Geisler-Kroigaard, and the server finds the nearest vectors with [encrypted argmax](#encrypted-argmax). The server learns neither the query nor the result, and the client learns only the indices or labels of the k nearest vectors, neither the distances nor the other vectors.

```typescript
// client encrypts its face embedding, quantized to integers
const clientCs = new LightPHE({ algorithmName: 'Damgard-Geisler-Kroigaard' });
const encryptedQuery = clientCs.encryptKnnQuery([12, -7, 33, 5]);

// server finds the 2 nearest vectors of its gallery - squared distances must fit into bitLength bits
const serverCs = new LightPHE({
  algorithmName: 'Damgard-Geisler-Kroigaard',
  keys: { public_key: clientCs.cs.keys.public_key },
});
const gallery = [
  [10, -5, 30, 4],
  [-40, 22, 1, 9],
  [13, -8, 35, 6],
];
const people = [101, 102, 103];
const result = await serverCs.evaluateKnn(
  encryptedQuery,
  gallery,
  2,
  16,
  clientCs.answerKnn,
  { labels: people }
);

// client learns only who the nearest people are
const nearest = result.labels!.map((label) => clientCs.decrypt(label));
console.assert(nearest.join() === '103,101');
```

If the gallery itself is stored in an untrusted cloud, the owner encrypts both the gallery and its queries with the [Catalano-Fiore](#adding-multiplication-support-to-additive-algorithms) boost. The cloud computes encrypted squared distances with the public key only, and the owner decrypts them to find the nearest vectors. The cloud learns nothing.

```typescript
// owner encrypts its gallery once, uploads it, and then encrypts queries
const ownerCs = new LightPHE({
  algorithmName: 'Paillier',
  boost: 'Catalano-Fiore',
});
const gallery = [
  [10, -5, 30, 4],
  [-40, 22, 1, 9],
  [13, -8, 35, 6],
];
const encryptedGallery = gallery.map((vector) =>
  vector.map((x) => ownerCs.encrypt(x))
);
const encryptedQuery = [12, -7, 33, 5].map((x) => ownerCs.encrypt(x));

// cloud computes encrypted distances with the public key only
const cloudCs = new LightPHE({
  algorithmName: 'Paillier',
  keys: { public_key: ownerCs.cs.keys.public_key },
  boost: 'Catalano-Fiore',
});
const encryptedDistances = cloudCs.evaluateKnnDistances(
  encryptedQuery,
  encryptedGallery
);

// owner decrypts them and finds the nearest vectors
console.assert(
  ownerCs.decryptKnn(encryptedDistances, 2).indices.join() === '2,0'
);
```

Scenarios:

- A user unlocks a door by face, and the building's server matches the encrypted face embedding against its gallery of employees, so the server never sees the user's face and the user learns only whether they are recognized, not who else is enrolled.
- A bank checks whether a new customer's encrypted face embedding matches anyone on a sanctions list held by a screening provider, so the provider does not learn the customer and the bank does not get the list.
- A company keeps the face embeddings of its employees in a public cloud, and searches them with encrypted queries, so a breach of the cloud reveals neither the gallery nor the queries.
- A retailer recommends products by finding the nearest items to a user's encrypted preference vector, so the server does not learn the user's taste.

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

### Threshold Decryption

ElGamal, Exponential ElGamal, Elliptic Curve ElGamal, Paillier and Damgard-Jurik support threshold decryption. ElGamal and Exponential ElGamal keys must be generated with `primeOrder: true` for this. A dealer splits the private key into shares, and any `threshold` of `parties` shareholders decrypt a ciphertext together, whereas fewer shareholders learn nothing. For instance, a board of 5 directors can let any 3 of them decrypt the company's encrypted data, so neither a single director can read it alone nor losing 2 of them blocks access.

```typescript
// dealer splits the private key into 5 shares, any 3 of them can decrypt
const dealerCs = new LightPHE({ algorithmName: 'Paillier' });
const shareKeys = dealerCs.generateThresholdKeys(3, 5);

// dealer forgets the private key, and publishes the public key with threshold parameters
dealerCs.exportKeys('public.txt', true);

// each share key is sent to its own shareholder secretly
const shareholders = shareKeys.map(
  (keys) => new LightPHE({ algorithmName: 'Paillier', keys })
);

// anyone encrypts and computes homomorphically with the public key
const publicCs = new LightPHE({
  algorithmName: 'Paillier',
  keyFile: 'public.txt',
});
const c = publicCs.encrypt(100).add(publicCs.encrypt(50));

// any 3 shareholders decrypt partially, a single partial decryption reveals nothing
const partials = [0, 2, 4].map((i) => shareholders[i].partialDecrypt(c));

// anyone having the public key combines partial decryptions
console.assert(publicCs.combinePartialDecryptions(c, partials) === 150n);
```

The dealer knows the private key while splitting it, so it must be trusted. By default, partial decryptions are not proven, so a cheating shareholder can cause a wrong plaintext silently. [Proof of partial decryption](#proof-of-partial-decryption) prevents this.

### Secure Aggregation for Federated Learning

In federated learning, clients train a model on their private data and send only model updates to a server, but updates can still leak the data. `lightphe-ts` lets clients encrypt their updates, the server sum them without decrypting, and a committee holding shares of the private key decrypt only the sum with [threshold decryption](#threshold-decryption). Updates are quantized with the precision of the cryptosystem, and many values are packed into a single ciphertext, so a client encrypts one ciphertext per chunk instead of one per value. With 1024-bit keys, 40 values fit into a ciphertext, and encrypting an update of 1000 values takes about 0.3 seconds instead of 13 seconds without packing. Paillier and Damgard-Jurik support this.

```typescript
// dealer splits the key among a committee of 5, any 3 of them can decrypt
const dealerCs = new LightPHE({ algorithmName: 'Paillier', safePrimes: true });
const shareKeys = dealerCs.generateThresholdKeys(3, 5);
const committee = shareKeys.map(
  (keys) => new LightPHE({ algorithmName: 'Paillier', keys })
);
const publicKey = { public_key: dealerCs.cs.keys.public_key };

// each client encrypts its update with the public key - values must be in [-maxValue, maxValue]
const clientCs = new LightPHE({ algorithmName: 'Paillier', keys: publicKey });
const updates = [
  [0.12, -0.53, 0.98],
  [0.33, 0.21, -0.47],
  [-0.25, 0.08, 0.61],
];
const encryptedUpdates = updates.map((update) =>
  clientCs.encryptUpdate(update, 1, 100)
);

// server sums encrypted updates without decrypting them
const serverCs = new LightPHE({ algorithmName: 'Paillier', keys: publicKey });
const encryptedSum = serverCs.aggregateUpdates(encryptedUpdates);

// any 3 members decrypt the sum only, and prove their partial decryptions
const partials = committee
  .slice(0, 3)
  .map((member) =>
    member.partialDecryptAggregate(encryptedSum, { prove: true })
  );
const result = serverCs.combineAggregate(encryptedSum, partials, {
  verify: true,
});

console.assert(
  result.mean.map((x) => x.toFixed(2)).join() === '0.07,-0.08,0.37'
);
```

The arguments of `encryptUpdate` are the update, `maxValue` and `maxClients`. `maxClients` reserves room in each slot, so that the sum of that many updates never overflows into the next value, and the server refuses to sum more. Clients must use the same key, length, precision, `maxValue` and `maxClients`. Updates of dropped clients are simply not summed, and the sum can still be decrypted if up to 2 committee members drop out.

Scenarios:

- Hospitals train a model to detect tumors on their own scans, and a central server averages their encrypted model updates, so neither the server nor the other hospitals see any hospital's update, which could leak information about its patients.
- A keyboard app improves next-word prediction from millions of phones, and a committee of independent organizations decrypts only the average update of each round, so no single party, including the app maker, can inspect the update of a particular phone.
- Banks build a shared fraud detection model, and verified partial decryptions stop a dishonest committee member from slipping a manipulated average into the shared model.

### Zero-Knowledge Proofs

`lightphe-ts` lets you prove facts about ciphertexts and decryptions without revealing the plaintexts or the private key, and anyone having the public key can verify them. For instance, a voter proves that a ballot is 0 or 1, an employee proves that an encrypted salary is in a sensible range, and an authority proves that the announced tally is really what the encrypted tally contains. Proofs are interoperable with the Python library.

| Algorithm              | Proof of<br>Decryption | Proof of<br>Partial Decryption | Proof of<br>Knowledge | Proof of<br>Allowed Values | Proof of<br>Range | E-Voting | Verifiable<br>Encryption |
| ---------------------- | ---------------------- | ------------------------------ | --------------------- | -------------------------- | ----------------- | -------- | ------------------------ |
| ElGamal                | ✅                     | ✅                             | ✅                    | ❌                         | ❌                | ❌       | ❌                       |
| Exponential ElGamal    | ✅                     | ✅                             | ✅                    | ✅                         | ✅                | ✅       | ❌                       |
| Elliptic Curve ElGamal | ✅                     | ✅                             | ✅                    | ✅                         | ✅                | ✅       | ❌                       |
| Paillier               | ✅                     | ✅                             | ✅                    | ✅                         | ✅                | ✅       | ❌                       |
| Damgard-Jurik          | ✅                     | ✅                             | ✅                    | ✅                         | ✅                | ✅       | ❌                       |
| Camenisch-Shoup        | ❌                     | ❌                             | ❌                    | ❌                         | ❌                | ❌       | ✅                       |

ElGamal and Exponential ElGamal keys must be generated with `primeOrder: true` for proofs. Paillier and Damgard-Jurik keys must be generated with `safePrimes: true` for proof of partial decryption.

#### Proof of Decryption

The private key owner can prove that a ciphertext decrypts to a plaintext, and anyone can check it with the public key only. ElGamal family uses a Chaum-Pedersen zero-knowledge proof, so the private key is never revealed. Paillier and Damgard-Jurik reveal the randomness of the ciphertext instead, which proves the plaintext and reveals nothing about the private key or other ciphertexts.

```typescript
// private key owner builds the cryptosystem and publishes its public key
const cs = new LightPHE({
  algorithmName: 'Exponential-ElGamal',
  primeOrder: true,
});
cs.exportKeys('public.txt', true);
const publicCs = new LightPHE({
  algorithmName: 'Exponential-ElGamal',
  keyFile: 'public.txt',
});

const c = publicCs.encrypt(17).add(publicCs.encrypt(25));

// private key owner decrypts with a proof
const [plaintext, proof] = cs.decryptWithProof(c);

// anyone verifies it with public key only
console.assert(publicCs.verifyDecryption(c, plaintext, proof) === true);
console.assert(publicCs.verifyDecryption(c, plaintext + 1n, proof) === false);
```

Scenarios:

- An election authority announces that 5,000 of 8,000 encrypted ballots are yes, and publishes a proof, so every voter can check that the announced result is really what the encrypted tally contains without trusting the authority.
- A cloud service computes the average salary over encrypted payroll data of a client company and decrypts it with a proof, so an external auditor can confirm that the reported average was not altered on its way to the board.
- A bank publishes the decrypted total of a day's encrypted transactions together with a proof, so a regulator can verify the total without being given the bank's private key or the individual transactions.

#### Proof of Partial Decryption

In [threshold decryption](#threshold-decryption), a cheating shareholder can send a wrong partial decryption and cause a wrong plaintext silently. A cheating shareholder can even shift the result by any amount it chooses, e.g. add 50 votes to a party, because lagrange coefficients of other shareholders are public. Shareholders can opt in to prove that their partial decryptions are computed with their own shares, and the combiner can opt in to verify them. Then, invalid or unproven partial decryptions are discarded. Paillier and Damgard-Jurik keys must be generated with `safePrimes: true` for this, e.g. `new LightPHE({ algorithmName: 'Paillier', safePrimes: true })`.

```typescript
// dealer splits the private key into 3 shares, any 2 of them can decrypt
const dealerCs = new LightPHE({
  algorithmName: 'Exponential-ElGamal',
  primeOrder: true,
});
const shareKeys = dealerCs.generateThresholdKeys(2, 3);
const shareholders = shareKeys.map(
  (keys) => new LightPHE({ algorithmName: 'Exponential-ElGamal', keys })
);

const c = dealerCs.encrypt(42);

// shareholders opt in to prove their partial decryptions
const partials = shareholders.map((shareholder) =>
  shareholder.partialDecrypt(c, { prove: true })
);

// anyone verifies a partial decryption with public key only, e.g. to find a cheating shareholder
console.assert(dealerCs.verifyPartialDecryption(c, partials[0]) === true);

// combiner opts in to verify partial decryptions while combining them
console.assert(
  dealerCs.combinePartialDecryptions(c, partials, { verify: true }) === 42n
);
```

Scenarios:

- Three trustees nominated by competing parties decrypt an election tally together, so a trustee who tries to add 50 votes to its own party by tampering with its partial decryption is detected and outvoted by the honest two.
- Five hospitals hold shares of a key protecting encrypted patient statistics, and any three of them decrypt the yearly average together, so a single hospital cannot quietly bias the published average in its favor.
- Servers of a federated learning committee decrypt the sum of encrypted model updates from thousands of phones, so a compromised server cannot slip a poisoned update into the global model without being caught.
- Two of three auditors are required to open the total of a company's encrypted transactions, so an auditor bribed to hide a loss cannot misreport the total.

#### Proof of Knowledge

Anyone having the public key can encrypt a value and prove knowledge of it, without revealing it. Otherwise, someone could copy another one's ciphertext, re-randomize it or modify it homomorphically, and submit it as their own without knowing the plaintext. The proof is bound to the ciphertext and a context such as the id of the encryptor.

```typescript
const cs = new LightPHE({ algorithmName: 'Paillier' });

// alice submits her sealed bid with a proof of knowledge
const [aliceBid, aliceProof] = cs.encryptWithProofOfKnowledge(950, {
  context: 'alice',
});
console.assert(
  cs.verifyKnowledge(aliceBid, aliceProof, { context: 'alice' }) === true
);

// mallory outbids alice by adding 1 to her encrypted bid without knowing it, but cannot prove it
const malloryBid = aliceBid.add(cs.encrypt(1));
console.assert(
  cs.verifyKnowledge(malloryBid, aliceProof, { context: 'mallory' }) === false
);
```

Scenarios:

- In a sealed-bid auction, Mallory sees Alice's encrypted bid and submits it plus 1 to win by the smallest margin without knowing the amount, but she cannot prove knowledge of that bid, so her submission is rejected.
- On a crowdfunding platform, a backer cannot copy a large encrypted pledge of another backer and scale it to look generous, because each pledge must come with a proof that its owner knows the amount.
- In an encrypted employee survey, a participant cannot re-randomize a colleague's encrypted answer and submit it as their own to double its weight, because a re-randomized copy cannot be proven.

#### Proof of Allowed Values

Anyone having the public key can encrypt a value and prove that it is one of the allowed values, without revealing which one. The proof is bound to a context such as the id of the encryptor, so a copied ciphertext with its proof is rejected for another context.

```typescript
const cs = new LightPHE({ algorithmName: 'Paillier' });

// a customer rates a product from 1 to 5 stars, and proves it without revealing the rating
const values = [1, 2, 3, 4, 5];
const [rating, proof] = cs.encryptWithProof(4, {
  values,
  context: 'customer-42',
});

// anyone verifies it with public key only
console.assert(
  cs.verifyCiphertext(rating, proof, { values, context: 'customer-42' }) ===
    true
);
console.assert(
  cs.verifyCiphertext(rating, proof, { values, context: 'customer-43' }) ===
    false
);
```

Scenarios:

- An online shop collects encrypted product ratings, and each customer proves that the rating is between 1 and 5 stars, so nobody can submit a rating of 1,000 to push the average up while individual ratings stay private.
- A company runs an anonymous satisfaction survey with answers from 1 (poor) to 4 (excellent), and each employee proves that the encrypted answer is one of them, so the average satisfaction is computed homomorphically and a malformed answer cannot corrupt it.
- In [e-voting](#e-voting), each voter proves that the ballot is 0 or 1, so nobody can cast a vote of 100 in the homomorphic tally without revealing how they voted.

#### Proof of Range

Anyone having the public key can encrypt a value and prove that it is in `[low, high]`, without revealing it. Proof size grows with the bit length of `high - low`.

```typescript
const cs = new LightPHE({ algorithmName: 'Paillier' });

// an employee proves that the encrypted salary is in [0, 500000], so cannot skew the average
const [salary, proof] = cs.encryptWithRangeProof(85000, 0, 500000, {
  context: 'alice',
});

// anyone verifies it with public key only
console.assert(
  cs.verifyRange(salary, proof, 0, 500000, { context: 'alice' }) === true
);
console.assert(
  cs.verifyRange(salary, proof, 0, 50000, { context: 'alice' }) === false
);
```

Scenarios:

- In an industry salary survey, each employee encrypts the salary with a proof that it is between 0 and 500,000, so a single participant cannot submit a negative or a billion-dollar salary to skew the published average.
- A website requires visitors to be adults, and a visitor proves that the encrypted age is between 18 and 120 without revealing the exact age or birth date.
- In a participatory budget, each citizen allocates up to 1,000 to public projects in encrypted form, so allocations are proven to be within the cap while individual preferences stay private.
- A lender accepts an encrypted credit score with a proof that it is between 650 and 850, so the applicant shows eligibility without revealing the exact score.

#### E-Voting

[Proof of allowed values](#proof-of-allowed-values) makes e-voting possible. Each voter proves that a ballot is 0 or 1, so cannot cast a vote of 100 in the homomorphic tally. The proof is bound to the id of the voter, so a copied ballot is rejected. Then, the authority decrypts the tally with a [proof of decryption](#proof-of-decryption).

```typescript
// authority builds the cryptosystem and publishes its public key
const authorityCs = new LightPHE({
  algorithmName: 'Exponential-ElGamal',
  primeOrder: true,
});
authorityCs.exportKeys('public.txt', true);
const publicCs = new LightPHE({
  algorithmName: 'Exponential-ElGamal',
  keyFile: 'public.txt',
});

// each voter encrypts a vote of 0 or 1 with a proof, having the public key only
const [aliceBallot, aliceProof] = publicCs.encryptWithProof(1, {
  context: 'alice',
});
const [bobBallot, bobProof] = publicCs.encryptWithProof(0, { context: 'bob' });

// anyone verifies ballots without decrypting them
console.assert(
  publicCs.verifyCiphertext(aliceBallot, aliceProof, { context: 'alice' })
);
console.assert(
  publicCs.verifyCiphertext(bobBallot, bobProof, { context: 'bob' })
);

// mallory's copy of alice's ballot is rejected
console.assert(
  !publicCs.verifyCiphertext(aliceBallot, aliceProof, { context: 'mallory' })
);

// valid ballots are tallied homomorphically, and the authority decrypts the tally with a proof
const tally = aliceBallot.add(bobBallot);
const [result, proof] = authorityCs.decryptWithProof(tally);
console.assert(publicCs.verifyDecryption(tally, result, proof));
console.assert(result === 1n);
```

For an election of parties, a vote for party `k` can be encrypted as `base^k`, so the tally keeps the votes of each party in its own digit in that base. The proof guarantees that a voter votes once for exactly one party. `base` must be greater than the votes a party can get, e.g. 100 allows up to 99 votes per party, and `base^parties` must be less than the modulus. Paillier fits here, as the tally is a large number.

```typescript
// authority builds the cryptosystem and publishes its public key
const authorityCs = new LightPHE({ algorithmName: 'Paillier' });
authorityCs.exportKeys('public.txt', true);
const publicCs = new LightPHE({
  algorithmName: 'Paillier',
  keyFile: 'public.txt',
});

// a vote for party k is encrypted as 100^k, i.e. 1 for red, 100 for green and 10000 for blue
const parties = ['red', 'green', 'blue'];
const values = parties.map((_, k) => 100n ** BigInt(k));

// each voter encrypts a vote for one party with a proof
const ballots = [
  ['alice', 'red'],
  ['bob', 'blue'],
  ['carol', 'red'],
].map(([voter, party]) => {
  const [ballot, proof] = publicCs.encryptWithProof(
    values[parties.indexOf(party)],
    { values, context: voter }
  );
  // anyone verifies ballots without decrypting them
  console.assert(
    publicCs.verifyCiphertext(ballot, proof, { values, context: voter })
  );
  return ballot;
});

// valid ballots are tallied homomorphically, and the authority decrypts the tally with a proof
const tally = ballots.reduce((sum, ballot) => sum.add(ballot));
const [result, proof] = authorityCs.decryptWithProof(tally);
console.assert(publicCs.verifyDecryption(tally, result, proof));

// tally is 2 x 1 + 0 x 100 + 1 x 10000 = 10002, read 2 digits at a time from right: 1 | 00 | 02
const votes = parties.map((_, k) => (result / 100n ** BigInt(k)) % 100n);
console.assert(votes.join() === '2,0,1');
```

Alternatively, for an election of many parties, each voter casts a one-hot ballot, i.e. one ciphertext per party where only the chosen party is 1, with a proof that exactly one party is chosen. Summing ballots slot by slot counts the votes of each party separately, so the number of parties is not limited.

```typescript
// authority builds the cryptosystem and publishes its public key
const authorityCs = new LightPHE({
  algorithmName: 'Exponential-ElGamal',
  primeOrder: true,
});
authorityCs.exportKeys('public.txt', true);
const publicCs = new LightPHE({
  algorithmName: 'Exponential-ElGamal',
  keyFile: 'public.txt',
});

const parties = ['red', 'green', 'blue', 'yellow'];

// each voter encrypts a vote for one party as a one-hot ballot with a proof
const ballots = [
  ['alice', 'red'],
  ['bob', 'blue'],
  ['carol', 'red'],
].map(([voter, party]) => {
  const [ballot, proof] = publicCs.encryptOneHot(
    parties.indexOf(party),
    parties.length,
    { context: voter }
  );
  // anyone verifies ballots without decrypting them
  console.assert(publicCs.verifyOneHot(ballot, proof, { context: voter }));
  return ballot;
});

// valid ballots are summed slot by slot, so each party's votes are counted in its own ciphertext
const tally = ballots.reduce((sums, ballot) =>
  sums.map((sum, i) => sum.add(ballot[i]))
);

// authority decrypts the count of each party with a proof
const votes = tally.map((count) => {
  const [result, proof] = authorityCs.decryptWithProof(count);
  console.assert(publicCs.verifyDecryption(count, result, proof));
  return result;
});
console.assert(votes.join() === '2,0,1,0');
```

Scenarios:

- A city runs a referendum on a new park, and every resident casts an encrypted yes or no ballot with a proof, so the city announces the result with a proof of decryption while nobody, including the city, learns how an individual voted.
- A national election of a few parties encrypts a vote for party k as `base^k`, so a single homomorphic sum and a single decryption reveal the votes of every party at once.
- A national election of dozens of parties uses one-hot ballots of `encryptOneHot` and `verifyOneHot`, so each party's votes are counted in its own ciphertext and the number of parties is not limited.
- Shareholders of a company vote on the board's proposals, and three independent trustees decrypt the tally with [threshold decryption](#threshold-decryption) and [proof of partial decryption](#proof-of-partial-decryption), so no single trustee can read or alter the result.

#### Verifiable Encryption

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

Scenarios:

- Alice escrows the private key of her crypto wallet with a trusted third party, and her bank verifies that the escrow really contains the key before granting her a loan, without ever seeing the key.
- A company escrows the encryption keys of its employees with a recovery service, so an auditor can verify that every key is recoverable if an employee leaves, while neither the auditor nor the service can use the keys under normal conditions.
- A crypto exchange verifies that a customer's key is escrowed under conditions agreed with a regulator, e.g. release only with a court order, without learning the key itself.

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

Most algorithms in `lightphe-ts` rely on factoring or discrete logarithm problems, which a large enough quantum computer could solve with Shor's algorithm. Regev, Lyubashevsky-Peikert-Regev, ML-KEM, Brakerski-Vaikuntanathan and Gentry-Sahai-Waters rely on learning with errors problems instead, which are believed to be hard for quantum computers too. Their default key sizes give about 128-bit security against quantum attacks.

Regev is additively homomorphic. Its key size is the lattice dimension, and its default is 2048.

```typescript
const cs = new LightPHE({ algorithmName: 'Regev' });

const c1 = cs.encrypt(1500);
const c2 = cs.encrypt(2500);

console.assert(cs.decrypt(c1.add(c2)) === 4000n);
console.assert(cs.decrypt(c1.multiply(3)) === 4500n);
```

Lyubashevsky-Peikert-Regev is Regev over a polynomial ring, so its security relies on the ring learning with errors problem like Brakerski-Vaikuntanathan. Its random matrix is replaced by a single polynomial, so it generates keys and encrypts many times faster than Regev with the same key and ciphertext sizes. Its key size is the degree of its polynomial ring, and its default is 2048.

```typescript
const cs = new LightPHE({ algorithmName: 'Lyubashevsky-Peikert-Regev' });

const c1 = cs.encrypt(1500);
const c2 = cs.encrypt(2500);

console.assert(cs.decrypt(c1.add(c2)) === 4000n);
console.assert(cs.decrypt(c1.multiply(3)) === 4500n);
```

ML-KEM uses the parameter sets standardized by NIST in FIPS 203: ML-KEM-512, ML-KEM-768 and ML-KEM-1024. It is homomorphic with respect to the exclusive or of 256-bit messages like Goldwasser-Micali. Its key size is the parameter set, and its default is 768. Notice that this is the CPA secure public key encryption K-PKE inside ML-KEM, without ciphertext compression and without the transform that makes ML-KEM CCA secure, because a CCA secure scheme cannot be homomorphic. So, it is not a FIPS 203 compliant ML-KEM implementation, and its keys and ciphertexts are not interoperable with other libraries. Its modulus is small, so only a few ciphertexts can be combined: exclusive or of 6 ciphertexts fails with a probability of about 2^-50 for ML-KEM-768.

```typescript
const cs = new LightPHE({ algorithmName: 'ML-KEM' });

const m1 = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefn;
const m2 = 0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321n;

const c1 = cs.encrypt(m1);
const c2 = cs.encrypt(m2);

console.assert(cs.decrypt(c1.xor(c2)) === (m1 ^ m2));
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

Gentry-Sahai-Waters encrypts bits, and supports both exclusive or and and, so boolean circuits can be evaluated on encrypted bits with more than one multiplication. Exclusive or is almost free. Products of products work up to a multiplicative depth of 2, e.g. `a.and(b).and(c.and(d))`, whereas chains like `acc = acc.and(fresh)`, e.g. carries of a ripple carry adder, can be very long because each step adds a small fixed noise. Its key size is the degree of its polynomial ring, and its default is 2048. Encrypting a bit takes about 0.4 seconds, an and takes about 0.3 seconds, and a ciphertext is about 256 KB.

```typescript
const cs = new LightPHE({ algorithmName: 'Gentry-Sahai-Waters' });

const [a, b, c, d] = [1, 1, 0, 1].map((bit) => cs.encrypt(bit));

// majority of three bits, and a product of products
console.assert(cs.decrypt(a.and(b).xor(a.and(c)).xor(b.and(c))) === 1n);
console.assert(cs.decrypt(a.and(b).and(c.and(d))) === 0n);
```

Every ciphertext of these algorithms carries a small noise, which grows with each homomorphic operation, and decryption silently fails once it grows too much. With default settings, plaintexts must be less than 2^24. Regev and Lyubashevsky-Peikert-Regev have room for thousands of additions or multiplications with constants up to a few thousands, and a product of Brakerski-Vaikuntanathan has room for millions of times more noise. You can increase the plaintext space with the `plaintextLimit` option in exchange of less room for noise. Floats and tensors are not supported.

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

To send ciphertexts and proofs to another party, see [Sending Ciphertexts over Network](#sending-ciphertexts-over-network).

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
