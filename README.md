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
[`Boneh-Goh-Nissim`](https://sefiks.com/2026/04/02/a-step-by-step-somewhat-homomorphic-encryption-example-with-boneh-goh-nissim-in-python/).

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

| Algorithm              | Multiplicatively<br>Homomorphic | Additively<br>Homomorphic | Scalar Multiplication | Bitwise-XOR Homomorphic | Bitwise-AND Homomorphic | Regeneration<br>of Ciphertext |
| ---------------------- | ------------------------------- | ------------------------- | --------------------- | ----------------------- | ----------------------- | ----------------------------- |
| RSA                    | ✅                              | ❌                        | ❌                    | ❌                      | ❌                      | ❌                            |
| ElGamal                | ✅                              | ❌                        | ❌                    | ❌                      | ❌                      | ✅                            |
| Exponential ElGamal    | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            |
| Elliptic Curve ElGamal | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            |
| Paillier               | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            |
| Damgard-Jurik          | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            |
| Benaloh                | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            |
| Naccache-Stern         | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            |
| Okamoto-Uchiyama       | ❌                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            |
| Goldwasser-Micali      | ❌                              | ❌                        | ❌                    | ✅                      | ❌                      | ✅                            |
| Sander-Young-Yung      | ❌                              | ❌                        | ❌                    | ❌                      | ✅                      | ✅                            |
| Boneh-Goh-Nissim       | 1️⃣                              | ✅                        | ✅                    | ❌                      | ❌                      | ✅                            |

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

| Language | Repository | Ecosystem Focus |
| :--- | :--- | :--- |
| **Python** | [`lightphe`](https://github.com/serengil/lightphe) | AI, Research & Prototyping |
| **Go** | [`lightphe-go`](https://github.com/serengil/lightphe-go) | Cloud-Native & High-Throughput Microservices |
| **Java** | [`lightphe4j`](https://github.com/serengil/lightphe4j) | Enterprise, Banking & Legacy Systems |
| **TypeScript** | [`lightphe-ts`](https://github.com/serengil/lightphe-ts) | Client-Side Privacy & Node.js Backend |

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
