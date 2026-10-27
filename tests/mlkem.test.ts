import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { LightPHE, Logger } from '../src';
import { randomBits } from '../src/commons/mathUtils';
import {
  expand,
  MLKEM_HALF_Q,
  MLKEM_N,
  MLKEM_PARAMETER_SETS,
  MLKEM_Q,
  polyMul,
} from '../src/cryptosystems/MLKEM';
import { randomInt, valuesEqual } from './helpers';

const logger = new Logger('tests/mlkem.test.ts');

const Q = MLKEM_Q;
const N = MLKEM_N;

const PARAMETER_SET_NAMES = [512, 768, 1024];
const systems = new Map<number, LightPHE>();
function getCs(parameterSet: number): LightPHE {
  if (!systems.has(parameterSet)) {
    systems.set(
      parameterSet,
      new LightPHE({ algorithmName: 'ML-KEM', keySize: parameterSet })
    );
  }
  return systems.get(parameterSet)!;
}

/** Schoolbook multiplication in `Z_q[x] / (x^256 + 1)`. */
function negacyclicProduct(
  poly1: readonly number[],
  poly2: readonly number[]
): number[] {
  const result = new Array<number>(N).fill(0);
  for (let i = 0; i < N; i++) {
    for (let j = 0; j < N; j++) {
      if (i + j < N) {
        result[i + j] += poly1[i] * poly2[j];
      } else {
        result[i + j - N] -= poly1[i] * poly2[j];
      }
    }
  }
  return result.map((x) => ((x % Q) + Q) % Q);
}

function centered(x: number): number {
  const r = ((x % Q) + Q) % Q;
  return r > Math.floor(Q / 2) ? r - Q : r;
}

/** `v - s^T u - m q / 2` for each coefficient. */
function noiseOf(
  cs: LightPHE,
  ciphertext: bigint[][],
  plaintext: bigint
): number[] {
  const s = (cs.cs.keys.private_key!.s as bigint[][]).map((poly) =>
    poly.map((x) => ((Number(x) % Q) + Q) % Q)
  );
  const u = ciphertext.slice(0, -1).map((poly) => poly.map(Number));
  const v = ciphertext[ciphertext.length - 1].map(Number);
  const products = u.map((poly, j) => negacyclicProduct(poly, s[j]));
  return v.map((vx, x) =>
    centered(
      vx -
        products.reduce((total, product) => total + product[x], 0) -
        Number((plaintext >> BigInt(x)) & 1n) * MLKEM_HALF_Q
    )
  );
}

describe.each(PARAMETER_SET_NAMES)('ML-KEM-%i', (parameterSet) => {
  it('is homomorphic with respect to exclusive or', () => {
    const tic = Date.now();
    const cs = getCs(parameterSet);
    let m1 = 0n;
    let c1 = cs.encrypt(0);
    for (let i = 0; i < 5; i++) {
      m1 = randomBits(256);
      const m2 = randomBits(256);
      c1 = cs.encrypt(m1);
      const c2 = cs.encrypt(m2);

      // proof of decryption
      expect(cs.decrypt(c1)).toBe(m1);
      expect(cs.decrypt(c2)).toBe(m2);

      // homomorphic exclusive or
      expect(cs.decrypt(c1.xor(c2))).toBe(m1 ^ m2);
      expect(cs.decrypt(c1.xor(c1))).toBe(0n);
    }

    // edge plaintexts and plaintexts exceeding 256 bits
    for (const m of [0n, 1n, 2n ** 255n, 2n ** 256n - 1n]) {
      expect(cs.decrypt(cs.encrypt(m))).toBe(m);
    }
    expect(cs.decrypt(cs.encrypt(2n ** 256n + 5n))).toBe(5n);
    expect(cs.decrypt(cs.encrypt(-1))).toBe(2n ** 256n - 1n);

    // re-randomization
    const c1Prime = cs.regenerateCiphertext(c1);
    expect(valuesEqual(c1Prime.value, c1.value)).toBe(false);
    expect(cs.decrypt(c1Prime)).toBe(m1);

    // unsupported homomorphic operations
    const c2 = cs.encrypt(1);
    expect(() => c1.add(c2)).toThrow();
    expect(() => c1.multiply(c2)).toThrow();
    expect(() => c1.multiply(3)).toThrow();
    expect(() => c1.and(c2)).toThrow();

    logger.info(
      `✅ ML-KEM-${parameterSet} api test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });

  it('uses the parameters of FIPS 203', () => {
    // FIPS 203, table 2
    expect(Q).toBe(3329);
    expect(N).toBe(256);
    expect(MLKEM_PARAMETER_SETS).toEqual({
      512: { k: 2, eta1: 3, eta2: 2 },
      768: { k: 3, eta1: 2, eta2: 2 },
      1024: { k: 4, eta1: 2, eta2: 2 },
    });

    const cs = getCs(parameterSet);
    const { k } = MLKEM_PARAMETER_SETS[parameterSet];
    const c = cs.encrypt(1).value as bigint[][];
    expect(c.length).toBe(k + 1);
    expect(
      c.every(
        (poly) =>
          poly.length === N && poly.every((x) => x >= 0n && x < BigInt(Q))
      )
    ).toBe(true);
  });

  it('generates well formed keys', () => {
    // t = A s + e where s and e are small
    const cs = getCs(parameterSet);
    const publicKey = cs.cs.keys.public_key!;
    const { k, eta1 } = MLKEM_PARAMETER_SETS[parameterSet];
    const s = (cs.cs.keys.private_key!.s as bigint[][]).map((poly) =>
      poly.map(Number)
    );
    const t = (publicKey.t as bigint[][]).map((poly) => poly.map(Number));
    const a = expand(publicKey.seed as bigint, k);

    expect(a.length).toBe(k);
    expect(a.every((row) => row.length === k)).toBe(true);
    expect(a.flat(2).every((x) => x >= 0 && x < Q)).toBe(true);
    expect(s.flat().every((x) => Math.abs(x) <= eta1)).toBe(true);

    for (let i = 0; i < k; i++) {
      const aS = new Array<number>(N).fill(0);
      for (let j = 0; j < k; j++) {
        const product = negacyclicProduct(
          a[i][j],
          s[j].map((x) => ((x % Q) + Q) % Q)
        );
        product.forEach((x, index) => (aS[index] += x));
      }
      expect(
        t[i].every((x, index) => Math.abs(centered(x - aS[index])) <= eta1)
      ).toBe(true);
    }
  });

  it('has noise matching the estimate', () => {
    // noise e^T r + e2 - s^T e1 has variance k * 256 * (var1^2 + var1 * var2) + var2
    const cs = getCs(parameterSet);
    const { k, eta1, eta2 } = MLKEM_PARAMETER_SETS[parameterSet];
    const var1 = eta1 / 2;
    const var2 = eta2 / 2;
    const sigma = Math.sqrt(k * N * (var1 * var1 + var1 * var2) + var2);

    const samples: number[] = [];
    for (let i = 0; i < 4; i++) {
      const m = randomBits(256);
      samples.push(...noiseOf(cs, cs.encrypt(m).value as bigint[][], m));
    }
    const measured = Math.sqrt(
      samples.reduce((total, x) => total + x * x, 0) / samples.length
    );
    expect(Math.abs(measured - sigma) / sigma).toBeLessThan(0.15);

    // fresh noise is far below q / 4
    expect(Math.max(...samples.map(Math.abs))).toBeLessThan(
      Math.floor(Q / 4) / 3
    );
  });

  it('combines a few ciphertexts with exclusive or', () => {
    // failure probability of combining 6 ciphertexts is about 2^-36 or less
    const cs = getCs(parameterSet);
    const messages = Array.from({ length: 6 }, () => randomBits(256));
    let total = cs.encrypt(messages[0]);
    let expected = messages[0];
    for (const m of messages.slice(1)) {
      total = total.xor(cs.encrypt(m));
      expected ^= m;
    }
    expect(cs.decrypt(total)).toBe(expected);
  });
});

describe('ML-KEM', () => {
  it('multiplies polynomials', () => {
    for (let i = 0; i < 5; i++) {
      const poly1 = Array.from({ length: N }, () => randomInt(0, Q - 1));
      const poly2 = Array.from({ length: N }, () => randomInt(-3, 3));
      expect(polyMul(poly1, poly2)).toEqual(
        negacyclicProduct(
          poly1,
          poly2.map((x) => ((x % Q) + Q) % Q)
        )
      );
    }
  });

  it('does not support floats and tensors', () => {
    const cs = new LightPHE({ algorithmName: 'ML-KEM', keySize: 512 });
    expect(() => cs.encrypt(1.5)).toThrow('ML-KEM does not support float');
    expect(() => cs.encrypt([1, 2, 3])).toThrow(
      'ML-KEM does not support float'
    );

    for (const keySize of [256, 1000, 2048]) {
      expect(() => new LightPHE({ algorithmName: 'ML-KEM', keySize })).toThrow(
        'parameter sets of ML-KEM'
      );
    }
  });

  it('uses ML-KEM-768 by default', () => {
    expect(
      new LightPHE({ algorithmName: 'ML-KEM' }).cs.keys.public_key!
        .parameter_set
    ).toBe(768n);
  });

  it('works with exported keys', () => {
    const cs = new LightPHE({ algorithmName: 'ML-KEM', keySize: 768 });
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-mlkem-'));
    const publicKeyFile = path.join(dir, 'public.txt');
    const privateKeyFile = path.join(dir, 'private.txt');
    cs.exportKeys(publicKeyFile, true);
    cs.exportKeys(privateKeyFile);

    const m1 = randomBits(256);
    const m2 = randomBits(256);
    const publicCs = new LightPHE({
      algorithmName: 'ML-KEM',
      keyFile: publicKeyFile,
    });
    const c = publicCs.encrypt(m1).xor(publicCs.encrypt(m2));

    expect(() => publicCs.decrypt(c)).toThrow('private key');

    const restoredCs = new LightPHE({
      algorithmName: 'ML-KEM',
      keyFile: privateKeyFile,
    });
    expect(restoredCs.decrypt(c)).toBe(m1 ^ m2);
    expect(cs.decrypt(c)).toBe(m1 ^ m2);
  });
});
