import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { Ciphertext, LightPHE, Logger } from '../src';
import {
  decompose,
  gadget,
  GSW_ELL,
  GSW_ETA,
  GSW_LOG_B,
  GSW_LOG_Q,
  GSW_OFFSET,
} from '../src/cryptosystems/GentrySahaiWaters';
import { expand } from '../src/cryptosystems/LyubashevskyPeikertRegev';
import {
  bitLength,
  pmod,
  randomBigInt,
  randomInt,
  valuesEqual,
} from './helpers';

const logger = new Logger('tests/gentrysahaiwaters.test.ts');

const ALGORITHM = 'Gentry-Sahai-Waters';
const cs = new LightPHE({ algorithmName: ALGORITHM, keySize: 64 });
const Q = 2n ** BigInt(GSW_LOG_Q);

// ring degree giving about 128-bit security against quantum attacks
let largeCs: LightPHE | undefined;
function getLargeCs(): LightPHE {
  largeCs ??= new LightPHE({ algorithmName: ALGORITHM, keySize: 2048 });
  return largeCs;
}

/** Schoolbook multiplication in `Z_q[x] / (x^d + 1)`. */
function negacyclicProduct(
  poly1: readonly bigint[],
  poly2: readonly bigint[],
  q: bigint
): bigint[] {
  const d = poly1.length;
  const result = new Array<bigint>(d).fill(0n);
  for (let i = 0; i < d; i++) {
    for (let j = 0; j < d; j++) {
      if (i + j < d) {
        result[i + j] += poly1[i] * poly2[j];
      } else {
        result[i + j - d] -= poly1[i] * poly2[j];
      }
    }
  }
  return result.map((x) => pmod(x, q));
}

function centered(x: bigint, q: bigint): bigint {
  const r = pmod(x, q);
  return r > q / 2n ? r - q : r;
}

/** Constant term of a product in `Z[x] / (x^d + 1)`, without the full product. */
function constantTerm(
  poly1: readonly bigint[],
  poly2: readonly bigint[]
): bigint {
  const d = poly1.length;
  let result = poly1[0] * poly2[0];
  for (let i = 1; i < d; i++) {
    result -= poly1[i] * poly2[d - i];
  }
  return result;
}

/** Bit length of the phase of the decrypted row minus `m q / 2`. */
function noiseBits(
  system: LightPHE,
  ciphertext: Ciphertext,
  bit: number
): number {
  const s = system.cs.keys.private_key!.s as bigint[];
  const [c0, c1] = (ciphertext.value as bigint[][][])[GSW_ELL - 1];
  const phase = centered(
    c0[0] + constantTerm(c1, s) - (BigInt(bit) * Q) / 2n,
    Q
  );
  return bitLength(phase);
}

describe('Gentry-Sahai-Waters', () => {
  it('evaluates truth tables', () => {
    const tic = Date.now();
    for (const a of [0, 1]) {
      for (const b of [0, 1]) {
        const ca = cs.encrypt(a);
        const cb = cs.encrypt(b);
        expect(cs.decrypt(ca)).toBe(BigInt(a));
        expect(cs.decrypt(ca.and(cb))).toBe(BigInt(a & b));
        expect(cs.decrypt(ca.multiply(cb))).toBe(BigInt(a * b));
        expect(cs.decrypt(ca.xor(cb))).toBe(BigInt(a ^ b));
      }
    }

    // not is exclusive or with 1
    const one = cs.encrypt(1);
    expect(cs.decrypt(cs.encrypt(0).xor(one))).toBe(1n);
    expect(cs.decrypt(cs.encrypt(1).xor(one))).toBe(0n);

    // re-randomization
    const c = cs.encrypt(1);
    const cPrime = cs.regenerateCiphertext(c);
    expect(valuesEqual(cPrime.value, c.value)).toBe(false);
    expect(cs.decrypt(cPrime)).toBe(1n);

    // unsupported homomorphic operations
    expect(() => c.add(cPrime)).toThrow();
    expect(() => c.multiply(3)).toThrow();

    logger.info(
      `✅ Gentry-Sahai-Waters truth tables succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });

  it('evaluates circuits of depth two', () => {
    for (let bits = 0; bits < 16; bits++) {
      const [a, b, c, d] = [3, 2, 1, 0].map((shift) => (bits >> shift) & 1);
      const [ca, cb, cc, cd] = [a, b, c, d].map((x) => cs.encrypt(x));
      // product of products
      expect(cs.decrypt(ca.and(cb).and(cc.and(cd)))).toBe(
        BigInt(a & b & c & d)
      );
      // majority of three
      const majority = ca.and(cb).xor(ca.and(cc)).xor(cb.and(cc));
      expect(cs.decrypt(majority)).toBe(a + b + c >= 2 ? 1n : 0n);
      // exclusive or of products, and product of exclusive ors
      expect(cs.decrypt(ca.and(cb).xor(cc.and(cd)))).toBe(
        BigInt((a & b) ^ (c & d))
      );
      expect(cs.decrypt(ca.xor(cb).and(cc.xor(cd)))).toBe(
        BigInt((a ^ b) & (c ^ d))
      );
    }
  });

  it('evaluates long chains of ands', () => {
    // acc = acc & fresh adds a fixed noise each time
    const ones = (n: number): number[] => new Array<number>(n).fill(1);
    for (const bits of [ones(40), [...ones(20), 0, ...ones(19)]]) {
      let acc = cs.encrypt(bits[0]);
      for (const bit of bits.slice(1)) {
        acc = acc.and(cs.encrypt(bit));
      }
      expect(cs.decrypt(acc)).toBe(BigInt(Math.min(...bits)));
    }
  });

  it('adds integers with a ripple carry adder', () => {
    // add two encrypted 8-bit integers bit by bit. carry is chained with fresh bits.
    for (let round = 0; round < 3; round++) {
      const x = randomInt(0, 255);
      const y = randomInt(0, 255);
      const xBits = Array.from({ length: 8 }, (_, i) =>
        cs.encrypt((x >> i) & 1)
      );
      const yBits = Array.from({ length: 8 }, (_, i) =>
        cs.encrypt((y >> i) & 1)
      );

      let carry = cs.encrypt(0);
      const resultBits: Ciphertext[] = [];
      xBits.forEach((a, i) => {
        const b = yBits[i];
        const half = a.xor(b);
        resultBits.push(half.xor(carry));
        // carry = a & b ^ carry & (a ^ b)
        carry = a.and(b).xor(carry.and(half));
      });
      resultBits.push(carry);

      const result = resultBits.reduce(
        (total, bit, i) => total + (Number(cs.decrypt(bit)) << i),
        0
      );
      expect(result).toBe(x + y);
    }
  });

  it('generates well formed keys', () => {
    // b + a s = e where e is small
    const publicKey = cs.cs.keys.public_key!;
    const d = Number(publicKey.d as bigint);
    const q = publicKey.q as bigint;
    const b = publicKey.b as bigint[];
    const s = cs.cs.keys.private_key!.s as bigint[];
    const a = expand(publicKey.seed as bigint, d);

    expect(q).toBe(Q);
    expect(s.every((x) => x >= -BigInt(GSW_ETA) && x <= BigInt(GSW_ETA))).toBe(
      true
    );
    const aS = negacyclicProduct(
      a,
      s.map((x) => pmod(x, q)),
      q
    );
    aS.forEach((x, i) => {
      const error = centered(x + b[i], q);
      expect(error >= -BigInt(GSW_ETA) && error <= BigInt(GSW_ETA)).toBe(true);
    });
  });

  it('decomposes polynomials with the gadget', () => {
    // sum of digits times gadget entries restores the polynomial up to rounding
    expect(GSW_OFFSET + GSW_LOG_B * (GSW_ELL - 1)).toBe(GSW_LOG_Q - 1);
    const poly = [
      ...Array.from({ length: 64 }, () => randomBigInt(Q)),
      0n,
      1n,
      Q - 1n,
      Q / 2n,
      Q / 2n - 1n,
    ];
    const digits = decompose(poly);
    expect(digits.length).toBe(GSW_ELL);
    const halfB = 2n ** BigInt(GSW_LOG_B - 1);
    poly.forEach((x, i) => {
      for (let j = 0; j < GSW_ELL; j++) {
        expect(digits[j][i] >= -halfB && digits[j][i] < halfB).toBe(true);
      }
      const restored = digits.reduce(
        (total, digit, j) => total + digit[i] * gadget(j),
        0n
      );
      const error = centered(x - restored, Q);
      expect(
        (error < 0n ? -error : error) <= 2n ** BigInt(GSW_OFFSET - 1)
      ).toBe(true);
    });
  });

  it('rejects invalid inputs', () => {
    for (const plaintext of [2, -1, 1.5]) {
      expect(() => cs.encrypt(plaintext)).toThrow('encrypts bits');
    }
    expect(() => cs.encrypt([0, 1])).toThrow('encrypts bits');

    expect(() => cs.encrypt(1).multiply(1.5)).toThrow('encrypts bits');

    for (const keySize of [4, 48, 100]) {
      expect(() => new LightPHE({ algorithmName: ALGORITHM, keySize })).toThrow(
        'must be a power of 2'
      );
    }
  });

  it('works with exported keys', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-gsw-'));
    const publicKeyFile = path.join(dir, 'public.txt');
    cs.exportKeys(publicKeyFile, true);

    const publicCs = new LightPHE({
      algorithmName: ALGORITHM,
      keyFile: publicKeyFile,
    });
    const c = publicCs.encrypt(1).and(publicCs.encrypt(1));
    expect(cs.decrypt(c)).toBe(1n);

    expect(() => publicCs.decrypt(c)).toThrow('private key');
  });

  it('keeps noise of large keys within the budget', () => {
    // products of products of depth 2 stay below q / 4 = 2^48 for the default degree
    const tic = Date.now();
    const large = getLargeCs();
    const [a, b, c, d] = [0, 1, 2, 3].map(() => large.encrypt(1));
    expect(noiseBits(large, a, 1)).toBeLessThanOrEqual(16);

    const ab = a.and(b);
    const cd = c.and(d);
    expect(noiseBits(large, ab, 1)).toBeLessThanOrEqual(32);

    const abcd = ab.and(cd);
    expect(large.decrypt(abcd)).toBe(1n);
    expect(noiseBits(large, abcd, 1)).toBeLessThanOrEqual(46);

    // a chain with a fresh ciphertext on the right adds a small noise
    const chain = abcd.and(large.encrypt(0));
    expect(large.decrypt(chain)).toBe(0n);

    logger.info(
      `✅ Gentry-Sahai-Waters 2048-degree test succeeded in ${(Date.now() - tic) / 1000} seconds`
    );
  });
});
