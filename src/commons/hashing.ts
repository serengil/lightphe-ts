/**
 * SHA-256 and SHAKE-128, implemented in-house so they work the same in Node and
 * in the browser, where no synchronous hash API exists.
 *
 * Camenisch-Shoup hashes with SHA-256 to bind labels and build Fiat-Shamir
 * challenges, and Regev and Brakerski-Vaikuntanathan expand their public
 * matrices and polynomials from a seed with SHAKE-128. Outputs match
 * `hashlib.sha256` and `hashlib.shake_128` byte for byte, which keeps keys and
 * proofs interoperable with the Python library.
 */

/* -------------------------------------------------------------------------- */
/* SHA-256                                                                     */
/* -------------------------------------------------------------------------- */

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n));
}

/** Returns the SHA-256 digest of the given bytes. */
export function sha256(data: Uint8Array): Uint8Array {
  const bitLength = data.length * 8;
  const paddedLength = Math.ceil((data.length + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLength);
  padded.set(data);
  padded[data.length] = 0x80;
  // message length in bits as a 64-bit big-endian integer
  const high = Math.floor(bitLength / 2 ** 32);
  const view = new DataView(padded.buffer);
  view.setUint32(paddedLength - 8, high);
  view.setUint32(paddedLength - 4, bitLength >>> 0);

  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19,
  ]);
  const w = new Uint32Array(64);

  for (let offset = 0; offset < paddedLength; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + s1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (s0 + maj) >>> 0;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
  }

  const digest = new Uint8Array(32);
  const digestView = new DataView(digest.buffer);
  for (let i = 0; i < 8; i++) {
    digestView.setUint32(i * 4, h[i]);
  }
  return digest;
}

/** Returns the SHA-256 digest of a string encoded as UTF-8. */
export function sha256Text(text: string): Uint8Array {
  return sha256(new TextEncoder().encode(text));
}

/* -------------------------------------------------------------------------- */
/* SHA-512                                                                     */
/* -------------------------------------------------------------------------- */

const SHA512_K: readonly bigint[] = [
  '428a2f98d728ae22',
  '7137449123ef65cd',
  'b5c0fbcfec4d3b2f',
  'e9b5dba58189dbbc',
  '3956c25bf348b538',
  '59f111f1b605d019',
  '923f82a4af194f9b',
  'ab1c5ed5da6d8118',
  'd807aa98a3030242',
  '12835b0145706fbe',
  '243185be4ee4b28c',
  '550c7dc3d5ffb4e2',
  '72be5d74f27b896f',
  '80deb1fe3b1696b1',
  '9bdc06a725c71235',
  'c19bf174cf692694',
  'e49b69c19ef14ad2',
  'efbe4786384f25e3',
  '0fc19dc68b8cd5b5',
  '240ca1cc77ac9c65',
  '2de92c6f592b0275',
  '4a7484aa6ea6e483',
  '5cb0a9dcbd41fbd4',
  '76f988da831153b5',
  '983e5152ee66dfab',
  'a831c66d2db43210',
  'b00327c898fb213f',
  'bf597fc7beef0ee4',
  'c6e00bf33da88fc2',
  'd5a79147930aa725',
  '06ca6351e003826f',
  '142929670a0e6e70',
  '27b70a8546d22ffc',
  '2e1b21385c26c926',
  '4d2c6dfc5ac42aed',
  '53380d139d95b3df',
  '650a73548baf63de',
  '766a0abb3c77b2a8',
  '81c2c92e47edaee6',
  '92722c851482353b',
  'a2bfe8a14cf10364',
  'a81a664bbc423001',
  'c24b8b70d0f89791',
  'c76c51a30654be30',
  'd192e819d6ef5218',
  'd69906245565a910',
  'f40e35855771202a',
  '106aa07032bbd1b8',
  '19a4c116b8d2d0c8',
  '1e376c085141ab53',
  '2748774cdf8eeb99',
  '34b0bcb5e19b48a8',
  '391c0cb3c5c95a63',
  '4ed8aa4ae3418acb',
  '5b9cca4f7763e373',
  '682e6ff3d6b2b8a3',
  '748f82ee5defb2fc',
  '78a5636f43172f60',
  '84c87814a1f0ab72',
  '8cc702081a6439ec',
  '90befffa23631e28',
  'a4506cebde82bde9',
  'bef9a3f7b2c67915',
  'c67178f2e372532b',
  'ca273eceea26619c',
  'd186b8c721c0c207',
  'eada7dd6cde0eb1e',
  'f57d4f7fee6ed178',
  '06f067aa72176fba',
  '0a637dc5a2c898a6',
  '113f9804bef90dae',
  '1b710b35131c471b',
  '28db77f523047d84',
  '32caab7b40c72493',
  '3c9ebe0a15c9bebc',
  '431d67c49c100d4c',
  '4cc5d4becb3e42b6',
  '597f299cfc657e2a',
  '5fcb6fab3ad6faec',
  '6c44198c4a475817',
].map((hex) => BigInt(`0x${hex}`));

const MASK_64 = (1n << 64n) - 1n;

function rotr64(x: bigint, n: bigint): bigint {
  return ((x >> n) | (x << (64n - n))) & MASK_64;
}

/**
 * Returns the SHA-512 digest of the given bytes. Words are 64-bit, so they are
 * handled as bigints. It hashes short Fiat-Shamir transcripts only, where this
 * is fast enough.
 */
export function sha512(data: Uint8Array): Uint8Array {
  const paddedLength = Math.ceil((data.length + 17) / 128) * 128;
  const padded = new Uint8Array(paddedLength);
  padded.set(data);
  padded[data.length] = 0x80;
  // message length in bits as a 128-bit big-endian integer
  const view = new DataView(padded.buffer);
  const bitLength = data.length * 8;
  view.setUint32(paddedLength - 8, Math.floor(bitLength / 2 ** 32));
  view.setUint32(paddedLength - 4, bitLength >>> 0);

  const h: bigint[] = [
    '6a09e667f3bcc908',
    'bb67ae8584caa73b',
    '3c6ef372fe94f82b',
    'a54ff53a5f1d36f1',
    '510e527fade682d1',
    '9b05688c2b3e6c1f',
    '1f83d9abfb41bd6b',
    '5be0cd19137e2179',
  ].map((hex) => BigInt(`0x${hex}`));
  const w: bigint[] = new Array<bigint>(80);

  for (let offset = 0; offset < paddedLength; offset += 128) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getBigUint64(offset + i * 8);
    }
    for (let i = 16; i < 80; i++) {
      const s0 =
        rotr64(w[i - 15], 1n) ^ rotr64(w[i - 15], 8n) ^ (w[i - 15] >> 7n);
      const s1 =
        rotr64(w[i - 2], 19n) ^ rotr64(w[i - 2], 61n) ^ (w[i - 2] >> 6n);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK_64;
    }

    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 80; i++) {
      const s1 = rotr64(e, 14n) ^ rotr64(e, 18n) ^ rotr64(e, 41n);
      const ch = (e & f) ^ (~e & MASK_64 & g);
      const t1 = (hh + s1 + ch + SHA512_K[i] + w[i]) & MASK_64;
      const s0 = rotr64(a, 28n) ^ rotr64(a, 34n) ^ rotr64(a, 39n);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (s0 + maj) & MASK_64;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) & MASK_64;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) & MASK_64;
    }

    for (const [i, value] of [a, b, c, d, e, f, g, hh].entries()) {
      h[i] = (h[i] + value) & MASK_64;
    }
  }

  const digest = new Uint8Array(64);
  const digestView = new DataView(digest.buffer);
  for (let i = 0; i < 8; i++) {
    digestView.setBigUint64(i * 8, h[i]);
  }
  return digest;
}

/* -------------------------------------------------------------------------- */
/* SHAKE-128                                                                   */
/* -------------------------------------------------------------------------- */

// bytes absorbed or squeezed per permutation for SHAKE-128
const SHAKE128_RATE = 168;

// round constants of Keccak-f[1600], split into 32-bit halves
const ROUND_CONSTANTS: ReadonlyArray<readonly [number, number]> = [
  [0x00000001, 0x00000000],
  [0x00008082, 0x00000000],
  [0x0000808a, 0x80000000],
  [0x80008000, 0x80000000],
  [0x0000808b, 0x00000000],
  [0x80000001, 0x00000000],
  [0x80008081, 0x80000000],
  [0x00008009, 0x80000000],
  [0x0000008a, 0x00000000],
  [0x00000088, 0x00000000],
  [0x80008009, 0x00000000],
  [0x8000000a, 0x00000000],
  [0x8000808b, 0x00000000],
  [0x0000008b, 0x80000000],
  [0x00008089, 0x80000000],
  [0x00008003, 0x80000000],
  [0x00008002, 0x80000000],
  [0x00000080, 0x80000000],
  [0x0000800a, 0x00000000],
  [0x8000000a, 0x80000000],
  [0x80008081, 0x80000000],
  [0x00008080, 0x80000000],
  [0x80000001, 0x00000000],
  [0x80008008, 0x80000000],
];

// rotation offsets of lane x + 5y
const ROTATIONS = [
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18,
  2, 61, 56, 14,
];

// lane x + 5y moves to lane y + 5(2x + 3y) in the pi step
const DESTINATIONS = Array.from({ length: 25 }, (_, index) => {
  const x = index % 5;
  const y = Math.floor(index / 5);
  return y + 5 * ((2 * x + 3 * y) % 5);
});

/** Keccak-f[1600] on a state of 25 lanes, each split into low and high words. */
function keccakF(lo: Uint32Array, hi: Uint32Array): void {
  const cLo = new Uint32Array(5);
  const cHi = new Uint32Array(5);
  const bLo = new Uint32Array(25);
  const bHi = new Uint32Array(25);

  for (let round = 0; round < 24; round++) {
    // theta
    for (let x = 0; x < 5; x++) {
      cLo[x] = lo[x] ^ lo[x + 5] ^ lo[x + 10] ^ lo[x + 15] ^ lo[x + 20];
      cHi[x] = hi[x] ^ hi[x + 5] ^ hi[x + 10] ^ hi[x + 15] ^ hi[x + 20];
    }
    for (let x = 0; x < 5; x++) {
      const next = (x + 1) % 5;
      const previous = (x + 4) % 5;
      // C[x - 1] ^ rotl(C[x + 1], 1)
      const dLo = cLo[previous] ^ ((cLo[next] << 1) | (cHi[next] >>> 31));
      const dHi = cHi[previous] ^ ((cHi[next] << 1) | (cLo[next] >>> 31));
      for (let y = 0; y < 25; y += 5) {
        lo[x + y] ^= dLo;
        hi[x + y] ^= dHi;
      }
    }

    // rho and pi
    for (let index = 0; index < 25; index++) {
      const shift = ROTATIONS[index];
      const l = lo[index];
      const h = hi[index];
      const destination = DESTINATIONS[index];
      if (shift === 0) {
        bLo[destination] = l;
        bHi[destination] = h;
      } else if (shift < 32) {
        bLo[destination] = (l << shift) | (h >>> (32 - shift));
        bHi[destination] = (h << shift) | (l >>> (32 - shift));
      } else if (shift === 32) {
        bLo[destination] = h;
        bHi[destination] = l;
      } else {
        const s = shift - 32;
        bLo[destination] = (h << s) | (l >>> (32 - s));
        bHi[destination] = (l << s) | (h >>> (32 - s));
      }
    }

    // chi
    for (let y = 0; y < 25; y += 5) {
      for (let x = 0; x < 5; x++) {
        const x1 = y + ((x + 1) % 5);
        const x2 = y + ((x + 2) % 5);
        lo[y + x] = bLo[y + x] ^ (~bLo[x1] & bLo[x2]);
        hi[y + x] = bHi[y + x] ^ (~bHi[x1] & bHi[x2]);
      }
    }

    // iota
    lo[0] ^= ROUND_CONSTANTS[round][0];
    hi[0] ^= ROUND_CONSTANTS[round][1];
  }
}

/** Returns `length` bytes of SHAKE-128 output for the given input. */
export function shake128(data: Uint8Array, length: number): Uint8Array {
  const lo = new Uint32Array(25);
  const hi = new Uint32Array(25);

  // absorb with SHAKE domain separation and pad10*1
  const blockCount = Math.floor(data.length / SHAKE128_RATE) + 1;
  const padded = new Uint8Array(blockCount * SHAKE128_RATE);
  padded.set(data);
  padded[data.length] ^= 0x1f;
  padded[padded.length - 1] ^= 0x80;

  for (let offset = 0; offset < padded.length; offset += SHAKE128_RATE) {
    for (let lane = 0; lane < SHAKE128_RATE / 8; lane++) {
      const at = offset + lane * 8;
      lo[lane] ^=
        padded[at] |
        (padded[at + 1] << 8) |
        (padded[at + 2] << 16) |
        (padded[at + 3] << 24);
      hi[lane] ^=
        padded[at + 4] |
        (padded[at + 5] << 8) |
        (padded[at + 6] << 16) |
        (padded[at + 7] << 24);
    }
    keccakF(lo, hi);
  }

  // squeeze
  const output = new Uint8Array(length);
  const block = new Uint8Array(SHAKE128_RATE);
  for (let offset = 0; offset < length; offset += SHAKE128_RATE) {
    if (offset > 0) {
      keccakF(lo, hi);
    }
    for (let lane = 0; lane < SHAKE128_RATE / 8; lane++) {
      const l = lo[lane];
      const h = hi[lane];
      const at = lane * 8;
      block[at] = l;
      block[at + 1] = l >>> 8;
      block[at + 2] = l >>> 16;
      block[at + 3] = l >>> 24;
      block[at + 4] = h;
      block[at + 5] = h >>> 8;
      block[at + 6] = h >>> 16;
      block[at + 7] = h >>> 24;
    }
    const take = Math.min(SHAKE128_RATE, length - offset);
    output.set(
      take === SHAKE128_RATE ? block : block.subarray(0, take),
      offset
    );
  }
  return output;
}

/* -------------------------------------------------------------------------- */
/* byte conversions                                                            */
/* -------------------------------------------------------------------------- */

/** Big-endian bytes of a non-negative integer, like Python's `to_bytes(length, "big")`. */
export function toBytesBigEndian(value: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) {
    throw new Error(`${value} does not fit into ${length} bytes`);
  }
  return bytes;
}

/** Integer of big-endian bytes, like Python's `int.from_bytes(data, "big")`. */
export function fromBytesBigEndian(bytes: Uint8Array): bigint {
  let hex = '';
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, '0');
  }
  return hex === '' ? 0n : BigInt(`0x${hex}`);
}

/** Integer of little-endian bytes, like Python's `int.from_bytes(data, "little")`. */
export function fromBytesLittleEndian(bytes: Uint8Array): bigint {
  let hex = '';
  for (let i = bytes.length - 1; i >= 0; i--) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex === '' ? 0n : BigInt(`0x${hex}`);
}
