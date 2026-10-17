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
