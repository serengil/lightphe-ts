/**
 * Secure aggregation of model updates for federated learning. Each client
 * quantizes its update to integers and packs many of them into a single
 * plaintext, so it encrypts one ciphertext per chunk of values instead of one
 * ciphertext per value. Server sums the encrypted updates of clients chunk by
 * chunk, and only the sum is decrypted, e.g. by a committee holding shares of
 * the private key with threshold decryption.
 *   - quantization: x is scaled by 10^precision and rounded, so it is an
 *     integer in [-B, B] where B is maxValue scaled the same way
 *   - packing: values are shifted by B to be non-negative, and placed into
 *     slots of slot_bits bits, i.e. plaintext = sum of (x_i + B) * 2^(slot_bits * i)
 *   - headroom: a slot of the sum of c updates is at most c * 2B, so slot_bits
 *     is the bit length of max_clients * 2B, and slots never overflow into
 *     each other
 *   - unpacking: slot of the sum minus c * B is the sum of values of c clients
 *
 * Ref: Bonawitz, K. et al. (2017). Practical Secure Aggregation for
 * Privacy-Preserving Machine Learning. ACM CCS 2017.
 *
 * Ref: Zhang, C. et al. (2020). BatchCrypt: Efficient Homomorphic Encryption
 * for Cross-Silo Federated Learning. USENIX ATC 2020.
 */

import { bitLength, ONE, ZERO } from './mathUtils.js';
import { roundHalfEven } from './pheUtils.js';

/** Packing layout of updates. Field names match the Python library. */
export interface PackingLayout {
  /** Number of values in an update. */
  length: number;
  /** Number of decimal digits kept after quantization. */
  precision: number;
  /** Quantized maximum absolute value B. */
  bound: bigint;
  /** Maximum number of updates to be summed. */
  max_clients: number;
  /** Bits of a slot. */
  slot_bits: number;
  /** Slots per chunk. */
  slots: number;
}

/**
 * Builds the packing layout of updates.
 *
 * @param length - number of values in an update.
 * @param precision - number of decimal digits kept after quantization.
 * @param maxValue - absolute values of updates must be at most this.
 * @param maxClients - maximum number of updates to be summed.
 * @param modulo - plaintext modulo of the cryptosystem.
 */
export function buildLayout(
  length: number,
  precision: number,
  maxValue: number,
  maxClients: number,
  modulo: bigint
): PackingLayout {
  if (!Number.isInteger(length) || length < 1) {
    throw new Error('Update must have at least one value');
  }
  if (!Number.isInteger(maxClients) || maxClients < 1) {
    throw new Error('Maximum number of clients must be a positive integer');
  }
  if (typeof maxValue !== 'number' || !(maxValue > 0)) {
    throw new Error('Maximum value must be a positive number');
  }
  if (!Number.isInteger(precision) || precision < 0) {
    throw new Error('Precision must be a non-negative integer');
  }

  const bound = roundHalfEven(maxValue * 10 ** precision);
  if (bound < ONE) {
    throw new Error(`Maximum value ${maxValue} is zero after quantization`);
  }

  const slotBits = bitLength(BigInt(maxClients) * 2n * bound);
  // packed plaintexts must be less than the plaintext modulo
  const slots = Math.floor((bitLength(modulo) - 1) / slotBits);
  if (slots < 1) {
    throw new Error(
      `Plaintext space is too small for ${slotBits}-bit slots. Use a larger key size,` +
        ' a smaller precision, a smaller maximum value or fewer clients.'
    );
  }
  return {
    length,
    precision,
    bound,
    max_clients: maxClients,
    slot_bits: slotBits,
    slots,
  };
}

/**
 * Quantizes an update and packs its values into plaintexts.
 *
 * @returns one plaintext for each chunk of values.
 */
export function pack(
  update: readonly unknown[],
  layout: PackingLayout
): bigint[] {
  const { bound, slots } = layout;
  const scale = 10 ** layout.precision;
  const slotBits = BigInt(layout.slot_bits);

  const shifted: bigint[] = [];
  for (const x of update) {
    if (typeof x !== 'number' || !Number.isFinite(x)) {
      throw new Error('Update must be a list of numbers');
    }
    const quantized = roundHalfEven(x * scale);
    if ((quantized < ZERO ? -quantized : quantized) > bound) {
      throw new Error(`Value ${x} of the update exceeds the maximum value`);
    }
    shifted.push(quantized + bound);
  }

  const plaintexts: bigint[] = [];
  for (let start = 0; start < shifted.length; start += slots) {
    let plaintext = ZERO;
    shifted.slice(start, start + slots).forEach((value, i) => {
      plaintext |= value << (slotBits * BigInt(i));
    });
    plaintexts.push(plaintext);
  }
  return plaintexts;
}

/**
 * Unpacks the sum of count updates from decrypted plaintexts.
 *
 * @param plaintexts - decrypted chunks of the sum.
 * @param count - number of summed updates.
 */
export function unpack(
  plaintexts: readonly bigint[],
  layout: PackingLayout,
  count: number
): number[] {
  const { bound, slots } = layout;
  const scale = 10 ** layout.precision;
  const slotBits = BigInt(layout.slot_bits);
  const mask = (ONE << slotBits) - ONE;

  const values: number[] = [];
  for (const plaintext of plaintexts) {
    for (let i = 0; i < slots; i++) {
      if (values.length === layout.length) {
        break;
      }
      const slot = (plaintext >> (slotBits * BigInt(i))) & mask;
      values.push(Number(slot - BigInt(count) * bound) / scale);
    }
  }
  return values;
}

/** Number of chunks of an update. */
export function chunksOf(layout: PackingLayout): number {
  return Math.ceil(layout.length / layout.slots);
}

/** Reports whether two layouts are the same. */
export function sameLayout(a: PackingLayout, b: PackingLayout): boolean {
  return (
    a.length === b.length &&
    a.precision === b.precision &&
    a.bound === b.bound &&
    a.max_clients === b.max_clients &&
    a.slot_bits === b.slot_bits &&
    a.slots === b.slots
  );
}
