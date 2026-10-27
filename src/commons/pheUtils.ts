/**
 * Mapping real numbers onto the integer message space of a cryptosystem.
 *
 * Partially homomorphic schemes only know integers modulo some `n`, so a real
 * number is carried as a scaled integer over a power of ten. This module is the
 * TypeScript counterpart of `lightphe/commons/phe_utils.py`.
 */

import { Logger } from './logger.js';
import { mod, modInverse, ZERO, ONE } from './mathUtils.js';

const logger = new Logger('lightphe-ts/commons/pheUtils.ts');

/**
 * Returns `trunc(value * 10^scale)` exactly.
 *
 * A JavaScript number is `mantissa * 2^exponent` for an integral mantissa, so
 * scaling it by a power of ten can be done entirely in `bigint` arithmetic
 * without ever losing a digit. Python reaches the same result by wrapping the
 * float in a `Decimal`, which likewise expands the exact binary value.
 */
export function scaleToInteger(value: number, scale: number): bigint {
  if (!Number.isFinite(value)) {
    throw new Error(`cannot scale a non-finite value (${value})`);
  }
  if (Number.isInteger(value) && Number.isSafeInteger(value)) {
    return BigInt(value) * 10n ** BigInt(scale);
  }

  const buffer = new DataView(new ArrayBuffer(8));
  buffer.setFloat64(0, value);
  const bits = buffer.getBigUint64(0);

  const negative = bits >> 63n === ONE;
  const rawExponent = Number((bits >> 52n) & 0x7ffn);
  const rawMantissa = bits & 0xfffffffffffffn;

  // Subnormals carry no implicit leading one and sit one exponent step higher.
  const mantissa = rawExponent === 0 ? rawMantissa : rawMantissa | (ONE << 52n);
  const exponent = (rawExponent === 0 ? 1 : rawExponent) - 1075;

  const scaled = mantissa * 10n ** BigInt(scale);
  // Truncate toward zero, the way Python's int() does.
  const magnitude =
    exponent >= 0 ? scaled << BigInt(exponent) : scaled >> BigInt(-exponent);
  return negative ? -magnitude : magnitude;
}

/** How many digits `value` carries after the decimal point, as Python's `str` shows it. */
function decimalPlaces(value: number): number {
  const text = String(value);
  const dot = text.indexOf('.');
  if (dot === -1) {
    // Python renders a whole float as "6.0", so it always sees one place.
    return 1;
  }
  const fraction = text.slice(dot + 1);
  const exponent = fraction.search(/[eE]/);
  return exponent === -1 ? fraction.length : exponent;
}

/**
 * Splits a real number into `[dividend, divisor]` such that
 * `dividend / divisor` reproduces `value` to the requested precision, with the
 * dividend reduced modulo `modulo`.
 *
 * When `precision` is omitted the scale is taken from how many decimal places
 * the value actually has.
 */
export function fractionize(
  value: number,
  modulo: bigint,
  precision?: number
): [bigint, bigint] {
  // The scale is tracked as the exponent of ten so it stays exact for the
  // large precisions embeddings ask for.
  let scaleExponent =
    precision === undefined ? decimalPlaces(value) : precision;
  let current = value;

  let integerValue = ZERO;
  for (;;) {
    integerValue = mod(scaleToInteger(current, scaleExponent), modulo);

    if (precision === undefined || scaleExponent >= precision - 1) {
      break;
    }
    // Scale is too coarse: shift both dividend and divisor one decade up.
    current *= 10;
    scaleExponent += 1;
  }

  const scalingFactor = 10n ** BigInt(scaleExponent);
  logger.debug(`${integerValue}*${scalingFactor}^-1 mod ${modulo}`);
  return [integerValue, scalingFactor];
}

/**
 * Maps a plain value onto `[0, modulo)`.
 *
 * Integers are reduced directly; non-negative reals become the modular fraction
 * `dividend * divisor^-1`. Negative reals have no representative that survives
 * the round trip, so they are rejected — the same limitation the Python library
 * documents.
 */
export function normalizeInput(
  value: number | bigint,
  modulo: bigint | string
): bigint {
  const modulus = typeof modulo === 'string' ? BigInt(`0b${modulo}`) : modulo;

  if (typeof value === 'bigint') {
    if (value > modulus) {
      logger.warn(
        `Value ${value} is greater than modulo ${modulus}. Normalizing it to be in the range of modulo.`
      );
    }
    return mod(value, modulus);
  }

  if (Number.isInteger(value)) {
    const asBigInt = BigInt(value);
    if (asBigInt > modulus) {
      logger.warn(
        `Value ${asBigInt} is greater than modulo ${modulus}. Normalizing it to be in the range of modulo.`
      );
    }
    return mod(asBigInt, modulus);
  }

  if (value >= 0) {
    const [dividend, divisor] = fractionize(value, modulus);
    logger.debug(`${dividend}*${divisor}^-1 mod ${modulus}`);
    return mod(dividend * modInverse(divisor, modulus), modulus);
  }

  throw new Error('Case constant float and negative not implemented yet');
}

/**
 * Rounds a number to the nearest integer, and ties to the even one, as
 * Python's `round` does. `Math.round` rounds ties up instead.
 */
export function roundHalfEven(value: number): bigint {
  if (!Number.isFinite(value)) {
    throw new Error(`cannot round a non-finite value (${value})`);
  }
  const floor = Math.floor(value);
  const fraction = value - floor;
  let rounded = floor;
  if (fraction > 0.5 || (fraction === 0.5 && floor % 2 !== 0)) {
    rounded = floor + 1;
  }
  return BigInt(rounded);
}
