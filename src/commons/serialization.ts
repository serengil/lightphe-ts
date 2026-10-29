/**
 * Serialization of ciphertexts, proofs and messages of interactive protocols,
 * to send them to another party.
 *
 * The layout matches the Python library: integers are written as json
 * integers, and objects json cannot represent natively are tagged. As json has
 * no `bigint`, a `bigint` is written as an integer literal and a `number` with
 * a decimal point, so both come back with their own types. Keys of the
 * cryptosystem are never encoded, the receiver restores ciphertexts with its
 * own keys.
 */

import { FP2 } from '../ecc/fp2.js';
import { EllipticCurvePoint } from '../ecc/point.js';
import { CatalanoFioreCiphertext } from '../models/CatalanoFiore.js';
import { Ciphertext } from '../models/Ciphertext.js';
import { EncryptedTensor, Fraction } from '../models/Tensor.js';
import type { CiphertextValue } from '../models/types.js';

/** Key marking an encoded object that json cannot represent natively. */
export const TAG = '__lightphe__';

/** Version of the encoding, increased if it changes in a backward incompatible way. */
export const VERSION = 1;

// kinds of objects that need a cryptosystem of the receiver to be restored
export const CIPHERTEXT = 'ciphertext';
export const CATALANO_FIORE = 'catalano-fiore';
export const TENSOR = 'tensor';
export const POINT = 'point';

// kinds of objects restored without a cryptosystem
export const TUPLE = 'tuple';
export const DICT = 'dict';
export const FLOAT = 'float';
export const FRACTION = 'fraction';

/**
 * Builds ciphertexts, tensors and elliptic curve points with the cryptosystem
 * of the receiver. It gets the kind of the object and its decoded fields.
 */
export type Restore = (
  kind: string,
  fields: Record<string, unknown>
) => unknown;

/**
 * Converts an item into a json serializable form, where integers stay as
 * `bigint`. Keys of the cryptosystem are never encoded, receiver restores
 * ciphertexts with its own keys.
 *
 * @param item - Ciphertext, CatalanoFioreCiphertext, EncryptedTensor,
 *   elliptic curve point, or bigint, number, string, boolean, null, arrays,
 *   plain objects and maps of them, e.g. proofs and messages of interactive
 *   protocols.
 */
export function encode(item: unknown): unknown {
  if (
    item === null ||
    item === undefined ||
    typeof item === 'boolean' ||
    typeof item === 'bigint' ||
    typeof item === 'string'
  ) {
    return item ?? null;
  }
  if (typeof item === 'number') {
    // identity element of some elliptic curve forms is (inf, inf) in Python
    if (Number.isFinite(item)) {
      return item;
    }
    return { [TAG]: FLOAT, value: floatName(item) };
  }
  if (Array.isArray(item)) {
    return item.map(encode);
  }
  if (item instanceof Map) {
    return {
      [TAG]: DICT,
      items: [...item.entries()].map(([key, value]) => [
        encode(key),
        encode(value),
      ]),
    };
  }
  if (item instanceof Ciphertext) {
    return {
      [TAG]: CIPHERTEXT,
      version: BigInt(VERSION),
      algorithm_name: item.algorithmName,
      value: encode(item.value),
    };
  }
  if (item instanceof CatalanoFioreCiphertext) {
    return {
      [TAG]: CATALANO_FIORE,
      version: BigInt(VERSION),
      algorithm_name: item.cf.cs.algorithmName,
      a: item.a ?? null,
      beta: encode(item.beta),
      alpha: encode(item.alpha),
      pairs: item.pairs.map(([beta1, beta2]) => [encode(beta1), encode(beta2)]),
    };
  }
  if (item instanceof EncryptedTensor) {
    return {
      [TAG]: TENSOR,
      version: BigInt(VERSION),
      algorithm_name: item.cs.getAlgorithmName(),
      // integers in Python
      precision: BigInt(item.precision),
      fractions: item.fractions.map(encode),
    };
  }
  if (item instanceof Fraction) {
    return {
      [TAG]: FRACTION,
      dividend: encode(item.dividend),
      abs_dividend: encode(item.absDividend),
      divisor: encode(item.divisor),
      sign: BigInt(item.sign),
    };
  }
  if (item instanceof EllipticCurvePoint) {
    if (item.infinity) {
      return { [TAG]: POINT, x: encode(Infinity), y: encode(Infinity) };
    }
    return { [TAG]: POINT, x: item.x, y: item.y };
  }
  if (item instanceof FP2) {
    // an element a + b*i of F_{p^2} is the tuple (a, b) in Python
    return { [TAG]: TUPLE, items: [item.a, item.b] };
  }
  if (isPlainObject(item)) {
    const entries = Object.entries(item).filter(([, v]) => v !== undefined);
    if (!entries.some(([key]) => key === TAG)) {
      const result: Record<string, unknown> = {};
      for (const [key, value] of entries) {
        setProperty(result, key, encode(value));
      }
      return result;
    }
    return {
      [TAG]: DICT,
      items: entries.map(([key, value]) => [key, encode(value)]),
    };
  }
  throw new Error(`Object of type ${typeName(item)} cannot be serialized`);
}

/**
 * Restores an item from its json serializable form created by
 * {@link encode}.
 *
 * @param restore - builds ciphertexts, tensors and elliptic curve points with
 *   the cryptosystem of the receiver.
 */
export function decode(item: unknown, restore: Restore): unknown {
  if (
    item === null ||
    typeof item === 'boolean' ||
    typeof item === 'bigint' ||
    typeof item === 'number' ||
    typeof item === 'string'
  ) {
    return item;
  }
  if (Array.isArray(item)) {
    return item.map((i: unknown) => decode(i, restore));
  }
  if (!isPlainObject(item)) {
    throw new Error(`Object of type ${typeName(item)} cannot be deserialized`);
  }
  if (!Object.prototype.hasOwnProperty.call(item, TAG)) {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(item)) {
      setProperty(result, key, decode(value, restore));
    }
    return result;
  }

  const kind = item[TAG];
  if (kind === TUPLE) {
    return listField(item, 'items').map((i) => decode(i, restore));
  }
  if (kind === DICT) {
    const pairs: [unknown, unknown][] = listField(item, 'items').map((pair) => {
      if (!Array.isArray(pair) || pair.length !== 2) {
        throw new Error('Items of an encoded dict must be key value pairs');
      }
      return [decode(pair[0], restore), decode(pair[1], restore)];
    });
    // a dict with string keys only becomes a plain object, as Python's dict
    if (pairs.every(([key]) => typeof key === 'string')) {
      const result: Record<string, unknown> = {};
      for (const [key, value] of pairs) {
        setProperty(result, key as string, value);
      }
      return result;
    }
    return new Map(pairs);
  }
  if (kind === FLOAT) {
    const value = item.value;
    if (value !== 'inf' && value !== '-inf' && value !== 'nan') {
      throw new Error(`Invalid encoded float ${String(value)}`);
    }
    return value === 'nan' ? NaN : value === 'inf' ? Infinity : -Infinity;
  }
  if (kind === FRACTION) {
    const sign = integerField(item, 'sign');
    if (sign !== 1 && sign !== -1) {
      throw new Error('Sign of a fraction must be 1 or -1');
    }
    return new Fraction({
      dividend: decodeCiphertextValue(item.dividend, restore),
      absDividend: decodeCiphertextValue(item.abs_dividend, restore),
      divisor: decodeCiphertextValue(item.divisor, restore),
      sign,
    });
  }
  if (kind === CIPHERTEXT || kind === CATALANO_FIORE || kind === TENSOR) {
    if (!isVersion(item.version)) {
      throw new Error(
        `Unsupported serialization version ${String(item.version)}, expected ${VERSION}`
      );
    }
    stringField(item, 'algorithm_name');
  }
  if (kind === CIPHERTEXT) {
    return restore(kind, {
      algorithm_name: item.algorithm_name,
      value: decodeCiphertextValue(item.value, restore),
    });
  }
  if (kind === CATALANO_FIORE) {
    const pairs = listField(item, 'pairs').map((pair) => {
      if (!Array.isArray(pair) || pair.length !== 2) {
        throw new Error(
          'Pairs of a Catalano-Fiore ciphertext must have 2 ciphertexts'
        );
      }
      return [decode(pair[0], restore), decode(pair[1], restore)];
    });
    return restore(kind, {
      algorithm_name: item.algorithm_name,
      a: item.a ?? null,
      beta: decode(item.beta ?? null, restore),
      alpha: decode(item.alpha ?? null, restore),
      pairs,
    });
  }
  if (kind === TENSOR) {
    const fractions = listField(item, 'fractions').map((f) =>
      decode(f, restore)
    );
    if (fractions.some((f) => !(f instanceof Fraction))) {
      throw new Error('Items of an encrypted tensor must be fractions');
    }
    return restore(kind, {
      algorithm_name: item.algorithm_name,
      precision: integerField(item, 'precision'),
      fractions,
    });
  }
  if (kind === POINT) {
    return restore(kind, {
      x: decode(item.x ?? null, restore),
      y: decode(item.y ?? null, restore),
    });
  }
  throw new Error(`Unknown serialized object ${String(kind)}`);
}

/**
 * Decodes the content of a ciphertext, which must consist of integers, arrays
 * of them, or elliptic curve points.
 *
 * @param restore - builds elliptic curve points with the cryptosystem of the
 *   receiver.
 */
export function decodeCiphertextValue(
  item: unknown,
  restore: Restore
): CiphertextValue {
  const value = decode(item ?? null, restore);

  const isValid = (content: unknown): boolean =>
    content instanceof EllipticCurvePoint ||
    typeof content === 'bigint' ||
    (Array.isArray(content) && content.every(isValid));

  if (!isValid(value)) {
    throw new Error(
      'Ciphertext must consist of integers, or tuples and lists of them'
    );
  }
  return value as CiphertextValue;
}

/** Renders an encoded item as json text, writing every `bigint` as an integer. */
export function stringify(item: unknown): string {
  if (item === null) {
    return 'null';
  }
  if (typeof item === 'bigint') {
    return item.toString();
  }
  if (typeof item === 'number') {
    const text = JSON.stringify(item);
    // a number is a float, so that it is not restored as a bigint
    return /^-?\d+$/.test(text) ? `${text}.0` : text;
  }
  if (typeof item === 'boolean' || typeof item === 'string') {
    return JSON.stringify(item);
  }
  if (Array.isArray(item)) {
    return `[${item.map(stringify).join(', ')}]`;
  }
  const entries = Object.entries(item as Record<string, unknown>).map(
    ([key, value]) => `${JSON.stringify(key)}: ${stringify(value)}`
  );
  return `{${entries.join(', ')}}`;
}

/**
 * Parses json text, restoring integer literals as `bigint` and other numbers
 * as `number`, as `JSON.parse` loses the precision of large integers.
 */
export function parse(text: string): unknown {
  let position = 0;
  const NUMBER = /-?(?:0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/y;

  const fail = (): never => {
    throw new SyntaxError(`Unexpected token at position ${position}`);
  };
  const skipWhitespace = (): void => {
    while (' \t\n\r'.includes(text[position]) && position < text.length) {
      position++;
    }
  };
  const expect = (token: string): void => {
    if (!text.startsWith(token, position)) {
      fail();
    }
    position += token.length;
  };

  const parseString = (): string => {
    const start = position;
    position++;
    while (position < text.length && text[position] !== '"') {
      position += text[position] === '\\' ? 2 : 1;
    }
    if (position >= text.length) {
      fail();
    }
    position++;
    // escapes are decoded and validated by JSON.parse
    return JSON.parse(text.slice(start, position)) as string;
  };

  const parseValue = (): unknown => {
    skipWhitespace();
    const char = text[position];
    if (char === '{') {
      position++;
      const result: Record<string, unknown> = {};
      skipWhitespace();
      if (text[position] === '}') {
        position++;
        return result;
      }
      for (;;) {
        skipWhitespace();
        if (text[position] !== '"') {
          fail();
        }
        const key = parseString();
        skipWhitespace();
        expect(':');
        setProperty(result, key, parseValue());
        skipWhitespace();
        if (text[position] === '}') {
          position++;
          return result;
        }
        expect(',');
      }
    }
    if (char === '[') {
      position++;
      const result: unknown[] = [];
      skipWhitespace();
      if (text[position] === ']') {
        position++;
        return result;
      }
      for (;;) {
        result.push(parseValue());
        skipWhitespace();
        if (text[position] === ']') {
          position++;
          return result;
        }
        expect(',');
      }
    }
    if (char === '"') {
      return parseString();
    }
    for (const [token, value] of [
      ['true', true],
      ['false', false],
      ['null', null],
    ] as const) {
      if (text.startsWith(token, position)) {
        position += token.length;
        return value;
      }
    }
    NUMBER.lastIndex = position;
    const match = NUMBER.exec(text);
    if (match === null) {
      return fail();
    }
    position += match[0].length;
    const isFloat = match[1] !== undefined || match[2] !== undefined;
    return isFloat ? Number(match[0]) : BigInt(match[0]);
  };

  const result = parseValue();
  skipWhitespace();
  if (position !== text.length) {
    fail();
  }
  return result;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

/** Sets an own property, so that a `__proto__` key cannot change the prototype. */
function setProperty(
  target: Record<string, unknown>,
  key: string,
  value: unknown
): void {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
}

function floatName(value: number): string {
  if (Number.isNaN(value)) {
    return 'nan';
  }
  return value > 0 ? 'inf' : '-inf';
}

function isVersion(value: unknown): boolean {
  return value === BigInt(VERSION) || value === VERSION;
}

/** Gets a list field of an encoded object. */
function listField(item: Record<string, unknown>, name: string): unknown[] {
  const value = item[name];
  if (!Array.isArray(value)) {
    throw new Error(
      `Field ${name} of serialized ${String(item[TAG])} must be list`
    );
  }
  return value;
}

/** Gets a string field of an encoded object. */
function stringField(item: Record<string, unknown>, name: string): string {
  const value = item[name];
  if (typeof value !== 'string') {
    throw new Error(
      `Field ${name} of serialized ${String(item[TAG])} must be str`
    );
  }
  return value;
}

/** Gets an integer field of an encoded object as a number. */
function integerField(item: Record<string, unknown>, name: string): number {
  const value = item[name];
  if (typeof value === 'bigint' && BigInt(Number(value)) === value) {
    return Number(value);
  }
  if (typeof value === 'number' && Number.isSafeInteger(value)) {
    return value;
  }
  throw new Error(
    `Field ${name} of serialized ${String(item[TAG])} must be int`
  );
}

function typeName(value: unknown): string {
  if (typeof value === 'object' && value !== null) {
    return (value as object).constructor?.name ?? 'object';
  }
  return typeof value;
}
