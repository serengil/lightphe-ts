/**
 * Threshold decryption splits a private key into shares with Shamir's secret
 * sharing. Any `threshold` of `parties` shareholders decrypt a ciphertext
 * together, whereas fewer shareholders learn nothing about the plaintext.
 *
 * Ref: Shamir, "How to share a secret", 1979
 *
 * Ref: Shoup, "Practical threshold signatures", 2000
 *
 * Ref: Damgard & Jurik, "A generalisation, a simplification and some
 * applications of Paillier's probabilistic public-key system", 2001
 */

import type { KeyPart, Keys, PartialDecryption } from '../models/types.js';
import { Logger } from './logger.js';
import {
  bitLength,
  gcd,
  isPrime,
  isqrt,
  mod,
  modInverse,
  modPow,
  randomBelow,
  randomRange,
  ONE,
  TWO,
  ZERO,
} from './mathUtils.js';
import { findSafePrime } from './safePrimes.js';
import * as zkp from './zkp.js';

const logger = new Logger('lightphe-ts/commons/threshold.ts');

export const SAFE_PRIMES_REQUIRED_MSG =
  'Partial decryptions of Paillier and Damgard-Jurik can be proven only if keys are' +
  ' generated with safe_primes=True';

/** Checks that a threshold scheme is well defined. */
export function validateThreshold(threshold: number, parties: number): void {
  if (!Number.isInteger(threshold) || !Number.isInteger(parties)) {
    throw new Error('threshold and parties must be integers');
  }
  if (threshold < 1) {
    throw new Error(`threshold must be at least 1, got ${threshold}`);
  }
  if (parties < threshold) {
    throw new Error(
      `parties (${parties}) must be greater than or equal to threshold (${threshold})`
    );
  }
}

/**
 * Splits a secret into shares with a random polynomial f of degree
 * `threshold - 1` where `f(0) = secret`. Share of the party with index i is
 * `f(i) mod modulo`.
 *
 * @returns party index (1, ..., parties) to its share.
 */
export function splitSecret(
  secret: bigint,
  threshold: number,
  parties: number,
  modulo: bigint
): Map<number, bigint> {
  validateThreshold(threshold, parties);
  const coefficients = [mod(secret, modulo)];
  for (let i = 0; i < threshold - 1; i++) {
    coefficients.push(randomBelow(modulo));
  }

  const shares = new Map<number, bigint>();
  for (let index = 1; index <= parties; index++) {
    // horner's method
    let share = ZERO;
    for (let i = coefficients.length - 1; i >= 0; i--) {
      share = (share * BigInt(index) + coefficients[i]) % modulo;
    }
    shares.set(index, share);
  }
  return shares;
}

/**
 * Lagrange coefficient of a party at 0 in a modulo where differences of
 * indices are invertible, e.g. a prime order of a group.
 *
 * @returns `Π j / (j - index) mod modulo` over other indices j.
 */
export function lagrangeCoefficient(
  index: number,
  indices: readonly number[],
  modulo: bigint
): bigint {
  let numerator = ONE;
  let denominator = ONE;
  for (const j of indices) {
    if (j === index) {
      continue;
    }
    numerator = mod(numerator * BigInt(j), modulo);
    denominator = mod(denominator * BigInt(j - index), modulo);
  }
  return mod(numerator * modInverse(denominator, modulo), modulo);
}

/**
 * Lagrange coefficient of a party at 0 multiplied by `delta = parties!`. This
 * is always an integer, so it works in groups of unknown order.
 */
export function scaledLagrangeCoefficient(
  index: number,
  indices: readonly number[],
  delta: bigint
): bigint {
  let numerator = delta;
  let denominator = ONE;
  for (const j of indices) {
    if (j === index) {
      continue;
    }
    numerator *= BigInt(j);
    denominator *= BigInt(j - index);
  }
  if (numerator % denominator !== ZERO) {
    throw new Error('scaled lagrange coefficient must be an integer');
  }
  return numerator / denominator;
}

/** Factorial of a non-negative integer. */
export function factorial(n: number): bigint {
  let result = ONE;
  for (let i = 2; i <= n; i++) {
    result *= BigInt(i);
  }
  return result;
}

/** Deep copy of a key structure, keeping bigints and arrays. */
function deepCopy<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((item: unknown) => deepCopy(item)) as unknown as T;
  }
  if (typeof value === 'object' && value !== null) {
    const result: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      result[key] = deepCopy(entry);
    }
    return result as T;
  }
  return value;
}

/**
 * Adds threshold parameters into public key, and creates key of each
 * shareholder consisting of public key and its own share. Keys of
 * shareholders do not have private key.
 *
 * @param keys - private - public key pair of the dealer. It is updated in place.
 * @param verificationKeys - public commitments to shares, e.g. `g^share`, to
 *   verify partial decryptions. Item k belongs to the party with index k + 1.
 */
export function buildShareKeys(
  keys: Keys,
  shares: Map<number, bigint>,
  threshold: number,
  parties: number,
  verificationKeys?: unknown[]
): Keys[] {
  const publicKey = keys.public_key as KeyPart;
  publicKey.threshold = BigInt(threshold);
  publicKey.parties = BigInt(parties);
  if (verificationKeys !== undefined) {
    publicKey.verification_keys = verificationKeys;
  }

  const publicKeys: Keys = {};
  for (const [key, value] of Object.entries(keys)) {
    if (key !== 'private_key') {
      publicKeys[key] = value;
    }
  }

  const shareKeys: Keys[] = [];
  for (const [index, share] of shares) {
    const shareKey = deepCopy(publicKeys);
    shareKey.threshold_key = { index: BigInt(index), share };
    shareKeys.push(shareKey);
  }
  return shareKeys;
}

/** The index and share of a shareholder. */
export function getThresholdKey(keys: Keys): { index: number; share: bigint } {
  const thresholdKey = keys.threshold_key as
    { index: bigint | number; share: bigint } | undefined;
  if (thresholdKey == null) {
    throw new Error(
      'You must have threshold key to perform partial decryption'
    );
  }
  return { index: Number(thresholdKey.index), share: thresholdKey.share };
}

/** Threshold parameters of a public key, or undefined if it has none. */
function getThresholdParameters(
  keys: Keys
): { threshold: number; parties: number } | undefined {
  const publicKey = keys.public_key as KeyPart;
  if (publicKey.threshold == null || publicKey.parties == null) {
    return undefined;
  }
  return {
    threshold: Number(publicKey.threshold as bigint),
    parties: Number(publicKey.parties as bigint),
  };
}

/**
 * Reads the index of a partial decryption. Partial decryptions restored from
 * json may carry it as a bigint.
 */
export function indexOf(partialDecryption: unknown): number | undefined {
  if (typeof partialDecryption !== 'object' || partialDecryption === null) {
    return undefined;
  }
  const index = zkp.asInteger((partialDecryption as { index?: unknown }).index);
  return index === undefined ? undefined : Number(index);
}

/**
 * Validates partial decryptions and picks threshold many of them.
 *
 * @param verify - checks the proof of a partial decryption. Partial
 *   decryptions with invalid proofs are discarded if this is set.
 */
export function selectPartialDecryptions(
  keys: Keys,
  partialDecryptions: readonly unknown[],
  verify?: (partialDecryption: unknown) => boolean
): PartialDecryption[] {
  const parameters = getThresholdParameters(keys);
  if (parameters === undefined) {
    throw new Error(
      'Public key does not have threshold parameters. ' +
        'Generate threshold keys first.'
    );
  }
  const { threshold, parties } = parameters;

  const selected = new Map<number, PartialDecryption>();
  for (const partialDecryption of partialDecryptions) {
    if (verify !== undefined && !verify(partialDecryption)) {
      logger.warn(
        `Partial decryption of party ${String(indexOf(partialDecryption))} has` +
          ' an invalid proof. It is discarded.'
      );
      continue;
    }
    const index = indexOf(partialDecryption);
    if (index === undefined || index < 1 || index > parties) {
      throw new Error(
        `Index of partial decryption must be in [1, ${parties}], got ${String(index)}`
      );
    }
    const candidate = partialDecryption as PartialDecryption;
    const existing = selected.get(index);
    if (existing !== undefined) {
      if (!zkp.sameCanonical(existing.value, candidate.value)) {
        throw new Error(`Conflicting partial decryptions for index ${index}`);
      }
      continue;
    }
    selected.set(index, { ...candidate, index });
  }

  if (selected.size < threshold) {
    throw new Error(
      `At least ${threshold} valid partial decryptions from distinct parties are` +
        ` required, got ${selected.size}`
    );
  }

  return [...selected.values()].slice(0, threshold);
}

/**
 * Shares the decryption exponent of Paillier and Damgard-Jurik. The exponent d
 * satisfies `d = 0 mod phi` and `d = 1 mod n^s`, so `c^d = (1 + n)^m`.
 *
 * @param s - ciphertext modulo is `n^(s+1)`.
 */
export function sharePaillierKey(
  n: bigint,
  phi: bigint,
  s: bigint,
  threshold: number,
  parties: number
): Map<number, bigint> {
  if (gcd(factorial(parties), n) !== ONE) {
    throw new Error(
      `Number of parties ${parties} is too large for the modulus`
    );
  }
  const nS = n ** s;
  const d = phi * modInverse(phi, nS);
  // order of the multiplicative group of n^(s+1)
  return splitSecret(d, threshold, parties, nS * phi);
}

/**
 * Generates Paillier or Damgard-Jurik keys with `n = p * q` for safe primes
 * `p = 2p' + 1` and `q = 2q' + 1`. Then, the group of squares modulo `n^(s+1)`
 * is cyclic, which partial decryptions are proven in. Key format is the same
 * as regular keys.
 *
 * @param keySize - bit length of n.
 * @param s - Damgard-Jurik only, ciphertext modulo is `n^(s+1)`.
 */
export function generateSafePaillierKeys(
  keySize: number,
  maxTries: number,
  s?: number
): Keys {
  const bits = Math.floor(keySize / 2);
  const p = findSafePrime(bits, maxTries);
  let q = findSafePrime(bits, maxTries);
  while (q === p) {
    q = findSafePrime(bits, maxTries);
  }
  const n = p * q;
  const publicKey: KeyPart = { g: ONE + n, n };
  if (s !== undefined) {
    publicKey.s = BigInt(s);
  }
  return {
    private_key: { phi: (p - ONE) * (q - ONE) },
    public_key: publicKey,
  };
}

/** Checks whether n is a product of two safe primes, restoring them from n and phi. */
export function isSafePaillierKey(n: bigint, phi: bigint): boolean {
  // p + q = n - phi + 1, and p, q are roots of x^2 - (p + q) x + n
  const total = n - phi + ONE;
  const discriminant = total * total - 4n * n;
  if (discriminant < ZERO) {
    return false;
  }
  const root = isqrt(discriminant);
  if (root * root !== discriminant) {
    return false;
  }
  const p = (total + root) / TWO;
  const q = (total - root) / TWO;
  return (
    p * q === n &&
    p % TWO === ONE &&
    q % TWO === ONE &&
    isPrime((p - ONE) / TWO) &&
    isPrime((q - ONE) / TWO)
  );
}

/**
 * Splits the private key of Paillier or Damgard-Jurik into shares. If n is a
 * product of safe primes, verification keys `v^(delta * share)` are published
 * to prove partial decryptions.
 *
 * @param keys - private - public key pair of the dealer. It is updated in place.
 * @param s - ciphertext modulo is `n^(s+1)`.
 * @param modulo - ciphertext modulo `n^(s+1)`.
 */
export function generatePaillierThresholdKeys(
  keys: Keys,
  s: bigint,
  modulo: bigint,
  threshold: number,
  parties: number
): Keys[] {
  const publicKey = keys.public_key as KeyPart;
  const n = publicKey.n as bigint;
  const phi = (keys.private_key as KeyPart).phi as bigint;
  const shares = sharePaillierKey(n, phi, s, threshold, parties);

  let verificationKeys: bigint[] | undefined;
  if (isSafePaillierKey(n, phi)) {
    // a random square generates the cyclic group of squares with high probability
    let r = randomRange(TWO, modulo - ONE);
    while (gcd(r, n) !== ONE) {
      r = randomRange(TWO, modulo - ONE);
    }
    const v = modPow(r, TWO, modulo);
    const delta = factorial(parties);
    publicKey.verification_base = v;
    verificationKeys = [];
    for (let index = 1; index <= parties; index++) {
      verificationKeys.push(modPow(v, delta * shares.get(index)!, modulo));
    }
  }

  return buildShareKeys(keys, shares, threshold, parties, verificationKeys);
}

/** Statement of a partial decryption of Paillier or Damgard-Jurik. */
function partialDecryptionStatement(
  keys: Keys,
  ciphertext: bigint,
  value: bigint,
  index: number,
  modulo: bigint,
  domain: string
) {
  const publicKey = keys.public_key as KeyPart;
  const delta = factorial(Number(publicKey.parties as bigint));
  return {
    n: publicKey.n as bigint,
    modulo,
    g1: modPow(ciphertext, 4n, modulo),
    h1: modPow(value, TWO, modulo),
    g2: publicKey.verification_base as bigint,
    h2: (publicKey.verification_keys as bigint[])[index - 1],
    xBits: bitLength(delta * modulo),
    domain,
    context: [index, ciphertext],
    delta,
  };
}

/**
 * Decrypts a Paillier or Damgard-Jurik ciphertext partially. Keys with
 * verification keys compute `c^(2 * delta * share)` as Shoup does, and can
 * prove it.
 *
 * @param modulo - ciphertext modulo `n^(s+1)`.
 * @param prove - attach a proof of correct partial decryption.
 * @param domain - name of the statement being proven.
 */
export function paillierPartialDecrypt(
  keys: Keys,
  ciphertext: bigint,
  modulo: bigint,
  prove: boolean,
  domain: string
): PartialDecryption {
  const { index, share } = getThresholdKey(keys);
  const publicKey = keys.public_key as KeyPart;

  if (publicKey.verification_base == null) {
    if (prove) {
      throw new Error(SAFE_PRIMES_REQUIRED_MSG);
    }
    return { index, value: modPow(ciphertext, share, modulo) };
  }

  const delta = factorial(Number(publicKey.parties as bigint));
  const value = modPow(ciphertext, TWO * delta * share, modulo);
  if (!prove) {
    return { index, value };
  }

  const statement = partialDecryptionStatement(
    keys,
    ciphertext,
    value,
    index,
    modulo,
    domain
  );
  const proof = zkp.proveDleqUnknownOrder({
    ...statement,
    x: statement.delta * share,
  });
  return { index, value, proof };
}

/**
 * Verifies that a partial decryption of Paillier or Damgard-Jurik is computed
 * with the share of its shareholder.
 */
export function verifyPaillierPartialDecryption(
  keys: Keys,
  ciphertext: bigint,
  partialDecryption: unknown,
  modulo: bigint,
  domain: string
): boolean {
  const publicKey = keys.public_key as KeyPart;
  if (publicKey.verification_base == null) {
    throw new Error(SAFE_PRIMES_REQUIRED_MSG);
  }
  const verificationKeys = publicKey.verification_keys as bigint[];
  try {
    const index = indexOf(partialDecryption);
    if (index === undefined || index < 1 || index > verificationKeys.length) {
      return false;
    }
    const { value, proof } = partialDecryption as {
      value?: unknown;
      proof?: unknown;
    };
    const integer = zkp.asInteger(value);
    if (integer === undefined || integer <= ZERO || integer >= modulo) {
      return false;
    }
    return zkp.verifyDleqUnknownOrder({
      ...partialDecryptionStatement(
        keys,
        ciphertext,
        integer,
        index,
        modulo,
        domain
      ),
      proof,
    });
  } catch {
    return false;
  }
}

/**
 * Combines partial decryptions of Paillier and Damgard-Jurik. Order of the
 * group is secret, so lagrange coefficients are scaled with
 * `delta = parties!` to be integers.
 *
 * @param verify - check proofs and discard invalid or unproven partial
 *   decryptions.
 * @returns restored message in modulo n.
 */
export function combinePaillierPartialDecryptions(
  keys: Keys,
  ciphertext: bigint,
  partialDecryptions: readonly unknown[],
  modulo: bigint,
  verify: boolean,
  domain: string
): bigint {
  const publicKey = keys.public_key as KeyPart;
  const verifiable = publicKey.verification_base != null;
  if (verify && !verifiable) {
    throw new Error(SAFE_PRIMES_REQUIRED_MSG);
  }

  const selected = selectPartialDecryptions(
    keys,
    partialDecryptions,
    verify
      ? (partialDecryption) =>
          verifyPaillierPartialDecryption(
            keys,
            ciphertext,
            partialDecryption,
            modulo,
            domain
          )
      : undefined
  );

  const n = publicKey.n as bigint;
  const delta = factorial(Number(publicKey.parties as bigint));
  const indices = selected.map((partialDecryption) => partialDecryption.index);

  // c^(delta * d) = (1 + n)^(delta * m) for regular partial decryptions, and
  // c^(4 * delta^2 * d) = (1 + n)^(4 * delta^2 * m) for c^(2 * delta * share)
  const exponent = verifiable ? TWO : ONE;
  const factor = verifiable ? 4n * delta * delta : delta;

  let combined = ONE;
  for (const partialDecryption of selected) {
    const value = zkp.asInteger(partialDecryption.value);
    if (value === undefined) {
      throw new Error('Value of a partial decryption must be an integer');
    }
    const coefficient = scaledLagrangeCoefficient(
      partialDecryption.index,
      indices,
      delta
    );
    combined =
      (combined * modPow(value, exponent * coefficient, modulo)) % modulo;
  }

  const factorM = mod((combined - ONE) / n, n);
  return mod(factorM * modInverse(factor, n), n);
}
