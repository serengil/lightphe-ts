/**
 * Zero-knowledge proofs on ciphertexts and decryptions.
 *
 * Proofs are made non-interactive with Fiat-Shamir heuristic. Challenge is the
 * hash of everything the verifier sees, so the prover cannot pick it.
 * Transcripts are hashed exactly as the Python library hashes them, so proofs
 * are interoperable between the two.
 *
 * Ref: Fiat & Shamir, "How to prove yourself", 1986
 *
 * Ref: Chaum & Pedersen, "Wallet databases with observers", 1992
 */

import { EllipticCurvePoint } from '../ecc/point.js';
import type { LightECC } from '../ecc/index.js';
import type { Homomorphic } from '../models/Homomorphic.js';
import type {
  CiphertextValue,
  MembershipProof,
  OneHotProof,
  RandomKey,
  RangeProof,
} from '../models/types.js';
import { fromBytesBigEndian, sha512 } from './hashing.js';
import {
  bitLength,
  gcd,
  mod,
  modPow,
  randomBelow,
  randomBits,
  randomRange,
  ONE,
  ZERO,
} from './mathUtils.js';

/** Challenge length of proofs in groups of unknown order in bits. */
export const CHALLENGE_BITS = 128;

/** Statistical hiding of responses in groups of unknown order, in bits. */
export const STATISTICAL_BITS = 80;

/** An element of a group of prime order: an integer or a curve point. */
export type Element = bigint | EllipticCurvePoint;

/* -------------------------------------------------------------------------- */
/* transcripts                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Converts an item into the form it is hashed in, which does not change after
 * a json round trip, e.g. curve points are mapped to their coordinates. The
 * point at infinity is mapped to `["inf", "inf"]` as the Python library does.
 */
export function canonicalize(item: unknown): unknown {
  if (item instanceof EllipticCurvePoint) {
    return item.infinity ? ['inf', 'inf'] : [item.x, item.y];
  }
  if (Array.isArray(item)) {
    return item.map(canonicalize);
  }
  if (typeof item === 'number' && !Number.isInteger(item)) {
    // python hashes floats as their string representation
    return String(item);
  }
  if (isPlainObject(item)) {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(item)) {
      result[key] = canonicalize(value);
    }
    return result;
  }
  return item ?? null;
}

/**
 * Renders a canonical item as compact json, the way Python's `json.dumps`
 * with `separators=(",", ":")` does: integers of any size as digits, and
 * non-ASCII characters escaped.
 */
export function toJson(item: unknown): string {
  if (item === null || item === undefined) {
    return 'null';
  }
  if (typeof item === 'bigint') {
    return item.toString();
  }
  if (typeof item === 'number') {
    return Number.isInteger(item) ? BigInt(item).toString() : String(item);
  }
  if (typeof item === 'boolean') {
    return item ? 'true' : 'false';
  }
  if (typeof item === 'string') {
    return JSON.stringify(item).replace(/[\u007f-￿]/g, (character) =>
      character === '\u007f'
        ? character
        : `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`
    );
  }
  if (Array.isArray(item)) {
    return `[${item.map(toJson).join(',')}]`;
  }
  if (typeof item === 'object') {
    const entries = Object.entries(item as Record<string, unknown>).map(
      ([key, value]) => `${toJson(key)}:${toJson(value)}`
    );
    return `{${entries.join(',')}}`;
  }
  throw new Error(`${typeof item} cannot be hashed into a transcript`);
}

/**
 * Fiat-Shamir challenge as the hash of a domain and all public items of a
 * proof.
 *
 * @param domain - separates challenges of different proofs.
 * @param modulo - challenge is reduced in this modulo, e.g. order of the group.
 * @param items - public items of the proof.
 */
export function challenge(
  domain: string,
  modulo: bigint,
  ...items: unknown[]
): bigint {
  const transcript = toJson([domain, canonicalize(items)]);
  const digest = sha512(new TextEncoder().encode(transcript));
  return fromBytesBigEndian(digest) % modulo;
}

/** Reports whether two ciphertexts or proofs have the same canonical form. */
export function sameCanonical(a: unknown, b: unknown): boolean {
  try {
    return toJson(canonicalize(a)) === toJson(canonicalize(b));
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* groups                                                                      */
/* -------------------------------------------------------------------------- */

/** A cyclic group of a known prime order q used in proofs. */
export interface PrimeOrderGroup<E extends Element = Element> {
  readonly q: bigint;
  exp(base: E, k: bigint): E;
  mul(a: E, b: E): E;
  isMember(a: unknown): a is E;
  encode(a: E): unknown;
}

/**
 * Subgroup of prime order q in the multiplicative group of integers modulo
 * prime p.
 */
export class ModularGroup implements PrimeOrderGroup<bigint> {
  constructor(
    readonly p: bigint,
    readonly q: bigint
  ) {}

  exp(base: bigint, k: bigint): bigint {
    return modPow(base, mod(k, this.q), this.p);
  }

  mul(a: bigint, b: bigint): bigint {
    return (a * b) % this.p;
  }

  isMember(a: unknown): a is bigint {
    return (
      typeof a === 'bigint' &&
      a > ZERO &&
      a < this.p &&
      modPow(a, this.q, this.p) === ONE
    );
  }

  encode(a: bigint): bigint {
    return a;
  }
}

/**
 * Subgroup generated by the base point of an elliptic curve. Group operation
 * is written multiplicatively here, i.e. exp is scalar multiplication and mul
 * is addition.
 */
export class EllipticCurveGroup implements PrimeOrderGroup<EllipticCurvePoint> {
  readonly q: bigint;

  constructor(readonly ecc: LightECC) {
    this.q = ecc.n;
  }

  exp(base: EllipticCurvePoint, k: bigint): EllipticCurvePoint {
    return base.multiply(mod(k, this.q));
  }

  mul(a: EllipticCurvePoint, b: EllipticCurvePoint): EllipticCurvePoint {
    return a.add(b);
  }

  isMember(a: unknown): a is EllipticCurvePoint {
    if (!(a instanceof EllipticCurvePoint)) {
      return false;
    }
    if (a.isIdentity()) {
      return true;
    }
    // scalar multiplication reduces q to 0, so q a is computed as (q - 1) a + a
    return (
      this.ecc.curve.isOnCurve(a) &&
      a
        .multiply(this.q - ONE)
        .add(a)
        .isIdentity()
    );
  }

  encode(a: EllipticCurvePoint): unknown {
    return canonicalize(a);
  }
}

/* -------------------------------------------------------------------------- */
/* helpers                                                                     */
/* -------------------------------------------------------------------------- */

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    !(value instanceof EllipticCurvePoint)
  );
}

/**
 * Reads an integer of a proof. Proofs restored from json may carry small
 * integers as numbers, so safe integers are accepted as well.
 */
export function asInteger(value: unknown): bigint | undefined {
  if (typeof value === 'bigint') {
    return value;
  }
  if (typeof value === 'number' && Number.isSafeInteger(value)) {
    return BigInt(value);
  }
  return undefined;
}

/** Reads a list of integers of a proof. */
function asIntegers(value: unknown): bigint[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }
  const result: bigint[] = [];
  for (const item of value) {
    const integer = asInteger(item);
    if (integer === undefined) {
      return undefined;
    }
    result.push(integer);
  }
  return result;
}

/* -------------------------------------------------------------------------- */
/* proofs of equal discrete logarithms                                         */
/* -------------------------------------------------------------------------- */

/** Public elements of a Chaum-Pedersen statement `h1 = g1^x` and `h2 = g2^x`. */
interface DleqStatement<E extends Element> {
  group: PrimeOrderGroup<E>;
  g1: E;
  h1: E;
  g2: E;
  h2: E;
  /** Name of the statement being proven. */
  domain: string;
  /** Extra public data bound to the proof. */
  context?: unknown;
}

/**
 * Chaum-Pedersen proof that `log_g1(h1) = log_g2(h2) = x` without revealing x.
 *
 * @returns challenge and response.
 */
export function proveDleq<E extends Element>(
  statement: DleqStatement<E> & { x: bigint }
): { challenge: bigint; response: bigint } {
  const { group, g1, h1, g2, h2, x, domain, context } = statement;
  const w = randomRange(ONE, group.q - ONE);
  const a1 = group.exp(g1, w);
  const a2 = group.exp(g2, w);
  const e = challenge(
    domain,
    group.q,
    context,
    ...[g1, h1, g2, h2, a1, a2].map((element) => group.encode(element))
  );
  const z = mod(w + e * x, group.q);
  return { challenge: e, response: z };
}

/** Verifies a Chaum-Pedersen proof that `log_g1(h1) = log_g2(h2)`. */
export function verifyDleq<E extends Element>(
  statement: DleqStatement<E> & { proof: unknown }
): boolean {
  const { group, g1, h1, g2, h2, proof, domain, context } = statement;
  if (!isPlainObject(proof)) {
    return false;
  }
  const e = asInteger(proof.challenge);
  const z = asInteger(proof.response);
  if (e === undefined || z === undefined) {
    return false;
  }
  if (e < ZERO || e >= group.q || z < ZERO || z >= group.q) {
    return false;
  }

  // soundness requires all elements to be in the group of prime order
  if (![g1, h1, g2, h2].every((element) => group.isMember(element))) {
    return false;
  }

  // a = g^z * h^(-e) is the commitment of an honest prover
  const a1 = group.mul(group.exp(g1, z), group.exp(h1, -e));
  const a2 = group.mul(group.exp(g2, z), group.exp(h2, -e));
  return (
    e ===
    challenge(
      domain,
      group.q,
      context,
      ...[g1, h1, g2, h2, a1, a2].map((element) => group.encode(element))
    )
  );
}

/** Public elements of a disjunctive statement `h1 = g1^x` and `h2s[i] = g2^x`. */
interface DleqOrStatement<E extends Element> {
  group: PrimeOrderGroup<E>;
  g1: E;
  h1: E;
  g2: E;
  h2s: readonly E[];
  domain: string;
  context?: unknown;
}

/**
 * Disjunctive Chaum-Pedersen proof that `log_g1(h1) = log_g2(h2)` for at least
 * one h2 in h2s, without revealing which one. Proofs of other items are
 * simulated.
 *
 * @param statement.x - the common discrete logarithm known by the prover.
 * @param statement.index - index of the true statement.
 */
export function proveDleqOr<E extends Element>(
  statement: DleqOrStatement<E> & { x: bigint; index: number }
): MembershipProof {
  const { group, g1, h1, g2, h2s, x, index, domain, context } = statement;
  const q = group.q;
  const challenges: bigint[] = [];
  const responses: bigint[] = [];
  const commitments: E[] = [];
  const w = randomRange(ONE, q - ONE);
  h2s.forEach((h2, i) => {
    if (i === index) {
      challenges.push(ZERO);
      responses.push(ZERO);
      commitments.push(group.exp(g1, w), group.exp(g2, w));
      return;
    }
    // simulated proof for a false statement
    const eI = randomBelow(q);
    const zI = randomBelow(q);
    challenges.push(eI);
    responses.push(zI);
    commitments.push(
      group.mul(group.exp(g1, zI), group.exp(h1, -eI)),
      group.mul(group.exp(g2, zI), group.exp(h2, -eI))
    );
  });

  const e = challenge(
    domain,
    q,
    context,
    ...[g1, h1, g2, ...h2s, ...commitments].map((element) =>
      group.encode(element)
    )
  );
  // challenge of the true statement completes the sum
  const others = challenges.reduce((total, value) => total + value, ZERO);
  challenges[index] = mod(e - others, q);
  responses[index] = mod(w + challenges[index] * x, q);
  return { challenges, responses };
}

/** Verifies a disjunctive Chaum-Pedersen proof. */
export function verifyDleqOr<E extends Element>(
  statement: DleqOrStatement<E> & { proof: unknown }
): boolean {
  const { group, g1, h1, g2, h2s, proof, domain, context } = statement;
  if (!isPlainObject(proof)) {
    return false;
  }
  const challenges = asIntegers(proof.challenges);
  const responses = asIntegers(proof.responses);
  if (challenges === undefined || responses === undefined) {
    return false;
  }
  if (challenges.length !== h2s.length || responses.length !== h2s.length) {
    return false;
  }
  const q = group.q;
  if (
    [...challenges, ...responses].some((value) => value < ZERO || value >= q)
  ) {
    return false;
  }

  // soundness requires all elements to be in the group of prime order
  if (![g1, h1, g2, ...h2s].every((element) => group.isMember(element))) {
    return false;
  }

  const commitments: E[] = [];
  h2s.forEach((h2, i) => {
    commitments.push(
      group.mul(group.exp(g1, responses[i]), group.exp(h1, -challenges[i])),
      group.mul(group.exp(g2, responses[i]), group.exp(h2, -challenges[i]))
    );
  });

  const e = challenge(
    domain,
    q,
    context,
    ...[g1, h1, g2, ...h2s, ...commitments].map((element) =>
      group.encode(element)
    )
  );
  return (
    mod(
      challenges.reduce((total, value) => total + value, ZERO),
      q
    ) === e
  );
}

/* -------------------------------------------------------------------------- */
/* proofs of knowledge of discrete logarithms                                  */
/* -------------------------------------------------------------------------- */

/** Public elements of a Schnorr statement `h = g^x`. */
interface DlogStatement<E extends Element> {
  group: PrimeOrderGroup<E>;
  g: E;
  h: E;
  domain: string;
  context?: unknown;
}

/** Schnorr proof of knowledge of `x = log_g(h)` without revealing x. */
export function proveDlog<E extends Element>(
  statement: DlogStatement<E> & { x: bigint }
): { challenge: bigint; response: bigint } {
  const { group, g, h, x, domain, context } = statement;
  const w = randomRange(ONE, group.q - ONE);
  const a = group.exp(g, w);
  const e = challenge(
    domain,
    group.q,
    context,
    group.encode(g),
    group.encode(h),
    group.encode(a)
  );
  return { challenge: e, response: mod(w + e * x, group.q) };
}

/** Verifies a Schnorr proof of knowledge of `log_g(h)`. */
export function verifyDlog<E extends Element>(
  statement: DlogStatement<E> & { proof: unknown }
): boolean {
  const { group, g, h, proof, domain, context } = statement;
  if (!isPlainObject(proof)) {
    return false;
  }
  const e = asInteger(proof.challenge);
  const z = asInteger(proof.response);
  if (e === undefined || z === undefined) {
    return false;
  }
  if (e < ZERO || e >= group.q || z < ZERO || z >= group.q) {
    return false;
  }
  if (!group.isMember(g) || !group.isMember(h)) {
    return false;
  }

  // a = g^z * h^(-e) is the commitment of an honest prover
  const a = group.mul(group.exp(g, z), group.exp(h, -e));
  return (
    e ===
    challenge(
      domain,
      group.q,
      context,
      group.encode(g),
      group.encode(h),
      group.encode(a)
    )
  );
}

/* -------------------------------------------------------------------------- */
/* proofs of Paillier and Damgard-Jurik                                        */
/* -------------------------------------------------------------------------- */

/**
 * Proof of correct decryption for Paillier and Damgard-Jurik. A ciphertext is
 * `g^m * r^n mod n^2`, and this is one to one for m in `Z_n` and r in `Z*_n`.
 * So, revealing r proves m without a zero-knowledge proof. Only the private
 * key owner can recover r. It reveals nothing about other ciphertexts.
 *
 * @param plaintext - restored message in modulo n.
 * @param phi - euler's totient of n.
 * @returns randomness r of the ciphertext in `Z*_n`.
 */
export function provePaillierDecryption(
  ciphertext: bigint,
  plaintext: bigint,
  n: bigint,
  phi: bigint
): { randomness: bigint } {
  const n2 = n * n;
  if (gcd(n, phi) !== ONE) {
    throw new Error('Randomness cannot be recovered because gcd(n, phi) != 1');
  }
  // c * g^-m = r^n mod n^2, and r^n mod n is enough to find r mod n
  const rN = (ciphertext * modPow(ONE + n, -plaintext, n2)) % n;
  return { randomness: modPow(rN, modPow(n, -ONE, phi), n) };
}

/** Verifies a proof of correct decryption for Paillier and Damgard-Jurik. */
export function verifyPaillierDecryption(
  ciphertext: unknown,
  plaintext: unknown,
  proof: unknown,
  n: bigint
): boolean {
  if (!isPlainObject(proof) || typeof plaintext !== 'bigint') {
    return false;
  }
  const r = asInteger(proof.randomness);
  if (r === undefined || typeof ciphertext !== 'bigint') {
    return false;
  }
  if (r <= ZERO || r >= n || gcd(r, n) !== ONE || gcd(ciphertext, n) !== ONE) {
    return false;
  }
  if (plaintext < ZERO || plaintext >= n) {
    return false;
  }
  const n2 = n * n;
  return (
    mod(ciphertext, n2) ===
    (modPow(ONE + n, plaintext, n2) * modPow(r, n, n2)) % n2
  );
}

/**
 * Challenge length of proofs of n-th powers. Challenges must be smaller than
 * the smallest prime factor of n for soundness.
 */
export function nthPowerChallengeBits(n: bigint): number {
  return Math.max(
    1,
    Math.min(CHALLENGE_BITS, Math.floor(bitLength(n) / 2) - 2)
  );
}

/** Random element of the multiplicative group of the modulo, a power of n. */
export function randomUnit(n: bigint, modulo: bigint): bigint {
  for (;;) {
    const r = randomRange(ONE, modulo - ONE);
    if (gcd(r, n) === ONE) {
      return r;
    }
  }
}

/** Public elements of a statement that one of us is an n-th power. */
interface NthPowerOrStatement {
  /** Public modulus. */
  n: bigint;
  /** `n^(s+1)`. */
  modulo: bigint;
  /** Candidates, one of which is an n-th power. */
  us: readonly bigint[];
  domain: string;
  context?: unknown;
}

/**
 * Proves that at least one of us is an n-th power in modulo, without
 * revealing which. This is the 1-out-of-k proof of Damgard & Jurik, showing
 * that a ciphertext c encrypts one of k values v, where us are `c * g^-v`.
 *
 * @param statement.r - n-th root of `us[index]` known by the prover.
 * @param statement.index - index of the true statement.
 */
export function proveNthPowerOr(
  statement: NthPowerOrStatement & { r: bigint; index: number }
): MembershipProof {
  const { n, modulo, us, r, index, domain, context } = statement;
  const bound = ONE << BigInt(nthPowerChallengeBits(n));
  const challenges: bigint[] = [];
  const responses: bigint[] = [];
  const commitments: bigint[] = [];
  const rho = randomUnit(n, modulo);
  us.forEach((u, i) => {
    if (i === index) {
      challenges.push(ZERO);
      responses.push(ZERO);
      commitments.push(modPow(rho, n, modulo));
      return;
    }
    // simulated proof for a false statement
    const eI = randomBelow(bound);
    const zI = randomUnit(n, modulo);
    challenges.push(eI);
    responses.push(zI);
    commitments.push((modPow(zI, n, modulo) * modPow(u, -eI, modulo)) % modulo);
  });

  const e = challenge(domain, bound, context, n, modulo, us, commitments);
  // challenge of the true statement completes the sum
  const others = challenges.reduce((total, value) => total + value, ZERO);
  challenges[index] = mod(e - others, bound);
  responses[index] = (rho * modPow(r, challenges[index], modulo)) % modulo;
  return { challenges, responses };
}

/** Verifies a proof that at least one of us is an n-th power in modulo. */
export function verifyNthPowerOr(
  statement: NthPowerOrStatement & { proof: unknown }
): boolean {
  const { n, modulo, us, proof, domain, context } = statement;
  if (!isPlainObject(proof)) {
    return false;
  }
  const challenges = asIntegers(proof.challenges);
  const responses = asIntegers(proof.responses);
  if (challenges === undefined || responses === undefined) {
    return false;
  }
  if (challenges.length !== us.length || responses.length !== us.length) {
    return false;
  }
  const bound = ONE << BigInt(nthPowerChallengeBits(n));
  if (challenges.some((eI) => eI < ZERO || eI >= bound)) {
    return false;
  }
  for (const value of [...responses, ...us]) {
    if (value <= ZERO || value >= modulo || gcd(value, n) !== ONE) {
      return false;
    }
  }

  const commitments = us.map(
    (u, i) =>
      (modPow(responses[i], n, modulo) * modPow(u, -challenges[i], modulo)) %
      modulo
  );
  const e = challenge(domain, bound, context, n, modulo, us, commitments);
  return (
    mod(
      challenges.reduce((total, value) => total + value, ZERO),
      bound
    ) === e
  );
}

/**
 * Candidates `c * g^-v` for each value v. Ciphertext encrypts v if and only if
 * its candidate is an n-th power, i.e. an encryption of 0.
 *
 * @param modulo - ciphertext modulo `n^(s+1)`.
 */
export function paillierMembershipCandidates(
  ciphertext: bigint,
  values: readonly bigint[],
  n: bigint,
  modulo: bigint
): bigint[] {
  return values.map(
    (value) => (ciphertext * modPow(ONE + n, -value, modulo)) % modulo
  );
}

/** Public elements of a statement about a Paillier or Damgard-Jurik ciphertext. */
interface PaillierKnowledgeStatement {
  ciphertext: bigint;
  n: bigint;
  /** Ciphertext modulo `n^(s+1)`. */
  modulo: bigint;
  domain: string;
  context?: unknown;
}

/**
 * Proof of knowledge of plaintext m and randomness r of a Paillier or
 * Damgard-Jurik ciphertext `c = g^m * r^n mod n^(s+1)`, without revealing
 * them.
 */
export function provePaillierKnowledge(
  statement: PaillierKnowledgeStatement & { plaintext: bigint; r: bigint }
): {
  challenge: bigint;
  plaintext_response: bigint;
  randomness_response: bigint;
} {
  const { ciphertext, plaintext, r, n, modulo, domain, context } = statement;
  const g = ONE + n;
  const bound = ONE << BigInt(nthPowerChallengeBits(n));
  const a = randomBelow(n);
  const b = randomUnit(n, modulo);
  const t = (modPow(g, a, modulo) * modPow(b, n, modulo)) % modulo;
  const e = challenge(domain, bound, context, n, modulo, ciphertext, t);

  // a + e * m = z_m + carry * n, and g^(carry * n) is moved into the n-th power
  const total = a + e * plaintext;
  const carry = total / n;
  const zM = total % n;
  const zR = (b * modPow(r, e, modulo) * modPow(g, carry, modulo)) % modulo;
  return { challenge: e, plaintext_response: zM, randomness_response: zR };
}

/**
 * Verifies a proof of knowledge of plaintext and randomness of a Paillier or
 * Damgard-Jurik ciphertext.
 */
export function verifyPaillierKnowledge(
  statement: Omit<PaillierKnowledgeStatement, 'ciphertext'> & {
    ciphertext: unknown;
    proof: unknown;
  }
): boolean {
  const { ciphertext, proof, n, modulo, domain, context } = statement;
  if (!isPlainObject(proof) || typeof ciphertext !== 'bigint') {
    return false;
  }
  const e = asInteger(proof.challenge);
  const zM = asInteger(proof.plaintext_response);
  const zR = asInteger(proof.randomness_response);
  if (e === undefined || zM === undefined || zR === undefined) {
    return false;
  }
  const bound = ONE << BigInt(nthPowerChallengeBits(n));
  if (e < ZERO || e >= bound || zM < ZERO || zM >= n) {
    return false;
  }
  for (const value of [ciphertext, zR]) {
    if (value <= ZERO || value >= modulo || gcd(value, n) !== ONE) {
      return false;
    }
  }

  // t = g^z_m * z_r^n * c^-e is the commitment of an honest prover
  const g = ONE + n;
  const t =
    (modPow(g, zM, modulo) *
      modPow(zR, n, modulo) *
      modPow(ciphertext, -e, modulo)) %
    modulo;
  return e === challenge(domain, bound, context, n, modulo, ciphertext, t);
}

/**
 * Bit length of random values of proofs in groups of unknown order, so that
 * responses hide the secret statistically.
 *
 * @param xBits - upper bound of the bit length of the secret.
 */
export function dleqUnknownOrderBits(
  n: bigint,
  modulo: bigint,
  xBits: number
): number {
  return (
    Math.max(bitLength(modulo), xBits) +
    nthPowerChallengeBits(n) +
    STATISTICAL_BITS
  );
}

/** Public elements of a statement in the group of squares modulo `n^(s+1)`. */
interface DleqUnknownOrderStatement {
  /** Public modulus, product of two safe primes. */
  n: bigint;
  /** `n^(s+1)`. */
  modulo: bigint;
  g1: bigint;
  h1: bigint;
  g2: bigint;
  h2: bigint;
  /** Upper bound of the bit length of the secret. */
  xBits: number;
  domain: string;
  context?: unknown;
}

/**
 * Proof that `log_g1(h1) = log_g2(h2) = x` in the group of squares modulo
 * `n^(s+1)`, whose order is secret. Response is computed over the integers and
 * hides x statistically. This is the proof of correct partial decryption of
 * Shoup and Damgard-Jurik.
 */
export function proveDleqUnknownOrder(
  statement: DleqUnknownOrderStatement & { x: bigint }
): { challenge: bigint; response: bigint } {
  const { n, modulo, g1, h1, g2, h2, x, xBits, domain, context } = statement;
  const w = randomBits(dleqUnknownOrderBits(n, modulo, xBits));
  const a1 = modPow(g1, w, modulo);
  const a2 = modPow(g2, w, modulo);
  const e = challenge(
    domain,
    ONE << BigInt(nthPowerChallengeBits(n)),
    context,
    modulo,
    g1,
    h1,
    g2,
    h2,
    a1,
    a2
  );
  return { challenge: e, response: w + e * x };
}

/**
 * Verifies a proof that `log_g1(h1) = log_g2(h2)` in the group of squares
 * modulo `n^(s+1)`.
 */
export function verifyDleqUnknownOrder(
  statement: DleqUnknownOrderStatement & { proof: unknown }
): boolean {
  const { n, modulo, g1, h1, g2, h2, proof, xBits, domain, context } =
    statement;
  if (!isPlainObject(proof)) {
    return false;
  }
  const e = asInteger(proof.challenge);
  const z = asInteger(proof.response);
  if (e === undefined || z === undefined) {
    return false;
  }
  if (e < ZERO || e >= ONE << BigInt(nthPowerChallengeBits(n))) {
    return false;
  }
  if (
    z < ZERO ||
    z >= ONE << BigInt(dleqUnknownOrderBits(n, modulo, xBits) + 1)
  ) {
    return false;
  }
  for (const element of [g1, h1, g2, h2]) {
    if (element <= ZERO || element >= modulo || gcd(element, n) !== ONE) {
      return false;
    }
  }

  // a = g^z * h^(-e) is the commitment of an honest prover
  const a1 = (modPow(g1, z, modulo) * modPow(h1, -e, modulo)) % modulo;
  const a2 = (modPow(g2, z, modulo) * modPow(h2, -e, modulo)) % modulo;
  return (
    e ===
    challenge(
      domain,
      ONE << BigInt(nthPowerChallengeBits(n)),
      context,
      modulo,
      g1,
      h1,
      g2,
      h2,
      a1,
      a2
    )
  );
}

/* -------------------------------------------------------------------------- */
/* range proofs                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Weights of bits to represent every integer in `[0, width]` exactly, i.e.
 * `1, 2, 4, ..., 2^(k-2)` and `width - (2^(k-1) - 1)` where k is the bit
 * length of width. Sums of 0/1 bits with these weights cover `[0, width]`, and
 * nothing out of it.
 */
export function rangeWeights(width: bigint): bigint[] {
  const k = bitLength(width);
  if (k === 0) {
    return [];
  }
  const weights: bigint[] = [];
  for (let i = 0; i < k - 1; i++) {
    weights.push(ONE << BigInt(i));
  }
  weights.push(width - ((ONE << BigInt(k - 1)) - ONE));
  return weights;
}

/** Finds 0/1 bits of a value in `[0, sum of weights]` for weights of {@link rangeWeights}. */
export function decompose(value: bigint, weights: readonly bigint[]): bigint[] {
  if (weights.length === 0) {
    return [];
  }
  const last = value >= weights[weights.length - 1] ? ONE : ZERO;
  const rest = value - last * weights[weights.length - 1];
  const bits: bigint[] = [];
  for (let i = 0; i < weights.length - 1; i++) {
    bits.push((rest >> BigInt(i)) & ONE);
  }
  bits.push(last);
  return bits;
}

/**
 * Context of a part of a range proof. It binds every part to its position and
 * range, so parts cannot be reordered or moved into another proof.
 */
export function rangeContext(
  context: unknown,
  low: bigint,
  high: bigint,
  index: number
): unknown[] {
  return ['range', low, high, index, context ?? null];
}

/** Restores the ciphertext of a range proof homomorphically as `c_low + Σ w_i * c_i`. */
function combineRangeCiphertexts(
  cs: Homomorphic,
  ciphertexts: readonly CiphertextValue[],
  weights: readonly bigint[]
): CiphertextValue {
  let combined = ciphertexts[0];
  weights.forEach((weight, i) => {
    combined = cs.add(
      combined,
      cs.multiplyByConstant(ciphertexts[i + 1], weight)
    );
  });
  return combined;
}

/**
 * Encrypts a plaintext in `[low, high]` and proves that it is in this range
 * without revealing it. It is decomposed into bits, each bit is encrypted with
 * a proof that it is 0 or 1, and low is encrypted with a proof that it is low.
 * Ciphertext is `c_low + Σ w_i * c_i`, so anyone can restore it from the
 * parts.
 *
 * @param values - normalized `[low, 0, 1]` in plaintext modulo.
 */
export function proveRange(
  cs: Homomorphic,
  plaintext: bigint,
  low: bigint,
  high: bigint,
  values: readonly [bigint, bigint, bigint],
  context?: unknown
): [CiphertextValue, RangeProof] {
  const [normalizedLow, zero, one] = values;
  const weights = rangeWeights(high - low);
  const bits = decompose(plaintext - low, weights);

  const parts: Array<[bigint, bigint[]]> = [
    [normalizedLow, [normalizedLow]],
    ...bits.map((bit): [bigint, bigint[]] => [
      bit === ONE ? one : zero,
      [zero, one],
    ]),
  ];
  const ciphertexts: CiphertextValue[] = [];
  const proofs: MembershipProof[] = [];
  parts.forEach(([value, allowed], index) => {
    const [ciphertext, proof] = cs.encryptWithProof(
      value,
      allowed,
      rangeContext(context, low, high, index)
    );
    ciphertexts.push(ciphertext);
    proofs.push(proof);
  });

  const ciphertext = combineRangeCiphertexts(cs, ciphertexts, weights);
  return [ciphertext, { ciphertexts, proofs }];
}

/**
 * Verifies that a ciphertext encrypts a value in `[low, high]` with public key
 * only.
 *
 * @param values - normalized `[low, 0, 1]` in plaintext modulo.
 */
export function verifyRange(
  cs: Homomorphic,
  ciphertext: CiphertextValue,
  proof: unknown,
  low: bigint,
  high: bigint,
  values: readonly [bigint, bigint, bigint],
  context?: unknown
): boolean {
  if (!isPlainObject(proof)) {
    return false;
  }
  const { ciphertexts, proofs } = proof;
  const weights = rangeWeights(high - low);
  if (!Array.isArray(ciphertexts) || !Array.isArray(proofs)) {
    return false;
  }
  if (
    ciphertexts.length !== weights.length + 1 ||
    proofs.length !== weights.length + 1
  ) {
    return false;
  }

  const [normalizedLow, zero, one] = values;
  for (let index = 0; index < ciphertexts.length; index++) {
    const allowed = index === 0 ? [normalizedLow] : [zero, one];
    if (
      !cs.verifyCiphertext(
        ciphertexts[index] as CiphertextValue,
        proofs[index],
        allowed,
        rangeContext(context, low, high, index)
      )
    ) {
      return false;
    }
  }

  let combined: CiphertextValue;
  try {
    combined = combineRangeCiphertexts(
      cs,
      ciphertexts as CiphertextValue[],
      weights
    );
  } catch {
    // malformed parts raise errors of the cryptosystem
    return false;
  }
  return sameCanonical(combined, ciphertext);
}

/* -------------------------------------------------------------------------- */
/* one-hot proofs                                                              */
/* -------------------------------------------------------------------------- */

/**
 * Context of a part of a one-hot proof. It binds every slot to its position
 * and the number of options, so slots cannot be reordered or moved into
 * another ballot.
 */
export function oneHotContext(
  context: unknown,
  options: number,
  slot: number | 'sum'
): unknown[] {
  return ['one-hot', options, slot, context ?? null];
}

/**
 * Encrypts a one-hot vector, i.e. 1 for the chosen option and 0 for others,
 * and proves that each slot is 0 or 1 and that slots sum to 1 without
 * revealing the choice.
 *
 * @param values - normalized `[0, 1]` in plaintext modulo.
 */
export function proveOneHot(
  cs: Homomorphic,
  choice: number,
  options: number,
  values: readonly [bigint, bigint],
  context?: unknown
): [CiphertextValue[], OneHotProof] {
  const [zero, one] = values;
  const ciphertexts: CiphertextValue[] = [];
  const randomKeys: RandomKey[] = [];
  const slotProofs: MembershipProof[] = [];
  for (let slot = 0; slot < options; slot++) {
    const plaintext = slot === choice ? one : zero;
    const randomKey = cs.generateRandomKey();
    const ciphertext = cs.encrypt(plaintext, randomKey);
    slotProofs.push(
      cs.proveMembership(
        ciphertext,
        plaintext,
        randomKey,
        [zero, one],
        oneHotContext(context, options, slot)
      )
    );
    ciphertexts.push(ciphertext);
    randomKeys.push(randomKey);
  }

  // sum of slots encrypts 1, and its random key is combined from random keys of slots
  const total = ciphertexts
    .slice(1)
    .reduce((sum, c) => cs.add(sum, c), ciphertexts[0]);
  const sumProof = cs.proveMembership(
    total,
    one,
    cs.combineRandomKeys(randomKeys),
    [one],
    oneHotContext(context, options, 'sum')
  );
  return [ciphertexts, { slots: slotProofs, sum: sumProof }];
}

/**
 * Verifies that encrypted slots are a one-hot vector with public key only.
 *
 * @param values - normalized `[0, 1]` in plaintext modulo.
 */
export function verifyOneHot(
  cs: Homomorphic,
  ciphertexts: readonly CiphertextValue[],
  proof: unknown,
  values: readonly [bigint, bigint],
  context?: unknown
): boolean {
  if (!isPlainObject(proof) || ciphertexts.length === 0) {
    return false;
  }
  const slotProofs = proof.slots;
  if (!Array.isArray(slotProofs) || slotProofs.length !== ciphertexts.length) {
    return false;
  }
  const options = ciphertexts.length;
  const [zero, one] = values;

  for (let slot = 0; slot < options; slot++) {
    if (
      !cs.verifyCiphertext(
        ciphertexts[slot],
        slotProofs[slot],
        [zero, one],
        oneHotContext(context, options, slot)
      )
    ) {
      return false;
    }
  }

  let total: CiphertextValue;
  try {
    total = ciphertexts
      .slice(1)
      .reduce((sum, c) => cs.add(sum, c), ciphertexts[0]);
  } catch {
    // malformed slots raise errors of the cryptosystem
    return false;
  }
  return cs.verifyCiphertext(
    total,
    proof.sum,
    [one],
    oneHotContext(context, options, 'sum')
  );
}
