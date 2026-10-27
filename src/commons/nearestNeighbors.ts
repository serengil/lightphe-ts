/**
 * Encrypted k nearest neighbor search. Client (private key owner) encrypts a
 * query vector, and server finds the k nearest vectors of its database by
 * squared euclidean distance without learning the query, the distances or the
 * result. Client learns only the indices, or the labels, of the k nearest
 * vectors in order.
 *   - distance: `||q - x||^2 = ||q||^2 - 2 <q, x> + ||x||^2` is linear in the
 *     encrypted q when client sends `E(||q||^2)` as well, so server computes it
 *     with additions and multiplications with constants only.
 *   - argmin: argmax of `2^bitLength - 1 - distance` with the interactive
 *     argmax of Damgard-Geisler-Kroigaard, which reveals nothing to both
 *     parties.
 *   - exclusion: server turns the encrypted index of the nearest vector into
 *     an encrypted one-hot vector with the client's help, and lifts every
 *     other value by `2^bitLength`, so the next argmax finds the next nearest
 *     vector.
 *
 * Ref: Erkin, Z. et al. (2009). Privacy-Preserving Face Recognition. PETS 2009.
 */

import type { DamgardGeislerKroigaard } from '../cryptosystems/DamgardGeislerKroigaard.js';
import type { Homomorphic } from '../models/Homomorphic.js';
import type { ArgmaxClient, ArgmaxMessage } from '../models/types.js';
import {
  bitLength,
  mod,
  randomBelow,
  randomRange,
  ONE,
  ZERO,
} from './mathUtils.js';

/** Encrypted entries of a query and its squared norm. */
export interface EncryptedQueryValues {
  query: bigint[];
  norm: bigint;
}

/** Encrypted indices, and labels if set, of the nearest vectors. */
export interface KnnValues {
  indices: bigint[];
  labels?: bigint[];
}

/** Encrypts a query vector and its squared norm. Runs on client side. */
export function encryptQuery(
  cs: Homomorphic,
  query: readonly bigint[]
): EncryptedQueryValues {
  const u = cs.plaintextModulo;
  return {
    query: query.map((x) => cs.encrypt(mod(x, u)) as bigint),
    norm: cs.encrypt(
      mod(
        query.reduce((total, x) => total + x * x, ZERO),
        u
      )
    ) as bigint,
  };
}

/**
 * Finds the k nearest vectors of a database to an encrypted query. Runs on
 * server side and interacts with the client through the client callable.
 *
 * @param cs - Damgard-Geisler-Kroigaard cryptosystem having the public key.
 * @param bitLength - squared distances must be less than `2^bitLength`.
 * @param labels - optional labels of vectors. If set, encrypted labels of the
 *   nearest vectors are returned as well.
 * @returns encrypted indices, and encrypted labels if labels are set, of the k
 *   nearest vectors from the nearest one.
 */
export async function evaluateKnn(
  cs: Homomorphic,
  encryptedQuery: EncryptedQueryValues,
  database: readonly (readonly bigint[])[],
  k: number,
  bitLengthOfDistances: number,
  client: ArgmaxClient,
  labels?: readonly bigint[]
): Promise<KnnValues> {
  const u = cs.plaintextModulo;
  const size = database.length;
  const offset = ONE << BigInt(bitLengthOfDistances);
  const { query, norm } = encryptedQuery;

  // values = 2^bitLength - 1 - distance, so the nearest vector has the greatest value
  let values = database.map((vector) => {
    const squaredNorm = vector.reduce((total, x) => total + x * x, ZERO);
    let value = cs.add(
      cs.encrypt(mod(offset - ONE - squaredNorm, u)),
      cs.multiplyByConstant(norm, u - ONE)
    );
    vector.forEach((x, i) => {
      if (mod(x, u) !== ZERO) {
        value = cs.add(value, cs.multiplyByConstant(query[i], mod(2n * x, u)));
      }
    });
    return value as bigint;
  });

  // values are lifted by 2^bitLength in each round, so they need more bits
  const argmaxBitLength = bitLengthOfDistances + bitLength(BigInt(k));

  const indices: bigint[] = [];
  const foundLabels: bigint[] = [];
  for (let round = 0; round < k; round++) {
    const index = await cs.evaluateArgmax(values, argmaxBitLength, client);
    indices.push(index);

    const lastRound = round === k - 1;
    if (lastRound && labels === undefined) {
      break;
    }

    const oneHot = await oneHotIndex(cs, index, size, client);

    if (labels !== undefined) {
      let label = cs.encrypt(ZERO);
      oneHot.forEach((bit, i) => {
        if (mod(labels[i], u) !== ZERO) {
          label = cs.add(label, cs.multiplyByConstant(bit, mod(labels[i], u)));
        }
      });
      foundLabels.push(cs.reencrypt(label) as bigint);
    }

    if (!lastRound) {
      // every value except the found one is lifted by 2^bitLength: value + offset (1 - bit)
      const lift = cs.encrypt(mod(offset, u));
      values = values.map(
        (value, i) =>
          cs.add(
            cs.add(value, lift),
            cs.multiplyByConstant(oneHot[i], mod(u - offset, u))
          ) as bigint
      );
    }
  }

  return labels === undefined ? { indices } : { indices, labels: foundLabels };
}

/**
 * Turns an encrypted index into an encrypted one-hot vector with the client's
 * help. Client receives `E(r_i (index - i))` for random non-zero r_i in a
 * random order, so it learns only that one of them is zero, but not its
 * position.
 *
 * @returns `E(1)` at the index, and `E(0)` elsewhere.
 */
async function oneHotIndex(
  cs: Homomorphic,
  encryptedIndex: bigint,
  size: number,
  client: ArgmaxClient
): Promise<bigint[]> {
  const u = cs.plaintextModulo;
  const order = Array.from({ length: size }, (_, i) => i);
  shuffle(order);

  const blinded = order.map((i) => {
    const difference = cs.add(encryptedIndex, cs.encrypt(mod(BigInt(-i), u)));
    return cs.reencrypt(
      cs.multiplyByConstant(difference, randomRange(ONE, u - ONE))
    ) as bigint;
  });

  const bits = await client({ type: 'equality', payload: blinded });

  const oneHot = new Array<bigint>(size);
  order.forEach((i, position) => {
    oneHot[i] = bits[position];
  });
  return oneHot;
}

/**
 * Answers a message of the server during encrypted nearest neighbor search.
 * Runs on client side. Messages of argmax are answered by the cryptosystem's
 * answerArgmax.
 *
 * @param cs - Damgard-Geisler-Kroigaard cryptosystem having the private key.
 * @returns ciphertexts to be sent back to the server.
 */
export function answerKnn(cs: Homomorphic, message: ArgmaxMessage): bigint[] {
  if (message.type === 'equality') {
    const dgk = cs as DamgardGeislerKroigaard;
    return (message.payload as readonly bigint[]).map(
      (c) => dgk.encrypt(dgk.isZero(c) ? ONE : ZERO) as bigint
    );
  }
  return cs.answerArgmax(message);
}

/** Shuffles an array in place with a cryptographically secure random source. */
function shuffle<T>(items: T[]): void {
  for (let i = items.length - 1; i > 0; i--) {
    const j = Number(randomBelow(BigInt(i + 1)));
    [items[i], items[j]] = [items[j], items[i]];
  }
}
