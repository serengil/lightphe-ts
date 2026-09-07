/** Encrypted vectors of real numbers. */

import { Logger } from '../commons/logger.js';
import { fractionize, normalizeInput } from '../commons/pheUtils.js';
import type { AlgorithmName } from './Algorithm.js';
import { Ciphertext } from './Ciphertext.js';
import { Homomorphic } from './Homomorphic.js';
import type { CiphertextValue } from './types.js';

const logger = new Logger('lightphe-ts/models/Tensor.ts');

/**
 * One element of an encrypted tensor.
 *
 * A real number is stored as a scaled integer over a scale factor, both
 * encrypted, with the sign kept in the clear because no partially homomorphic
 * scheme can recover it. `dividend` and `absDividend` differ only for negative
 * values: the first carries the modular representative of the signed value, the
 * second its magnitude. Keeping both lets multiplication track signs without
 * decrypting.
 */
export class Fraction {
  readonly dividend: CiphertextValue;
  readonly absDividend: CiphertextValue;
  readonly divisor: CiphertextValue;
  readonly sign: number;

  constructor(options: {
    dividend: CiphertextValue;
    absDividend: CiphertextValue;
    divisor: CiphertextValue;
    sign?: number;
  }) {
    this.dividend = options.dividend;
    this.absDividend = options.absDividend;
    this.divisor = options.divisor;
    this.sign = options.sign ?? 1;
  }

  toString(): string {
    const sign = this.sign === -1 ? '-' : '+';
    return `Fraction(${sign}${String(this.absDividend)} / ${String(this.divisor)})`;
  }
}

/** A vector of encrypted real numbers. */
export class EncryptedTensor {
  readonly fractions: Fraction[];
  readonly cs: Homomorphic;
  readonly precision: number;

  constructor(options: {
    fractions: Fraction[];
    cs: Homomorphic;
    precision?: number;
  }) {
    this.fractions = options.fractions;
    this.cs = options.cs;
    this.precision = options.precision ?? 5;
  }

  /** The number of elements. */
  get length(): number {
    return this.fractions.length;
  }

  toString(): string {
    return this.fractions.map((fraction) => fraction.toString()).join(', ');
  }

  /** Element-wise homomorphic addition of two encrypted tensors. */
  add(other: EncryptedTensor): EncryptedTensor {
    if (this.fractions.length !== other.fractions.length) {
      throw new Error('Fraction sizes must be equal');
    }

    const currentTensors: Fraction[] = [];
    this.fractions.forEach((alpha, i) => {
      const beta = other.fractions[i];

      const currentDividend = this.cs.add(alpha.dividend, beta.dividend);
      const currentAbsDividend = this.cs.add(
        alpha.absDividend,
        beta.absDividend
      );

      // Note that the divisor is alpha's divisor rather than a sum.
      if (alpha.sign === -1 && beta.sign === -1) {
        currentTensors.push(
          new Fraction({
            dividend: currentDividend,
            absDividend: currentAbsDividend,
            divisor: alpha.divisor,
            sign: -1,
          })
        );
        return;
      }

      // With one positive and one negative operand the sign of the result
      // cannot be known without decrypting, so trust the modular arithmetic.
      if (alpha.sign !== beta.sign) {
        logger.warn(
          `${i}-th items of the vectors have different signs, and result's sign ` +
            'cannot be determined in PHE. Result will be shown for positive for this anyway.'
        );
      }

      currentTensors.push(
        new Fraction({
          dividend: currentDividend,
          absDividend: currentDividend,
          divisor: alpha.divisor,
          sign: 1,
        })
      );
    });

    return new EncryptedTensor({
      fractions: currentTensors,
      cs: this.cs,
      precision: this.precision,
    });
  }

  /**
   * Element-wise homomorphic multiplication with another encrypted tensor or a
   * plain tensor, or multiplication of the whole tensor by a constant.
   */
  multiply(
    other: EncryptedTensor | number | bigint | number[]
  ): EncryptedTensor {
    if (other instanceof EncryptedTensor) {
      if (this.fractions.length !== other.fractions.length) {
        throw new Error(
          'Tensor sizes must be equal in homomorphic multiplication'
        );
      }

      const fractions = this.fractions.map((alpha, i) => {
        const beta = other.fractions[i];
        return new Fraction({
          dividend: this.cs.multiply(alpha.dividend, beta.dividend),
          absDividend: this.cs.multiply(alpha.absDividend, beta.absDividend),
          divisor: this.cs.multiply(alpha.divisor, beta.divisor),
          sign: alpha.sign * beta.sign,
        });
      });

      return new EncryptedTensor({
        fractions,
        cs: this.cs,
        precision: this.precision,
      });
    }

    if (Array.isArray(other)) {
      // element-wise multiplication of an encrypted tensor with a plain one
      if (this.fractions.length !== other.length) {
        throw new Error(
          'Tensor sizes must be equal in homomorphic multiplication'
        );
      }

      if (
        other.some((value) => value < 0) ||
        this.fractions.some((fraction) => fraction.sign < 0)
      ) {
        throw new Error(
          'all items in the plain and encrypted tensor must be positive' +
            ' to perform element wise multiplication'
        );
      }

      const dividends: Fraction[] = [];
      let divisor: Ciphertext | undefined;
      this.fractions.forEach((alpha, i) => {
        const beta = Math.abs(other[i]);
        const modulo = this.cs.plaintextModulo;
        // Number(modulo) overflows to Infinity for realistic key sizes, which
        // correctly leaves beta alone; small test moduli compare exactly.
        const limit = Number(modulo);
        const bounded = beta > limit ? beta % limit : beta;

        const [absDividend, currentDivisor] = fractionize(
          bounded,
          modulo,
          this.precision
        );

        const dividend = castCiphertext(this.cs, alpha.absDividend).multiply(
          absDividend
        );

        divisor ??= castCiphertext(this.cs, alpha.divisor).multiply(
          currentDivisor
        );

        dividends.push(
          new Fraction({
            dividend: dividend.value,
            absDividend: dividend.value,
            divisor: divisor.value,
            sign: 1,
          })
        );
      });

      return new EncryptedTensor({
        fractions: dividends,
        cs: this.cs,
        precision: this.precision,
      });
    }

    if (typeof other === 'bigint' || typeof other === 'number') {
      const constantSign = other >= 0 ? 1 : -1;
      const magnitude = other < 0 ? -other : other;
      const constant =
        typeof magnitude === 'bigint' || Number.isInteger(magnitude)
          ? BigInt(magnitude)
          : normalizeInput(magnitude as number, this.cs.plaintextModulo);

      const fractions = this.fractions.map(
        (alpha) =>
          new Fraction({
            dividend: this.cs.multiplyByConstant(alpha.dividend, constant),
            absDividend: this.cs.multiplyByConstant(
              alpha.absDividend,
              constant
            ),
            // Note that the divisor is alpha's divisor, not a product.
            divisor: alpha.divisor,
            sign: constantSign * alpha.sign,
          })
      );

      return new EncryptedTensor({
        fractions,
        cs: this.cs,
        precision: this.precision,
      });
    }

    throw new Error(
      'Encrypted tensor can be multiplied by an encrypted tensor or constant'
    );
  }

  /**
   * Dot product with a plain tensor, the counterpart of Python's `@` operator.
   *
   * Multiplies element-wise and then sums the encrypted products, which is what
   * makes an encrypted cosine similarity possible.
   */
  dot(other: number[]): EncryptedTensor {
    if (!Array.isArray(other)) {
      throw new Error(
        'Dot product can be run for EncryptedTensor and List of float / int'
      );
    }

    const encryptedTensor = this.multiply(other);

    if (encryptedTensor.fractions.length === 0) {
      throw new Error('Dot product cannot be calculated for empty tensor');
    }

    const divisor = castCiphertext(
      this.cs,
      encryptedTensor.fractions[0].divisor
    );

    let sumDividend = castCiphertext(
      this.cs,
      encryptedTensor.fractions[0].absDividend
    );
    for (const fraction of encryptedTensor.fractions.slice(1)) {
      sumDividend = sumDividend.add(
        castCiphertext(this.cs, fraction.absDividend)
      );
    }

    const fraction = new Fraction({
      dividend: sumDividend.value,
      absDividend: sumDividend.value,
      divisor: divisor.value,
      sign: 1,
    });

    return new EncryptedTensor({ fractions: [fraction], cs: this.cs });
  }
}

/** Wraps a raw payload back into a `Ciphertext` bound to the same cryptosystem. */
export function castCiphertext(
  cs: Homomorphic,
  value: CiphertextValue
): Ciphertext {
  return new Ciphertext({
    algorithmName: cs.getAlgorithmName() as AlgorithmName,
    keys: cs.keys,
    value,
    form: cs.keys.form,
    curve: cs.keys.curve,
  });
}
