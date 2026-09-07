import { LightPHE, Logger } from '../src';
import { bitLength, valuesEqual } from './helpers';

const logger = new Logger('tests/sanderyoungyung.test.ts');

function runApi(plaintextLimit?: number): void {
  const started = Date.now();

  const cs = new LightPHE({
    algorithmName: 'Sander-Young-Yung',
    keySize: 50,
    plaintextLimit,
  });

  const modulo = cs.cs.plaintextModulo;
  const securityLevel = bitLength(cs.cs.keys.public_key!.n as bigint);

  // try different bit size messages
  const messages: Array<[number, number]> = [
    [17, 22],
    [117, 23],
    [23, 117],
  ];

  for (const [m1, m2] of messages) {
    const c1 = cs.encrypt(m1);
    const c2 = cs.encrypt(m2);

    // proof of decryption
    expect(cs.decrypt(c1)).toBe(BigInt(m1) % modulo);
    expect(cs.decrypt(c2)).toBe(BigInt(m2) % modulo);

    // re-randomization
    const c1Prime = cs.cs.reencrypt(c1.value);
    const c2Prime = cs.cs.reencrypt(c2.value);
    expect(valuesEqual(c1.value, c1Prime)).toBe(false);
    expect(valuesEqual(c2.value, c2Prime)).toBe(false);
    expect(cs.cs.decrypt(c1Prime)).toBe(BigInt(m1) % modulo);
    expect(cs.cs.decrypt(c2Prime)).toBe(BigInt(m2) % modulo);

    // homomorphic bitwise AND
    expect(cs.decrypt(c1.and(c2))).toBe(
      (BigInt(m1) % modulo) & (BigInt(m2) % modulo)
    );

    // unsupported homomorphic operations
    expect(() => c1.multiply(c2)).toThrow();
    expect(() => c1.add(c2)).toThrow();
    expect(() => c1.multiply(5)).toThrow();
    expect(() => c1.multiplyByConstant(5)).toThrow();
  }

  logger.info(
    `✅ Sander-Young-Yung test (plaintextLimit=${String(plaintextLimit)}) succeeded ` +
      `(${securityLevel} bit security level) in ${(Date.now() - started) / 1000} seconds`
  );
}

describe('Sander-Young-Yung', () => {
  it('is homomorphic with respect to bitwise and', () => {
    runApi();
  });

  it('honours an explicit plaintext limit', () => {
    runApi(200);
  });
});
