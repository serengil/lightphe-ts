import { LightPHE } from '../src';

describe('salary example', () => {
  it('raises an encrypted salary without decrypting it', () => {
    const cs = new LightPHE({ algorithmName: 'Paillier', keySize: 50 });

    // set the initial base salary to 10000 usd
    const salary = 10000;
    const salaryEncrypted = cs.encrypt(salary);

    // add 1000 usd to the base salary
    const wageIncrease = 1000;
    const increaseEncrypted = cs.encrypt(wageIncrease);

    // perform homomorphic addition
    expect(cs.decrypt(salaryEncrypted.add(increaseEncrypted))).toBe(
      BigInt(salary + wageIncrease)
    );

    // increase the base salary by 5%
    const ratio = 1.05;
    expect(cs.decrypt(salaryEncrypted.multiply(ratio))).toBe(
      BigInt(salary * ratio)
    );
  });
});
