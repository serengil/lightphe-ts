import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { LightPHE, Logger } from '../src';

const logger = new Logger('tests/keys.test.ts');

describe('key export and restoration', () => {
  it('round-trips keys through a file for every algorithm', () => {
    const algorithms = [
      'RSA',
      'ElGamal',
      'Exponential-ElGamal',
      'Paillier',
      'Damgard-Jurik',
      'Okamoto-Uchiyama',
      'Benaloh',
      'Naccache-Stern',
      'Goldwasser-Micali',
      'EllipticCurve-ElGamal',
    ];

    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-keys-'));

    try {
      for (const algorithmName of algorithms) {
        const privateKeyFile = path.join(tmp, `${algorithmName}_secret.json`);
        const publicKeyFile = path.join(tmp, `${algorithmName}_public.json`);

        const onpremCs = new LightPHE({ algorithmName, keySize: 37 });

        onpremCs.exportKeys(privateKeyFile);
        onpremCs.exportKeys(publicKeyFile, true);

        const cloudCs = new LightPHE({
          algorithmName,
          keyFile: publicKeyFile,
        });

        const m1 = 217;
        const m2 = 23;
        const k = 3;

        const c1 = cloudCs.encrypt(m1);
        const c2 = cloudCs.encrypt(m2);

        // restore the on-prem cryptosystem from the private key file
        const restoredCs = new LightPHE({
          algorithmName,
          keyFile: privateKeyFile,
        });

        if (algorithmName === 'RSA' || algorithmName === 'ElGamal') {
          expect(restoredCs.decrypt(c1.multiply(c2))).toBe(BigInt(m1 * m2));
        } else if (algorithmName === 'Goldwasser-Micali') {
          expect(restoredCs.decrypt(c1.xor(c2))).toBe(BigInt(m1 ^ m2));
        } else {
          expect(restoredCs.decrypt(c1.add(c2))).toBe(BigInt(m1 + m2));
          expect(restoredCs.decrypt(c1.multiplyByConstant(k))).toBe(
            BigInt(k * m1)
          );
        }

        logger.info(`✅ Key restoration test succeeded for ${algorithmName}`);
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
