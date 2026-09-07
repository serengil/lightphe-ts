import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { LightPHE, Logger, deserializeKeys } from '../src';

const logger = new Logger('tests/exportingKeys.test.ts');

describe('exporting keys', () => {
  it('keeps the private key in memory after exporting only the public one', () => {
    const targetFile = path.join(
      fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-export-')),
      'my_public_key.lphe'
    );

    const cs = new LightPHE({ algorithmName: 'RSA', keySize: 50 });

    // the private key is dropped while writing the public key file
    cs.exportKeys(targetFile, true);
    expect(cs.cs.keys.private_key).toBeDefined();
    logger.info(
      '✅ private key is available in cryptosystem after its public key exported as expected'
    );

    const keys = deserializeKeys(
      fs.readFileSync(targetFile, { encoding: 'utf-8' })
    );
    expect(keys.private_key).toBeUndefined();
    logger.info(
      '✅ private key is not available in public key file as expected'
    );

    fs.rmSync(path.dirname(targetFile), { recursive: true, force: true });
  });
});
