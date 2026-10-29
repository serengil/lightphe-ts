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

  it('does not execute the content of a malicious key file', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lightphe-export-'));
    const markerFile = path.join(dir, 'pwned.txt');
    const keyFile = path.join(dir, 'malicious.lphe');
    const payload = `require('fs').writeFileSync(${JSON.stringify(markerFile)}, 'pwned')`;
    fs.writeFileSync(keyFile, payload, { encoding: 'utf-8' });

    expect(() => new LightPHE({ algorithmName: 'RSA', keyFile })).toThrow();

    expect(fs.existsSync(markerFile)).toBe(false);
    logger.info('✅ key file content is not executed while restoring keys');

    fs.rmSync(dir, { recursive: true, force: true });
  });
});
