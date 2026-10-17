import * as crypto from 'crypto';

import { sha256, sha256Text, shake128 } from '../src/commons/hashing';

describe('hashing', () => {
  it('matches SHA-256 of node', () => {
    for (const length of [0, 1, 55, 56, 63, 64, 65, 200, 1000]) {
      const data = crypto.randomBytes(length);
      const expected = crypto.createHash('sha256').update(data).digest();
      expect(Buffer.from(sha256(new Uint8Array(data)))).toEqual(expected);
    }
    expect(Buffer.from(sha256Text('tag|1|2|çğ')).toString('hex')).toBe(
      crypto.createHash('sha256').update('tag|1|2|çğ', 'utf8').digest('hex')
    );
  });

  it('matches SHAKE-128 of node', () => {
    for (const length of [0, 32, 167, 168, 169, 400]) {
      const data = crypto.randomBytes(length);
      for (const outputLength of [1, 168, 169, 1000]) {
        const expected = crypto
          .createHash('shake128', { outputLength })
          .update(data)
          .digest();
        expect(
          Buffer.from(shake128(new Uint8Array(data), outputLength))
        ).toEqual(expected);
      }
    }
  });
});
