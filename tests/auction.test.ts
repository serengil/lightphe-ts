import { Ciphertext, LightPHE, Logger, type KnowledgeProof } from '../src';

const logger = new Logger('tests/auction.test.ts');

describe('sealed-bid auction', () => {
  it.each([
    ['Exponential-ElGamal', 128, true],
    ['Paillier', 128, false],
  ] as Array<[string, number, boolean]>)(
    'rejects copied bids for %s',
    (algorithmName, keySize, primeOrder) => {
      // bidders submit encrypted bids with proofs of knowledge. A bidder who copies
      // someone else's encrypted bid and adds 1 to it homomorphically cannot prove
      // knowledge of the result, so cannot outbid without knowing the bid. After the
      // deadline, the auctioneer decrypts valid bids with proofs and announces the winner.
      const auctioneerCs = new LightPHE({ algorithmName, keySize, primeOrder });
      const publicCs = new LightPHE({
        algorithmName,
        keys: { public_key: auctioneerCs.cs.keys.public_key },
      });

      const bids: Record<string, bigint> = {
        alice: 950n,
        bob: 870n,
        carol: 910n,
      };
      const submissions: Record<string, [Ciphertext, KnowledgeProof]> = {};
      for (const [bidder, bid] of Object.entries(bids)) {
        submissions[bidder] = publicCs.encryptWithProofOfKnowledge(bid, {
          context: bidder,
        });
      }

      // mallory copies alice's encrypted bid, adds 1 to it, and reuses alice's proof
      const [aliceBid, aliceProof] = submissions.alice;
      submissions.mallory = [aliceBid.add(publicCs.encrypt(1)), aliceProof];

      // oscar re-randomizes bob's encrypted bid to make it look different
      const [bobBid, bobProof] = submissions.bob;
      submissions.oscar = [publicCs.regenerateCiphertext(bobBid), bobProof];

      // trent submits a copy of carol's submission as is
      submissions.trent = submissions.carol;

      const valid = Object.entries(submissions).filter(
        ([bidder, [bid, proof]]) =>
          publicCs.verifyKnowledge(bid, proof, { context: bidder })
      );
      expect(valid.map(([bidder]) => bidder).sort()).toEqual(
        Object.keys(bids).sort()
      );

      // after the deadline, auctioneer decrypts valid bids with proofs, and anyone verifies them
      const opened: Record<string, bigint> = {};
      for (const [bidder, [bid]] of valid) {
        const [amount, proof] = auctioneerCs.decryptWithProof(bid);
        expect(publicCs.verifyDecryption(bid, amount, proof)).toBe(true);
        opened[bidder] = amount;
      }

      expect(opened).toEqual(bids);
      const winner = Object.entries(opened).reduce((a, b) =>
        b[1] > a[1] ? b : a
      );
      expect(winner[0]).toBe('alice');

      logger.info(`✅ Sealed-bid auction test succeeded for ${algorithmName}`);
    }
  );
});
