import { LightPHE, Logger } from '../src';
import { bitLength } from './helpers';

const logger = new Logger('tests/naccache.test.ts');

describe('Naccache-Stern', () => {
  /**
   * Key generation is probabilistic and slow, and occasionally gives up, so
   * encryption, decryption and the homomorphic operations are also exercised
   * against a fixed key pair.
   */
  it('works with pre-defined keys', () => {
    const keys = {
      public_key: {
        n: 75275183223356977395233015128636801841182684353869611205877871399639096259927846711964449336873721703958210179653876541687516247046310691985977881277598653839478670263258301833023097636036737220721033604997817044724812266620826468829212603338614968953684914579782761554925497589591101127424868060977977362624693729n,
        g: 2322858651861384064537514431822509724460178869240342120700966005387085547272373554253264326744794826709642720143603083090045603237528622393527254537059946505389885957837759097286992580665451178640443489482838164247603492906332153298019557819758033383394570549848334276102748452532710144646257390863266986629778942n,
        sigma: 255255n,
      },
      private_key: {
        a: 11597041531885171702428009785553891872754255798746286340205448513302430749967682685453809973100036260110796582178813477436613205882229456042479325870287379n,
        b: 6357265649357031680615244845679689252112451833267362870520093680285536565908774220658104716644696735431871010152670595233003071273441498122136618828384989n,
        p: 2435378721695886057509882054966317293278393717736720131443144187793510457493213363945300094351007614623267282257550830261688773235268185768920658432760349591n,
        q: 30909025587173888031151320439694649143770740813345918276468695473548278783448460260839705132326515527669756851362284434022860932531472563869828240743607816519n,
        phi: 75275183223356977395233015128636801841182684353869611205877871399639096259927846711964449336873721703958210179653876541687516247046310691985977881277598653806134265954388527744361895141375770783671899073915178636812972605279037227887538978553609742276161772286758627935090233305041395360684118422229078186256527620n,
      },
    };

    const cs = new LightPHE({ algorithmName: 'Naccache-Stern', keys });

    const securityLevel = bitLength(cs.cs.keys.public_key!.n as bigint);
    logger.debug(
      `Naccache-Stern cs built with ${securityLevel} bits key. Recommended >= 768.`
    );

    const m1 = 17;
    const m2 = 21;

    const c1 = cs.encrypt(m1);
    const c2 = cs.encrypt(m2);

    // homomorphic addition
    expect(cs.decrypt(c1.add(c2))).toBe(BigInt(m1 + m2));

    // homomorphic scalar multiplication
    expect(cs.decrypt(c1.multiply(m2))).toBe(BigInt(m1 * m2));
    expect(cs.decrypt(c2.multiply(m1))).toBe(BigInt(m1 * m2));
    expect(cs.decrypt(c1.multiplyByConstant(m2))).toBe(BigInt(m1 * m2));
    expect(cs.decrypt(c2.multiplyByConstant(m1))).toBe(BigInt(m1 * m2));

    // unsupported homomorphic operations
    expect(() => c1.multiply(c2)).toThrow();
    expect(() => c1.xor(c2)).toThrow();

    logger.info('✅ Naccache-Stern api test with pre-defined keys succeeded');
  });

  it('is additively homomorphic with generated keys', () => {
    const cs = new LightPHE({ algorithmName: 'Naccache-Stern', keySize: 37 });

    const m1 = 17;
    const m2 = 21;

    const c1 = cs.encrypt(m1);
    const c2 = cs.encrypt(m2);

    // homomorphic addition
    expect(cs.decrypt(c1.add(c2))).toBe(BigInt(m1 + m2));

    // homomorphic scalar multiplication
    expect(cs.decrypt(c1.multiply(m2))).toBe(BigInt(m1 * m2));
    expect(cs.decrypt(c2.multiply(m1))).toBe(BigInt(m1 * m2));
    expect(cs.decrypt(c1.multiplyByConstant(m2))).toBe(BigInt(m1 * m2));
    expect(cs.decrypt(c2.multiplyByConstant(m1))).toBe(BigInt(m1 * m2));

    // unsupported homomorphic operations
    expect(() => c1.multiply(c2)).toThrow();
    expect(() => c1.xor(c2)).toThrow();

    logger.info('✅ Naccache-Stern api test succeeded');
  });
});
