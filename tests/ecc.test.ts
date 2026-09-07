/**
 * Tests for the folded-in elliptic curve layer.
 *
 * The Python library delegates this to LightECC, which carries its own suite;
 * this port implements it in-tree, so it is covered here.
 */

import {
  EdwardsCurve,
  EllipticCurveElGamal,
  EllipticCurvePoint,
  FP2,
  FORMS,
  KoblitzCurve,
  LightECC,
  WeierstrassCurve,
  getDefaultCurve,
  listCurveNames,
  mathUtils,
} from '../src';

describe('curve inventory', () => {
  it('exposes the three supported forms with sane defaults', () => {
    expect([...FORMS]).toEqual(['weierstrass', 'edwards', 'koblitz']);
    expect(getDefaultCurve('weierstrass')).toBe('secp256k1');
    expect(getDefaultCurve('edwards')).toBe('ed25519');
    expect(getDefaultCurve('koblitz')).toBe('k163');
  });

  it('lists curves for every form', () => {
    for (const form of FORMS) {
      const names = listCurveNames(form);
      expect(names.length).toBeGreaterThan(0);
      expect([...names].sort()).toEqual(names);
    }
  });

  it('rejects an unknown curve name', () => {
    expect(() => WeierstrassCurve.named('no-such-curve')).toThrow(
      /unsupported weierstrass curve/
    );
    expect(() => EdwardsCurve.named('no-such-curve')).toThrow(
      /unsupported edwards curve/
    );
    expect(() => KoblitzCurve.named('no-such-curve')).toThrow(
      /unsupported koblitz curve/
    );
  });
});

describe.each(['weierstrass', 'edwards', 'koblitz'] as const)(
  '%s arithmetic',
  (form) => {
    const ecc = new LightECC({ formName: form });

    it('places the base point on the curve', () => {
      expect(ecc.curve.isOnCurve(ecc.G)).toBe(true);
      expect(ecc.form).toBe(form);
    });

    it('treats the identity as neutral', () => {
      expect(ecc.O.isIdentity()).toBe(true);
      expect(ecc.G.add(ecc.O).equals(ecc.G)).toBe(true);
      expect(ecc.O.add(ecc.G).equals(ecc.G)).toBe(true);
      expect(ecc.G.multiply(0n).isIdentity()).toBe(true);
    });

    it('cancels a point against its negation', () => {
      expect(ecc.G.add(ecc.G.negate()).isIdentity()).toBe(true);
      expect(ecc.G.sub(ecc.G).isIdentity()).toBe(true);
    });

    it('agrees between doubling and repeated addition', () => {
      const twice = ecc.G.double();
      expect(twice.equals(ecc.G.add(ecc.G))).toBe(true);
      expect(ecc.G.multiply(2n).equals(twice)).toBe(true);

      const thrice = twice.add(ecc.G);
      expect(ecc.G.multiply(3n).equals(thrice)).toBe(true);
      expect(ecc.curve.isOnCurve(thrice)).toBe(true);
    });

    it('is distributive over scalars', () => {
      const five = ecc.G.multiply(5n);
      const seven = ecc.G.multiply(7n);
      expect(five.add(seven).equals(ecc.G.multiply(12n))).toBe(true);
    });

    it('negates a scalar by negating the point', () => {
      expect(ecc.G.multiply(-5n).equals(ecc.G.multiply(5n).negate())).toBe(
        true
      );
    });

    it('annihilates the base point at the curve order', () => {
      expect(
        ecc.G.multiply(ecc.n - 1n)
          .add(ecc.G)
          .isIdentity()
      ).toBe(true);
    });

    it('recovers a small scalar by discrete logarithm', () => {
      expect(ecc.G.multiply(9n).divide(ecc.G)).toBe(9n);
    });

    it('rejects coordinates that are off the curve', () => {
      expect(() =>
        EllipticCurvePoint.create(ecc.G.x + 1n, ecc.G.y, ecc.curve)
      ).toThrow(/is not on curve/);
    });

    it('refuses to mix points from different curves', () => {
      const other = new LightECC({
        formName: form,
        curveName: form === 'weierstrass' ? 'p256' : listCurveNames(form)[0],
      });
      if (other.curve.name !== ecc.curve.name) {
        expect(() => ecc.G.add(other.G)).toThrow(
          /points are not on the same curve/
        );
      }
    });
  }
);

describe('Koblitz binary field', () => {
  const ecc = new LightECC({ formName: 'koblitz', curveName: 'k163' });

  it('uses the reduction polynomial from the coefficient list', () => {
    const curve = ecc.curve as KoblitzCurve;
    expect(curve.m).toBe(163);
    // 163, 7, 6, 3, 0 -> those bits, and only those, are set
    expect(mathUtils.bitLength(curve.modulo)).toBe(164);
    for (const exponent of curve.coefficients) {
      expect((curve.modulo >> BigInt(exponent)) & 1n).toBe(1n);
    }
  });

  it('supports Elliptic Curve ElGamal over a binary field', () => {
    const cs = new EllipticCurveElGamal({ form: 'koblitz', curve: 'k163' });

    const m1 = 10n;
    const m2 = 5n;

    const c1 = cs.encrypt(m1);
    const c2 = cs.encrypt(m2);

    expect(cs.decrypt(c1)).toBe(m1);
    expect(cs.decrypt(c2)).toBe(m2);
    expect(cs.decrypt(cs.add(c1, c2))).toBe(m1 + m2);
    expect(cs.decrypt(cs.multiplyByConstant(c1, m2))).toBe(m1 * m2);

    const reencrypted = cs.reencrypt(c1);
    expect(cs.decrypt(reencrypted)).toBe(m1);

    expect(() => cs.multiply(c1, c2)).toThrow();
    expect(() => cs.xor(c1, c2)).toThrow();
  });
});

describe('F_{p^2} arithmetic', () => {
  const p = 23n; // 23 = 3 (mod 4), so i^2 = -1 has no root in F_p

  it('has a neutral element for each operation', () => {
    const value = new FP2(5n, 7n);
    expect(value.add(FP2.zero(), p).equals(value)).toBe(true);
    expect(value.mul(FP2.one(), p).equals(value)).toBe(true);
    expect(FP2.zero().isZero()).toBe(true);
    expect(FP2.one().isOne()).toBe(true);
  });

  it('inverts every non-zero element', () => {
    const value = new FP2(5n, 7n);
    expect(value.mul(value.inverse(p), p).isOne()).toBe(true);
    expect(() => FP2.zero().inverse(p)).toThrow(/cannot invert zero/);
  });

  it('subtracts as the inverse of addition', () => {
    const a = new FP2(5n, 7n);
    const b = new FP2(11n, 3n);
    expect(a.add(b, p).sub(b, p).equals(a)).toBe(true);
  });

  it('exponentiates by square-and-multiply', () => {
    const value = new FP2(5n, 7n);
    expect(value.exp(0n, p).isOne()).toBe(true);
    expect(value.exp(1n, p).equals(value)).toBe(true);
    expect(value.exp(3n, p).equals(value.mul(value, p).mul(value, p))).toBe(
      true
    );
    // a negative exponent inverts first
    expect(value.exp(-1n, p).equals(value.inverse(p))).toBe(true);
  });

  it('embeds base field elements and unpacks to a tuple', () => {
    expect(FP2.fromBase(9n).toTuple()).toEqual([9n, 0n]);
    expect(new FP2(1n, 2n).toString()).toBe('1 + 2*i');
  });
});

describe('pairings', () => {
  it('computes a Weil pairing over the base field', () => {
    // y^2 = x^3 + x + 1 over F_23, order 28 — the textbook example curve.
    // b != 0, so this takes the plain Weil path rather than the Tate one.
    const ecc = new LightECC({
      formName: 'weierstrass',
      curveName: 'test-curve',
    });
    const r = 7n;

    const cofactor = ecc.n / r;
    const p = ecc.G.multiply(cofactor);
    const q = p.multiply(2n);
    expect(p.multiply(r).isIdentity()).toBe(true);
    expect(q.multiply(r).isIdentity()).toBe(true);

    // E(F_23) is cyclic here, so the whole 7-torsion is generated by P and the
    // pairing of two dependent points is 1 — but the full Miller loop and the
    // auxiliary-point search still run to produce it.
    const result = ecc.pairing(p, q, r);
    expect(result.extended).toBe(false);
    expect(result.base).toBe(1n);

    // The Weil pairing is alternating, so e(P, P) = 1 as well.
    expect(ecc.pairing(p, p, r).base).toBe(1n);
  });

  it('rejects points outside the requested torsion subgroup', () => {
    const ecc = new LightECC({
      formName: 'weierstrass',
      curveName: 'test-curve',
    });
    // G itself has order 28, so it is not a 7-torsion point.
    expect(() => ecc.pairing(ecc.G, ecc.G.multiply(2n), 7n)).toThrow(
      /is not an 7-torsion point/
    );
  });

  it('is bilinear on the supersingular curve BGN uses', () => {
    // y^2 = x^3 + x over F_307, which is 3 (mod 4): supersingular with
    // embedding degree 2, so the pairing lands in F_{p^2}.
    const ecc = new LightECC({
      formName: 'weierstrass',
      curveName: 'ss-weierstrass-307',
    });

    const G = ecc.G;
    const eGG = ecc.pairingFP2(G, G);
    expect(eGG.isZero()).toBe(false);

    // e(aG, bG) = e(G, G)^(ab)
    const a = 3n;
    const b = 5n;
    const paired = ecc.pairingFP2(G.multiply(a), G.multiply(b));
    expect(paired.equals(eGG.exp(a * b, ecc.modulo))).toBe(true);
  });

  it('returns one when either argument is the identity', () => {
    const ecc = new LightECC({
      formName: 'weierstrass',
      curveName: 'ss-weierstrass-307',
    });
    expect(ecc.pairing(ecc.O, ecc.G).base).toBe(1n);
    expect(ecc.pairing(ecc.G, ecc.O).base).toBe(1n);
  });

  it('refuses to pair on a non-Weierstrass curve', () => {
    const ecc = new LightECC({ formName: 'edwards' });
    expect(() => ecc.pairing(ecc.G, ecc.G)).toThrow(
      /pairings need a weierstrass curve/
    );
  });
});

describe('custom curves', () => {
  it('builds a validated custom Weierstrass curve', () => {
    const ecc = new LightECC({
      formName: 'weierstrass',
      curveName: 'custom',
      config: { a: 1n, b: 0n, p: 307n, G: [182n, 240n], n: 77n },
    });
    expect(ecc.name).toBe('custom');
    expect(ecc.curve.isOnCurve(ecc.G)).toBe(true);
    expect(
      ecc.G.multiply(ecc.n - 1n)
        .add(ecc.G)
        .isIdentity()
    ).toBe(true);
  });

  it('rejects a custom curve whose declared order is wrong', () => {
    expect(
      () =>
        new LightECC({
          formName: 'weierstrass',
          curveName: 'custom',
          config: { a: 1n, b: 0n, p: 307n, G: [182n, 240n], n: 76n },
        })
    ).toThrow(/n\*G is not the identity/);
  });

  it('requires a config for a custom curve', () => {
    expect(
      () => new LightECC({ formName: 'weierstrass', curveName: 'custom' })
    ).toThrow(/a custom curve needs a config/);
  });

  it('rejects an unknown form', () => {
    expect(() => new LightECC({ formName: 'hyperbolic' })).toThrow(
      /unsupported curve form/
    );
  });
});
