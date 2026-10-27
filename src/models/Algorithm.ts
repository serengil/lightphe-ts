/** User-facing names of the cryptosystems LightPHE implements. */
export const Algorithm = {
  RSA: 'RSA',
  ElGamal: 'ElGamal',
  ExponentialElGamal: 'Exponential-ElGamal',
  EllipticCurveElGamal: 'EllipticCurve-ElGamal',
  Paillier: 'Paillier',
  DamgardJurik: 'Damgard-Jurik',
  OkamotoUchiyama: 'Okamoto-Uchiyama',
  Benaloh: 'Benaloh',
  NaccacheStern: 'Naccache-Stern',
  GoldwasserMicali: 'Goldwasser-Micali',
  SanderYoungYung: 'Sander-Young-Yung',
  BonehGohNissim: 'Boneh-Goh-Nissim',
  JoyeLibert: 'Joye-Libert',
  CastagnosLaguillaumie: 'Castagnos-Laguillaumie',
  IshaiPaskin: 'Ishai-Paskin',
  DamgardGeislerKroigaard: 'Damgard-Geisler-Kroigaard',
  BressonCatalanoPointcheval: 'Bresson-Catalano-Pointcheval',
  CamenischShoup: 'Camenisch-Shoup',
  EllipticCurvePaillier: 'EllipticCurve-Paillier',
  Regev: 'Regev',
  BrakerskiVaikuntanathan: 'Brakerski-Vaikuntanathan',
  FreemanBonehGohNissim: 'Freeman-Boneh-Goh-Nissim',
  GentryHaleviVaikuntanathan: 'Gentry-Halevi-Vaikuntanathan',
  LyubashevskyPeikertRegev: 'Lyubashevsky-Peikert-Regev',
  MLKEM: 'ML-KEM',
  GentrySahaiWaters: 'Gentry-Sahai-Waters',
} as const;

/** The name of any algorithm LightPHE can build a cryptosystem for. */
export type AlgorithmName = (typeof Algorithm)[keyof typeof Algorithm];

/** Every supported algorithm name, in the order the README lists them. */
export const ALGORITHM_NAMES: readonly AlgorithmName[] =
  Object.values(Algorithm);
