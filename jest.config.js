/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.test.ts'],
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  // The sources import with explicit `.js` extensions so the ESM build resolves
  // under Node. Map them back to the TypeScript files Jest actually compiles.
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  // Key generation and discrete-log decryption are deliberately expensive.
  testTimeout: 300000,
  collectCoverageFrom: ['src/**/*.ts', '!src/ecc/curves/*Data.ts'],
  coverageDirectory: 'coverage',
  transform: {
    '^.+\\.ts$': ['ts-jest', { tsconfig: 'tsconfig.json' }],
  },
};
