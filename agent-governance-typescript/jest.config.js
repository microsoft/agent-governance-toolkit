// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.test.ts'],
  collectCoverageFrom: ['src/**/*.ts'],
  coverageDirectory: 'coverage',
  moduleNameMapper: {
    '^@noble/curves/(.+?)(\\.js)?$': '<rootDir>/node_modules/@noble/curves/$1.js',
    '^@noble/hashes/(.+?)(\\.js)?$': '<rootDir>/node_modules/@noble/hashes/$1.js',
    '^@noble/ciphers/(.+?)(\\.js)?$': '<rootDir>/node_modules/@noble/ciphers/$1.js',
  },
  transformIgnorePatterns: [
    'node_modules/(?!(@noble)/)',
  ],
  transform: {
    '^.+\\.tsx?$': ['@swc/jest', {
      jsc: { parser: { syntax: 'typescript' }, target: 'es2022' },
      module: { type: 'commonjs' },
    }],
    '^.+\\.js$': ['@swc/jest', {
      jsc: { target: 'es2022' },
      module: { type: 'commonjs' },
    }],
  },
};
