// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: 'ts-jest',
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
    '^.+\\.tsx?$': 'ts-jest',
    '.*@noble.+\\.js$': ['ts-jest', { tsconfig: { allowJs: true } }],
  },
};
