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
  testPathIgnorePatterns: ['/node_modules/', '/dist/'],
};
