// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
describe('CORS allowlist configuration', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv, VERCEL: '1' };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  test('fails fast when ALLOWED_ORIGINS is configured but invalid', async () => {
    process.env.ALLOWED_ORIGINS = 'ftp://example.com,not-a-url';

    await expect(import('../index')).rejects.toThrow(
      'Invalid ALLOWED_ORIGINS configuration'
    );
  });

  test('boots when ALLOWED_ORIGINS contains at least one valid origin', async () => {
    process.env.ALLOWED_ORIGINS = 'https://github.com,ftp://invalid-origin';

    await expect(import('../index')).resolves.toBeDefined();
  });

  test('boots with secure default allowlist when ALLOWED_ORIGINS is not set', async () => {
    delete process.env.ALLOWED_ORIGINS;

    await expect(import('../index')).resolves.toBeDefined();
  });
});
