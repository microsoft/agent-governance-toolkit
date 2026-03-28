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
});
