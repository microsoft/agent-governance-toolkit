// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { CredentialRedactor } from '../src/credential-redactor';

describe('CredentialRedactor', () => {
  it('redacts known credential formats in nested objects', () => {
    const redactor = new CredentialRedactor();
    const input = {
      token: 'ghp_12345678901234567890123456789012',
      nested: {
        connectionString: 'AccountKey=abc123',
      },
    };

    const result = redactor.redact(input);

    expect(result.redacted).toEqual({
      token: '[REDACTED]',
      nested: {
        connectionString: '[REDACTED]',
      },
    });
    expect(result.redactions.map((item) => item.path)).toEqual([
      '$.token',
      '$.nested.connectionString',
    ]);
  });

  it('redacts full PEM blocks instead of only the header line', () => {
    const redactor = new CredentialRedactor();
    const pem = '-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----';

    const result = redactor.redact({
      keyMaterial: pem,
    });

    expect(result.redacted).toEqual({
      keyMaterial: '[REDACTED]',
    });
    expect(result.redactions[0]?.type).toBe('pem_block');
  });

  it('rejects pathological custom regex patterns', () => {
    expect(() => new CredentialRedactor({
      // codeql-suppress js/polynomial-redos -- Intentionally pathological regex to test validateRegex rejection
      customPatterns: [{ name: 'bad', pattern: /(a+)+$/ }],
    })).toThrow('possible ReDoS');
  });
});
