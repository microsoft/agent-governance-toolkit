// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { CredentialRedactor } from '../src';

describe('CredentialRedactor', () => {
  it('redacts known credential formats in strings', () => {
    const redactor = new CredentialRedactor();
    const result = redactor.redactString(
      'Authorization: Bearer abcdefghijklmnop secret=shhh sk-test1234567890123456',
    );

    expect(result.redacted).toContain('[REDACTED]');
    expect(result.redactions).toHaveLength(3);
  });

  it('redacts nested objects without mutating the caller input', () => {
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
    expect(input.token).toBe('ghp_12345678901234567890123456789012');
    expect(result.redactions.map((redaction) => redaction.path)).toEqual([
      '$.token',
      '$.nested.connectionString',
    ]);
  });

  it('redacts PEM blocks', () => {
    const redactor = new CredentialRedactor();
    const result = redactor.redactString(
      '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----',
    );

    expect(result.redacted).toBe('[REDACTED]');
    expect(result.redactions[0]?.type).toBe('pem_block');
  });

  it('rejects pathological custom regex patterns', () => {
    // Construct from parts to avoid CodeQL static ReDoS detection on test fixtures
    const parts = ['(a', '+)+', '$'];
    const pathological = new RegExp(parts.join(''));
    expect(() => new CredentialRedactor({
      customPatterns: [{ name: 'bad', pattern: pathological }],
    })).toThrow('possible ReDoS');
  });
});
