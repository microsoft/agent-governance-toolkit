// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  InMemoryMCPNonceStore,
  MCPMessageSigner,
} from '../src';

const SHARED_SECRET = '0123456789abcdef0123456789abcdef';

describe('MCPMessageSigner', () => {
  it('signs and verifies envelopes', async () => {
    const nonceStore = new InMemoryMCPNonceStore();
    const signer = new MCPMessageSigner({
      secret: SHARED_SECRET,
      nonceStore,
    });

    const envelope = signer.sign({ action: 'read_file', path: '/tmp/a' });
    const verification = await signer.verify(envelope);

    expect(verification.valid).toBe(true);
  });

  it('rejects replayed messages', async () => {
    const nonceStore = new InMemoryMCPNonceStore();
    const signer = new MCPMessageSigner({
      secret: SHARED_SECRET,
      nonceStore,
    });

    const envelope = signer.sign({ action: 'read_file' });

    expect((await signer.verify(envelope)).valid).toBe(true);
    expect((await signer.verify(envelope)).valid).toBe(false);
    expect((await signer.verify(envelope)).reason).toContain('Replay');
  });

  it('rejects envelopes outside the allowed clock skew', async () => {
    let now = 1_000;
    const clock = {
      now: () => new Date(now),
      monotonic: () => now,
    };
    const signer = new MCPMessageSigner({
      secret: SHARED_SECRET,
      clock,
      maxClockSkewMs: 100,
    });

    const envelope = signer.sign({ action: 'read_file' });
    now = 5_000;

    const verifier = new MCPMessageSigner({
      secret: SHARED_SECRET,
      clock,
      maxClockSkewMs: 100,
    });
    const verification = await verifier.verify(envelope);

    expect(verification.valid).toBe(false);
    expect(verification.reason).toContain('Timestamp');
  });

  it('rejects tampered payloads', async () => {
    const signer = new MCPMessageSigner({
      secret: SHARED_SECRET,
    });

    const envelope = signer.sign({ action: 'read_file' });
    const tampered = { ...envelope, payload: { action: 'delete_file' } };
    const verification = await signer.verify(tampered);

    expect(verification.valid).toBe(false);
    expect(verification.reason).toContain('Signature mismatch');
  });

  it('rejects undersized HMAC secrets', () => {
    expect(() => new MCPMessageSigner({
      secret: 'too-short',
    })).toThrow('HMAC secret must be at least 32 bytes');
  });

  it('fails closed when nonce verification throws', async () => {
    const signer = new MCPMessageSigner({
      secret: SHARED_SECRET,
      nonceStore: {
        consume: async () => {
          throw new Error('nonce failure');
        },
        reset: () => undefined,
      },
    });

    const envelope = signer.sign({ action: 'read_file' });
    const verification = await signer.verify(envelope);

    expect(verification).toEqual({
      valid: false,
      reason: 'Internal error - message rejected (fail-closed)',
    });
  });
});
