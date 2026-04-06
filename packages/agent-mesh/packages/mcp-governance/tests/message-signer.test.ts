// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { McpMessageSigner } from '../src/message-signer';
import { InMemoryNonceStore } from '../src/stores';

class FakeClock {
  constructor(private current: Date) {}
  now(): Date { return this.current; }
  monotonic(): number { return this.current.getTime(); }
  advance(ms: number): void { this.current = new Date(this.current.getTime() + ms); }
}

describe('McpMessageSigner', () => {
  it('verifies signed envelopes and blocks replay', async () => {
    const signer = new McpMessageSigner({
      secret: 'shared-secret',
    });

    const envelope = signer.sign({ action: 'read' });

    expect((await signer.verify(envelope)).valid).toBe(true);
    expect((await signer.verify(envelope)).valid).toBe(false);
  });

  it('serializes concurrent replay checks', async () => {
    const signer = new McpMessageSigner({
      secret: 'shared-secret',
    });
    const envelope = signer.sign({ action: 'read' });

    const results = await Promise.all([
      signer.verify(envelope),
      signer.verify(envelope),
    ]);

    expect(results.filter((result) => result.valid)).toHaveLength(1);
    expect(results.filter((result) => !result.valid)).toHaveLength(1);
  });

  it('evicts the oldest nonce entries when the cache is full', async () => {
    const clock = new FakeClock(new Date('2026-01-01T00:00:00Z'));
    const nonceStore = new InMemoryNonceStore(clock, 2);
    const signer = new McpMessageSigner({
      secret: 'shared-secret',
      clock,
      nonceStore,
      maxNonceEntries: 2,
    });

    const first = signer.sign({ action: 'first' });
    clock.advance(1);
    const second = signer.sign({ action: 'second' });
    clock.advance(1);
    const third = signer.sign({ action: 'third' });

    await signer.verify(first);
    await signer.verify(second);
    await signer.verify(third);

    expect(await nonceStore.has(`default:${first.nonce}`)).toBe(false);
    expect(await nonceStore.has(`default:${second.nonce}`)).toBe(true);
    expect(await nonceStore.has(`default:${third.nonce}`)).toBe(true);
  });
});
