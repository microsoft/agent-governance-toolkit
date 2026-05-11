// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { AuditLogger } from '../src/audit';

describe('AuditLogger', () => {
  let logger: AuditLogger;

  beforeEach(() => {
    logger = new AuditLogger();
  });

  describe('log()', () => {
    it('creates an entry with timestamp and hashes', () => {
      const entry = logger.log({
        agentId: 'agent-1',
        action: 'data.read',
        decision: 'allow',
      });

      expect(entry.timestamp).toBeDefined();
      expect(entry.hash).toHaveLength(64); // SHA-256 hex
      expect(entry.previousHash).toHaveLength(64);
      expect(entry.agentId).toBe('agent-1');
      expect(entry.action).toBe('data.read');
      expect(entry.decision).toBe('allow');
    });

    it('chains entries with previous hashes', () => {
      const first = logger.log({ agentId: 'a', action: 'x', decision: 'allow' });
      const second = logger.log({ agentId: 'b', action: 'y', decision: 'deny' });

      expect(second.previousHash).toBe(first.hash);
    });

    it('first entry uses genesis hash', () => {
      const entry = logger.log({ agentId: 'a', action: 'x', decision: 'allow' });
      expect(entry.previousHash).toBe('0'.repeat(64));
    });
  });

  describe('verify()', () => {
    it('returns true for an empty log', () => {
      expect(logger.verify()).toBe(true);
    });

    it('returns true for a valid chain', () => {
      logger.log({ agentId: 'a', action: 'x', decision: 'allow' });
      logger.log({ agentId: 'b', action: 'y', decision: 'deny' });
      logger.log({ agentId: 'c', action: 'z', decision: 'review' });

      expect(logger.verify()).toBe(true);
    });

    it('detects tampering', () => {
      logger.log({ agentId: 'a', action: 'x', decision: 'allow' });
      logger.log({ agentId: 'b', action: 'y', decision: 'deny' });

      // Tamper with the internal state via JSON export/reimport hack
      const entries = JSON.parse(logger.exportJSON());
      entries[0].action = 'TAMPERED';

      // Create a new logger and inject tampered entries
      const tampered = new AuditLogger();
      // Access private field for testing
      (tampered as any).entries = entries;

      expect(tampered.verify()).toBe(false);
    });
  });

  describe('getEntries()', () => {
    beforeEach(() => {
      logger.log({ agentId: 'agent-1', action: 'data.read', decision: 'allow' });
      logger.log({ agentId: 'agent-2', action: 'data.write', decision: 'deny' });
      logger.log({ agentId: 'agent-1', action: 'data.delete', decision: 'review' });
    });

    it('returns all entries without filter', () => {
      expect(logger.getEntries()).toHaveLength(3);
    });

    it('filters by agentId', () => {
      const entries = logger.getEntries({ agentId: 'agent-1' });
      expect(entries).toHaveLength(2);
      entries.forEach((e) => expect(e.agentId).toBe('agent-1'));
    });

    it('filters by action', () => {
      const entries = logger.getEntries({ action: 'data.write' });
      expect(entries).toHaveLength(1);
      expect(entries[0].decision).toBe('deny');
    });

    it('filters by date', () => {
      const past = new Date(Date.now() - 60_000);
      const entries = logger.getEntries({ since: past });
      expect(entries).toHaveLength(3);

      const future = new Date(Date.now() + 60_000);
      expect(logger.getEntries({ since: future })).toHaveLength(0);
    });
  });

  describe('exportJSON()', () => {
    it('exports valid JSON', () => {
      logger.log({ agentId: 'a', action: 'x', decision: 'allow' });
      const json = logger.exportJSON();
      const parsed = JSON.parse(json);
      expect(Array.isArray(parsed)).toBe(true);
      expect(parsed).toHaveLength(1);
    });
  });

  describe('maxEntries', () => {
    it('evicts old entries when limit is exceeded', () => {
      const small = new AuditLogger({ maxEntries: 3 });
      for (let i = 0; i < 5; i++) {
        small.log({ agentId: `a${i}`, action: 'x', decision: 'allow' });
      }
      expect(small.length).toBe(3);
    });

    it('verify() returns true after rollover eviction', () => {
      const small = new AuditLogger({ maxEntries: 3 });
      for (let i = 0; i < 10; i++) {
        small.log({ agentId: `a${i}`, action: 'x', decision: 'allow' });
      }
      expect(small.length).toBe(3);
      expect(small.verify()).toBe(true);
    });

    it('detects tampering of the surviving head after rollover eviction', () => {
      const small = new AuditLogger({ maxEntries: 3 });
      for (let i = 0; i < 10; i++) {
        small.log({ agentId: `a${i}`, action: 'x', decision: 'allow' });
      }
      // Replace the surviving head's previousHash with a bogus value — the
      // seam from the evicted prefix should still be checked.
      const entries = (small as any).entries as Array<{ previousHash: string }>;
      entries[0].previousHash = '0'.repeat(64);
      expect(small.verify()).toBe(false);
    });
  });
});
