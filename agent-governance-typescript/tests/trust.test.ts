// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { TrustManager } from '../src/trust';
import { AgentIdentity } from '../src/identity';

describe('TrustManager', () => {
  let tm: TrustManager;

  beforeEach(() => {
    tm = new TrustManager({ initialScore: 0.5 });
  });

  describe('getTrustScore()', () => {
    it('returns the initial score for an unknown agent', () => {
      const score = tm.getTrustScore('agent-1');
      expect(score.overall).toBe(0.5);
      expect(score.tier).toBe('Provisional');
    });

    it('includes dimensions', () => {
      const score = tm.getTrustScore('agent-1');
      expect(score.dimensions).toHaveProperty('reliability');
      expect(score.dimensions).toHaveProperty('consistency');
    });
  });

  describe('recordSuccess() / recordFailure()', () => {
    it('increases score on success', () => {
      tm.recordSuccess('agent-1', 0.1);
      const score = tm.getTrustScore('agent-1');
      expect(score.overall).toBeGreaterThan(0.5);
    });

    it('decreases score on failure', () => {
      tm.recordFailure('agent-1', 0.2);
      const score = tm.getTrustScore('agent-1');
      expect(score.overall).toBeLessThan(0.5);
    });

    it('clamps score to [0, 1]', () => {
      for (let i = 0; i < 50; i++) tm.recordSuccess('agent-1', 0.1);
      expect(tm.getTrustScore('agent-1').overall).toBeLessThanOrEqual(1);

      for (let i = 0; i < 100; i++) tm.recordFailure('agent-1', 0.1);
      expect(tm.getTrustScore('agent-1').overall).toBeGreaterThanOrEqual(0);
    });

    it('updates trust tier based on score', () => {
      // Drive score high
      for (let i = 0; i < 20; i++) tm.recordSuccess('agent-1', 0.05);
      expect(['Trusted', 'Verified']).toContain(tm.getTrustScore('agent-1').tier);

      // Drive score low
      for (let i = 0; i < 50; i++) tm.recordFailure('agent-1', 0.1);
      expect(tm.getTrustScore('agent-1').tier).toBe('Untrusted');
    });

    it('tracks reliability across successes and failures', () => {
      tm.recordSuccess('agent-1');
      tm.recordSuccess('agent-1');
      tm.recordFailure('agent-1');
      const score = tm.getTrustScore('agent-1');
      // 2 successes, 1 failure → ~0.667 reliability
      expect(score.dimensions.reliability).toBeCloseTo(0.667, 2);
    });
  });

  describe('verifyPeer()', () => {
    it('verifies a valid peer identity', async () => {
      const peer = AgentIdentity.generate('peer-agent');
      const result = await tm.verifyPeer('peer-agent', peer);
      expect(result.verified).toBe(true);
      expect(result.trustScore).toBeDefined();
      expect(result.reason).toBeUndefined();
    });

    it('returns a trust score in the result', async () => {
      const peer = AgentIdentity.generate('peer-agent');
      tm.recordSuccess('peer-agent', 0.2);
      const result = await tm.verifyPeer('peer-agent', peer);
      expect(result.trustScore.overall).toBeGreaterThan(0.5);
    });
  });

  describe('custom config', () => {
    it('uses custom initial score', () => {
      const custom = new TrustManager({ initialScore: 0.8 });
      expect(custom.getTrustScore('new-agent').overall).toBe(0.8);
    });

    it('uses custom thresholds', () => {
      const custom = new TrustManager({
        initialScore: 0.5,
        thresholds: { untrusted: 0, provisional: 0.2, trusted: 0.4, verified: 0.6 },
      });
      expect(custom.getTrustScore('agent').tier).toBe('Trusted');
    });
  });
});
