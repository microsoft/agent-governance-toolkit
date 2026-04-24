// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { GovernanceMetrics } from '../src/metrics';

describe('GovernanceMetrics', () => {
  it('should default to disabled', () => {
    const m = new GovernanceMetrics();
    expect((m as any).enabled).toBe(false);
  });

  it('should accept enabled flag', () => {
    const m = new GovernanceMetrics(true);
    expect((m as any).enabled).toBe(true);
  });

  it('should not throw on recordPolicyDecision', () => {
    const m = new GovernanceMetrics(true);
    expect(() => m.recordPolicyDecision('allow', 1.5)).not.toThrow();
  });

  it('should not throw on recordTrustScore', () => {
    const m = new GovernanceMetrics(true);
    expect(() => m.recordTrustScore('agent-1', 750)).not.toThrow();
  });

  it('should not throw on recordAuditEntry', () => {
    const m = new GovernanceMetrics(true);
    expect(() => m.recordAuditEntry(42)).not.toThrow();
  });
});
