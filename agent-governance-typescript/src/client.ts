// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { AgentIdentity } from './identity';
import { TrustManager } from './trust';
import { PolicyEngine } from './policy';
import { AuditLogger } from './audit';
import { AgentMeshConfig, GovernanceResult } from './types';

/**
 * Unified client that ties identity, trust, policy, and audit together
 * into a single governance-aware entry point.
 */
export class AgentMeshClient {
  readonly identity: AgentIdentity;
  readonly trust: TrustManager;
  readonly policy: PolicyEngine;
  readonly audit: AuditLogger;

  constructor(config: AgentMeshConfig) {
    this.identity = AgentIdentity.generate(config.agentId, config.capabilities);
    this.trust = new TrustManager(config.trust);
    this.policy = new PolicyEngine(config.policyRules);
    this.audit = new AuditLogger(config.audit);
  }

  /** Convenience factory. */
  static create(
    agentId: string,
    options?: Partial<AgentMeshConfig>,
  ): AgentMeshClient {
    return new AgentMeshClient({ agentId, ...options });
  }

  /**
   * Execute an action through the full governance pipeline:
   * 1. Evaluate policy
   * 2. Check trust score
   * 3. Log to audit trail
   */
  async executeWithGovernance(
    action: string,
    params: Record<string, unknown> = {},
  ): Promise<GovernanceResult> {
    const start = performance.now();

    const decision = this.policy.evaluate(action, params);
    const trustScore = this.trust.getTrustScore(this.identity.did);

    const auditEntry = this.audit.log({
      agentId: this.identity.did,
      action,
      decision,
    });

    if (decision === 'allow') {
      this.trust.recordSuccess(this.identity.did);
    } else if (decision === 'deny') {
      this.trust.recordFailure(this.identity.did);
    }

    const executionTime = Math.round((performance.now() - start) * 1000) / 1000;

    return { decision, trustScore, auditEntry, executionTime };
  }
}
