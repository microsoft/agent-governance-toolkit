// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { AgentIdentity } from './identity';
import { TrustManager } from './trust';
import { PolicyEngine } from './policy';
import { AuditLogger } from './audit';
import { AgentMeshConfig, GovernanceResult } from './types';
import { KillSwitch } from './kill-switch';
import { LifecycleManager, LifecycleState } from './lifecycle';
import { RingBreachError, RingEnforcer } from './rings';

/**
 * Unified client that ties identity, trust, policy, and audit together
 * into a single governance-aware entry point.
 */
export class AgentMeshClient {
  readonly identity: AgentIdentity;
  readonly trust: TrustManager;
  readonly policy: PolicyEngine;
  readonly audit: AuditLogger;
  readonly lifecycle: LifecycleManager;
  readonly ringEnforcer: RingEnforcer;
  readonly killSwitch?: KillSwitch;
  private readonly quarantineOnBreach: boolean;
  private readonly killOnBreach: boolean;

  constructor(config: AgentMeshConfig) {
    this.identity = AgentIdentity.generate(config.agentId, config.capabilities);
    this.trust = new TrustManager(config.trust);
    this.policy = new PolicyEngine(config.policyRules);
    this.audit = new AuditLogger(config.audit);
    this.lifecycle = new LifecycleManager(this.identity.did);
    this.ringEnforcer = new RingEnforcer(config.execution);
    this.quarantineOnBreach = config.execution?.quarantineOnBreach ?? true;
    this.killOnBreach = config.execution?.killOnBreach ?? false;
    this.killSwitch = config.killSwitch?.enabled === false ? undefined : new KillSwitch(config.killSwitch);
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

    if (this.lifecycle.state === LifecycleState.Provisioning) {
      this.lifecycle.activate('Governance pipeline initialized');
    }

    try {
      this.ringEnforcer.enforce(action);
    } catch (error) {
      if (error instanceof RingBreachError) {
        let lifecycleReason = error.message;
        if (this.quarantineOnBreach && this.lifecycle.canTransition(LifecycleState.Quarantined)) {
          this.lifecycle.quarantine(error.message);
        }

        const killSwitchResult = this.killOnBreach && this.killSwitch
          ? await this.killSwitch.kill(this.identity.did, {
              action,
              reason: error.message,
            })
          : undefined;

        const auditEntry = this.audit.log({
          agentId: this.identity.did,
          action,
          decision: 'deny',
        });

        this.trust.recordFailure(this.identity.did);

        return {
          decision: 'deny',
          trustScore: this.trust.getTrustScore(this.identity.did),
          auditEntry,
          executionTime: Math.round((performance.now() - start) * 1000) / 1000,
          ringViolation: error.violation,
          killSwitchResult,
          lifecycleState: this.lifecycle.state,
          lifecycleReason,
        };
      }

      throw error;
    }

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

    return {
      decision,
      trustScore,
      auditEntry,
      executionTime,
      lifecycleState: this.lifecycle.state,
    };
  }
}
