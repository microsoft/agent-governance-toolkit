// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { randomUUID } from 'crypto';
import { CircuitBreaker, type CircuitBreakerState } from './metrics';
import type {
  AgentHealthStatus,
  AgentNode,
  BlastRadiusPolicy,
  CascadeAction,
  CascadeAnalysis,
  CascadeContainmentConfig,
  CascadeEvent,
  TrustTier,
} from './types';

const DEFAULT_BLAST_RADIUS_POLICY: BlastRadiusPolicy = {
  maxDependencyDepth: 5,
  maxFanout: 10,
  circuitBreakerThreshold: 5,
  circuitBreakerResetMs: 30_000,
  autoQuarantine: true,
  autoRollback: false,
};

const TIER_DEFAULTS: Record<TrustTier, Partial<BlastRadiusPolicy>> = {
  Untrusted: {
    maxDependencyDepth: 2,
    maxFanout: 3,
    circuitBreakerThreshold: 3,
    autoQuarantine: true,
    autoRollback: true,
  },
  Provisional: {
    maxDependencyDepth: 3,
    maxFanout: 5,
    circuitBreakerThreshold: 4,
    autoQuarantine: true,
    autoRollback: false,
  },
  Trusted: {
    maxDependencyDepth: 5,
    maxFanout: 10,
    circuitBreakerThreshold: 5,
    autoQuarantine: false,
    autoRollback: false,
  },
  Verified: {
    maxDependencyDepth: 8,
    maxFanout: 20,
    circuitBreakerThreshold: 8,
    autoQuarantine: false,
    autoRollback: false,
  },
};

/**
 * Manages cascading failure containment for multi-agent systems (OWASP ASI-08).
 *
 * Tracks agent dependency graphs, maintains per-link circuit breakers,
 * and applies blast radius policies based on trust tier to contain
 * failures before they propagate through the system.
 */
export class CascadeContainmentManager {
  private readonly nodes = new Map<string, AgentNode>();
  private readonly breakers = new Map<string, CircuitBreaker>();
  private readonly events: CascadeEvent[] = [];
  private readonly config: CascadeContainmentConfig;

  constructor(config?: Partial<CascadeContainmentConfig>) {
    this.config = {
      defaultPolicy: { ...DEFAULT_BLAST_RADIUS_POLICY, ...config?.defaultPolicy },
      tierPolicies: config?.tierPolicies,
      cascadeThreshold: config?.cascadeThreshold ?? 3,
    };
  }

  /**
   * Register an agent in the dependency graph.
   */
  registerAgent(agentId: string, trustTier: TrustTier = 'Provisional'): AgentNode {
    if (this.nodes.has(agentId)) {
      return this.nodes.get(agentId)!;
    }

    const node: AgentNode = {
      agentId,
      trustTier,
      healthStatus: 'healthy',
      dependencies: [],
      dependents: [],
      lastHealthCheck: new Date().toISOString(),
    };

    this.nodes.set(agentId, node);
    return node;
  }

  /**
   * Declare a dependency: `fromAgent` depends on `toAgent`.
   * Creates a circuit breaker for this link.
   */
  addDependency(fromAgent: string, toAgent: string): void {
    this.ensureAgent(fromAgent);
    this.ensureAgent(toAgent);

    const from = this.nodes.get(fromAgent)!;
    const to = this.nodes.get(toAgent)!;

    if (!from.dependencies.includes(toAgent)) {
      const policy = this.getPolicyForAgent(fromAgent);

      if (from.dependencies.length >= policy.maxFanout) {
        throw new Error(
          `Agent "${fromAgent}" exceeds max fanout (${policy.maxFanout}) for tier ${from.trustTier}`,
        );
      }

      const depth = this.getDepthTo(toAgent) + 1;
      if (depth > policy.maxDependencyDepth) {
        throw new Error(
          `Dependency depth ${depth} exceeds max (${policy.maxDependencyDepth}) for tier ${from.trustTier}`,
        );
      }

      from.dependencies.push(toAgent);
      to.dependents.push(fromAgent);

      const linkKey = this.linkKey(fromAgent, toAgent);
      if (!this.breakers.has(linkKey)) {
        this.breakers.set(
          linkKey,
          new CircuitBreaker(policy.circuitBreakerThreshold, policy.circuitBreakerResetMs),
        );
      }
    }
  }

  /**
   * Check if an agent can call its dependency (circuit breaker is not open).
   */
  canCall(fromAgent: string, toAgent: string): boolean {
    const breaker = this.breakers.get(this.linkKey(fromAgent, toAgent));
    if (!breaker) return true;
    return breaker.canExecute();
  }

  /**
   * Record a successful call between agents.
   */
  recordSuccess(fromAgent: string, toAgent: string): void {
    const breaker = this.breakers.get(this.linkKey(fromAgent, toAgent));
    if (breaker) {
      breaker.onSuccess();
    }

    const target = this.nodes.get(toAgent);
    if (target && target.healthStatus !== 'healthy') {
      target.healthStatus = 'healthy';
      target.lastHealthCheck = new Date().toISOString();
    }
  }

  /**
   * Record a failed call between agents. May trigger containment actions.
   */
  recordFailure(fromAgent: string, toAgent: string, reason: string = 'call failed'): CascadeEvent[] {
    const triggered: CascadeEvent[] = [];
    const breaker = this.breakers.get(this.linkKey(fromAgent, toAgent));

    if (breaker) {
      breaker.onFailure();

      if (breaker.state === 'open') {
        const evt = this.emitEvent(toAgent, [fromAgent], 'circuit_opened', reason);
        triggered.push(evt);
      }
    }

    // Update health status of target agent
    const target = this.nodes.get(toAgent);
    if (target) {
      const openBreakersToTarget = this.countOpenBreakersTo(toAgent);
      if (openBreakersToTarget >= (this.config.cascadeThreshold ?? 3)) {
        target.healthStatus = 'failing';
      } else if (openBreakersToTarget > 0) {
        target.healthStatus = 'degraded';
      }
      target.lastHealthCheck = new Date().toISOString();
    }

    // Apply containment based on policy
    const containmentEvents = this.applyContainment(toAgent, reason);
    triggered.push(...containmentEvents);

    return triggered;
  }

  /**
   * Propagate health status through dependency graph.
   * When a node fails, its dependents are notified and may degrade.
   */
  propagateHealth(agentId: string): CascadeEvent[] {
    const triggered: CascadeEvent[] = [];
    const node = this.nodes.get(agentId);
    if (!node) return triggered;

    if (node.healthStatus !== 'failing' && node.healthStatus !== 'unreachable') {
      return triggered;
    }

    const affected: string[] = [];
    for (const dependentId of node.dependents) {
      const dependent = this.nodes.get(dependentId);
      if (dependent && dependent.healthStatus === 'healthy') {
        dependent.healthStatus = 'degraded';
        dependent.lastHealthCheck = new Date().toISOString();
        affected.push(dependentId);
      }
    }

    if (affected.length > 0) {
      const evt = this.emitEvent(
        agentId,
        affected,
        'health_propagated',
        `Health degradation propagated from ${agentId}`,
      );
      triggered.push(evt);

      // Recursive propagation for transitive dependents
      for (const affectedId of affected) {
        const deeper = this.propagateHealth(affectedId);
        triggered.push(...deeper);
      }
    }

    return triggered;
  }

  /**
   * Compute the blast radius for a given agent: how many agents would
   * be affected if this agent fails completely.
   */
  computeBlastRadius(agentId: string): number {
    const visited = new Set<string>();
    this.collectDependents(agentId, visited);
    visited.delete(agentId);
    return visited.size;
  }

  /**
   * Analyze the current state of the agent graph for cascade risk.
   */
  analyze(): CascadeAnalysis {
    let healthyAgents = 0;
    let degradedAgents = 0;
    let failingAgents = 0;

    for (const node of this.nodes.values()) {
      switch (node.healthStatus) {
        case 'healthy':
          healthyAgents++;
          break;
        case 'degraded':
          degradedAgents++;
          break;
        case 'failing':
        case 'unreachable':
          failingAgents++;
          break;
      }
    }

    let openCircuitBreakers = 0;
    for (const breaker of this.breakers.values()) {
      if (breaker.state === 'open') {
        openCircuitBreakers++;
      }
    }

    const blastRadiusMap: Record<string, number> = {};
    for (const agentId of this.nodes.keys()) {
      blastRadiusMap[agentId] = this.computeBlastRadius(agentId);
    }

    const totalAgents = this.nodes.size;
    const cascadeRisk = this.assessCascadeRisk(
      failingAgents,
      degradedAgents,
      totalAgents,
      openCircuitBreakers,
    );

    return {
      totalAgents,
      healthyAgents,
      degradedAgents,
      failingAgents,
      openCircuitBreakers,
      cascadeRisk,
      blastRadiusMap,
      events: [...this.events],
    };
  }

  /**
   * Get the dependency graph as a list of agent nodes.
   */
  getGraph(): AgentNode[] {
    return [...this.nodes.values()].map((n) => ({ ...n }));
  }

  /**
   * Get the circuit breaker state for a specific link.
   */
  getBreakerState(fromAgent: string, toAgent: string): CircuitBreakerState | undefined {
    return this.breakers.get(this.linkKey(fromAgent, toAgent))?.state;
  }

  /**
   * Get all containment events.
   */
  getEvents(): CascadeEvent[] {
    return [...this.events];
  }

  /**
   * Get the effective blast radius policy for an agent.
   */
  getPolicyForAgent(agentId: string): BlastRadiusPolicy {
    const node = this.nodes.get(agentId);
    const tier = node?.trustTier ?? 'Provisional';
    return this.getPolicyForTier(tier);
  }

  /**
   * Get the effective blast radius policy for a trust tier.
   */
  getPolicyForTier(tier: TrustTier): BlastRadiusPolicy {
    const tierOverrides = this.config.tierPolicies?.[tier] ?? TIER_DEFAULTS[tier];
    return { ...this.config.defaultPolicy, ...tierOverrides };
  }

  /**
   * Reset a specific agent back to healthy status.
   */
  resetAgent(agentId: string): void {
    const node = this.nodes.get(agentId);
    if (node) {
      node.healthStatus = 'healthy';
      node.lastHealthCheck = new Date().toISOString();
    }
  }

  // ── Internal helpers ──

  private ensureAgent(agentId: string): void {
    if (!this.nodes.has(agentId)) {
      this.registerAgent(agentId);
    }
  }

  private linkKey(from: string, to: string): string {
    return `${from}->${to}`;
  }

  private countOpenBreakersTo(agentId: string): number {
    const node = this.nodes.get(agentId);
    if (!node) return 0;

    let count = 0;
    for (const depId of node.dependents) {
      const breaker = this.breakers.get(this.linkKey(depId, agentId));
      if (breaker && breaker.state === 'open') {
        count++;
      }
    }
    return count;
  }

  private getDepthTo(agentId: string, visited = new Set<string>()): number {
    if (visited.has(agentId)) return 0;
    visited.add(agentId);

    const node = this.nodes.get(agentId);
    if (!node || node.dependencies.length === 0) return 0;

    let maxDepth = 0;
    for (const dep of node.dependencies) {
      maxDepth = Math.max(maxDepth, 1 + this.getDepthTo(dep, visited));
    }
    return maxDepth;
  }

  private collectDependents(agentId: string, visited: Set<string>): void {
    if (visited.has(agentId)) return;
    visited.add(agentId);

    const node = this.nodes.get(agentId);
    if (!node) return;

    for (const depId of node.dependents) {
      this.collectDependents(depId, visited);
    }
  }

  private applyContainment(agentId: string, reason: string): CascadeEvent[] {
    const triggered: CascadeEvent[] = [];
    const node = this.nodes.get(agentId);
    if (!node) return triggered;

    const policy = this.getPolicyForAgent(agentId);

    if (node.healthStatus === 'failing' && policy.autoQuarantine) {
      node.healthStatus = 'unreachable';
      const evt = this.emitEvent(
        agentId,
        [agentId],
        'agent_quarantined',
        `Auto-quarantined: ${reason}`,
      );
      triggered.push(evt);

      // Propagate health to dependents
      const propagated = this.propagateHealth(agentId);
      triggered.push(...propagated);
    }

    if (node.healthStatus === 'unreachable' && policy.autoRollback) {
      const evt = this.emitEvent(
        agentId,
        [agentId],
        'rollback_triggered',
        `Auto-rollback triggered: ${reason}`,
      );
      triggered.push(evt);
    }

    return triggered;
  }

  private assessCascadeRisk(
    failing: number,
    degraded: number,
    total: number,
    openBreakers: number,
  ): 'low' | 'medium' | 'high' | 'critical' {
    if (total === 0) return 'low';

    const failRatio = failing / total;
    const degradeRatio = degraded / total;

    if (failRatio >= 0.3 || openBreakers >= 5) return 'critical';
    if (failRatio >= 0.15 || degradeRatio >= 0.3) return 'high';
    if (failRatio > 0 || degradeRatio >= 0.15) return 'medium';
    return 'low';
  }

  private emitEvent(
    sourceAgentId: string,
    affectedAgentIds: string[],
    action: CascadeAction,
    reason: string,
  ): CascadeEvent {
    const blastRadius = this.computeBlastRadius(sourceAgentId);
    const event: CascadeEvent = {
      eventId: randomUUID(),
      timestamp: new Date().toISOString(),
      sourceAgentId,
      affectedAgentIds,
      action,
      reason,
      blastRadius,
      containedAt: this.events.length,
    };
    this.events.push(event);
    return event;
  }
}
