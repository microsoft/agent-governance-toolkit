// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Policy Types
 *
 * Type definitions for policy data visualization in the Governance Hub.
 * Mirrors Agent OS PolicyAction enum for consistency.
 */

/** Policy action matching Agent OS PolicyAction enum. */
export type PolicyAction = 'ALLOW' | 'DENY' | 'AUDIT' | 'BLOCK';

/** A single policy rule. */
export interface PolicyRule {
    id: string;
    name: string;
    description: string;
    action: PolicyAction;
    pattern: string;
    scope: 'file' | 'tool' | 'agent' | 'global';
    enabled: boolean;
    evaluationsToday: number;
    violationsToday: number;
}

/** A recorded policy violation. */
export interface PolicyViolation {
    id: string;
    ruleId: string;
    ruleName: string;
    timestamp: Date;
    agentDid?: string;
    file?: string;
    line?: number;
    context: string;
    action: PolicyAction;
}

/** Policy data snapshot. */
export interface PolicySnapshot {
    rules: PolicyRule[];
    recentViolations: PolicyViolation[];
    totalEvaluationsToday: number;
    totalViolationsToday: number;
    /** OWASP ASI coverage map (from agent-failsafe). */
    asiCoverage?: Record<string, { label: string; covered: boolean; feature: string }>;
    /** ISO timestamp of when this data was fetched. */
    fetchedAt?: string;
}

/** Contract for fetching policy data. */
export interface PolicyDataProvider {
    getSnapshot(): Promise<PolicySnapshot>;
}
