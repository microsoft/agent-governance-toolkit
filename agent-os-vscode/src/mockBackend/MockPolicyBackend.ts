// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Mock Policy Backend
 *
 * Simulates policy data for development.
 * Implements PolicyDataProvider interface for swappable backends.
 */

import {
    PolicyDataProvider,
    PolicySnapshot,
    PolicyRule,
    PolicyViolation
} from '../views/policyTypes';

const MOCK_RULES: PolicyRule[] = [
    {
        id: 'rule-001',
        name: 'Block Secret Patterns',
        description: 'Deny file writes containing API keys or secrets',
        action: 'BLOCK',
        pattern: '(?i)(api[_-]?key|secret|password)\\s*=',
        scope: 'file',
        enabled: true,
        evaluationsToday: 342,
        violationsToday: 2,
    },
    {
        id: 'rule-002',
        name: 'Audit External URLs',
        description: 'Log all HTTP requests to external domains',
        action: 'AUDIT',
        pattern: 'https?://(?!localhost)',
        scope: 'tool',
        enabled: true,
        evaluationsToday: 156,
        violationsToday: 0,
    },
    {
        id: 'rule-003',
        name: 'Sandbox New Agents',
        description: 'Force Ring 3 for agents with trust score < 400',
        action: 'ALLOW',
        pattern: 'trustScore < 400',
        scope: 'agent',
        enabled: true,
        evaluationsToday: 28,
        violationsToday: 0,
    },
    {
        id: 'rule-004',
        name: 'Deny Shell Commands',
        description: 'Block direct shell execution outside approved tools',
        action: 'DENY',
        pattern: 'exec|spawn|system|shell',
        scope: 'tool',
        enabled: true,
        evaluationsToday: 89,
        violationsToday: 1,
    },
    {
        id: 'rule-005',
        name: 'Require CMVK for Destructive',
        description: 'Require multi-model review for delete operations',
        action: 'AUDIT',
        pattern: 'delete|remove|drop|truncate',
        scope: 'file',
        enabled: false,
        evaluationsToday: 0,
        violationsToday: 0,
    },
];

/** Create mock violations based on current time. */
function createMockViolations(): PolicyViolation[] {
    return [
        {
            id: 'viol-001',
            ruleId: 'rule-001',
            ruleName: 'Block Secret Patterns',
            timestamp: new Date(Date.now() - 1800000),
            file: 'src/config.ts',
            line: 42,
            context: 'API_KEY = "sk-..."',
            action: 'BLOCK',
        },
        {
            id: 'viol-002',
            ruleId: 'rule-004',
            ruleName: 'Deny Shell Commands',
            timestamp: new Date(Date.now() - 3600000),
            agentDid: 'did:mesh:f1e2d3c4b5a6...',
            context: 'exec("rm -rf /")',
            action: 'DENY',
        },
    ];
}

/** Create a mock policy data provider. */
export function createMockPolicyBackend(): PolicyDataProvider {
    return {
        async getSnapshot(): Promise<PolicySnapshot> {
            const rules = MOCK_RULES.map(r => {
                if (!r.enabled) { return { ...r }; }
                return {
                    ...r,
                    violationsToday: r.violationsToday + (Math.random() < 0.1 ? 1 : 0),
                    evaluationsToday: r.evaluationsToday + Math.floor(Math.random() * 5),
                };
            });

            const recentViolations = createMockViolations();

            return {
                rules,
                recentViolations,
                totalEvaluationsToday: rules.reduce((s, r) => s + r.evaluationsToday, 0),
                totalViolationsToday: rules.reduce((s, r) => s + r.violationsToday, 0),
            };
        },
    };
}
