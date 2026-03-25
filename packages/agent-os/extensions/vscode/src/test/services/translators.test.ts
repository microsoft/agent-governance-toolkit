// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import * as assert from 'assert';
import {
    translateSLOSnapshot,
    translateAvailability,
    translateLatency,
    translateCompliance,
    translateTrustScore,
    translateAgent,
    translateBridge,
    translateDelegation,
    translatePolicySnapshot,
    translatePolicyRule,
    translatePolicyViolation,
    mapTrustToRing,
} from '../../services/translators';
import { ExecutionRing } from '../../views/topologyTypes';

suite('translators', () => {
    suite('translateSLOSnapshot', () => {
        test('maps all 4 sections correctly', () => {
            const raw = {
                task_success_rate: { value: 0.9982, target: 0.995, compliance: 0.99 },
                response_latency: { value: 145, target: 5000, p50: 120, p95: 350, p99: 890 },
                policy_compliance: { value: 0.998, target: 1.0, compliance: 0.998 },
                trust_scores: { mean: 720, min: 340, below_threshold: 1, distribution: [2, 5, 15, 28] },
            };
            const snap = translateSLOSnapshot(raw);
            assert.strictEqual(snap.availability.currentPercent, 99.82);
            assert.strictEqual(snap.availability.targetPercent, 99.5);
            assert.strictEqual(snap.latency.p50Ms, 120);
            assert.strictEqual(snap.latency.p95Ms, 350);
            assert.strictEqual(snap.latency.p99Ms, 890);
            assert.strictEqual(snap.latency.targetMs, 5000);
            assert.strictEqual(snap.policyCompliance.compliancePercent, 99.8);
            assert.strictEqual(snap.trustScore.meanScore, 720);
            assert.strictEqual(snap.trustScore.minScore, 340);
            assert.strictEqual(snap.trustScore.agentsBelowThreshold, 1);
            assert.deepStrictEqual(snap.trustScore.distribution, [2, 5, 15, 28]);
        });

        test('returns safe defaults for null input', () => {
            const snap = translateSLOSnapshot(null);
            assert.strictEqual(typeof snap.availability.currentPercent, 'number');
            assert.strictEqual(typeof snap.latency.p50Ms, 'number');
            assert.strictEqual(snap.policyCompliance.trend, 'stable');
            assert.deepStrictEqual(snap.trustScore.distribution, [0, 0, 0, 0]);
        });
    });

    suite('mapTrustToRing', () => {
        test('returns Ring3Sandbox for score < 400', () => {
            assert.strictEqual(mapTrustToRing(0), ExecutionRing.Ring3Sandbox);
            assert.strictEqual(mapTrustToRing(399), ExecutionRing.Ring3Sandbox);
        });

        test('returns Ring2User for score 400-699', () => {
            assert.strictEqual(mapTrustToRing(400), ExecutionRing.Ring2User);
            assert.strictEqual(mapTrustToRing(699), ExecutionRing.Ring2User);
        });

        test('returns Ring1Supervisor for score 700-899', () => {
            assert.strictEqual(mapTrustToRing(700), ExecutionRing.Ring1Supervisor);
            assert.strictEqual(mapTrustToRing(899), ExecutionRing.Ring1Supervisor);
        });

        test('returns Ring0Root for score >= 900', () => {
            assert.strictEqual(mapTrustToRing(900), ExecutionRing.Ring0Root);
            assert.strictEqual(mapTrustToRing(1000), ExecutionRing.Ring0Root);
        });
    });

    suite('translateAgent', () => {
        test('maps Python dict to AgentNode with correct ring', () => {
            const raw = {
                did: 'did:mesh:abc123',
                trust_score: 720,
                created_at: '2026-03-20T08:00:00Z',
                last_activity: '2026-03-24T10:00:00Z',
                capabilities: ['read', 'write'],
            };
            const agent = translateAgent(raw);
            assert.strictEqual(agent.did, 'did:mesh:abc123');
            assert.strictEqual(agent.trustScore, 720);
            assert.strictEqual(agent.ring, ExecutionRing.Ring1Supervisor);
            assert.strictEqual(agent.registeredAt, '2026-03-20T08:00:00Z');
            assert.deepStrictEqual(agent.capabilities, ['read', 'write']);
        });

        test('returns safe defaults for missing fields', () => {
            const agent = translateAgent(null);
            assert.strictEqual(agent.did, '');
            assert.strictEqual(agent.trustScore, 500);
            assert.strictEqual(agent.ring, ExecutionRing.Ring2User);
            assert.strictEqual(agent.registeredAt, '');
            assert.deepStrictEqual(agent.capabilities, []);
        });
    });

    suite('translateBridge', () => {
        test('maps protocol, connected, peerCount', () => {
            const bridge = translateBridge({ protocol: 'A2A', connected: true, peer_count: 5 });
            assert.strictEqual(bridge.protocol, 'A2A');
            assert.strictEqual(bridge.connected, true);
            assert.strictEqual(bridge.peerCount, 5);
        });

        test('returns defaults for null input', () => {
            const bridge = translateBridge(null);
            assert.strictEqual(bridge.protocol, 'unknown');
            assert.strictEqual(bridge.connected, false);
            assert.strictEqual(bridge.peerCount, 0);
        });
    });

    suite('translateDelegation', () => {
        test('maps from_did to fromDid, to_did to toDid', () => {
            const deleg = translateDelegation({
                from_did: 'did:mesh:abc',
                to_did: 'did:mesh:def',
                capability: 'read',
                expires_in: '2h',
            });
            assert.strictEqual(deleg.fromDid, 'did:mesh:abc');
            assert.strictEqual(deleg.toDid, 'did:mesh:def');
            assert.strictEqual(deleg.capability, 'read');
            assert.strictEqual(deleg.expiresIn, '2h');
        });
    });

    suite('translatePolicySnapshot', () => {
        test('maps rules and violations, includes totals', () => {
            const raw = {
                rules: [{ id: 'r1', name: 'Block Secrets', action: 'block', evaluations_today: 342 }],
                recent_violations: [{ id: 'v1', rule_id: 'r1', timestamp: '2026-03-24T12:00:00Z', action: 'block' }],
                total_evaluations_today: 615,
                total_violations_today: 3,
            };
            const snap = translatePolicySnapshot(raw);
            assert.strictEqual(snap.rules.length, 1);
            assert.strictEqual(snap.recentViolations.length, 1);
            assert.strictEqual(snap.totalEvaluationsToday, 615);
            assert.strictEqual(snap.totalViolationsToday, 3);
        });

        test('returns empty arrays for null input', () => {
            const snap = translatePolicySnapshot(null);
            assert.deepStrictEqual(snap.rules, []);
            assert.deepStrictEqual(snap.recentViolations, []);
            assert.strictEqual(snap.totalEvaluationsToday, 0);
        });
    });

    suite('translatePolicyRule', () => {
        test('normalizes action to uppercase', () => {
            const rule = translatePolicyRule({ id: 'r1', action: 'block' });
            assert.strictEqual(rule.action, 'BLOCK');
        });

        test('defaults invalid action to DENY', () => {
            const rule = translatePolicyRule({ id: 'r1', action: 'nope' });
            assert.strictEqual(rule.action, 'DENY');
        });
    });

    suite('translatePolicyViolation', () => {
        test('parses timestamp string to Date', () => {
            const v = translatePolicyViolation({
                id: 'v1',
                timestamp: '2026-03-24T12:30:00Z',
                action: 'deny',
            });
            assert.ok(v.timestamp instanceof Date);
            assert.strictEqual(v.timestamp.toISOString(), '2026-03-24T12:30:00.000Z');
        });

        test('returns epoch Date for missing timestamp', () => {
            const v = translatePolicyViolation({});
            assert.strictEqual(v.timestamp.getTime(), 0);
        });
    });
});
