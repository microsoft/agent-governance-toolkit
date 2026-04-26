// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Report Generator Tests
 *
 * Unit tests for the governance report generator.
 */

import * as assert from 'assert';
import { ReportGenerator, ReportData } from '../../export/ReportGenerator';
import { SLOSnapshot } from '../../views/sloTypes';
import { AgentNode, BridgeStatus, DelegationChain, ExecutionRing } from '../../views/topologyTypes';

suite('ReportGenerator', () => {
    let generator: ReportGenerator;
    let mockReportData: ReportData;

    setup(() => {
        generator = new ReportGenerator();

        const sloSnapshot: SLOSnapshot = {
            availability: {
                currentPercent: 99.9,
                targetPercent: 99.5,
                errorBudgetRemainingPercent: 80,
                burnRate: 1.2,
            },
            latency: {
                p50Ms: 45,
                p95Ms: 120,
                p99Ms: 250,
                targetMs: 300,
                errorBudgetRemainingPercent: 65,
            },
            policyCompliance: {
                totalEvaluations: 1500,
                violationsToday: 3,
                compliancePercent: 99.8,
                trend: 'up',
            },
            trustScore: {
                meanScore: 820,
                minScore: 450,
                agentsBelowThreshold: 1,
                distribution: [2, 5, 12, 25],
            },
        };

        const agents: AgentNode[] = [
            {
                did: 'did:mesh:test1',
                trustScore: 900,
                ring: ExecutionRing.Ring1Supervisor,
                registeredAt: '2026-03-20T00:00:00Z',
                lastActivity: '2026-03-22T12:00:00Z',
                capabilities: ['tool_call'],
            },
        ];

        const bridges: BridgeStatus[] = [
            { protocol: 'A2A', connected: true, peerCount: 3 },
        ];

        const delegations: DelegationChain[] = [];

        mockReportData = {
            sloSnapshot,
            agents,
            bridges,
            delegations,
            auditEvents: [
                { timestamp: new Date(), type: 'test', details: { action: 'allowed' } },
            ],
            timeRange: {
                start: new Date('2026-03-21T00:00:00Z'),
                end: new Date('2026-03-22T00:00:00Z'),
            },
        };
    });

    test('generates valid HTML', () => {
        const html = generator.generate(mockReportData);

        assert.ok(html.startsWith('<!DOCTYPE html>'));
        assert.ok(html.includes('<html'));
        assert.ok(html.includes('</html>'));
    });

    test('embeds data as JSON script tag', () => {
        const html = generator.generate(mockReportData);

        assert.ok(html.includes('type="application/json"'));
        assert.ok(html.includes('report-data'));
    });

    test('includes Chart.js CDN reference', () => {
        const html = generator.generate(mockReportData);

        assert.ok(html.includes('chart.js') || html.includes('Chart'));
    });

    test('includes timestamp watermark', () => {
        const html = generator.generate(mockReportData);

        assert.ok(html.includes('Generated:'));
    });

    test('includes time range', () => {
        const html = generator.generate(mockReportData);

        assert.ok(html.includes('Period:') || html.includes('2026-03-21'));
    });

    test('includes SLO metrics section', () => {
        const html = generator.generate(mockReportData);

        assert.ok(html.includes('SLO') || html.includes('slo'));
    });

    test('includes topology section', () => {
        const html = generator.generate(mockReportData);

        assert.ok(html.includes('Topology') || html.includes('Agent'));
    });

    test('includes audit section', () => {
        const html = generator.generate(mockReportData);

        assert.ok(html.includes('Audit'));
    });

    test('includes print-friendly CSS', () => {
        const html = generator.generate(mockReportData);

        assert.ok(html.includes('@media print') || html.includes('print'));
    });
});
