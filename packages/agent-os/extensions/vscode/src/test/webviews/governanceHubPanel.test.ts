// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Unit tests for GovernanceHubPanel serialization and message types.
 *
 * GovernanceHubPanel requires VS Code APIs for the webview panel, so we
 * test only the pure serialization/sanitization logic and type shapes
 * that the panel uses internally.
 */

import * as assert from 'assert';
import {
    HubOutboundMessage,
    HubInboundMessage,
    HubConfig,
    HubTabId,
} from '../../webviews/governanceHub/governanceHubTypes';

suite('GovernanceHubPanel Serialization', () => {
    test('audit entries with Date objects produce valid JSON', () => {
        const entries = [
            {
                type: 'blocked',
                timestamp: new Date('2026-03-24T00:00:00Z'),
                file: 'test.ts',
                violation: 'secret pattern',
            },
            {
                type: 'warning',
                timestamp: new Date('2026-03-24T01:00:00Z'),
                reason: 'untrusted agent',
            },
        ];

        // Simulate the sanitization from GovernanceHubPanel._sendAuditUpdate
        const sanitized = entries.map(e => ({
            type: e.type,
            timestamp: e.timestamp instanceof Date ? e.timestamp.toISOString() : e.timestamp,
            file: (e as Record<string, unknown>).file,
            language: (e as Record<string, unknown>).language,
            violation: (e as Record<string, unknown>).violation,
            reason: (e as Record<string, unknown>).reason,
        }));

        const json = JSON.stringify({ type: 'auditUpdate', payload: sanitized });
        assert.ok(json, 'Should produce valid JSON string');

        const parsed = JSON.parse(json);
        assert.strictEqual(parsed.payload[0].timestamp, '2026-03-24T00:00:00.000Z');
        assert.strictEqual(parsed.payload[1].timestamp, '2026-03-24T01:00:00.000Z');
    });

    test('audit entries without Date objects pass through unchanged', () => {
        const entries: Array<Record<string, unknown>> = [
            { type: 'allowed', timestamp: '2026-03-24T00:00:00Z', file: 'ok.ts' },
        ];

        const sanitized = entries.map(e => ({
            type: e.type,
            timestamp: e.timestamp instanceof Date ? e.timestamp.toISOString() : e.timestamp,
            file: e.file,
        }));

        const json = JSON.stringify(sanitized);
        assert.ok(json, 'Should produce valid JSON string');

        const parsed = JSON.parse(json);
        assert.strictEqual(parsed[0].timestamp, '2026-03-24T00:00:00Z',
            'String timestamp should pass through unchanged');
    });

    test('sanitization handles entries with undefined optional fields', () => {
        const entries = [
            { type: 'info', timestamp: new Date('2026-01-01T00:00:00Z') },
        ];

        const sanitized = entries.map(e => ({
            type: e.type,
            timestamp: e.timestamp instanceof Date ? e.timestamp.toISOString() : e.timestamp,
            file: (e as Record<string, unknown>).file,
            language: (e as Record<string, unknown>).language,
            violation: (e as Record<string, unknown>).violation,
            reason: (e as Record<string, unknown>).reason,
        }));

        const json = JSON.stringify({ type: 'auditUpdate', payload: sanitized });
        const parsed = JSON.parse(json);
        assert.strictEqual(parsed.payload[0].type, 'info');
        assert.strictEqual(parsed.payload[0].timestamp, '2026-01-01T00:00:00.000Z');
        // undefined fields become absent in JSON (not null)
        assert.ok(!('file' in parsed.payload[0]) || parsed.payload[0].file === null,
            'Missing file should be undefined or null');
    });

    test('empty audit entries array serializes to empty payload', () => {
        const entries: Record<string, unknown>[] = [];
        const sanitized = entries.map(e => ({
            type: e.type,
            timestamp: e.timestamp instanceof Date
                ? (e.timestamp as Date).toISOString()
                : e.timestamp,
        }));
        const json = JSON.stringify({ type: 'auditUpdate', payload: sanitized });
        const parsed = JSON.parse(json);
        assert.strictEqual(parsed.payload.length, 0);
    });
});

suite('GovernanceHubPanel Message Types', () => {
    test('HubOutboundMessage refresh type can be created', () => {
        const msg: HubOutboundMessage = { type: 'refresh' };
        assert.strictEqual(msg.type, 'refresh');
    });

    test('HubOutboundMessage openInBrowser type can be created', () => {
        const msg: HubOutboundMessage = { type: 'openInBrowser' };
        assert.strictEqual(msg.type, 'openInBrowser');
    });

    test('HubOutboundMessage export type can be created', () => {
        const msg: HubOutboundMessage = { type: 'export' };
        assert.strictEqual(msg.type, 'export');
    });

    test('HubOutboundMessage tabChange type includes activeTab', () => {
        const msg: HubOutboundMessage = { type: 'tabChange', activeTab: 'topology' };
        assert.strictEqual(msg.type, 'tabChange');
        assert.strictEqual(msg.activeTab, 'topology');
    });

    test('HubOutboundMessage agentSelected type includes did', () => {
        const msg: HubOutboundMessage = {
            type: 'agentSelected',
            did: 'did:mesh:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
        };
        assert.strictEqual(msg.type, 'agentSelected');
        assert.ok(msg.did?.startsWith('did:mesh:'));
    });

    test('HubOutboundMessage exportAudit type can be created', () => {
        const msg: HubOutboundMessage = { type: 'exportAudit' };
        assert.strictEqual(msg.type, 'exportAudit');
    });

    test('HubOutboundMessage openFullDashboard type can be created', () => {
        const msg: HubOutboundMessage = { type: 'openFullDashboard' };
        assert.strictEqual(msg.type, 'openFullDashboard');
    });

    test('HubInboundMessage sloUpdate type can be created', () => {
        const msg: HubInboundMessage = {
            type: 'sloUpdate',
            payload: { availability: {}, latency: {} },
        };
        assert.strictEqual(msg.type, 'sloUpdate');
        assert.ok(msg.payload);
    });

    test('HubInboundMessage topologyUpdate type can be created', () => {
        const msg: HubInboundMessage = {
            type: 'topologyUpdate',
            payload: { nodes: [], edges: [], bridges: [] },
        };
        assert.strictEqual(msg.type, 'topologyUpdate');
    });

    test('HubInboundMessage auditUpdate type can be created', () => {
        const msg: HubInboundMessage = { type: 'auditUpdate', payload: [] };
        assert.strictEqual(msg.type, 'auditUpdate');
    });

    test('HubInboundMessage policyUpdate type can be created', () => {
        const msg: HubInboundMessage = { type: 'policyUpdate', payload: {} };
        assert.strictEqual(msg.type, 'policyUpdate');
    });

    test('HubInboundMessage configUpdate type can be created', () => {
        const msg: HubInboundMessage = {
            type: 'configUpdate',
            payload: { lastUpdated: '12:00:00' },
        };
        assert.strictEqual(msg.type, 'configUpdate');
    });
});

suite('GovernanceHubPanel HubConfig', () => {
    test('HubConfig with all tabs enabled', () => {
        const config: HubConfig = {
            enabledTabs: ['slo', 'topology', 'audit', 'policies'],
            defaultTab: 'slo',
            refreshIntervalMs: 10000,
        };
        assert.strictEqual(config.enabledTabs.length, 4);
        assert.strictEqual(config.defaultTab, 'slo');
        assert.strictEqual(config.refreshIntervalMs, 10000);
    });

    test('HubConfig defaultTab is optional', () => {
        const config: HubConfig = {
            enabledTabs: ['slo'],
        };
        assert.strictEqual(config.defaultTab, undefined);
    });

    test('HubConfig refreshIntervalMs is optional', () => {
        const config: HubConfig = {
            enabledTabs: ['audit'],
            defaultTab: 'audit',
        };
        assert.strictEqual(config.refreshIntervalMs, undefined);
    });

    test('all HubTabId values are valid', () => {
        const validTabs: HubTabId[] = ['slo', 'topology', 'audit', 'policies'];
        assert.strictEqual(validTabs.length, 4);
        for (const tab of validTabs) {
            assert.ok(typeof tab === 'string', `Tab "${tab}" should be a string`);
        }
    });
});
