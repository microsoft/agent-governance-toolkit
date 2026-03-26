// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance Hub Tests
 *
 * Unit tests for the Governance Hub webview components.
 */

import * as assert from 'assert';
import { renderGovernanceHub } from '../../webviews/governanceHub/GovernanceHubTemplate';
import { governanceHubScript } from '../../webviews/governanceHub/GovernanceHubScript';
import { HubConfig } from '../../webviews/governanceHub/governanceHubTypes';

suite('Governance Hub', () => {
    suite('GovernanceHubTemplate', () => {
        const nonce = 'test-nonce-12345';
        const cspSource = 'https://test.vscode.resource';

        test('renders with default tabs', () => {
            const config: HubConfig = {
                enabledTabs: ['slo', 'topology', 'audit'],
                defaultTab: 'slo',
                refreshIntervalMs: 10000,
            };

            const html = renderGovernanceHub(nonce, cspSource, config);

            assert.ok(html.includes('nonce="test-nonce-12345"'));
            assert.ok(html.includes('SLO'));
            assert.ok(html.includes('Topology'));
            assert.ok(html.includes('Audit'));
        });

        test('respects enabled tabs order', () => {
            const config: HubConfig = {
                enabledTabs: ['audit', 'slo'],
                defaultTab: 'audit',
                refreshIntervalMs: 10000,
            };

            const html = renderGovernanceHub(nonce, cspSource, config);

            const auditIndex = html.indexOf('data-tab="audit"');
            const sloIndex = html.indexOf('data-tab="slo"');
            assert.ok(auditIndex < sloIndex, 'Audit tab should appear before SLO tab');
        });

        test('includes action buttons', () => {
            const config: HubConfig = {
                enabledTabs: ['slo'],
                defaultTab: 'slo',
                refreshIntervalMs: 10000,
            };

            const html = renderGovernanceHub(nonce, cspSource, config);

            assert.ok(html.includes('refresh-btn') || html.includes('Refresh'));
            assert.ok(html.includes('browser-btn') || html.includes('Browser'));
            assert.ok(html.includes('export-btn') || html.includes('Export'));
        });

        test('includes footer with connection status', () => {
            const config: HubConfig = {
                enabledTabs: ['slo'],
                defaultTab: 'slo',
                refreshIntervalMs: 10000,
            };

            const html = renderGovernanceHub(nonce, cspSource, config);

            assert.ok(html.includes('hub-footer') || html.includes('connection'));
        });
    });

    suite('GovernanceHubScript', () => {
        const nonce = 'script-nonce-67890';

        test('includes tab switching logic', () => {
            const script = governanceHubScript(nonce);

            assert.ok(script.includes('tab') || script.includes('click'));
            assert.ok(script.includes('active'));
        });

        test('includes message handlers', () => {
            const script = governanceHubScript(nonce);

            assert.ok(script.includes('sloUpdate'));
            assert.ok(script.includes('topologyUpdate'));
            assert.ok(script.includes('auditUpdate'));
        });

        test('includes refresh handler', () => {
            const script = governanceHubScript(nonce);

            assert.ok(script.includes('refresh'));
            assert.ok(script.includes('postMessage'));
        });

        test('includes openInBrowser handler', () => {
            const script = governanceHubScript(nonce);

            assert.ok(script.includes('openInBrowser'));
        });

        test('includes export handler', () => {
            const script = governanceHubScript(nonce);

            assert.ok(script.includes('export'));
        });

        test('persists active tab to localStorage', () => {
            const script = governanceHubScript(nonce);

            assert.ok(script.includes('localStorage'));
        });

        test('includes esc() function for HTML entity escaping', () => {
            const script = governanceHubScript(nonce);

            assert.ok(
                script.includes('function esc(s)'),
                'Script should define an esc() HTML escaping function'
            );
            assert.ok(
                script.includes('d.textContent = String(s)'),
                'esc() should use textContent for safe encoding'
            );
        });

        test('escapes agent DID in topology rendering', () => {
            const script = governanceHubScript(nonce);

            // The topology renderer should use esc() on agent DIDs
            assert.ok(
                script.includes("esc(a.did)"),
                'Agent DIDs should be escaped with esc()'
            );
            // Should NOT use inline onclick with string interpolation
            assert.ok(
                !script.includes("onclick=\"selectAgent"),
                'Should not use inline onclick handlers'
            );
            // Should use data-attribute delegation instead
            assert.ok(
                script.includes('data-agent-did'),
                'Should use data-agent-did attribute for click delegation'
            );
        });

        test('escapes policy rule fields', () => {
            const script = governanceHubScript(nonce);

            assert.ok(script.includes('esc(r.name)'), 'Rule name should be escaped');
            assert.ok(script.includes('esc(r.description)'), 'Rule description should be escaped');
            assert.ok(script.includes('esc(r.action)'), 'Rule action should be escaped');
            assert.ok(script.includes('esc(r.scope)'), 'Rule scope should be escaped');
        });

        test('escapes violation data', () => {
            const script = governanceHubScript(nonce);

            assert.ok(script.includes('esc(v.ruleName)'), 'Violation rule name should be escaped');
            assert.ok(script.includes('esc(loc)'), 'Violation location should be escaped');
        });

        test('escapes audit entry fields', () => {
            const script = governanceHubScript(nonce);

            assert.ok(script.includes('esc(e.type)'), 'Audit type should be escaped');
        });
    });
});
