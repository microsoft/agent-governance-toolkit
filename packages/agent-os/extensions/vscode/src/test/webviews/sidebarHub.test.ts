// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Unit tests for SidebarHubTemplate.
 *
 * Tests the renderSidebarHub pure function which produces
 * complete HTML for the sidebar-embedded Governance Hub view.
 */

import * as assert from 'assert';
import { renderSidebarHub } from '../../webviews/governanceHub/SidebarHubTemplate';
import { HubConfig, HubTabId } from '../../webviews/governanceHub/governanceHubTypes';

suite('SidebarHubTemplate — renderSidebarHub', () => {
    const nonce = 'test-sidebar-nonce-abc123';
    const cspSource = 'https://test.vscode-webview.net';

    function makeConfig(overrides?: Partial<HubConfig>): HubConfig {
        return {
            enabledTabs: ['slo', 'topology', 'audit', 'policies'],
            defaultTab: 'slo',
            refreshIntervalMs: 10000,
            ...overrides,
        };
    }

    test('returns a string containing <!DOCTYPE html>', () => {
        const html = renderSidebarHub(nonce, cspSource, makeConfig());
        assert.ok(html.includes('<!DOCTYPE html>'),
            'HTML should start with DOCTYPE declaration');
    });

    test('HTML includes the nonce in script tag', () => {
        const html = renderSidebarHub(nonce, cspSource, makeConfig());
        assert.ok(html.includes(`nonce-${nonce}`),
            'HTML should include nonce value in CSP or tags');
    });

    test('HTML includes CSP meta tag with the provided cspSource', () => {
        const html = renderSidebarHub(nonce, cspSource, makeConfig());
        assert.ok(html.includes('Content-Security-Policy'),
            'HTML should include CSP meta tag');
        assert.ok(html.includes(cspSource),
            `HTML should include cspSource "${cspSource}"`);
    });

    test('HTML includes icon tab buttons for each enabled tab', () => {
        const config = makeConfig({ enabledTabs: ['slo', 'topology', 'audit', 'policies'] });
        const html = renderSidebarHub(nonce, cspSource, config);

        assert.ok(html.includes('data-tab="slo"'), 'Should include slo tab button');
        assert.ok(html.includes('data-tab="topology"'), 'Should include topology tab button');
        assert.ok(html.includes('data-tab="audit"'), 'Should include audit tab button');
        assert.ok(html.includes('data-tab="policies"'), 'Should include policies tab button');
    });

    test('only renders enabled tabs', () => {
        const config = makeConfig({ enabledTabs: ['slo', 'audit'] });
        const html = renderSidebarHub(nonce, cspSource, config);

        assert.ok(html.includes('data-tab="slo"'), 'Should include slo tab');
        assert.ok(html.includes('data-tab="audit"'), 'Should include audit tab');
        assert.ok(!html.includes('data-tab="topology"'), 'Should not include topology tab');
        assert.ok(!html.includes('data-tab="policies"'), 'Should not include policies tab');
    });

    test('default tab gets active class', () => {
        const config = makeConfig({ enabledTabs: ['slo', 'audit'], defaultTab: 'audit' });
        const html = renderSidebarHub(nonce, cspSource, config);

        // The audit tab button should have class "tab active"
        const auditTabMatch = html.match(/class="tab\s+active"\s+data-tab="audit"/);
        assert.ok(auditTabMatch, 'Audit tab should have active class when set as default');
    });

    test('HTML includes compact-header with status dot and title', () => {
        const html = renderSidebarHub(nonce, cspSource, makeConfig());

        assert.ok(html.includes('compact-header'),
            'HTML should include compact-header');
        assert.ok(html.includes('status-dot'),
            'HTML should include status-dot');
        assert.ok(html.includes('Governance'),
            'HTML should include title text');
    });

    test('HTML includes compact-footer with expand button', () => {
        const html = renderSidebarHub(nonce, cspSource, makeConfig());

        assert.ok(html.includes('compact-footer'),
            'HTML should include compact-footer');
        assert.ok(html.includes('expand-btn'),
            'HTML should include expand button');
    });

    test('HTML includes refresh button', () => {
        const html = renderSidebarHub(nonce, cspSource, makeConfig());

        assert.ok(html.includes('refresh-btn'),
            'HTML should include refresh button');
    });

    test('HTML includes main content area', () => {
        const html = renderSidebarHub(nonce, cspSource, makeConfig());

        assert.ok(html.includes('id="content"'),
            'HTML should include main content area');
    });

    test('tab buttons include title attributes for tooltips', () => {
        const config = makeConfig({ enabledTabs: ['slo', 'topology', 'audit', 'policies'] });
        const html = renderSidebarHub(nonce, cspSource, config);

        assert.ok(html.includes('title="SLO Dashboard"'), 'SLO tab should have tooltip');
        assert.ok(html.includes('title="Agent Topology"'), 'Topology tab should have tooltip');
        assert.ok(html.includes('title="Audit Log"'), 'Audit tab should have tooltip');
        assert.ok(html.includes('title="Policies"'), 'Policies tab should have tooltip');
    });

    test('HTML is a complete document with html, head, and body', () => {
        const html = renderSidebarHub(nonce, cspSource, makeConfig());

        assert.ok(html.includes('<html'), 'Should have html tag');
        assert.ok(html.includes('<head>'), 'Should have head tag');
        assert.ok(html.includes('</head>'), 'Should have closing head tag');
        assert.ok(html.includes('<body>'), 'Should have body tag');
        assert.ok(html.includes('</body>'), 'Should have closing body tag');
        assert.ok(html.includes('</html>'), 'Should have closing html tag');
    });

    test('renders with single enabled tab', () => {
        const config = makeConfig({ enabledTabs: ['policies'], defaultTab: 'policies' });
        const html = renderSidebarHub(nonce, cspSource, config);

        assert.ok(html.includes('data-tab="policies"'), 'Should include policies tab');
        assert.ok(html.includes('<!DOCTYPE html>'), 'Should still be valid HTML');
    });
});
