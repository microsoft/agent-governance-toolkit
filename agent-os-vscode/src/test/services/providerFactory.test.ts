// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Provider Factory Tests
 *
 * Verifies that the factory returns disconnected providers when
 * agent-failsafe is not available, and handles endpoint override.
 */

import * as assert from 'assert';
import * as vscode from 'vscode';
import { createProviders } from '../../services/providerFactory';

suite('providerFactory', () => {
    let originalShowInfo: typeof vscode.window.showInformationMessage;
    setup(() => {
        originalShowInfo = vscode.window.showInformationMessage;
        (vscode.window as any).showInformationMessage = async () => undefined;
    });
    teardown(() => {
        (vscode.window as any).showInformationMessage = originalShowInfo;
    });

    test('unavailable python returns not-installed providers', async () => {
        const providers = await createProviders({ pythonPath: 'nonexistent-python-binary' });
        assert.strictEqual(providers.status, 'not-installed');
        const slo = await providers.slo.getSnapshot();
        assert.strictEqual(slo.policyCompliance.totalEvaluations, 0);
        assert.deepStrictEqual(providers.topology.getAgents(), []);
        const policy = await providers.policy.getSnapshot();
        assert.strictEqual(policy.rules.length, 0);
        providers.dispose();
    });

    test('disconnected providers never return mock/fake data', async () => {
        const providers = await createProviders({ pythonPath: 'nonexistent-python-binary' });
        const slo = await providers.slo.getSnapshot();
        assert.strictEqual(slo.policyCompliance.compliancePercent, 0);
        assert.strictEqual(slo.trustScore.meanScore, 0);
        providers.dispose();
    });

    test('dispose is idempotent', async () => {
        const providers = await createProviders({ pythonPath: 'nonexistent-python-binary' });
        providers.dispose();
        providers.dispose();
    });

    test('explicit endpoint override bypasses auto-start', async () => {
        const providers = await createProviders({
            pythonPath: 'python',
            endpoint: 'http://127.0.0.1:9377',
        });
        assert.strictEqual(providers.status, 'live');
        assert.ok(providers.slo);
        providers.dispose();
    });
});
