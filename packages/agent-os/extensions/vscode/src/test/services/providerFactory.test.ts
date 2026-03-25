// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Provider Factory Unit Tests
 */

import * as assert from 'assert';
import { createProviders } from '../../services/providerFactory';
import type { BackendConfig } from '../../services/serviceTypes';
import type { Providers } from '../../services/providerFactory';

suite('ProviderFactory Test Suite', () => {
    test('mock mode returns providers with getSnapshot', async () => {
        const config: BackendConfig = { mode: 'mock', pythonPath: 'python' };
        const providers: Providers = await createProviders(config);

        assert.ok(providers.slo, 'Expected slo provider');
        assert.ok(providers.topology, 'Expected topology provider');
        assert.ok(providers.policy, 'Expected policy provider');
        assert.strictEqual(typeof providers.slo.getSnapshot, 'function');
        assert.strictEqual(typeof providers.policy.getSnapshot, 'function');
    });

    test('mock mode returns providers with getAgents', async () => {
        const config: BackendConfig = { mode: 'mock', pythonPath: 'python' };
        const providers = await createProviders(config);

        assert.strictEqual(typeof providers.topology.getAgents, 'function');
        assert.strictEqual(typeof providers.topology.getBridges, 'function');
        assert.strictEqual(typeof providers.topology.getDelegations, 'function');
    });

    test('mock providers return valid data', async () => {
        const config: BackendConfig = { mode: 'mock', pythonPath: 'python' };
        const providers = await createProviders(config);

        const sloSnapshot = await providers.slo.getSnapshot();
        assert.ok(sloSnapshot.availability, 'Expected availability data');
        assert.ok(sloSnapshot.latency, 'Expected latency data');
        assert.strictEqual(typeof sloSnapshot.availability.currentPercent, 'number');

        const agents = providers.topology.getAgents();
        assert.ok(Array.isArray(agents), 'Expected agents array');
        assert.ok(agents.length > 0, 'Expected at least one agent');

        const policySnapshot = await providers.policy.getSnapshot();
        assert.ok(Array.isArray(policySnapshot.rules), 'Expected rules array');
        assert.ok(policySnapshot.rules.length > 0, 'Expected at least one rule');
    });

    test('mock providers dispose without throwing', async () => {
        const config: BackendConfig = { mode: 'mock', pythonPath: 'python' };
        const providers = await createProviders(config);

        assert.doesNotThrow(() => providers.dispose());
    });

    test('local mode with unreachable backend falls back to mock', async () => {
        const config: BackendConfig = { mode: 'local', pythonPath: '/nonexistent/python' };
        const providers = await createProviders(config);

        // Should still return working providers (mock fallback)
        assert.ok(providers.slo, 'Expected slo provider from fallback');
        assert.ok(providers.topology, 'Expected topology provider from fallback');
        assert.ok(providers.policy, 'Expected policy provider from fallback');

        const snapshot = await providers.slo.getSnapshot();
        assert.strictEqual(typeof snapshot.availability.currentPercent, 'number');

        providers.dispose();
    });

    test('Providers interface has dispose method', async () => {
        const config: BackendConfig = { mode: 'mock', pythonPath: 'python' };
        const providers = await createProviders(config);

        assert.strictEqual(typeof providers.dispose, 'function');
    });

    test('BackendConfig shape is correct', () => {
        const config: BackendConfig = { mode: 'mock', pythonPath: 'python' };
        assert.strictEqual(config.mode, 'mock');
        assert.strictEqual(config.pythonPath, 'python');

        const localConfig: BackendConfig = { mode: 'local', pythonPath: '/usr/bin/python3' };
        assert.strictEqual(localConfig.mode, 'local');
        assert.strictEqual(localConfig.pythonPath, '/usr/bin/python3');
    });
});
