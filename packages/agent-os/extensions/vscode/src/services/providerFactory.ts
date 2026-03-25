// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Provider Factory
 *
 * Reads VS Code settings to determine backend mode and creates the
 * appropriate data providers. Falls back to mock providers when the
 * local backend is unreachable.
 */

import * as vscode from 'vscode';
import { BackendConfig } from './serviceTypes';
import { SubprocessTransport } from './serviceTransport';
import { SLODataProvider } from '../views/sloTypes';
import { AgentTopologyDataProvider } from '../views/topologyTypes';
import { PolicyDataProvider } from '../views/policyTypes';
import { createMockSLOBackend } from '../mockBackend/MockSLOBackend';
import { createMockTopologyBackend } from '../mockBackend/MockTopologyBackend';
import { createMockPolicyBackend } from '../mockBackend/MockPolicyBackend';
import { AgentOSSLOClient } from './AgentOSSLOClient';
import { AgentOSTopologyClient } from './AgentOSTopologyClient';
import { AgentOSPolicyClient } from './AgentOSPolicyClient';

/** Bundle of all data providers used by the extension. */
export interface Providers {
    slo: SLODataProvider;
    topology: AgentTopologyDataProvider;
    policy: PolicyDataProvider;
    dispose(): void;
}

/** Read backend configuration from VS Code workspace settings. */
export function readBackendConfig(): BackendConfig {
    const config = vscode.workspace.getConfiguration('agent-os.backend');
    const mode = config.get<'mock' | 'local'>('mode', 'mock');
    const pythonPath = config.get<string>('pythonPath', 'python');
    return { mode, pythonPath };
}

/** Create mock providers with a no-op dispose. */
function createMockProviders(): Providers {
    return {
        slo: createMockSLOBackend(),
        topology: createMockTopologyBackend(),
        policy: createMockPolicyBackend(),
        dispose(): void { /* no resources to release */ },
    };
}

/**
 * Attempt to create providers backed by the local Python backend.
 * Falls back to mock providers if the health check fails.
 */
async function createLocalProviders(config: BackendConfig): Promise<Providers> {
    const transport = new SubprocessTransport(config.pythonPath);
    const healthy = await transport.healthCheck();

    if (!healthy) {
        transport.dispose();
        vscode.window.showWarningMessage(
            'Agent OS backend is unreachable. Falling back to mock data.',
        );
        return createMockProviders();
    }

    return {
        slo: new AgentOSSLOClient(transport),
        topology: new AgentOSTopologyClient(transport),
        policy: new AgentOSPolicyClient(transport),
        dispose(): void {
            transport.dispose();
        },
    };
}

/**
 * Create data providers based on the given backend configuration.
 *
 * - `mock` mode: returns simulated data providers immediately.
 * - `local` mode: attempts to connect to the Python Agent OS backend
 *   and falls back to mock providers if the backend is unreachable.
 */
export async function createProviders(config: BackendConfig): Promise<Providers> {
    if (config.mode === 'local') {
        return createLocalProviders(config);
    }
    return createMockProviders();
}
