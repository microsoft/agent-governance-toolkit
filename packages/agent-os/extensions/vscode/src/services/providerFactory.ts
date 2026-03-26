// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Provider Factory
 *
 * Creates data providers for the governance dashboard.
 * Currently returns mock providers for development.
 */

import { SLODataProvider } from '../views/sloTypes';
import { AgentTopologyDataProvider } from '../views/topologyTypes';
import { PolicyDataProvider } from '../views/policyTypes';
import { createMockSLOBackend } from '../mockBackend/MockSLOBackend';
import { createMockTopologyBackend } from '../mockBackend/MockTopologyBackend';
import { createMockPolicyBackend } from '../mockBackend/MockPolicyBackend';

/** Bundle of all data providers used by the extension. */
export interface Providers {
    slo: SLODataProvider;
    topology: AgentTopologyDataProvider;
    policy: PolicyDataProvider;
    dispose(): void;
}

/** Create data providers using mock backends. */
export function createProviders(): Providers {
    return {
        slo: createMockSLOBackend(),
        topology: createMockTopologyBackend(),
        policy: createMockPolicyBackend(),
        dispose(): void { /* no resources to release */ },
    };
}
