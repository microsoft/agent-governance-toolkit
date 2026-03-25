// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Agent OS Policy Client
 *
 * Real backend client that queries agent-os for policy data via the
 * ServiceTransport abstraction. Caches the last successful snapshot
 * to provide stale-while-revalidate behavior on transport failures.
 */

import type { PolicyDataProvider, PolicySnapshot } from '../views/policyTypes';
import type { ServiceTransport } from './serviceTypes';
import type { RawPolicyPayload } from './translators';
import { translatePolicySnapshot } from './translators';

export class AgentOSPolicyClient implements PolicyDataProvider {
    private readonly transport: ServiceTransport;
    private _lastSnapshot: PolicySnapshot | undefined;

    constructor(transport: ServiceTransport) {
        this.transport = transport;
    }

    async getSnapshot(): Promise<PolicySnapshot> {
        const response = await this.transport.query<RawPolicyPayload>(
            'agent_os.policies',
            'snapshot',
        );

        if (response.ok) {
            this._lastSnapshot = translatePolicySnapshot(response.data);
            return this._lastSnapshot;
        }

        if (this._lastSnapshot) {
            return this._lastSnapshot;
        }

        throw new Error(response.error ?? 'Policy query failed with no cached data');
    }
}
