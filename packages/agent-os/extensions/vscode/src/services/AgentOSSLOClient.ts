// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Agent OS SLO Client
 *
 * Real backend client that queries agent-sre for SLO data via the
 * ServiceTransport abstraction. Caches the last successful snapshot
 * to provide stale-while-revalidate behavior on transport failures.
 */

import type { SLODataProvider, SLOSnapshot } from '../views/sloTypes';
import type { ServiceTransport } from './serviceTypes';
import type { RawSLOPayload } from './translators';
import { translateSLOSnapshot } from './translators';

export class AgentOSSLOClient implements SLODataProvider {
    private readonly transport: ServiceTransport;
    private _lastSnapshot: SLOSnapshot | undefined;

    constructor(transport: ServiceTransport) {
        this.transport = transport;
    }

    async getSnapshot(): Promise<SLOSnapshot> {
        const response = await this.transport.query<RawSLOPayload>(
            'agent_sre.slo',
            'snapshot',
        );

        if (response.ok) {
            this._lastSnapshot = translateSLOSnapshot(response.data);
            return this._lastSnapshot;
        }

        if (this._lastSnapshot) {
            return this._lastSnapshot;
        }

        throw new Error(response.error ?? 'SLO query failed with no cached data');
    }
}
