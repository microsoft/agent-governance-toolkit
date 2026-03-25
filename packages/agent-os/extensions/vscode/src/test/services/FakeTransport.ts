// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import type { ServiceTransport, ServiceResponse } from '../../services/serviceTypes';

/**
 * Test stub for ServiceTransport. Allows tests to control the next
 * response returned by query() and healthCheck().
 */
export class FakeTransport implements ServiceTransport {
    private _nextResponse: ServiceResponse = { ok: false, data: undefined, durationMs: 0 };

    setNext<T>(res: ServiceResponse<T>): void {
        this._nextResponse = res as ServiceResponse;
    }

    async query<T>(): Promise<ServiceResponse<T>> {
        return this._nextResponse as ServiceResponse<T>;
    }

    async healthCheck(): Promise<boolean> {
        return this._nextResponse.ok;
    }

    dispose(): void {
        // no-op
    }
}
