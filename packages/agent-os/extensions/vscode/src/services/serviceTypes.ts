// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Service Transport Types
 *
 * Interfaces for communicating with Python Agent OS backend services.
 * Used by real backend clients and the provider factory.
 */

/** Raw JSON response from Python helper script. */
export interface ServiceResponse<T = unknown> {
    ok: boolean;
    data: T;
    error?: string;
    durationMs: number;
}

/** Transport abstraction -- how we talk to Python. */
export interface ServiceTransport {
    /** Execute a command and return parsed JSON. */
    query<T>(module: string, command: string, args?: Record<string, unknown>): Promise<ServiceResponse<T>>;
    /** Check if the backend is reachable. */
    healthCheck(): Promise<boolean>;
    /** Dispose resources. */
    dispose(): void;
}

/** Extension configuration for backend mode. */
export interface BackendConfig {
    mode: 'mock' | 'local';
    pythonPath: string;
}
