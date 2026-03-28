// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Credential error types for storage providers.
 *
 * Typed errors with provider and reason for zero-trust credential handling.
 */

/** Supported storage provider identifiers. */
export type CredentialProvider = 's3' | 'azure' | 'local';

/** Reason for credential failure. */
export type CredentialReason = 'missing' | 'invalid' | 'expired';

/**
 * Error thrown when storage provider credentials are invalid or missing.
 */
export class CredentialError extends Error {
    constructor(
        message: string,
        public readonly provider: CredentialProvider,
        public readonly reason: CredentialReason
    ) {
        super(message);
        this.name = 'CredentialError';
    }
}
