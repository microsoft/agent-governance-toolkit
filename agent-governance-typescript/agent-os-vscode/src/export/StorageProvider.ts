// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Storage provider interface for report uploads.
 *
 * Defines the contract for local, S3, and Azure Blob storage implementations.
 */

/** Result of a successful upload operation. */
export interface UploadResult {
    /** Public or pre-signed URL to access the uploaded file. */
    url: string;
    /** When the URL expires (for pre-signed URLs). */
    expiresAt: Date;
}

/**
 * Storage provider contract for uploading governance reports.
 *
 * All implementations must validate credentials on every upload (zero-trust).
 */
export interface StorageProvider {
    /**
     * Validate credentials before upload.
     *
     * @throws CredentialError if credentials are missing, invalid, or expired.
     */
    validateCredentials(): Promise<void>;

    /**
     * Upload HTML content to storage.
     *
     * @param html - The HTML content to upload.
     * @param filename - Desired filename for the upload.
     * @returns Upload result with URL and expiration.
     * @throws CredentialError if credentials fail validation.
     */
    upload(html: string, filename: string): Promise<UploadResult>;

    /**
     * Configure provider-specific settings.
     *
     * @param settings - Key-value settings for the provider.
     */
    configure(settings: Record<string, string>): void;
}
