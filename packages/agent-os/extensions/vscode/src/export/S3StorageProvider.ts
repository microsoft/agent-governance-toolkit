// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * AWS S3 storage provider for governance reports.
 *
 * Uses VS Code SecretStorage for credential management.
 * Generates pre-signed URLs for secure report sharing.
 */

import * as vscode from 'vscode';
import { CredentialError } from './CredentialError';
import { StorageProvider, UploadResult } from './StorageProvider';

/** S3 configuration settings. */
interface S3Config {
    bucket: string;
    region: string;
    prefix: string;
    expirationHours: number;
}

/**
 * Storage provider for AWS S3 with pre-signed URL generation.
 */
export class S3StorageProvider implements StorageProvider {
    private config: S3Config = {
        bucket: '',
        region: 'us-east-1',
        prefix: 'governance-reports/',
        expirationHours: 24,
    };

    constructor(private readonly secrets: vscode.SecretStorage) {}

    /**
     * Validate S3 credentials from SecretStorage.
     *
     * @throws CredentialError if credentials are missing or invalid.
     */
    async validateCredentials(): Promise<void> {
        const accessKeyId = await this.secrets.get('s3.accessKeyId');
        const secretAccessKey = await this.secrets.get('s3.secretAccessKey');

        if (!accessKeyId || !secretAccessKey) {
            throw new CredentialError(
                'AWS credentials not found in SecretStorage',
                's3',
                'missing'
            );
        }

        const isValid = await this.headBucket(accessKeyId, secretAccessKey);
        if (!isValid) {
            throw new CredentialError(
                'AWS credentials are invalid or expired',
                's3',
                'invalid'
            );
        }
    }

    /**
     * Upload HTML to S3 and return a pre-signed URL.
     *
     * @param html - HTML content to upload.
     * @param filename - Filename for the S3 object.
     * @returns Upload result with pre-signed URL.
     */
    async upload(html: string, filename: string): Promise<UploadResult> {
        await this.validateCredentials();

        const key = `${this.config.prefix}${filename}`;
        const expiresAt = new Date(
            Date.now() + this.config.expirationHours * 60 * 60 * 1000
        );

        // In production, use AWS SDK to put object and generate pre-signed URL
        const presignedUrl = await this.putObjectAndSign(key, html);

        return { url: presignedUrl, expiresAt };
    }

    /**
     * Configure S3 settings.
     *
     * @param settings - S3 configuration options.
     */
    configure(settings: Record<string, string>): void {
        if (settings.bucket) {
            this.config.bucket = settings.bucket;
        }
        if (settings.region) {
            this.config.region = settings.region;
        }
        if (settings.prefix) {
            this.config.prefix = settings.prefix;
        }
        if (settings.expirationHours) {
            this.config.expirationHours = parseInt(settings.expirationHours, 10);
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Validate bucket access with HeadBucket operation.
     */
    private async headBucket(
        _accessKeyId: string,
        _secretAccessKey: string
    ): Promise<boolean> {
        // TODO: Implement actual AWS SDK HeadBucket call
        // For now, return true if credentials are present
        return this.config.bucket.length > 0;
    }

    /**
     * Upload object to S3 and generate pre-signed URL.
     */
    private async putObjectAndSign(key: string, _content: string): Promise<string> {
        // TODO: Implement actual AWS SDK PutObject and getSignedUrl
        const encodedKey = encodeURIComponent(key);
        return `https://${this.config.bucket}.s3.${this.config.region}.amazonaws.com/${encodedKey}`;
    }
}
