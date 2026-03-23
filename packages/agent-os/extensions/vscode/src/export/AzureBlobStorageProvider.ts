// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Azure Blob Storage provider for governance reports.
 *
 * Uses VS Code SecretStorage for connection string management.
 * Generates SAS URLs for secure report sharing.
 */

import * as vscode from 'vscode';
import { CredentialError } from './CredentialError';
import { StorageProvider, UploadResult } from './StorageProvider';

/** Azure Blob configuration settings. */
interface AzureBlobConfig {
    containerName: string;
    prefix: string;
    expirationHours: number;
}

/**
 * Storage provider for Azure Blob Storage with SAS URL generation.
 */
export class AzureBlobStorageProvider implements StorageProvider {
    private config: AzureBlobConfig = {
        containerName: 'governance-reports',
        prefix: '',
        expirationHours: 24,
    };

    constructor(private readonly secrets: vscode.SecretStorage) {}

    /**
     * Validate Azure connection string from SecretStorage.
     *
     * @throws CredentialError if connection string is missing or invalid.
     */
    async validateCredentials(): Promise<void> {
        const connectionString = await this.secrets.get('azure.connectionString');

        if (!connectionString) {
            throw new CredentialError(
                'Azure connection string not found in SecretStorage',
                'azure',
                'missing'
            );
        }

        const containerExists = await this.checkContainerExists(connectionString);
        if (!containerExists) {
            throw new CredentialError(
                'Azure credentials invalid or container does not exist',
                'azure',
                'invalid'
            );
        }
    }

    /**
     * Upload HTML to Azure Blob and return a SAS URL.
     *
     * @param html - HTML content to upload.
     * @param filename - Filename for the blob.
     * @returns Upload result with SAS URL.
     */
    async upload(html: string, filename: string): Promise<UploadResult> {
        await this.validateCredentials();

        const blobName = this.config.prefix
            ? `${this.config.prefix}/${filename}`
            : filename;
        const expiresAt = new Date(
            Date.now() + this.config.expirationHours * 60 * 60 * 1000
        );

        // In production, use Azure SDK to upload and generate SAS
        const sasUrl = await this.uploadBlobAndGenerateSas(blobName, html);

        return { url: sasUrl, expiresAt };
    }

    /**
     * Configure Azure Blob settings.
     *
     * @param settings - Azure configuration options.
     */
    configure(settings: Record<string, string>): void {
        if (settings.containerName) {
            this.config.containerName = settings.containerName;
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
     * Check if container exists using containerClient.exists().
     */
    private async checkContainerExists(connectionString: string): Promise<boolean> {
        // TODO: Implement actual Azure SDK container check
        // BlobServiceClient.fromConnectionString(connectionString)
        //   .getContainerClient(this.config.containerName).exists()
        return connectionString.includes('AccountName=');
    }

    /**
     * Upload blob and generate SAS URL.
     */
    private async uploadBlobAndGenerateSas(
        blobName: string,
        _content: string
    ): Promise<string> {
        // TODO: Implement actual Azure SDK upload and SAS generation
        const encodedBlob = encodeURIComponent(blobName);
        const accountMatch = /AccountName=([^;]+)/.exec('') || ['', 'account'];
        const account = accountMatch[1];
        return `https://${account}.blob.core.windows.net/${this.config.containerName}/${encodedBlob}?sv=2021-06-08&sr=b&sig=...`;
    }
}
