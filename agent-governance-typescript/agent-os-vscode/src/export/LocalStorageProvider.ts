// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Local filesystem storage provider.
 *
 * Saves governance reports to a local directory with file:// URLs.
 */

import * as fs from 'fs';
import * as path from 'path';
import { CredentialError } from './CredentialError';
import { StorageProvider, UploadResult } from './StorageProvider';

/**
 * Storage provider that saves reports to the local filesystem.
 */
export class LocalStorageProvider implements StorageProvider {
    private outputDir: string;

    constructor(outputDir?: string) {
        this.outputDir = outputDir || process.cwd();
    }

    /**
     * Validate write permissions to the output directory.
     *
     * @throws CredentialError if directory is not writable.
     */
    async validateCredentials(): Promise<void> {
        try {
            await fs.promises.access(this.outputDir, fs.constants.W_OK);
        } catch {
            throw new CredentialError(
                `No write permission to directory: ${this.outputDir}`,
                'local',
                'invalid'
            );
        }
    }

    /**
     * Save HTML content to the local filesystem.
     *
     * @param html - HTML content to save.
     * @param filename - Filename for the report.
     * @returns Upload result with file:// URL.
     */
    async upload(html: string, filename: string): Promise<UploadResult> {
        await this.validateCredentials();

        const filePath = path.join(this.outputDir, filename);
        const resolved = path.resolve(filePath);
        if (!resolved.startsWith(path.resolve(this.outputDir) + path.sep)) {
            throw new Error('Export path must be within output directory');
        }
        await fs.promises.writeFile(resolved, html, 'utf8');

        return {
            url: `file://${resolved}`,
            expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year
        };
    }

    /**
     * Configure the output directory.
     *
     * @param settings - Must include 'outputDir' key.
     */
    configure(settings: Record<string, string>): void {
        if (settings.outputDir) {
            this.outputDir = settings.outputDir;
        }
    }
}
