// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Storage Provider Tests
 *
 * Unit tests for storage providers including credential validation.
 */

import * as assert from 'assert';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { LocalStorageProvider } from '../../export/LocalStorageProvider';
import { CredentialError } from '../../export/CredentialError';

suite('StorageProviders', () => {
    suite('LocalStorageProvider', () => {
        let tempDir: string;
        let provider: LocalStorageProvider;

        setup(() => {
            tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-os-test-'));
            provider = new LocalStorageProvider(tempDir);
        });

        teardown(() => {
            // Clean up temp directory
            try {
                fs.rmSync(tempDir, { recursive: true, force: true });
            } catch {
                // Ignore cleanup errors
            }
        });

        test('validates writable directory', async () => {
            await provider.validateCredentials();
            // Should not throw
        });

        test('throws CredentialError for unwritable directory', async () => {
            const badProvider = new LocalStorageProvider('/nonexistent/path/that/does/not/exist');

            try {
                await badProvider.validateCredentials();
                assert.fail('Should have thrown CredentialError');
            } catch (e) {
                assert.ok(e instanceof CredentialError);
                assert.strictEqual((e as CredentialError).reason, 'invalid');
            }
        });

        test('uploads file and returns file:// URL', async () => {
            const html = '<html><body>Test Report</body></html>';
            const filename = 'test-report.html';

            const result = await provider.upload(html, filename);

            assert.ok(result.url.startsWith('file://'));
            assert.ok(result.url.includes(filename));
            assert.ok(result.expiresAt > new Date());
        });

        test('creates file on disk', async () => {
            const html = '<html><body>Content Check</body></html>';
            const filename = 'content-check.html';

            const result = await provider.upload(html, filename);
            const filePath = result.url.replace('file://', '');

            assert.ok(fs.existsSync(filePath));
            const content = fs.readFileSync(filePath, 'utf-8');
            assert.strictEqual(content, html);
        });
    });

    suite('CredentialError', () => {
        test('contains provider and reason', () => {
            const error = new CredentialError(
                'Test error message',
                's3',
                'expired'
            );

            assert.strictEqual(error.provider, 's3');
            assert.strictEqual(error.reason, 'expired');
            assert.strictEqual(error.message, 'Test error message');
            assert.strictEqual(error.name, 'CredentialError');
        });

        test('is instanceof Error', () => {
            const error = new CredentialError('Test', 'azure', 'missing');
            assert.ok(error instanceof Error);
        });
    });
});
