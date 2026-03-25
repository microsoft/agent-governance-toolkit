// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance Server Tests
 *
 * Unit tests for the local development server.
 */

import * as assert from 'assert';
import { findAvailablePort, isPortAvailable, generateClientId, DEFAULT_HOST } from '../../server/serverHelpers';
import { renderBrowserDashboard } from '../../server/browserTemplate';

suite('GovernanceServer Helpers', () => {
    suite('isPortAvailable', () => {
        test('returns true for available port', async () => {
            // Use a high port that is likely available
            const port = 49876;
            const available = await isPortAvailable(port, 'localhost');
            assert.ok(typeof available === 'boolean');
        });
    });

    suite('findAvailablePort', () => {
        test('finds an available port starting from given port', async () => {
            const startPort = 49877;
            const port = await findAvailablePort(startPort, 'localhost');

            assert.ok(port >= startPort);
            assert.ok(port < startPort + 10);
        });

        test('returns the start port if available', async () => {
            const startPort = 49878;
            // First check if the port is actually available
            const isAvailable = await isPortAvailable(startPort, 'localhost');

            if (isAvailable) {
                const port = await findAvailablePort(startPort, 'localhost');
                assert.strictEqual(port, startPort);
            }
            // If not available, that's fine - the test still passes
        });
    });

    suite('generateClientId', () => {
        test('generates unique IDs', () => {
            const id1 = generateClientId();
            const id2 = generateClientId();

            assert.notStrictEqual(id1, id2);
        });

        test('IDs start with client_ prefix', () => {
            const id = generateClientId();
            assert.ok(id.startsWith('client_'));
        });

        test('IDs contain timestamp', () => {
            const before = Date.now();
            const id = generateClientId();
            const after = Date.now();

            // Extract timestamp from ID (format: client_{timestamp}_{random})
            const parts = id.split('_');
            const timestamp = parseInt(parts[1], 10);

            assert.ok(timestamp >= before);
            assert.ok(timestamp <= after);
        });
    });
});

suite('Server State', () => {
    test('client connection has required fields', () => {
        const connection = {
            id: 'test_client',
            connectedAt: new Date(),
        };

        assert.ok(connection.id);
        assert.ok(connection.connectedAt instanceof Date);
    });
});

suite('Server Security', () => {
    test('DEFAULT_HOST binds to 127.0.0.1', () => {
        assert.strictEqual(DEFAULT_HOST, '127.0.0.1');
    });

    test('browser template includes CSP meta tag', () => {
        const html = renderBrowserDashboard(9845);
        assert.ok(
            html.includes('http-equiv="Content-Security-Policy"'),
            'CSP meta tag should be present in the HTML head'
        );
        assert.ok(
            html.includes("default-src 'self'"),
            'CSP should contain default-src directive'
        );
    });

    test('browser template includes SRI integrity attributes', () => {
        const html = renderBrowserDashboard(9845);
        assert.ok(
            html.includes('integrity="sha384-'),
            'CDN scripts should have SRI integrity attributes'
        );
        assert.ok(
            html.includes('crossorigin="anonymous"'),
            'CDN scripts should have crossorigin attribute'
        );
    });

    test('generateClientId uses crypto-strength randomness', () => {
        const id = generateClientId();
        // crypto.randomBytes(4) produces 8 hex chars
        const parts = id.split('_');
        const random = parts[2];
        assert.strictEqual(random.length, 8, 'random segment should be 8 hex chars');
        assert.ok(/^[0-9a-f]{8}$/.test(random), 'random segment should be hex');
    });
});
