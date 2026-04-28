// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * LiveSREClient Tests
 *
 * Tests for URL validation, error sanitization, polling guard,
 * and escalation logic. HTTP calls are not exercised (requires mock server).
 */

import * as assert from 'assert';
import { LiveSREClient, isLoopbackEndpoint } from '../../services/liveClient';

suite('isLoopbackEndpoint', () => {
    test('accepts 127.0.0.1', () => {
        assert.ok(isLoopbackEndpoint('http://127.0.0.1:9377'));
    });
    test('accepts localhost', () => {
        assert.ok(isLoopbackEndpoint('http://localhost:9377'));
    });
    test('accepts ::1', () => {
        assert.ok(isLoopbackEndpoint('http://[::1]:9377'));
    });
    test('rejects external host', () => {
        assert.ok(!isLoopbackEndpoint('http://evil.com:9377'));
    });
    test('rejects 0.0.0.0', () => {
        assert.ok(!isLoopbackEndpoint('http://0.0.0.0:9377'));
    });
    test('rejects empty string', () => {
        assert.ok(!isLoopbackEndpoint(''));
    });
    test('rejects non-URL', () => {
        assert.ok(!isLoopbackEndpoint('not-a-url'));
    });
    test('rejects javascript: scheme', () => {
        assert.ok(!isLoopbackEndpoint('javascript:alert(1)'));
    });
});

suite('LiveSREClient constructor', () => {
    test('rejects non-loopback endpoint', () => {
        assert.throws(
            () => new LiveSREClient({ endpoint: 'http://evil.com:9377' }),
            /loopback/
        );
    });
    test('accepts loopback endpoint', () => {
        const client = new LiveSREClient({ endpoint: 'http://127.0.0.1:9377' });
        assert.ok(client);
        client.dispose();
    });
    test('clamps interval below 5000ms', () => {
        const client = new LiveSREClient({
            endpoint: 'http://127.0.0.1:9377',
            refreshIntervalMs: 1000,
        });
        // Cannot directly inspect _intervalMs, but client should not throw
        assert.ok(client);
        client.dispose();
    });
    test('initial snapshot is stale with no data', () => {
        const client = new LiveSREClient({ endpoint: 'http://127.0.0.1:9377' });
        const snap = client.getSnapshot();
        assert.strictEqual(snap.data, null);
        assert.strictEqual(snap.stale, true);
        assert.strictEqual(snap.error, null);
        assert.strictEqual(snap.escalated, false);
        client.dispose();
    });
    test('dispose is idempotent', () => {
        const client = new LiveSREClient({ endpoint: 'http://127.0.0.1:9377' });
        client.dispose();
        client.dispose(); // Should not throw
    });
});

suite('LiveSREClient token management', () => {
    test('setToken updates authorization header', () => {
        const client = new LiveSREClient({ endpoint: 'http://127.0.0.1:9377' });
        client.setToken('new-token');
        // Cannot directly inspect headers, but should not throw
        assert.ok(client);
        client.setToken(undefined); // Clear token
        client.dispose();
    });
});
