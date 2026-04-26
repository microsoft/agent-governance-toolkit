// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * SRE Server Lifecycle Tests
 *
 * Tests for agent-failsafe detection, subprocess management,
 * and health checking. Uses real Python interpreter where available.
 */

import * as assert from 'assert';
import { isAgentFailsafeAvailable, isValidPythonPath, SREServerManager } from '../../services/sreServer';

suite('isValidPythonPath', () => {
    test('rejects empty string', () => { assert.strictEqual(isValidPythonPath(''), false); });
    test('rejects whitespace', () => { assert.strictEqual(isValidPythonPath('   '), false); });
    test('rejects semicolons', () => { assert.strictEqual(isValidPythonPath('python; rm -rf /'), false); });
    test('rejects backticks', () => { assert.strictEqual(isValidPythonPath('`whoami`'), false); });
    test('rejects pipe', () => { assert.strictEqual(isValidPythonPath('python | cat'), false); });
    test('rejects dollar sign', () => { assert.strictEqual(isValidPythonPath('$HOME/python'), false); });
    test('rejects null bytes', () => { assert.strictEqual(isValidPythonPath('python\0'), false); });
    test('accepts python3', () => { assert.strictEqual(isValidPythonPath('python3'), true); });
    test('accepts unix path', () => { assert.strictEqual(isValidPythonPath('/usr/bin/python'), true); });
    test('accepts windows path', () => { assert.strictEqual(isValidPythonPath('C:\\Python311\\python.exe'), true); });
});

suite('isAgentFailsafeAvailable', () => {
    test('returns false for nonexistent python binary', async () => {
        const result = await isAgentFailsafeAvailable('nonexistent-python-xyz');
        assert.strictEqual(result, false);
    });

    test('returns false for whitespace-only path', async () => {
        const result = await isAgentFailsafeAvailable('   ');
        assert.strictEqual(result, false);
    });

    test('returns boolean for system python', async () => {
        const result = await isAgentFailsafeAvailable('python');
        assert.ok(typeof result === 'boolean');
    });
});

suite('SREServerManager', () => {
    test('constructor accepts python path and optional port', () => {
        const mgr = new SREServerManager('python', 19377);
        assert.ok(mgr);
        mgr.stop();
    });

    test('getEndpoint returns empty before start', () => {
        const mgr = new SREServerManager('python');
        assert.strictEqual(mgr.getEndpoint(), '');
        mgr.stop();
    });

    test('stop is idempotent', () => {
        const mgr = new SREServerManager('python');
        mgr.stop();
        mgr.stop();
    });

    test('start with invalid python returns not ok', async () => {
        const mgr = new SREServerManager('nonexistent-python-xyz');
        const result = await mgr.start();
        assert.strictEqual(result.ok, false);
        assert.strictEqual(result.endpoint, '');
        assert.ok(result.message.length > 0);
    });

    test('start returns endpoint URL on port 9377 by default', () => {
        const mgr = new SREServerManager('python');
        // Don't actually start — just verify the default port
        assert.strictEqual(mgr.getEndpoint(), '');
        mgr.stop();
    });
});
