// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Unit tests for pure helpers and enums in topologyTypes.ts.
 *
 * Only tests truncateDid (pure string function) and ExecutionRing enum values.
 * trustIcon and createMockTopologyProvider are skipped because they depend on
 * vscode.ThemeIcon / vscode.ThemeColor.
 */

import * as assert from 'assert';
import { truncateDid, ExecutionRing, RING_LABELS } from '../../views/topologyTypes';

suite('topologyTypes — truncateDid', () => {
    test('truncates a DID longer than default maxLen (22)', () => {
        const did = 'did:mesh:a1b2c3d4e5f6a7b8c9d0e1f2';
        assert.ok(did.length > 22, 'precondition: input is longer than 22');
        const result = truncateDid(did);
        assert.ok(result.endsWith('...'));
        assert.strictEqual(result.length, 25); // 22 + 3 for "..."
    });

    test('returns unchanged when DID is shorter than maxLen', () => {
        const did = 'did:mesh:short';
        assert.strictEqual(truncateDid(did), did);
    });

    test('returns unchanged when DID is exactly maxLen', () => {
        const did = 'did:mesh:exactly22char'; // 22 chars
        assert.strictEqual(did.length, 22);
        assert.strictEqual(truncateDid(did), did);
    });

    test('truncates at a custom maxLen', () => {
        const did = 'did:mesh:abcdef123456';
        const result = truncateDid(did, 10);
        assert.strictEqual(result, 'did:mesh:a...');
    });

    test('handles empty string', () => {
        assert.strictEqual(truncateDid(''), '');
    });
});

suite('topologyTypes — ExecutionRing enum', () => {
    test('Ring0Root equals 0', () => {
        assert.strictEqual(ExecutionRing.Ring0Root, 0);
    });

    test('Ring1Supervisor equals 1', () => {
        assert.strictEqual(ExecutionRing.Ring1Supervisor, 1);
    });

    test('Ring2User equals 2', () => {
        assert.strictEqual(ExecutionRing.Ring2User, 2);
    });

    test('Ring3Sandbox equals 3', () => {
        assert.strictEqual(ExecutionRing.Ring3Sandbox, 3);
    });
});

suite('topologyTypes — RING_LABELS', () => {
    test('maps Ring0Root to label containing Root', () => {
        assert.ok(RING_LABELS[ExecutionRing.Ring0Root].includes('Root'));
    });

    test('maps Ring3Sandbox to label containing Sandbox', () => {
        assert.ok(RING_LABELS[ExecutionRing.Ring3Sandbox].includes('Sandbox'));
    });

    test('has exactly four entries', () => {
        assert.strictEqual(Object.keys(RING_LABELS).length, 4);
    });
});
