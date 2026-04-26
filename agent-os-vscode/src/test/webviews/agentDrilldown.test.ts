// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Agent Drill-Down Unit Tests
 *
 * Tests for the agent selection and trust tier helpers
 * originally from GovernanceHubScript.ts, now tested independently
 */

import * as assert from 'assert';

/** Mock implementations of script functions for testing */

function getTrustTier(score: number): string {
    if (score > 700) return 'high';
    if (score >= 400) return 'medium';
    return 'low';
}

function truncateDid(did: string): string {
    return did.length > 24 ? did.slice(0, 24) + '...' : did;
}

suite('Agent Drill-Down Test Suite', () => {
    suite('getTrustTier', () => {
        test('Returns high for score > 700', () => {
            assert.strictEqual(getTrustTier(701), 'high');
            assert.strictEqual(getTrustTier(800), 'high');
            assert.strictEqual(getTrustTier(1000), 'high');
        });

        test('Returns medium for score 400-700', () => {
            assert.strictEqual(getTrustTier(400), 'medium');
            assert.strictEqual(getTrustTier(550), 'medium');
            assert.strictEqual(getTrustTier(700), 'medium');
        });

        test('Returns low for score < 400', () => {
            assert.strictEqual(getTrustTier(0), 'low');
            assert.strictEqual(getTrustTier(200), 'low');
            assert.strictEqual(getTrustTier(399), 'low');
        });

        test('Boundary values are correct', () => {
            assert.strictEqual(getTrustTier(700), 'medium');
            assert.strictEqual(getTrustTier(701), 'high');
            assert.strictEqual(getTrustTier(399), 'low');
            assert.strictEqual(getTrustTier(400), 'medium');
        });
    });

    suite('truncateDid', () => {
        test('Short DIDs are not truncated', () => {
            const shortDid = 'did:mesh:abc123';
            assert.strictEqual(truncateDid(shortDid), shortDid);
        });

        test('Long DIDs are truncated with ellipsis', () => {
            const longDid = 'did:mesh:a1b2c3d4e5f6a7b8c9d0e1f2';
            const result = truncateDid(longDid);
            assert.ok(result.endsWith('...'), 'Should end with ellipsis');
            assert.strictEqual(result.length, 27); // 24 chars + '...'
        });

        test('Exactly 24 chars not truncated', () => {
            const did24 = 'did:mesh:123456789012345';
            assert.strictEqual(did24.length, 24);
            assert.strictEqual(truncateDid(did24), did24);
        });

        test('25+ chars are truncated', () => {
            const did25 = 'did:mesh:1234567890123456';
            assert.strictEqual(did25.length, 25);
            const result = truncateDid(did25);
            assert.ok(result.endsWith('...'));
        });
    });
});
