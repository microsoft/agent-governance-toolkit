// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Unit tests for isValidAgentDID from governanceIntegrationRules.ts.
 *
 * isValidAgentDID is a pure regex-based validator with no VS Code dependency.
 * buildPythonRules and buildCrossLanguageRules are skipped because their rule
 * objects reference vscode.DiagnosticSeverity.
 */

import * as assert from 'assert';
import { isValidAgentDID } from '../../language/governanceIntegrationRules';

suite('governanceIntegrationRules — isValidAgentDID (did:mesh format)', () => {
    test('accepts valid did:mesh with 32 hex chars', () => {
        assert.strictEqual(isValidAgentDID('did:mesh:' + 'a'.repeat(32)), true);
    });

    test('accepts valid did:mesh with mixed-case hex', () => {
        assert.strictEqual(isValidAgentDID('did:mesh:' + 'A1B2'.repeat(8)), true);
    });

    test('accepts did:mesh with more than 32 hex chars', () => {
        assert.strictEqual(isValidAgentDID('did:mesh:' + 'f'.repeat(64)), true);
    });

    test('rejects did:mesh with fewer than 32 hex chars', () => {
        assert.strictEqual(isValidAgentDID('did:mesh:short'), false);
    });

    test('rejects did:mesh with 31 hex chars', () => {
        assert.strictEqual(isValidAgentDID('did:mesh:' + 'a'.repeat(31)), false);
    });

    test('rejects did:mesh with non-hex characters', () => {
        assert.strictEqual(isValidAgentDID('did:mesh:' + 'g'.repeat(32)), false);
    });
});

suite('governanceIntegrationRules — isValidAgentDID (did:myth format)', () => {
    test('accepts valid did:myth:sentinel with 32 hex chars', () => {
        assert.strictEqual(
            isValidAgentDID('did:myth:sentinel:' + 'b'.repeat(32)),
            true,
        );
    });

    test('accepts valid did:myth:judge with 32 hex chars', () => {
        assert.strictEqual(
            isValidAgentDID('did:myth:judge:' + 'c'.repeat(32)),
            true,
        );
    });

    test('accepts valid did:myth:scrivener with 32 hex chars', () => {
        assert.strictEqual(
            isValidAgentDID('did:myth:scrivener:' + 'd'.repeat(32)),
            true,
        );
    });

    test('accepts valid did:myth:overseer with 32 hex chars', () => {
        assert.strictEqual(
            isValidAgentDID('did:myth:overseer:' + 'e'.repeat(32)),
            true,
        );
    });

    test('rejects did:myth with missing hash', () => {
        assert.strictEqual(isValidAgentDID('did:myth:bad'), false);
    });

    test('rejects did:myth with 31 hex chars (too short)', () => {
        assert.strictEqual(
            isValidAgentDID('did:myth:sentinel:' + 'b'.repeat(31)),
            false,
        );
    });

    test('rejects did:myth with 33 hex chars (too long)', () => {
        assert.strictEqual(
            isValidAgentDID('did:myth:sentinel:' + 'b'.repeat(33)),
            false,
        );
    });
});

suite('governanceIntegrationRules — isValidAgentDID (invalid inputs)', () => {
    test('rejects wrong scheme prefix', () => {
        assert.strictEqual(isValidAgentDID('did:other:something'), false);
    });

    test('rejects empty string', () => {
        assert.strictEqual(isValidAgentDID(''), false);
    });

    test('rejects non-DID string', () => {
        assert.strictEqual(isValidAgentDID('not-a-did'), false);
    });

    test('rejects bare prefix without hash', () => {
        assert.strictEqual(isValidAgentDID('did:mesh:'), false);
    });

    test('rejects did:myth with uppercase persona', () => {
        assert.strictEqual(
            isValidAgentDID('did:myth:SENTINEL:' + 'a'.repeat(32)),
            false,
        );
    });
});
