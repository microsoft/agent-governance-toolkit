// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Unit tests for constants and pure values exported from governanceRules.ts.
 *
 * buildPolicyFileRules and isPolicyFile are skipped because they depend on
 * vscode.DiagnosticSeverity and vscode.TextDocument.
 */

import * as assert from 'assert';
import {
    DIAGNOSTIC_SOURCE,
    DIAGNOSTIC_COLLECTION_NAME,
    VALID_POLICY_ACTIONS,
    VALID_RING_VALUES,
    TRUST_SCORE_MIN,
    TRUST_SCORE_MAX,
    SUPPORTED_LANGUAGES,
} from '../../language/governanceRules';

suite('governanceRules — DIAGNOSTIC_SOURCE', () => {
    test('equals Agent OS Governance', () => {
        assert.strictEqual(DIAGNOSTIC_SOURCE, 'Agent OS Governance');
    });
});

suite('governanceRules — DIAGNOSTIC_COLLECTION_NAME', () => {
    test('equals agentOS.governance', () => {
        assert.strictEqual(DIAGNOSTIC_COLLECTION_NAME, 'agentOS.governance');
    });
});

suite('governanceRules — VALID_POLICY_ACTIONS', () => {
    test('contains ALLOW, DENY, AUDIT, BLOCK', () => {
        assert.deepStrictEqual(VALID_POLICY_ACTIONS, ['ALLOW', 'DENY', 'AUDIT', 'BLOCK']);
    });

    test('has exactly four entries', () => {
        assert.strictEqual(VALID_POLICY_ACTIONS.length, 4);
    });
});

suite('governanceRules — VALID_RING_VALUES', () => {
    test('contains rings 0 through 3', () => {
        assert.deepStrictEqual(VALID_RING_VALUES, [0, 1, 2, 3]);
    });
});

suite('governanceRules — trust score bounds', () => {
    test('TRUST_SCORE_MIN is 0', () => {
        assert.strictEqual(TRUST_SCORE_MIN, 0);
    });

    test('TRUST_SCORE_MAX is 1000', () => {
        assert.strictEqual(TRUST_SCORE_MAX, 1000);
    });

    test('min is less than max', () => {
        assert.ok(TRUST_SCORE_MIN < TRUST_SCORE_MAX);
    });
});

suite('governanceRules — SUPPORTED_LANGUAGES', () => {
    test('includes python', () => {
        assert.ok(SUPPORTED_LANGUAGES.includes('python'));
    });

    test('includes yaml', () => {
        assert.ok(SUPPORTED_LANGUAGES.includes('yaml'));
    });

    test('includes typescript', () => {
        assert.ok(SUPPORTED_LANGUAGES.includes('typescript'));
    });

    test('includes javascript', () => {
        assert.ok(SUPPORTED_LANGUAGES.includes('javascript'));
    });

    test('includes json', () => {
        assert.ok(SUPPORTED_LANGUAGES.includes('json'));
    });

    test('includes shell variants', () => {
        assert.ok(SUPPORTED_LANGUAGES.includes('shellscript'));
        assert.ok(SUPPORTED_LANGUAGES.includes('bash'));
        assert.ok(SUPPORTED_LANGUAGES.includes('sh'));
    });

    test('has expected count', () => {
        assert.strictEqual(SUPPORTED_LANGUAGES.length, 8);
    });
});
