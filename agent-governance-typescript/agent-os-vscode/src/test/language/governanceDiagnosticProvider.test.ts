// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Unit tests for governance diagnostic constants and the isValidAgentDID helper.
 *
 * GovernanceDiagnosticProvider, buildPolicyFileRules, buildPythonRules, and
 * buildCrossLanguageRules all depend on vscode APIs and cannot be tested here.
 * We test the pure constants and helper functions that are exported.
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
import { isValidAgentDID } from '../../language/governanceIntegrationRules';

suite('governanceDiagnosticProvider — DIAGNOSTIC_SOURCE', () => {
    test('is a non-empty string', () => {
        assert.ok(typeof DIAGNOSTIC_SOURCE === 'string');
        assert.ok(DIAGNOSTIC_SOURCE.length > 0, 'DIAGNOSTIC_SOURCE should not be empty');
    });

    test('equals "Agent OS Governance"', () => {
        assert.strictEqual(DIAGNOSTIC_SOURCE, 'Agent OS Governance');
    });
});

suite('governanceDiagnosticProvider — DIAGNOSTIC_COLLECTION_NAME', () => {
    test('is a non-empty string', () => {
        assert.ok(typeof DIAGNOSTIC_COLLECTION_NAME === 'string');
        assert.ok(DIAGNOSTIC_COLLECTION_NAME.length > 0);
    });

    test('uses dotted namespace format', () => {
        assert.ok(DIAGNOSTIC_COLLECTION_NAME.includes('.'),
            'Collection name should use dotted namespace format');
    });
});

suite('governanceDiagnosticProvider — VALID_POLICY_ACTIONS', () => {
    test('contains ALLOW', () => {
        assert.ok(VALID_POLICY_ACTIONS.includes('ALLOW'));
    });

    test('contains DENY', () => {
        assert.ok(VALID_POLICY_ACTIONS.includes('DENY'));
    });

    test('contains AUDIT', () => {
        assert.ok(VALID_POLICY_ACTIONS.includes('AUDIT'));
    });

    test('contains BLOCK', () => {
        assert.ok(VALID_POLICY_ACTIONS.includes('BLOCK'));
    });

    test('has exactly 4 actions', () => {
        assert.strictEqual(VALID_POLICY_ACTIONS.length, 4);
    });

    test('all actions are uppercase strings', () => {
        for (const action of VALID_POLICY_ACTIONS) {
            assert.strictEqual(action, action.toUpperCase(),
                `Action "${action}" should be uppercase`);
        }
    });
});

suite('governanceDiagnosticProvider — VALID_RING_VALUES', () => {
    test('contains 0, 1, 2, 3', () => {
        assert.deepStrictEqual(VALID_RING_VALUES, [0, 1, 2, 3]);
    });

    test('maps to ExecutionRing enum values', () => {
        // Ring0Root=0, Ring1Supervisor=1, Ring2User=2, Ring3Sandbox=3
        for (const ring of VALID_RING_VALUES) {
            assert.ok(ring >= 0 && ring <= 3,
                `Ring value ${ring} should be between 0 and 3`);
        }
    });
});

suite('governanceDiagnosticProvider — trust score bounds', () => {
    test('TRUST_SCORE_MIN is 0', () => {
        assert.strictEqual(TRUST_SCORE_MIN, 0);
    });

    test('TRUST_SCORE_MAX is 1000', () => {
        assert.strictEqual(TRUST_SCORE_MAX, 1000);
    });

    test('range covers 1001 discrete values', () => {
        assert.strictEqual(TRUST_SCORE_MAX - TRUST_SCORE_MIN + 1, 1001);
    });
});

suite('governanceDiagnosticProvider — SUPPORTED_LANGUAGES', () => {
    test('is a non-empty array', () => {
        assert.ok(Array.isArray(SUPPORTED_LANGUAGES));
        assert.ok(SUPPORTED_LANGUAGES.length > 0);
    });

    test('includes all expected languages', () => {
        const expected = ['javascript', 'typescript', 'python', 'yaml', 'json'];
        for (const lang of expected) {
            assert.ok(SUPPORTED_LANGUAGES.includes(lang),
                `Should include "${lang}"`);
        }
    });

    test('includes shell script variants', () => {
        assert.ok(SUPPORTED_LANGUAGES.includes('shellscript'));
        assert.ok(SUPPORTED_LANGUAGES.includes('bash'));
        assert.ok(SUPPORTED_LANGUAGES.includes('sh'));
    });

    test('all entries are lowercase strings', () => {
        for (const lang of SUPPORTED_LANGUAGES) {
            assert.strictEqual(lang, lang.toLowerCase(),
                `Language "${lang}" should be lowercase`);
        }
    });
});

suite('governanceDiagnosticProvider — isValidAgentDID edge cases', () => {
    test('rejects did:mesh with special characters', () => {
        assert.strictEqual(isValidAgentDID('did:mesh:' + 'a'.repeat(31) + '!'), false);
    });

    test('rejects did:mesh with spaces', () => {
        assert.strictEqual(isValidAgentDID('did:mesh: ' + 'a'.repeat(32)), false);
    });

    test('rejects did:myth with numeric persona', () => {
        assert.strictEqual(isValidAgentDID('did:myth:123:' + 'a'.repeat(32)), false);
    });

    test('rejects did:myth with empty persona', () => {
        assert.strictEqual(isValidAgentDID('did:myth::' + 'a'.repeat(32)), false);
    });

    test('accepts did:mesh with exactly 32 hex chars', () => {
        assert.strictEqual(isValidAgentDID('did:mesh:' + 'abcdef01'.repeat(4)), true);
    });

    test('accepts did:myth with any lowercase persona name', () => {
        // The regex accepts any [a-z]+ persona, not just known ones
        assert.strictEqual(
            isValidAgentDID('did:myth:custompersona:' + 'a'.repeat(32)),
            true,
        );
    });

    test('rejects did:myth with mixed-case persona', () => {
        assert.strictEqual(
            isValidAgentDID('did:myth:Sentinel:' + 'a'.repeat(32)),
            false,
        );
    });
});
