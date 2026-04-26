// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Unit tests for pure functions and constants from governanceStatusBarTypes.ts.
 *
 * All tested functions are pure with no VS Code dependency.
 */

import * as assert from 'assert';
import {
    formatTime,
    truncateAgentDid,
    buildModeTooltip,
    buildViolationTooltip,
    MODE_LABELS,
    MODE_DESCRIPTIONS,
} from '../governanceStatusBarTypes';

suite('governanceStatusBarTypes — formatTime', () => {
    test('returns a non-empty string', () => {
        const result = formatTime(new Date(2026, 2, 22, 14, 30, 45));
        assert.strictEqual(typeof result, 'string');
        assert.ok(result.length > 0);
    });
});

suite('governanceStatusBarTypes — truncateAgentDid', () => {
    test('truncates a long DID to expected format', () => {
        const did = 'did:mesh:' + 'a'.repeat(40);
        const result = truncateAgentDid(did);
        assert.ok(result.length <= 25, `expected max 25 chars, got ${result.length}`);
        assert.ok(result.includes('...'));
    });

    test('preserves first 16 chars of a long DID', () => {
        const did = 'did:mesh:' + 'a'.repeat(40);
        const result = truncateAgentDid(did);
        assert.strictEqual(result.slice(0, 16), did.slice(0, 16));
    });

    test('preserves last 6 chars of a long DID', () => {
        const did = 'did:mesh:' + 'a'.repeat(40);
        const result = truncateAgentDid(did);
        assert.strictEqual(result.slice(-6), did.slice(-6));
    });

    test('returns unchanged when DID is 24 chars or shorter', () => {
        const did = 'did:mesh:short';
        assert.strictEqual(truncateAgentDid(did), did);
    });

    test('returns unchanged at exactly 24 chars', () => {
        const did = 'did:mesh:exactly24chars!';
        assert.strictEqual(did.length, 24);
        assert.strictEqual(truncateAgentDid(did), did);
    });
});

suite('governanceStatusBarTypes — buildModeTooltip', () => {
    test('contains the mode label for strict', () => {
        const tip = buildModeTooltip('strict', 5, new Date());
        assert.ok(tip.includes('Strict'));
    });

    test('contains active policies count', () => {
        const tip = buildModeTooltip('strict', 5, new Date());
        assert.ok(tip.includes('Active policies: 5'));
    });

    test('contains mode description for permissive', () => {
        const tip = buildModeTooltip('permissive', 0, new Date());
        assert.ok(tip.includes('Permissive'));
        assert.ok(tip.includes('logged but not blocked'));
    });

    test('contains audit-only description', () => {
        const tip = buildModeTooltip('audit-only', 3, new Date());
        assert.ok(tip.includes('Audit-Only'));
    });

    test('includes click instruction', () => {
        const tip = buildModeTooltip('strict', 1, new Date());
        assert.ok(tip.includes('Click to configure policy'));
    });
});

suite('governanceStatusBarTypes — buildViolationTooltip', () => {
    test('contains violation count with plural', () => {
        const tip = buildViolationTooltip(3, { errors: 2, warnings: 1 });
        assert.ok(tip.includes('3 violations'));
    });

    test('uses singular for exactly 1 violation', () => {
        const tip = buildViolationTooltip(1, { errors: 1, warnings: 0 });
        assert.ok(tip.includes('1 violation today'));
        assert.ok(!tip.includes('1 violations'));
    });

    test('shows error and warning breakdown', () => {
        const tip = buildViolationTooltip(3, { errors: 2, warnings: 1 });
        assert.ok(tip.includes('Errors:   2'));
        assert.ok(tip.includes('Warnings: 1'));
    });

    test('handles zero violations without crashing', () => {
        const tip = buildViolationTooltip(0, { errors: 0, warnings: 0 });
        assert.ok(tip.includes('0 violations'));
    });

    test('includes last violation time when provided', () => {
        const lastViolation = new Date(2026, 2, 22, 10, 15, 30);
        const tip = buildViolationTooltip(1, { errors: 1, warnings: 0, lastViolation });
        assert.ok(tip.includes('Last violation:'));
    });

    test('omits last violation line when not provided', () => {
        const tip = buildViolationTooltip(2, { errors: 1, warnings: 1 });
        assert.ok(!tip.includes('Last violation:'));
    });

    test('includes click instruction', () => {
        const tip = buildViolationTooltip(0, { errors: 0, warnings: 0 });
        assert.ok(tip.includes('Click to view audit log'));
    });
});

suite('governanceStatusBarTypes — MODE_LABELS', () => {
    test('strict maps to Strict', () => {
        assert.strictEqual(MODE_LABELS['strict'], 'Strict');
    });

    test('permissive maps to Permissive', () => {
        assert.strictEqual(MODE_LABELS['permissive'], 'Permissive');
    });

    test('audit-only maps to Audit-Only', () => {
        assert.strictEqual(MODE_LABELS['audit-only'], 'Audit-Only');
    });
});

suite('governanceStatusBarTypes — MODE_DESCRIPTIONS', () => {
    test('each mode has a non-empty description', () => {
        const modes: Array<'strict' | 'permissive' | 'audit-only'> = [
            'strict', 'permissive', 'audit-only',
        ];
        for (const mode of modes) {
            assert.ok(MODE_DESCRIPTIONS[mode].length > 0, `${mode} description is empty`);
        }
    });
});
