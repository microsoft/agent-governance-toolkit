// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Unit tests for getSuppressComment from governanceCodeActions.ts.
 *
 * getSuppressComment is a pure string function with no VS Code dependency.
 * QUICK_FIXES and GovernanceCodeActionProvider are skipped because they use
 * vscode.WorkspaceEdit and vscode.CodeAction.
 */

import * as assert from 'assert';
import { getSuppressComment } from '../../language/governanceCodeActions';

suite('governanceCodeActions — getSuppressComment', () => {
    test('returns noqa comment for python', () => {
        assert.strictEqual(getSuppressComment('python', 'GOV001'), '  # noqa: GOV001');
    });

    test('returns hash-style ignore for yaml', () => {
        assert.strictEqual(getSuppressComment('yaml', 'GOV003'), '  # @agent-os-ignore GOV003');
    });

    test('returns hash-style ignore for json', () => {
        assert.strictEqual(getSuppressComment('json', 'GOV004'), '  # @agent-os-ignore GOV004');
    });

    test('returns slash-style ignore for typescript', () => {
        assert.strictEqual(
            getSuppressComment('typescript', 'GOV001'),
            '  // @agent-os-ignore GOV001',
        );
    });

    test('returns slash-style ignore for javascript', () => {
        assert.strictEqual(
            getSuppressComment('javascript', 'GOV002'),
            '  // @agent-os-ignore GOV002',
        );
    });

    test('defaults to slash-style ignore for unknown language', () => {
        assert.strictEqual(
            getSuppressComment('unknown', 'GOV005'),
            '  // @agent-os-ignore GOV005',
        );
    });

    test('defaults to slash-style ignore for empty language id', () => {
        assert.strictEqual(
            getSuppressComment('', 'GOV099'),
            '  // @agent-os-ignore GOV099',
        );
    });

    test('all comments start with two-space indent', () => {
        const languages = ['python', 'yaml', 'json', 'typescript', 'javascript', 'rust'];
        for (const lang of languages) {
            const comment = getSuppressComment(lang, 'GOV001');
            assert.ok(comment.startsWith('  '), `${lang}: expected 2-space indent`);
        }
    });
});

suite('governanceCodeActions — getSuppressComment (extended)', () => {
    test('preserves the exact GOV code in the output', () => {
        const codes = ['GOV001', 'GOV003', 'GOV005', 'GOV101', 'GOV103', 'GOV201', 'GOV202'];
        for (const code of codes) {
            const comment = getSuppressComment('python', code);
            assert.ok(comment.includes(code),
                `Comment for ${code} should contain the exact code`);
        }
    });

    test('python comments use hash-style (not slash-style)', () => {
        const comment = getSuppressComment('python', 'GOV101');
        assert.ok(comment.includes('#'), 'Python comment should use # style');
        assert.ok(!comment.includes('//'), 'Python comment should not use // style');
    });

    test('yaml and json use identical comment format', () => {
        const yamlComment = getSuppressComment('yaml', 'GOV003');
        const jsonComment = getSuppressComment('json', 'GOV003');
        assert.strictEqual(yamlComment, jsonComment,
            'yaml and json should produce identical suppress comments');
    });

    test('typescript and javascript use identical comment format prefix', () => {
        const tsComment = getSuppressComment('typescript', 'GOV001');
        const jsComment = getSuppressComment('javascript', 'GOV001');
        assert.strictEqual(tsComment, jsComment,
            'typescript and javascript should produce identical suppress comments');
    });

    test('python uses noqa prefix, not @agent-os-ignore', () => {
        const comment = getSuppressComment('python', 'GOV102');
        assert.ok(comment.includes('noqa:'), 'Python should use noqa: prefix');
        assert.ok(!comment.includes('@agent-os-ignore'),
            'Python should not use @agent-os-ignore');
    });

    test('non-python languages use @agent-os-ignore prefix', () => {
        const languages = ['yaml', 'json', 'typescript', 'javascript', 'go', 'rust'];
        for (const lang of languages) {
            const comment = getSuppressComment(lang, 'GOV001');
            assert.ok(comment.includes('@agent-os-ignore'),
                `${lang} should use @agent-os-ignore prefix`);
        }
    });

    test('output is a single line (no newlines)', () => {
        const languages = ['python', 'yaml', 'json', 'typescript', 'javascript', ''];
        for (const lang of languages) {
            const comment = getSuppressComment(lang, 'GOV005');
            assert.ok(!comment.includes('\n'),
                `Comment for "${lang}" should not contain newlines`);
        }
    });

    test('handles GOV2xx (cross-language) codes correctly', () => {
        const comment = getSuppressComment('typescript', 'GOV201');
        assert.strictEqual(comment, '  // @agent-os-ignore GOV201');
    });

    test('handles GOV1xx (python) codes in non-python contexts', () => {
        // A python-specific rule code used in yaml context should still work
        const comment = getSuppressComment('yaml', 'GOV103');
        assert.strictEqual(comment, '  # @agent-os-ignore GOV103');
    });
});
