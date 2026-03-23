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
