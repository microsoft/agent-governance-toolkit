// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import * as assert from 'assert';
import { escapeHtml } from '../../utils/escapeHtml';

suite('escapeHtml', () => {
    test('escapes & to &amp;', () => {
        assert.strictEqual(escapeHtml('a&b'), 'a&amp;b');
    });

    test('escapes < to &lt;', () => {
        assert.strictEqual(escapeHtml('<script>'), '&lt;script&gt;');
    });

    test('escapes > to &gt;', () => {
        assert.strictEqual(escapeHtml('a>b'), 'a&gt;b');
    });

    test('escapes " to &quot;', () => {
        assert.strictEqual(escapeHtml('a"b'), 'a&quot;b');
    });

    test("escapes ' to &#39;", () => {
        assert.strictEqual(escapeHtml("a'b"), 'a&#39;b');
    });

    test('handles number input', () => {
        assert.strictEqual(escapeHtml(42), '42');
    });

    test('handles null input', () => {
        assert.strictEqual(escapeHtml(null), '');
    });

    test('handles undefined input', () => {
        assert.strictEqual(escapeHtml(undefined), '');
    });

    test('returns empty string for empty input', () => {
        assert.strictEqual(escapeHtml(''), '');
    });

    test('does not double-escape already-escaped content', () => {
        assert.strictEqual(escapeHtml('&amp;'), '&amp;amp;');
    });

    test('handles all special characters in one string', () => {
        assert.strictEqual(
            escapeHtml('<div class="test">O\'Brien & Co</div>'),
            '&lt;div class=&quot;test&quot;&gt;O&#39;Brien &amp; Co&lt;/div&gt;',
        );
    });
});
