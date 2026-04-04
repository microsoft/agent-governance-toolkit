// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Audit Filter Unit Tests
 *
 * Tests for the client-side audit filtering logic
 * originally from GovernanceHubScript.ts, now tested independently
 */

import * as assert from 'assert';

interface AuditEntry {
    type: string;
    violation?: string;
    file?: string;
    reason?: string;
    timestamp: Date;
}

/** Mock filter implementation matching GovernanceHubScript */
function filterEntries(
    entries: AuditEntry[],
    search: string,
    type: string
): AuditEntry[] {
    const searchLower = search.toLowerCase();
    return entries.filter(e => {
        const matchesSearch = !searchLower ||
            (e.violation && e.violation.toLowerCase().includes(searchLower)) ||
            (e.file && e.file.toLowerCase().includes(searchLower)) ||
            (e.reason && e.reason.toLowerCase().includes(searchLower));
        const matchesType = !type || e.type === type;
        return matchesSearch && matchesType;
    });
}

/** Mock CSV escape matching extension.ts */
function escapeCSV(value: string | undefined): string {
    if (!value) return '';
    return value.replace(/,/g, ';');
}

suite('Audit Filter Test Suite', () => {
    const mockEntries: AuditEntry[] = [
        { type: 'blocked', violation: 'SQL Injection detected', file: 'src/db.ts', timestamp: new Date() },
        { type: 'warning', reason: 'Hardcoded API key', file: 'config.js', timestamp: new Date() },
        { type: 'allowed', file: 'utils.ts', timestamp: new Date() },
        { type: 'blocked', violation: 'Shell command blocked', file: 'script.py', timestamp: new Date() },
        { type: 'cmvk_review', reason: 'Multi-model review passed', timestamp: new Date() },
    ];

    suite('Type Filter', () => {
        test('Filter by type returns only matching entries', () => {
            const result = filterEntries(mockEntries, '', 'blocked');
            assert.strictEqual(result.length, 2);
            result.forEach(e => assert.strictEqual(e.type, 'blocked'));
        });

        test('Empty type returns all entries', () => {
            const result = filterEntries(mockEntries, '', '');
            assert.strictEqual(result.length, mockEntries.length);
        });

        test('Non-matching type returns empty', () => {
            const result = filterEntries(mockEntries, '', 'nonexistent');
            assert.strictEqual(result.length, 0);
        });
    });

    suite('Search Filter', () => {
        test('Search is case-insensitive', () => {
            const result1 = filterEntries(mockEntries, 'SQL', '');
            const result2 = filterEntries(mockEntries, 'sql', '');
            const result3 = filterEntries(mockEntries, 'SQL INJECTION', '');

            assert.strictEqual(result1.length, 1);
            assert.strictEqual(result2.length, 1);
            assert.strictEqual(result3.length, 1);
        });

        test('Search matches violation field', () => {
            const result = filterEntries(mockEntries, 'Shell', '');
            assert.strictEqual(result.length, 1);
            assert.ok(result[0].violation?.includes('Shell'));
        });

        test('Search matches file field', () => {
            const result = filterEntries(mockEntries, 'config', '');
            assert.strictEqual(result.length, 1);
            assert.strictEqual(result[0].file, 'config.js');
        });

        test('Search matches reason field', () => {
            const result = filterEntries(mockEntries, 'API key', '');
            assert.strictEqual(result.length, 1);
            assert.ok(result[0].reason?.includes('API key'));
        });

        test('Empty search returns all entries', () => {
            const result = filterEntries(mockEntries, '', '');
            assert.strictEqual(result.length, mockEntries.length);
        });
    });

    suite('Combined Filter', () => {
        test('Search and type filter combined', () => {
            const result = filterEntries(mockEntries, 'blocked', 'blocked');
            assert.strictEqual(result.length, 1);
            assert.ok(result[0].violation?.toLowerCase().includes('blocked'));
        });

        test('Non-matching combination returns empty', () => {
            const result = filterEntries(mockEntries, 'API key', 'blocked');
            assert.strictEqual(result.length, 0);
        });
    });

    suite('CSV Export', () => {
        test('Commas in fields are escaped with semicolons', () => {
            assert.strictEqual(escapeCSV('hello, world'), 'hello; world');
            assert.strictEqual(escapeCSV('a,b,c'), 'a;b;c');
        });

        test('Empty values return empty string', () => {
            assert.strictEqual(escapeCSV(undefined), '');
            assert.strictEqual(escapeCSV(''), '');
        });

        test('Values without commas are unchanged', () => {
            assert.strictEqual(escapeCSV('hello world'), 'hello world');
        });
    });
});
