// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';

const EXTENSION_ROOT = path.resolve(__dirname, '..', '..', '..');

suite('Vendor Assets', () => {
    test('d3.v7.8.5.min.js exists and is non-empty', () => {
        const filePath = path.join(EXTENSION_ROOT, 'assets', 'vendor', 'd3.v7.8.5.min.js');
        assert.ok(fs.existsSync(filePath), 'D3 vendor file should exist');
        const stat = fs.statSync(filePath);
        assert.ok(stat.size > 100_000, `D3 should be > 100KB, got ${stat.size}`);
    });

    test('chart.v4.4.1.umd.min.js exists and is non-empty', () => {
        const filePath = path.join(EXTENSION_ROOT, 'assets', 'vendor', 'chart.v4.4.1.umd.min.js');
        assert.ok(fs.existsSync(filePath), 'Chart.js vendor file should exist');
        const stat = fs.statSync(filePath);
        assert.ok(stat.size > 100_000, `Chart.js should be > 100KB, got ${stat.size}`);
    });

    test('no CDN references remain in production source', () => {
        const srcDir = path.join(EXTENSION_ROOT, 'src');
        const files = walkSync(srcDir)
            .filter(f => (f.endsWith('.ts') || f.endsWith('.tsx')) && !f.includes('test'));
        const violations: string[] = [];
        for (const file of files) {
            const content = fs.readFileSync(file, 'utf8');
            if (content.includes('://cdn.jsdelivr.net')) {
                violations.push(path.relative(EXTENSION_ROOT, file));
            }
        }
        assert.deepStrictEqual(violations, [], `CDN references found in: ${violations.join(', ')}`);
    });
});

function walkSync(dir: string): string[] {
    const results: string[] = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) { results.push(...walkSync(full)); }
        else { results.push(full); }
    }
    return results;
}
