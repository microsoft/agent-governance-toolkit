// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Unit tests for the timeAgo utility.
 *
 * Tests relative time formatting from AuditSummary with no React dependency.
 */

import * as assert from 'assert';
import { timeAgo } from '../../webviews/sidebar/timeUtils';

suite('AuditSummary — timeAgo', () => {
    test('returns "just now" for timestamps less than 1 minute ago', () => {
        const recent = new Date(Date.now() - 30_000).toISOString(); // 30s ago
        assert.strictEqual(timeAgo(recent), 'just now');
    });

    test('returns "just now" for future timestamps', () => {
        const future = new Date(Date.now() + 60_000).toISOString();
        assert.strictEqual(timeAgo(future), 'just now');
    });

    test('returns minutes for 1-59 minutes ago', () => {
        const fiveMinAgo = new Date(Date.now() - 5 * 60_000).toISOString();
        assert.strictEqual(timeAgo(fiveMinAgo), '5m ago');
    });

    test('returns hours for 1-23 hours ago', () => {
        const threeHoursAgo = new Date(Date.now() - 3 * 3_600_000).toISOString();
        assert.strictEqual(timeAgo(threeHoursAgo), '3h ago');
    });

    test('returns days for 24+ hours ago', () => {
        const twoDaysAgo = new Date(Date.now() - 2 * 86_400_000).toISOString();
        assert.strictEqual(timeAgo(twoDaysAgo), '2d ago');
    });

    test('returns "1m ago" at exactly 1 minute', () => {
        const oneMinAgo = new Date(Date.now() - 60_000).toISOString();
        assert.strictEqual(timeAgo(oneMinAgo), '1m ago');
    });

    test('returns "1h ago" at exactly 60 minutes', () => {
        const oneHourAgo = new Date(Date.now() - 60 * 60_000).toISOString();
        assert.strictEqual(timeAgo(oneHourAgo), '1h ago');
    });

    test('returns "1d ago" at exactly 24 hours', () => {
        const oneDayAgo = new Date(Date.now() - 24 * 3_600_000).toISOString();
        assert.strictEqual(timeAgo(oneDayAgo), '1d ago');
    });
});
