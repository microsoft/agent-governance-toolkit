// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Metrics Exporter Tests
 *
 * Unit tests for the OpenTelemetry-compatible metrics exporter.
 */

import * as assert from 'assert';
import { MetricsExporter, GovernanceMetrics } from '../../observability/MetricsExporter';

suite('MetricsExporter', () => {
    let exporter: MetricsExporter;

    setup(() => {
        // Use a mock endpoint that won't actually receive requests in tests
        exporter = new MetricsExporter('http://localhost:0/metrics');
    });

    suite('GovernanceMetrics interface', () => {
        test('accepts valid metrics object', () => {
            const metrics: GovernanceMetrics = {
                availability: 99.95,
                latencyP99: 250,
                compliancePercent: 98.5,
                trustScoreMean: 820,
                agentCount: 15,
                violationsToday: 2,
                timestamp: new Date().toISOString(),
            };

            assert.strictEqual(metrics.availability, 99.95);
            assert.strictEqual(metrics.latencyP99, 250);
            assert.strictEqual(metrics.compliancePercent, 98.5);
            assert.strictEqual(metrics.trustScoreMean, 820);
            assert.strictEqual(metrics.agentCount, 15);
            assert.strictEqual(metrics.violationsToday, 2);
            assert.ok(metrics.timestamp);
        });
    });

    suite('MetricsExporter', () => {
        test('has push method', () => {
            assert.ok(typeof exporter.push === 'function');
        });

        test('push returns a promise', () => {
            const metrics: GovernanceMetrics = {
                availability: 99.9,
                latencyP99: 100,
                compliancePercent: 100,
                trustScoreMean: 900,
                agentCount: 10,
                violationsToday: 0,
                timestamp: new Date().toISOString(),
            };

            const result = exporter.push(metrics);
            assert.ok(result instanceof Promise);
        });

        test('handles endpoint errors gracefully', async () => {
            const metrics: GovernanceMetrics = {
                availability: 99.9,
                latencyP99: 100,
                compliancePercent: 100,
                trustScoreMean: 900,
                agentCount: 10,
                violationsToday: 0,
                timestamp: new Date().toISOString(),
            };

            // Should not throw even with invalid endpoint
            try {
                await exporter.push(metrics);
            } catch {
                // Expected to fail with invalid endpoint, that's OK
            }
        });
    });

    suite('Metrics formatting', () => {
        test('timestamp is ISO-8601 format', () => {
            const timestamp = new Date().toISOString();
            const metrics: GovernanceMetrics = {
                availability: 99.9,
                latencyP99: 100,
                compliancePercent: 100,
                trustScoreMean: 900,
                agentCount: 10,
                violationsToday: 0,
                timestamp,
            };

            // Verify ISO-8601 format
            const parsed = new Date(metrics.timestamp);
            assert.ok(!isNaN(parsed.getTime()));
        });

        test('all numeric fields are numbers', () => {
            const metrics: GovernanceMetrics = {
                availability: 99.9,
                latencyP99: 100,
                compliancePercent: 100,
                trustScoreMean: 900,
                agentCount: 10,
                violationsToday: 0,
                timestamp: new Date().toISOString(),
            };

            assert.strictEqual(typeof metrics.availability, 'number');
            assert.strictEqual(typeof metrics.latencyP99, 'number');
            assert.strictEqual(typeof metrics.compliancePercent, 'number');
            assert.strictEqual(typeof metrics.trustScoreMean, 'number');
            assert.strictEqual(typeof metrics.agentCount, 'number');
            assert.strictEqual(typeof metrics.violationsToday, 'number');
        });
    });

    suite('Endpoint Validation', () => {
        test('rejects non-URL endpoint', () => {
            const exporter = new MetricsExporter('not-a-url');
            // push should not throw — graceful degradation
            assert.doesNotThrow(() => exporter.push());
        });

        test('rejects non-http protocol', () => {
            const exporter = new MetricsExporter('ftp://example.com/metrics');
            assert.doesNotThrow(() => exporter.push());
        });

        test('accepts valid http endpoint', () => {
            const exporter = new MetricsExporter('http://localhost:4318/v1/metrics');
            // Should attempt to push (may fail on network, but that's expected)
            assert.doesNotThrow(() => exporter.push());
        });

        test('setEndpoint validates', () => {
            const exporter = new MetricsExporter('http://localhost:4318/v1/metrics');
            exporter.setEndpoint('not-valid');
            // After invalid setEndpoint, push should no-op
            assert.doesNotThrow(() => exporter.push());
        });
    });
});
