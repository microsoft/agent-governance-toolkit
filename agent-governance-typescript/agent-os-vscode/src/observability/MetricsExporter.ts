// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance metrics exporter for observability.
 *
 * Pushes metrics to configured endpoints with retry logic.
 */

/** Governance metrics snapshot for export. */
export interface GovernanceMetrics {
    /** System availability percentage (0-100). */
    availability: number;
    /** 99th percentile latency in milliseconds. */
    latencyP99: number;
    /** Policy compliance percentage (0-100). */
    compliancePercent: number;
    /** Mean trust score across agents (0-1000). */
    trustScoreMean: number;
    /** Total number of registered agents. */
    agentCount: number;
    /** Number of policy violations today. */
    violationsToday: number;
    /** ISO-8601 timestamp of the metrics snapshot. */
    timestamp: string;
}

/** Retry configuration. */
interface RetryConfig {
    maxRetries: number;
    baseDelayMs: number;
    maxDelayMs: number;
}

/**
 * Export governance metrics to observability endpoints.
 */
export class MetricsExporter {
    private readonly retryConfig: RetryConfig = {
        maxRetries: 3,
        baseDelayMs: 1000,
        maxDelayMs: 10000,
    };

    constructor(private endpoint: string) {
        this.endpoint = this._validateEndpoint(endpoint);
    }

    /**
     * Push metrics to the configured endpoint.
     *
     * @param metrics - Governance metrics to export.
     * @throws Error if all retries are exhausted.
     */
    async push(metrics?: GovernanceMetrics): Promise<void> {
        if (!this.endpoint || !metrics) { return; }

        let lastError: Error | undefined;

        for (let attempt = 0; attempt < this.retryConfig.maxRetries; attempt++) {
            try {
                await this.sendMetrics(metrics);
                return;
            } catch (err) {
                lastError = err instanceof Error ? err : new Error(String(err));
                await this.delay(this.calculateBackoff(attempt));
            }
        }

        throw new Error(
            `Failed to push metrics after ${this.retryConfig.maxRetries} retries: ${lastError?.message}`
        );
    }

    /**
     * Update the metrics endpoint.
     *
     * @param endpoint - New endpoint URL.
     */
    setEndpoint(endpoint: string): void {
        this.endpoint = this._validateEndpoint(endpoint);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private _validateEndpoint(endpoint: string): string {
        let url: URL;
        try {
            url = new URL(endpoint);
        } catch {
            console.warn('MetricsExporter: invalid endpoint URL, metrics disabled:', endpoint);
            return '';
        }
        if (url.protocol !== 'http:' && url.protocol !== 'https:') {
            console.warn('MetricsExporter: endpoint must use http(s) protocol:', endpoint);
            return '';
        }
        return endpoint;
    }

    private async sendMetrics(metrics: GovernanceMetrics): Promise<void> {
        const response = await fetch(this.endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(metrics),
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
    }

    private calculateBackoff(attempt: number): number {
        const delay = this.retryConfig.baseDelayMs * Math.pow(2, attempt);
        return Math.min(delay, this.retryConfig.maxDelayMs);
    }

    private delay(ms: number): Promise<void> {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }
}
