// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Mock SLO Backend Service
 *
 * Simulates a realistic SLO data feed with time-varying metrics.
 * Values drift over time with occasional incidents and recoveries,
 * producing a convincing live dashboard experience.
 */

import {
    SLODataProvider,
    SLOSnapshot,
    AvailabilitySLOData,
    LatencySLOData,
    PolicyComplianceSLOData,
    TrustScoreSLOData,
} from '../views/sloTypes';
import { drift } from './mockUtils';

/**
 * Creates an SLODataProvider backed by a simulated time-varying feed.
 *
 * Each call to `getSnapshot()` returns slightly different values,
 * simulating real SLO metric drift. Occasional "incidents" cause
 * brief dips in availability and spikes in latency.
 */
export function createMockSLOBackend(): SLODataProvider {
    let availability = 99.82;
    let errorBudget = 63.0;
    let burnRate = 1.05;
    let p50 = 42, p95 = 115, p99 = 225;
    let compliance = 99.7;
    let violations = 2;
    let totalEvals = 1284;
    let meanTrust = 820, minTrust = 410;
    let belowThreshold = 1;
    let callCount = 0;

    /** Apply incident/recovery/normal drift to core metrics. */
    function applyDrift(): void {
        const incident = callCount % 30 === 0;
        const recovery = callCount % 30 === 3;

        if (incident) {
            availability = drift(availability, 1.2, 97.5, 99.0);
            p99 = drift(p99, 80, 280, 450);
            violations += Math.floor(Math.random() * 4) + 2;
            burnRate = drift(burnRate, 1.5, 2.0, 4.0);
        } else if (recovery) {
            availability = drift(availability, 0.5, 99.5, 99.95);
            p99 = drift(p99, 30, 180, 250);
            burnRate = drift(burnRate, 0.5, 0.8, 1.2);
        } else {
            availability = drift(availability, 0.08, 99.2, 99.99);
            burnRate = drift(burnRate, 0.15, 0.6, 2.0);
        }

        p50 = drift(p50, 5, 25, 80);
        p95 = drift(p95, 10, 80, 200);
        p99 = drift(p99, 12, Math.max(p95 + 20, 150), 400);
        errorBudget = drift(errorBudget, 2, 5, 90);
        compliance = drift(compliance, 0.15, 98.0, 100.0);
        totalEvals += Math.floor(Math.random() * 20) + 5;
        violations = Math.max(0, violations + (Math.random() > 0.7 ? 1 : 0));
        meanTrust = Math.round(drift(meanTrust, 15, 650, 950));
        minTrust = Math.round(drift(minTrust, 20, 200, meanTrust - 100));
        belowThreshold = Math.max(0, Math.round(drift(belowThreshold, 0.8, 0, 5)));
    }

    /** Build availability snapshot from current state. */
    function buildAvailabilitySnapshot(): AvailabilitySLOData {
        return {
            currentPercent: +availability.toFixed(2),
            targetPercent: 99.5,
            errorBudgetRemainingPercent: +errorBudget.toFixed(1),
            burnRate: +burnRate.toFixed(2),
        };
    }

    /** Build latency snapshot from current state. */
    function buildLatencySnapshot(): LatencySLOData {
        return {
            p50Ms: +p50.toFixed(0),
            p95Ms: +p95.toFixed(0),
            p99Ms: +p99.toFixed(0),
            targetMs: 300,
            errorBudgetRemainingPercent: +drift(72, 5, 20, 95).toFixed(1),
        };
    }

    /** Build compliance snapshot from current state. */
    function buildComplianceSnapshot(): PolicyComplianceSLOData {
        return {
            totalEvaluations: totalEvals,
            violationsToday: Math.round(violations),
            compliancePercent: +compliance.toFixed(2),
            trend: compliance > 99.5 ? 'up' : compliance > 99.0 ? 'stable' : 'down',
        };
    }

    /** Build trust score snapshot from current state. */
    function buildTrustSnapshot(): TrustScoreSLOData {
        const dist: [number, number, number, number] = [
            Math.max(0, Math.round(drift(belowThreshold, 1, 0, 4))),
            Math.max(0, Math.round(drift(3, 1.5, 1, 8))),
            Math.round(drift(15, 3, 8, 25)),
            Math.round(drift(40, 4, 28, 55)),
        ];
        return {
            meanScore: meanTrust,
            minScore: minTrust,
            agentsBelowThreshold: belowThreshold,
            distribution: dist,
        };
    }

    return {
        async getSnapshot(): Promise<SLOSnapshot> {
            callCount++;
            applyDrift();
            return {
                availability: buildAvailabilitySnapshot(),
                latency: buildLatencySnapshot(),
                policyCompliance: buildComplianceSnapshot(),
                trustScore: buildTrustSnapshot(),
            };
        },
    };
}
