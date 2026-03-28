// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * OpenTelemetry bootstrap for the Agent OS Copilot Extension.
 */

import { trace } from '@opentelemetry/api';
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import { logger } from './logger';

const SERVICE_NAME = 'agent-os-copilot-extension';
const SERVICE_VERSION = '1.0.0';

let initialized = false;

function isTelemetryEnabled(): boolean {
    const value = (process.env.OTEL_ENABLED || 'true').trim().toLowerCase();
    return value !== 'false' && value !== '0' && value !== 'no';
}

export function initializeTelemetry(): boolean {
    if (initialized || !isTelemetryEnabled()) {
        return initialized;
    }

    try {
        const provider = new NodeTracerProvider();
        provider.register();
        initialized = true;
        logger.info('OpenTelemetry initialized', {
            service: SERVICE_NAME,
            version: SERVICE_VERSION
        });
    } catch (error) {
        logger.warn('Failed to initialize OpenTelemetry', { error });
    }

    return initialized;
}

export function getTracer() {
    return trace.getTracer(SERVICE_NAME, SERVICE_VERSION);
}

export function telemetryEnabled(): boolean {
    return initialized;
}