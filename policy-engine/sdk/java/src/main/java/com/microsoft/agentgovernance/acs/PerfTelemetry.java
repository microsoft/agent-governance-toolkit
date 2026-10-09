// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

/** How much timing detail the native runtime records while it evaluates. Independent of any host telemetry. */
public enum PerfTelemetry {
    OFF(0),
    EXTERNAL(1),
    FULL(2);

    private final int level;

    PerfTelemetry(int level) {
        this.level = level;
    }

    /** The value the C ABI takes. */
    int level() {
        return level;
    }
}
