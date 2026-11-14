// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

/** Whether a decision is acted upon ({@link #ENFORCE}) or only reported ({@link #EVALUATE_ONLY}). */
public enum EnforcementMode {
    ENFORCE("enforce"),
    EVALUATE_ONLY("evaluate_only");

    private final String wireName;

    EnforcementMode(String wireName) {
        this.wireName = wireName;
    }

    public String wireName() {
        return wireName;
    }
}
