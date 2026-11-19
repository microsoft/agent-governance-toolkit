// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

/** An action was stopped by the engine: see {@link AgentControlBlockedException} and {@link AgentControlSuspendedException}. */
public abstract class AgentControlInterruptionException extends IllegalStateException {

    private static final long serialVersionUID = 1L;

    private final InterventionPoint interventionPoint;
    private final transient InterventionPointResult result;

    protected AgentControlInterruptionException(String message, InterventionPoint interventionPoint, InterventionPointResult result,
                                                Throwable cause) {
        super(message, cause);
        this.interventionPoint = interventionPoint;
        this.result = result;
    }

    public InterventionPoint interventionPoint() {
        return interventionPoint;
    }

    public InterventionPointResult result() {
        return result;
    }

    static String reasonSuffix(InterventionPointResult result) {
        String reason = result.verdict().reason();
        return reason == null || reason.isBlank() ? "" : " (" + reason + ")";
    }
}
