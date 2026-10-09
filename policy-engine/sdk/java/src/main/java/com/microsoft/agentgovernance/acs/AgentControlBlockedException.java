// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

/** The engine denied the action, or an approval was refused or could not be given. */
public final class AgentControlBlockedException extends AgentControlInterruptionException {

    private static final long serialVersionUID = 1L;

    public AgentControlBlockedException(InterventionPoint interventionPoint, InterventionPointResult result) {
        this(interventionPoint, result, null);
    }

    public AgentControlBlockedException(InterventionPoint interventionPoint, InterventionPointResult result, Throwable cause) {
        super("Agent Control Specification blocked " + interventionPoint.wireName() + reasonSuffix(result) + ".",
                interventionPoint, result, cause);
    }
}
