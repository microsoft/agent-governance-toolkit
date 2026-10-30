// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

import com.fasterxml.jackson.databind.JsonNode;

/** The action waits for an approval that is decided elsewhere; {@link #handle()} is what the resolver returned to find it again. */
public final class AgentControlSuspendedException extends AgentControlInterruptionException {

    private static final long serialVersionUID = 1L;

    private final transient JsonNode handle;

    public AgentControlSuspendedException(InterventionPoint interventionPoint, InterventionPointResult result, JsonNode handle) {
        super("Agent Control Specification suspended " + interventionPoint.wireName() + " pending approval" + reasonSuffix(result) + ".",
                interventionPoint, result, null);
        this.handle = handle;
    }

    public JsonNode handle() {
        return handle;
    }
}
