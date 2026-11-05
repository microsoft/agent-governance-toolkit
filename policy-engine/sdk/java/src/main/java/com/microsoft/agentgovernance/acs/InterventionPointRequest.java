// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Objects;

/** What the host asks the engine to decide: a point, the snapshot of the agent's state at that point, and how to enforce. */
public record InterventionPointRequest(InterventionPoint interventionPoint, JsonNode snapshot, EnforcementMode mode) {

    public InterventionPointRequest {
        Objects.requireNonNull(interventionPoint, "interventionPoint");
        Objects.requireNonNull(snapshot, "snapshot");
        mode = mode == null ? EnforcementMode.ENFORCE : mode;
    }

    public InterventionPointRequest(InterventionPoint interventionPoint, JsonNode snapshot) {
        this(interventionPoint, snapshot, EnforcementMode.ENFORCE);
    }
}
