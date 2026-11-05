// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

/**
 * Anything that can decide an intervention point. {@link NativeRuntime} (the Rust engine) is the one that ships; a different
 * implementation can stand in for it in tests or for an alternative backend.
 */
@FunctionalInterface
public interface AgentControlRuntime {

    /**
     * Decides one request. A failure while evaluating is a deny verdict in the result, not an exception; an exception means the
     * runtime itself cannot be used.
     */
    InterventionPointResult evaluate(InterventionPointRequest request);
}
