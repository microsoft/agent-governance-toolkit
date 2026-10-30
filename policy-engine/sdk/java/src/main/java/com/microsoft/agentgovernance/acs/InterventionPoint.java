// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

/** Where in an agent's life the Agent Control Specification is asked for a decision. */
public enum InterventionPoint {
    AGENT_STARTUP("agent_startup"),
    INPUT("input"),
    PRE_MODEL_CALL("pre_model_call"),
    POST_MODEL_CALL("post_model_call"),
    PRE_TOOL_CALL("pre_tool_call"),
    POST_TOOL_CALL("post_tool_call"),
    OUTPUT("output"),
    AGENT_SHUTDOWN("agent_shutdown");

    private final String wireName;

    InterventionPoint(String wireName) {
        this.wireName = wireName;
    }

    /** The name the engine uses for this point on the wire. */
    public String wireName() {
        return wireName;
    }

    /** True for the two points that surround a tool call. */
    public boolean isToolInterventionPoint() {
        return this == PRE_TOOL_CALL || this == POST_TOOL_CALL;
    }

    /**
     * @throws IllegalArgumentException if the name is not an intervention point of the specification
     */
    public static InterventionPoint fromWireName(String value) {
        for (InterventionPoint point : values()) {
            if (point.wireName.equals(value)) {
                return point;
            }
        }
        throw new IllegalArgumentException("Unknown Agent Control Specification intervention point: " + value);
    }
}
