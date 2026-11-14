// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

/**
 * What the policy decided. The engine returns {@link #ALLOW}, {@link #DENY} and {@link #TRANSFORM}.
 *
 * <p>{@link #WARN} and {@link #ESCALATE} are retired: a warning is an allow that carries {@link Verdict#warnings()}, and an
 * escalation is a deny that carries {@link Verdict#approval()}. They stay so that a verdict written by an older engine can still
 * be read and fails closed in the same way.
 */
public enum Decision {
    ALLOW("allow"),
    DENY("deny"),
    /** Retired, see the class comment. */
    WARN("warn"),
    /** Retired, see the class comment. */
    ESCALATE("escalate"),
    TRANSFORM("transform");

    private final String wireName;

    Decision(String wireName) {
        this.wireName = wireName;
    }

    public String wireName() {
        return wireName;
    }

    /** True only for {@link #TRANSFORM}, the one decision that replaces the policy target. */
    public boolean appliesTransform() {
        return this == TRANSFORM;
    }

    /** True for the decisions after which the action proceeds ({@code allow}, {@code warn}, {@code transform}). */
    public boolean permits() {
        return this == ALLOW || this == WARN || this == TRANSFORM;
    }

    /**
     * @throws IllegalArgumentException if the name is not a decision of the specification
     */
    public static Decision fromWireName(String value) {
        for (Decision decision : values()) {
            if (decision.wireName.equals(value)) {
                return decision;
            }
        }
        throw new IllegalArgumentException("Unknown Agent Control Specification decision: " + value);
    }
}
