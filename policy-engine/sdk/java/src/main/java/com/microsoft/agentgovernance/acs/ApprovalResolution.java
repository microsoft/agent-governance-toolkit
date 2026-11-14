// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * The answer of an {@link ApprovalResolver}. An approval is bound to one exact action: {@link #allow} and {@link #suspend} must carry
 * the identity of the action that was approved (taken from {@link InterventionPointResult#actionIdentity()}), and the SDK refuses
 * the approval if it does not match what is about to run.
 *
 * @param handle opaque handle of a suspended approval, handed back to the caller inside {@link AgentControlSuspendedException}
 */
public record ApprovalResolution(ApprovalOutcome outcome, JsonNode handle, String actionIdentity) {

    public static ApprovalResolution allow(String actionIdentity) {
        return new ApprovalResolution(ApprovalOutcome.ALLOW, null, actionIdentity);
    }

    public static ApprovalResolution deny() {
        return new ApprovalResolution(ApprovalOutcome.DENY, null, null);
    }

    public static ApprovalResolution suspend(JsonNode handle, String actionIdentity) {
        return new ApprovalResolution(ApprovalOutcome.SUSPEND, handle, actionIdentity);
    }
}
