// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Result of one intervention-point evaluation. The action identity is split in two: {@code inputIdentity} pins what the policy saw,
 * {@code enforcedIdentity} what the host will carry out (equal for every decision but a transform). {@code actionIdentity} is the
 * older alias of {@code enforcedIdentity}.
 *
 * @param transformedPolicyTarget the replacement target, present when {@code transformedPolicyTargetApplied}
 * @param policyInput             what the policy was given
 */
public record InterventionPointResult(Verdict verdict, JsonNode transformedPolicyTarget, JsonNode policyInput, String actionIdentity,
                                      boolean transformedPolicyTargetApplied, String inputIdentity, String enforcedIdentity) {

    /** A result that only carries a verdict (what an SDK builds when it refuses before or after asking the engine). */
    public static InterventionPointResult of(Verdict verdict) {
        return new InterventionPointResult(verdict, null, null, null, false, null, null);
    }
}
