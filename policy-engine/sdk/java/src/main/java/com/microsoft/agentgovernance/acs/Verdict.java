// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;

/**
 * The decision of the engine about one intervention point.
 *
 * @param resultLabels labels the policy attached to the result (never null)
 * @param warnings     warnings carried by an allow (never null)
 * @param approval     present only on a deny, making it liftable: the host routes it to an approval seam. A deny without it is final.
 *                     Its content is opaque to the SDK.
 */
public record Verdict(Decision decision, String reason, String message, Transform transform, Evidence evidence,
                      List<String> resultLabels, List<Warning> warnings, JsonNode approval) {

    public Verdict {
        resultLabels = resultLabels == null ? List.of() : List.copyOf(resultLabels);
        warnings = warnings == null ? List.of() : List.copyOf(warnings);
    }

    /** A verdict with only a decision, a reason and a message. */
    public static Verdict of(Decision decision, String reason, String message) {
        return new Verdict(decision, reason, message, null, null, null, null, null);
    }
}
