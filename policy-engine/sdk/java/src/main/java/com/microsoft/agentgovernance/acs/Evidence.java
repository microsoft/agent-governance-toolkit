// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

import java.util.Map;

/** Opaque evidence a high-assurance dispatcher may attach to a verdict; the runtime passes it through unchanged. */
public record Evidence(String artefact, Map<String, String> verificationPointers) {

    public Evidence {
        verificationPointers = verificationPointers == null ? null : Map.copyOf(verificationPointers);
    }
}
