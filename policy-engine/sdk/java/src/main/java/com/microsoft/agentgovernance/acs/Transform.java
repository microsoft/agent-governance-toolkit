// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Single-target replacement carried by a {@link Decision#TRANSFORM} verdict: the runtime applies {@code value} at {@code path}
 * (rooted at {@code $target}) before the action proceeds.
 */
public record Transform(String path, JsonNode value) {
}
