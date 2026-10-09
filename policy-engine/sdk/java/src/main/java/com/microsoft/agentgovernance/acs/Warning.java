// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

/** A warning that rides along with an allow. */
public record Warning(String reason, String message) {
}
