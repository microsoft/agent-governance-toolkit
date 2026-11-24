// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Evaluates one prepared policy invocation and returns the verdict as JSON. It may be called from any thread, so an implementation
 * must be thread-safe. An exception makes the invocation fail, which the engine turns into a deny.
 */
@FunctionalInterface
public interface PolicyDispatcher {

    JsonNode evaluate(JsonNode preparedInvocation) throws Exception;
}
