// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Computes the annotations a manifest asks for (a classifier, a moderation call, ...). It may be called from any thread, so an
 * implementation must be thread-safe. An exception makes the annotation fail, which the engine turns into a deny. To signal a timeout,
 * throw an exception whose message contains {@value #ANNOTATION_TIMEOUT_REASON}.
 */
@FunctionalInterface
public interface AnnotatorDispatcher {

    /** The reason the engine reserves for an annotator that timed out. */
    String ANNOTATION_TIMEOUT_REASON = "runtime_error:annotation_timeout";

    JsonNode dispatch(String annotatorName, JsonNode annotatorConfig, JsonNode preliminaryPolicyInput) throws Exception;
}
