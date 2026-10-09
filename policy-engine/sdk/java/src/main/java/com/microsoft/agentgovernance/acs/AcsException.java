// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

/**
 * The native engine could not be loaded, or refused a call that is not a policy decision (a manifest that does not load, a runtime that
 * cannot be built). Policy decisions, including every failure while evaluating, come back as a deny verdict and never as this exception.
 */
public class AcsException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public AcsException(String message) {
        super(message);
    }

    public AcsException(String message, Throwable cause) {
        super(message, cause);
    }
}
