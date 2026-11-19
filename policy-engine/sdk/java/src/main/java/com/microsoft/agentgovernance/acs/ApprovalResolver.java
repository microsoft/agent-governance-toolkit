// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

/**
 * Host callback that decides whether a liftable deny (a deny that carries an {@code approval} block) may proceed. It is consulted only
 * in {@link EnforcementMode#ENFORCE} and only for such a deny; a deny without {@code approval} is final. With no resolver the deny
 * stands. A resolver that throws, or returns null, fails closed.
 */
@FunctionalInterface
public interface ApprovalResolver {

    ApprovalResolution resolve(InterventionPoint interventionPoint, InterventionPointResult result) throws Exception;
}
