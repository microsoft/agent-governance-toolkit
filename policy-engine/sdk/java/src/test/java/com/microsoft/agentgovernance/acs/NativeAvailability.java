// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Tests that need the real engine run only when the native library is built and named by {@code -Dacs.native.library=...} (the Gradle
 * property {@code acs.native.library} or the environment variable {@code ACS_NATIVE_LIBRARY}). Without it they are skipped, not failed,
 * so the pure Java tests run anywhere.
 */
final class NativeAvailability {

    private NativeAvailability() {
    }

    /** Used by {@code @EnabledIf}. */
    static boolean available() {
        String path = System.getProperty("acs.native.library");
        if (path == null || path.isBlank()) {
            path = System.getenv("ACS_NATIVE_LIBRARY");
        }
        return path != null && !path.isBlank() && Files.isRegularFile(Path.of(path.strip()));
    }

    /** The policy-engine directory (the parent of {@code tests/conformance}). */
    static Path policyEngineDir() {
        String dir = System.getProperty("acs.policy.engine.dir");
        return Path.of(dir != null ? dir : "../..").toAbsolutePath().normalize();
    }
}
