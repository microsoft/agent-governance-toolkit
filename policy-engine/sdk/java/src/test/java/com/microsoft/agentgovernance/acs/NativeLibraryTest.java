// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Finding the native library: the order of the places, and an error that says what to do. Needs no library. */
class NativeLibraryTest {

    @TempDir
    Path dir;

    private static String saved(String key) {
        return System.getProperty(key);
    }

    private static void restore(String key, String value) {
        if (value == null) {
            System.clearProperty(key);
        } else {
            System.setProperty(key, value);
        }
    }

    @Test
    void theSystemPropertyNamesTheFileAndAMissingFileIsAnError() throws Exception {
        String before = saved(NativeLibrary.PROPERTY);
        try {
            Path file = Files.createFile(dir.resolve("acs.dll"));
            System.setProperty(NativeLibrary.PROPERTY, file.toString());
            NativeLibrary.Location location = NativeLibrary.locate();
            assertTrue(location.isFile());
            assertEquals(file.toAbsolutePath(), location.file());

            System.setProperty(NativeLibrary.PROPERTY, dir.resolve("nothing.dll").toString());
            AcsException e = assertThrows(AcsException.class, NativeLibrary::locate);
            assertTrue(e.getMessage().contains("does not exist"), e.getMessage());
        } finally {
            restore(NativeLibrary.PROPERTY, before);
        }
    }

    @Test
    void withNothingConfiguredTheOperatingSystemLoaderGetsTheLibraryName() {
        String before = saved(NativeLibrary.PROPERTY);
        try {
            System.clearProperty(NativeLibrary.PROPERTY);
            if (System.getenv(NativeLibrary.ENVIRONMENT) == null) {
                NativeLibrary.Location location = NativeLibrary.locate();
                assertFalse(location.isFile());
                assertTrue(location.name().contains(NativeLibrary.BASE_NAME), location.name());
            }
        } finally {
            restore(NativeLibrary.PROPERTY, before);
        }
    }

    @Test
    void thePlatformNameIsOsAndArchitecture() {
        String platform = NativeLibrary.platform();

        assertTrue(platform.matches("(windows|linux|macos)-[a-z0-9_]+"), platform);
    }

    @Test
    void aMissingLibraryFailsWithInstructionsAndNotAnObscureLinkError() {
        String before = saved(NativeLibrary.PROPERTY);
        try {
            // a file that exists but is not a library
            Path notALibrary = dir.resolve("agent_control_specification.dll");
            Files.writeString(notALibrary, "not a library");
            System.setProperty(NativeLibrary.PROPERTY, notALibrary.toString());
            // NativeApi caches the library once it loaded, so this only checks the loading failure when none was loaded before
            try {
                NativeApi.get();
            } catch (AcsException e) {
                assertTrue(e.getMessage().contains("cargo build"), e.getMessage());
            }
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        } finally {
            restore(NativeLibrary.PROPERTY, before);
        }
    }
}
