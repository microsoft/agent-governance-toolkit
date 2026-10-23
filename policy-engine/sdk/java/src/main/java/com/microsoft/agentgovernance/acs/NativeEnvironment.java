// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;

/**
 * Sets an environment variable of the <em>process</em>, which is what the native engine reads. {@link System#getenv} is a read-only
 * snapshot of the environment the JVM started with and cannot be changed, so the one variable that matters here ({@code ACS_OPA_PATH},
 * the OPA executable for Rego policies) is set through the C runtime: {@code setenv} on Linux and macOS, {@code SetEnvironmentVariableW}
 * on Windows.
 */
@SuppressWarnings("restricted")
final class NativeEnvironment {

    static final String OPA_PATH = "ACS_OPA_PATH";

    private NativeEnvironment() {
    }

    static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("win");
    }

    /** Sets the variable for the whole process (all threads, and the native engine). */
    static void set(String name, String value) {
        if (name.indexOf('\0') >= 0 || value.indexOf('\0') >= 0 || name.contains("=")) {
            throw new IllegalArgumentException("Not a valid environment variable: " + name);
        }
        Linker linker = Linker.nativeLinker();
        try (Arena arena = Arena.ofConfined()) {
            if (isWindows()) {
                SymbolLookup kernel32 = SymbolLookup.libraryLookup("kernel32", arena);
                MethodHandle setW = linker.downcallHandle(kernel32.find("SetEnvironmentVariableW").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
                int ok = (int) setW.invokeExact(arena.allocateFrom(name, StandardCharsets.UTF_16LE),
                        arena.allocateFrom(value, StandardCharsets.UTF_16LE));
                if (ok == 0) {
                    throw new AcsException("SetEnvironmentVariableW failed for " + name);
                }
            } else {
                MethodHandle setenv = linker.downcallHandle(linker.defaultLookup().find("setenv").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
                int rc = (int) setenv.invokeExact(arena.allocateFrom(name), arena.allocateFrom(value), 1);
                if (rc != 0) {
                    throw new AcsException("setenv failed for " + name);
                }
            }
        } catch (AcsException | IllegalArgumentException e) {
            throw e;
        } catch (Throwable t) {
            throw new AcsException("Cannot set the environment variable " + name + ": " + t.getMessage(), t);
        }
    }
}
