// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.util.List;

/**
 * The C ABI of {@code policy-engine/sdk/rust/src/ffi.rs}, one method handle per function, and the rules for the memory that crosses it:
 *
 * <ul>
 *   <li>Strings are NUL-terminated UTF-8. A Java string that contains a NUL is refused, never truncated.</li>
 *   <li>Every string the engine returns, and every error written to an {@code err} out-parameter, belongs to the caller and is released
 *       with {@code acs_free_string} (see {@link #take}).</li>
 *   <li>The {@code err} slot is zeroed before each call.</li>
 *   <li>{@code acs_builder_build} consumes its builder whether it succeeds or not; every other builder function leaves it alive.</li>
 * </ul>
 *
 * Package-private: the public API is {@link AgentControl}.
 */
@SuppressWarnings("restricted")
final class NativeApi {

    private static final Object LOCK = new Object();
    private static volatile NativeApi instance;

    private final Linker linker = Linker.nativeLinker();
    private final MethodHandle builderFromPath;
    private final MethodHandle builderFromYamlChain;
    private final MethodHandle builderFromYaml;
    private final MethodHandle builderFromJson;
    private final MethodHandle registerAnnotatorDispatcher;
    private final MethodHandle registerPolicyDispatcher;
    private final MethodHandle enableDefaultAnnotatorDispatcher;
    private final MethodHandle enableDefaultPolicyDispatcher;
    private final MethodHandle setPerfTelemetry;
    private final MethodHandle builderBuild;
    private final MethodHandle builderFree;
    private final MethodHandle runtimeEvaluate;
    private final MethodHandle runtimePolicyLabels;
    private final MethodHandle runtimeFree;
    private final MethodHandle validateArtifacts;
    private final MethodHandle freeString;

    /** Loads the library on first use. A library that is missing, or lacks a function, fails here with an {@link AcsException}. */
    static NativeApi get() {
        NativeApi api = instance;
        if (api == null) {
            synchronized (LOCK) {
                api = instance;
                if (api == null) {
                    instance = api = new NativeApi(NativeLibrary.locate());
                }
            }
        }
        return api;
    }

    private NativeApi(NativeLibrary.Location location) {
        SymbolLookup lookup;
        try {
            lookup = location.isFile()
                    ? SymbolLookup.libraryLookup(location.file(), Arena.global())
                    : SymbolLookup.libraryLookup(location.name(), Arena.global());
        } catch (IllegalArgumentException | UnsatisfiedLinkError e) {
            throw new AcsException("Cannot load the native library " + location + ": " + e.getMessage()
                    + ". Build it with 'cargo build --release -p agent_control_specification --features opa,bundled-dispatchers' and point "
                    + NativeLibrary.PROPERTY + " (or " + NativeLibrary.ENVIRONMENT + ") at it.", e);
        }
        MemoryLayout sizeT = linker.canonicalLayouts().get("size_t");
        MemoryLayout a = ValueLayout.ADDRESS;
        MemoryLayout i = ValueLayout.JAVA_INT;
        builderFromPath = bind(lookup, "acs_builder_from_path", FunctionDescriptor.of(a, a, a));
        builderFromYamlChain = bind(lookup, "acs_builder_from_yaml_chain", FunctionDescriptor.of(a, a, sizeT, a));
        builderFromYaml = bind(lookup, "acs_builder_from_yaml", FunctionDescriptor.of(a, a, a));
        builderFromJson = bind(lookup, "acs_builder_from_json", FunctionDescriptor.of(a, a, a));
        registerAnnotatorDispatcher = bind(lookup, "acs_builder_register_annotator_dispatcher", FunctionDescriptor.of(i, a, a, a, a, a));
        registerPolicyDispatcher = bind(lookup, "acs_builder_register_policy_dispatcher", FunctionDescriptor.of(i, a, a, a, a, a));
        enableDefaultAnnotatorDispatcher = bind(lookup, "acs_builder_enable_default_annotator_dispatcher", FunctionDescriptor.of(i, a, a));
        enableDefaultPolicyDispatcher = bind(lookup, "acs_builder_enable_default_policy_dispatcher", FunctionDescriptor.of(i, a, a));
        setPerfTelemetry = bind(lookup, "acs_builder_set_perf_telemetry", FunctionDescriptor.of(i, a, i, a));
        builderBuild = bind(lookup, "acs_builder_build", FunctionDescriptor.of(a, a, a));
        builderFree = bind(lookup, "acs_builder_free", FunctionDescriptor.ofVoid(a));
        runtimeEvaluate = bind(lookup, "acs_runtime_evaluate", FunctionDescriptor.of(a, a, a, a));
        runtimePolicyLabels = bind(lookup, "acs_runtime_policy_labels", FunctionDescriptor.of(a, a, a));
        runtimeFree = bind(lookup, "acs_runtime_free", FunctionDescriptor.ofVoid(a));
        validateArtifacts = bind(lookup, "acs_validate_artifacts", FunctionDescriptor.of(a, a, a, a, a));
        freeString = bind(lookup, "acs_free_string", FunctionDescriptor.ofVoid(a));
    }

    private MethodHandle bind(SymbolLookup lookup, String name, FunctionDescriptor descriptor) {
        MemorySegment symbol = lookup.find(name).orElseThrow(() -> new AcsException(
                "The native library does not export " + name + "; it was built from a different version of the engine."));
        return linker.downcallHandle(symbol, descriptor);
    }

    Linker linker() {
        return linker;
    }

    // ------------------------------------------------------------------ strings

    /** A NUL-terminated UTF-8 copy of the string, owned by the arena. */
    static MemorySegment cstr(Arena arena, String value) {
        if (value.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("A string passed to the engine must not contain a NUL character");
        }
        return arena.allocateFrom(value);
    }

    /** The string at a pointer the engine (or the callback arguments) handed over, up to its NUL. */
    static String read(MemorySegment pointer) {
        return pointer.reinterpret(Long.MAX_VALUE).getString(0);
    }

    /** Reads an engine-owned string and releases it. */
    String take(MemorySegment pointer) {
        try {
            return read(pointer);
        } finally {
            free(pointer);
        }
    }

    void free(MemorySegment pointer) {
        if (pointer.equals(MemorySegment.NULL)) {
            return;
        }
        try {
            freeString.invokeExact(pointer);
        } catch (Throwable t) {
            throw new AcsException("acs_free_string failed", t);
        }
    }

    /** The error the engine wrote to an out-parameter (and releases it), or null if it wrote none. */
    String takeError(MemorySegment errSlot) {
        MemorySegment pointer = errSlot.get(ValueLayout.ADDRESS, 0);
        return pointer.equals(MemorySegment.NULL) ? null : take(pointer);
    }

    // ------------------------------------------------------------------ builders

    private MemorySegment builder(String operation, java.util.function.Function<MemorySegment, MemorySegment> call) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment err = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment builder = call.apply(err);
            String error = takeError(err);
            if (builder.equals(MemorySegment.NULL)) {
                throw new AcsException("Failed to " + operation + ": " + (error != null ? error : "the engine returned null without an error"));
            }
            return builder;
        }
    }

    MemorySegment builderFromPath(String path) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment p = cstr(arena, path);
            return builder("load the manifest " + path, err -> {
                try {
                    return (MemorySegment) builderFromPath.invokeExact(p, err);
                } catch (Throwable t) {
                    throw new AcsException("acs_builder_from_path failed", t);
                }
            });
        }
    }

    MemorySegment builderFromYaml(String yaml) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment y = cstr(arena, yaml);
            return builder("load the YAML manifest", err -> {
                try {
                    return (MemorySegment) builderFromYaml.invokeExact(y, err);
                } catch (Throwable t) {
                    throw new AcsException("acs_builder_from_yaml failed", t);
                }
            });
        }
    }

    MemorySegment builderFromJson(String json) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment j = cstr(arena, json);
            return builder("load the JSON manifest", err -> {
                try {
                    return (MemorySegment) builderFromJson.invokeExact(j, err);
                } catch (Throwable t) {
                    throw new AcsException("acs_builder_from_json failed", t);
                }
            });
        }
    }

    MemorySegment builderFromYamlChain(List<String> manifests) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment array = arena.allocate(ValueLayout.ADDRESS, manifests.size());
            for (int index = 0; index < manifests.size(); index++) {
                array.setAtIndex(ValueLayout.ADDRESS, index, cstr(arena, manifests.get(index)));
            }
            long count = manifests.size();
            return builder("load the manifest chain", err -> {
                try {
                    return (MemorySegment) builderFromYamlChain.invokeExact(array, count, err);
                } catch (Throwable t) {
                    throw new AcsException("acs_builder_from_yaml_chain failed", t);
                }
            });
        }
    }

    private void code(String operation, java.util.function.Function<MemorySegment, Integer> call) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment err = arena.allocate(ValueLayout.ADDRESS);
            int code = call.apply(err);
            String error = takeError(err);
            if (code != 0) {
                throw new AcsException("Failed to " + operation + ": " + (error != null ? error : "the engine returned code " + code));
            }
        }
    }

    void registerAnnotatorDispatcher(MemorySegment builder, MemorySegment callback, MemorySegment freeResult) {
        code("register the annotator dispatcher", err -> {
            try {
                return (int) registerAnnotatorDispatcher.invokeExact(builder, callback, freeResult, MemorySegment.NULL, err);
            } catch (Throwable t) {
                throw new AcsException("acs_builder_register_annotator_dispatcher failed", t);
            }
        });
    }

    void registerPolicyDispatcher(MemorySegment builder, MemorySegment callback, MemorySegment freeResult) {
        code("register the policy dispatcher", err -> {
            try {
                return (int) registerPolicyDispatcher.invokeExact(builder, callback, freeResult, MemorySegment.NULL, err);
            } catch (Throwable t) {
                throw new AcsException("acs_builder_register_policy_dispatcher failed", t);
            }
        });
    }

    void enableDefaultAnnotatorDispatcher(MemorySegment builder) {
        code("enable the bundled annotator dispatcher", err -> {
            try {
                return (int) enableDefaultAnnotatorDispatcher.invokeExact(builder, err);
            } catch (Throwable t) {
                throw new AcsException("acs_builder_enable_default_annotator_dispatcher failed", t);
            }
        });
    }

    void enableDefaultPolicyDispatcher(MemorySegment builder) {
        code("enable the bundled policy dispatcher", err -> {
            try {
                return (int) enableDefaultPolicyDispatcher.invokeExact(builder, err);
            } catch (Throwable t) {
                throw new AcsException("acs_builder_enable_default_policy_dispatcher failed", t);
            }
        });
    }

    void setPerfTelemetry(MemorySegment builder, PerfTelemetry level) {
        code("set the perf telemetry level", err -> {
            try {
                return (int) setPerfTelemetry.invokeExact(builder, level.level(), err);
            } catch (Throwable t) {
                throw new AcsException("acs_builder_set_perf_telemetry failed", t);
            }
        });
    }

    /** Consumes the builder, whatever the outcome. */
    MemorySegment build(MemorySegment builder) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment err = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment runtime;
            try {
                runtime = (MemorySegment) builderBuild.invokeExact(builder, err);
            } catch (Throwable t) {
                throw new AcsException("acs_builder_build failed", t);
            }
            String error = takeError(err);
            if (runtime.equals(MemorySegment.NULL)) {
                throw new AcsException("Failed to build the runtime: " + (error != null ? error : "the engine returned null without an error"));
            }
            return runtime;
        }
    }

    void freeBuilder(MemorySegment builder) {
        try {
            builderFree.invokeExact(builder);
        } catch (Throwable t) {
            throw new AcsException("acs_builder_free failed", t);
        }
    }

    // ------------------------------------------------------------------ runtime

    /** The response JSON of one evaluation. */
    String evaluate(MemorySegment runtime, String requestJson) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment request = cstr(arena, requestJson);
            MemorySegment err = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment result;
            try {
                result = (MemorySegment) runtimeEvaluate.invokeExact(runtime, request, err);
            } catch (Throwable t) {
                throw new AcsException("acs_runtime_evaluate failed", t);
            }
            String error = takeError(err);
            if (result.equals(MemorySegment.NULL)) {
                throw new AcsException("Failed to evaluate: " + (error != null ? error : "the engine returned null without an error"));
            }
            return take(result);
        }
    }

    String policyLabels(MemorySegment runtime) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment err = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment result;
            try {
                result = (MemorySegment) runtimePolicyLabels.invokeExact(runtime, err);
            } catch (Throwable t) {
                throw new AcsException("acs_runtime_policy_labels failed", t);
            }
            String error = takeError(err);
            if (result.equals(MemorySegment.NULL)) {
                throw new AcsException("Failed to read the policy labels: " + (error != null ? error : "the engine returned null without an error"));
            }
            return take(result);
        }
    }

    void freeRuntime(MemorySegment runtime) {
        try {
            runtimeFree.invokeExact(runtime);
        } catch (Throwable t) {
            throw new AcsException("acs_runtime_free failed", t);
        }
    }

    // ------------------------------------------------------------------ validation

    /** The validation result JSON for a manifest and its Rego modules ({@code opaPath} may be null). */
    String validate(String manifestYaml, String regoModulesJson, String opaPath) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment manifest = cstr(arena, manifestYaml);
            MemorySegment modules = cstr(arena, regoModulesJson);
            MemorySegment opa = opaPath == null ? MemorySegment.NULL : cstr(arena, opaPath);
            MemorySegment err = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment result;
            try {
                result = (MemorySegment) validateArtifacts.invokeExact(manifest, modules, opa, err);
            } catch (Throwable t) {
                throw new AcsException("acs_validate_artifacts failed", t);
            }
            String error = takeError(err);
            if (result.equals(MemorySegment.NULL)) {
                throw new AcsException(error != null ? error : "ACS artifact validation failed.");
            }
            return take(result);
        }
    }
}
