// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The host side of the two callbacks the engine can call: the annotator dispatcher and the policy dispatcher, as FFM upcall stubs.
 *
 * <p>Rules this class enforces, because a mistake here takes the JVM down or opens a hole:
 * <ul>
 *   <li><b>Nothing escapes an upcall.</b> An exception that leaves an upcall terminates the JVM. Every callback catches
 *       {@link Throwable} and answers with NULL, which the engine reports as a failed dispatch and turns into a deny (the .NET SDK
 *       does the same). The one exception that is passed on is an annotation timeout, as the reserved reason string.</li>
 *   <li><b>The engine frees what it is given.</b> A result string is allocated in its own arena and released by the free callback
 *       the engine calls after reading it; no allocator of the C runtime is involved.</li>
 *   <li><b>The stubs live as long as the runtime.</b> They belong to one arena that {@link NativeRuntime} closes after
 *       {@code acs_runtime_free}.</li>
 *   <li><b>Any thread.</b> The engine may call from any of its threads; the dispatchers given here must be thread-safe.</li>
 * </ul>
 */
@SuppressWarnings("restricted")
final class HostCallbacks implements AutoCloseable {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final AnnotatorDispatcher annotator;
    private final PolicyDispatcher policy;
    private final Arena stubs = Arena.ofShared();
    private final Map<Long, Arena> results = new ConcurrentHashMap<>();
    private final MemorySegment annotatorStub;
    private final MemorySegment policyStub;
    private final MemorySegment freeStub;

    /** @param annotator null to use the bundled annotator dispatcher; @param policy null to use the bundled (OPA) policy dispatcher */
    HostCallbacks(NativeApi api, AnnotatorDispatcher annotator, PolicyDispatcher policy) {
        this.annotator = annotator;
        this.policy = policy;
        try {
            MethodHandles.Lookup lookup = MethodHandles.lookup();
            MemorySegment none = MemorySegment.NULL; // no callback registered: the engine uses its bundled dispatcher
            annotatorStub = annotator == null ? none : api.linker().upcallStub(
                    lookup.findVirtual(HostCallbacks.class, "dispatchAnnotator",
                            MethodType.methodType(MemorySegment.class, MemorySegment.class, MemorySegment.class, MemorySegment.class, MemorySegment.class))
                            .bindTo(this),
                    FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
                    stubs);
            policyStub = policy == null ? none : api.linker().upcallStub(
                    lookup.findVirtual(HostCallbacks.class, "evaluatePolicy",
                            MethodType.methodType(MemorySegment.class, MemorySegment.class, MemorySegment.class))
                            .bindTo(this),
                    FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
                    stubs);
            MethodHandle free = lookup.findVirtual(HostCallbacks.class, "freeResult",
                    MethodType.methodType(void.class, MemorySegment.class, MemorySegment.class)).bindTo(this);
            freeStub = api.linker().upcallStub(free, FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS), stubs);
        } catch (ReflectiveOperationException | RuntimeException e) {
            stubs.close();
            throw new AcsException("Cannot create the native callbacks: " + e.getMessage(), e);
        }
    }

    MemorySegment annotatorCallback() {
        return annotatorStub;
    }

    MemorySegment policyCallback() {
        return policyStub;
    }

    MemorySegment freeCallback() {
        return freeStub;
    }

    boolean hasAnnotator() {
        return annotator != null;
    }

    boolean hasPolicy() {
        return policy != null;
    }

    // ------------------------------------------------------------------ called by the engine

    @SuppressWarnings("unused") // bound to the upcall stub through a method handle
    private MemorySegment dispatchAnnotator(MemorySegment namePointer, MemorySegment configPointer, MemorySegment preliminaryPointer,
                                            MemorySegment userData) {
        try {
            String name = NativeApi.read(namePointer);
            JsonNode config = JSON.readTree(NativeApi.read(configPointer));
            JsonNode preliminary = JSON.readTree(NativeApi.read(preliminaryPointer));
            JsonNode result = annotator.dispatch(name, config, preliminary);
            return result(JSON.writeValueAsString(result));
        } catch (Throwable t) {
            try {
                String message = t.getMessage();
                if (message != null && message.contains(AnnotatorDispatcher.ANNOTATION_TIMEOUT_REASON)) {
                    return result(AnnotatorDispatcher.ANNOTATION_TIMEOUT_REASON);
                }
            } catch (Throwable ignored) {
                // fall through to NULL
            }
            return MemorySegment.NULL;
        }
    }

    @SuppressWarnings("unused") // bound to the upcall stub through a method handle
    private MemorySegment evaluatePolicy(MemorySegment invocationPointer, MemorySegment userData) {
        try {
            JsonNode invocation = JSON.readTree(NativeApi.read(invocationPointer));
            JsonNode result = policy.evaluate(invocation);
            return result(JSON.writeValueAsString(result));
        } catch (Throwable t) {
            return MemorySegment.NULL;
        }
    }

    @SuppressWarnings("unused") // bound to the upcall stub through a method handle
    private void freeResult(MemorySegment pointer, MemorySegment userData) {
        try {
            Arena owner = results.remove(pointer.address());
            if (owner != null) {
                owner.close();
            }
        } catch (Throwable ignored) {
            // nothing may escape; at worst the string stays allocated until the runtime is closed
        }
    }

    private MemorySegment result(String json) {
        Arena owner = Arena.ofShared();
        MemorySegment string = owner.allocateFrom(json);
        results.put(string.address(), owner);
        return string;
    }

    /** Releases the stubs and any result the engine did not free. Call it after the runtime was freed. */
    @Override
    public void close() {
        stubs.close();
        results.values().forEach(Arena::close);
        results.clear();
    }
}
