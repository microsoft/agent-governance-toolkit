// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.lang.foreign.MemorySegment;
import java.lang.ref.Cleaner;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * The Rust engine behind the C ABI. Thread-safe: any number of threads may {@link #evaluate} at once (the ABI takes a shared reference
 * to the runtime), and {@link #close()} waits for evaluations in progress before it frees the engine. A runtime that is dropped without
 * being closed is freed by a {@link Cleaner} as a last resort; close it.
 *
 * <p>Create one with {@link #builder()}, or use {@link AgentControl}, which wraps one.
 */
public final class NativeRuntime implements AgentControlRuntime, AutoCloseable {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Cleaner CLEANER = Cleaner.create();

    /** What the cleaner frees. It must not refer to the runtime object, or the runtime could never be collected. */
    private static final class Resources implements Runnable {
        private final NativeApi api;
        private final MemorySegment runtime;
        private final HostCallbacks callbacks;
        private boolean freed;

        Resources(NativeApi api, MemorySegment runtime, HostCallbacks callbacks) {
            this.api = api;
            this.runtime = runtime;
            this.callbacks = callbacks;
        }

        @Override
        public synchronized void run() {
            if (freed) {
                return;
            }
            freed = true;
            try {
                api.freeRuntime(runtime); // first: nothing can call the stubs once the runtime is gone
            } finally {
                callbacks.close();
            }
        }
    }

    private final NativeApi api;
    private final MemorySegment pointer;
    private final Resources resources;
    private final Cleaner.Cleanable cleanable;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private volatile boolean closed;

    private NativeRuntime(NativeApi api, MemorySegment pointer, HostCallbacks callbacks) {
        this.api = api;
        this.pointer = pointer;
        this.resources = new Resources(api, pointer, callbacks);
        this.cleanable = CLEANER.register(this, resources);
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Collects what a runtime is built from. */
    public static final class Builder {
        private enum Source { PATH, YAML, JSON, YAML_CHAIN }

        private Source source;
        private String path;
        private String text;
        private List<String> chain;
        private AnnotatorDispatcher annotator;
        private PolicyDispatcher policy;
        private PerfTelemetry perfTelemetry = PerfTelemetry.OFF;
        private String opaPath;

        private Builder() {
        }

        /** A manifest file. */
        public Builder manifestPath(String path) {
            this.source = Source.PATH;
            this.path = Objects.requireNonNull(path, "path");
            return this;
        }

        public Builder manifestYaml(String yaml) {
            this.source = Source.YAML;
            this.text = Objects.requireNonNull(yaml, "yaml");
            return this;
        }

        public Builder manifestJson(String json) {
            this.source = Source.JSON;
            this.text = Objects.requireNonNull(json, "json");
            return this;
        }

        /** Several YAML manifests merged in order; later ones refine earlier ones. */
        public Builder manifestChain(List<String> yamls) {
            if (yamls == null || yamls.isEmpty()) {
                throw new IllegalArgumentException("A manifest chain must not be empty");
            }
            this.source = Source.YAML_CHAIN;
            this.chain = List.copyOf(yamls);
            return this;
        }

        /** Computes annotations itself. Without it the bundled annotator dispatcher is used. */
        public Builder annotatorDispatcher(AnnotatorDispatcher annotator) {
            this.annotator = annotator;
            return this;
        }

        /** Evaluates policies itself. Without it the bundled dispatcher is used, which runs Rego through the OPA executable. */
        public Builder policyDispatcher(PolicyDispatcher policy) {
            this.policy = policy;
            return this;
        }

        public Builder perfTelemetry(PerfTelemetry level) {
            this.perfTelemetry = Objects.requireNonNull(level, "level");
            return this;
        }

        /**
         * The OPA executable (or its directory) the bundled policy dispatcher runs. It sets {@code ACS_OPA_PATH} for the whole process
         * before the runtime is built. Without it the variable is read as the JVM was started with it.
         */
        public Builder opaPath(String opaPath) {
            this.opaPath = opaPath;
            return this;
        }

        /**
         * @throws AcsException if the library cannot be loaded, the manifest does not load or the runtime cannot be built
         */
        public NativeRuntime build() {
            if (source == null) {
                throw new IllegalStateException("Name a manifest: manifestPath, manifestYaml, manifestJson or manifestChain");
            }
            NativeApi api = NativeApi.get();
            if (opaPath != null && !opaPath.isBlank()) {
                NativeEnvironment.set(NativeEnvironment.OPA_PATH, opaPath);
            }
            HostCallbacks callbacks = new HostCallbacks(api, annotator, policy);
            MemorySegment builder = null;
            boolean consumed = false;
            try {
                builder = switch (source) {
                    case PATH -> api.builderFromPath(path);
                    case YAML -> api.builderFromYaml(text);
                    case JSON -> api.builderFromJson(text);
                    case YAML_CHAIN -> api.builderFromYamlChain(chain);
                };
                if (annotator == null) {
                    api.enableDefaultAnnotatorDispatcher(builder);
                } else {
                    api.registerAnnotatorDispatcher(builder, callbacks.annotatorCallback(), callbacks.freeCallback());
                }
                if (policy == null) {
                    api.enableDefaultPolicyDispatcher(builder);
                } else {
                    api.registerPolicyDispatcher(builder, callbacks.policyCallback(), callbacks.freeCallback());
                }
                api.setPerfTelemetry(builder, perfTelemetry);
                consumed = true; // acs_builder_build takes the builder whether or not it succeeds
                MemorySegment runtime = api.build(builder);
                return new NativeRuntime(api, runtime, callbacks);
            } catch (RuntimeException e) {
                callbacks.close();
                throw e;
            } finally {
                if (builder != null && !consumed) {
                    api.freeBuilder(builder);
                }
            }
        }
    }

    @Override
    public InterventionPointResult evaluate(InterventionPointRequest request) {
        Objects.requireNonNull(request, "request");
        ObjectNode body = JSON.createObjectNode();
        body.put("intervention_point", request.interventionPoint().wireName());
        body.put("mode", request.mode().wireName());
        body.set("snapshot", request.snapshot());
        String requestJson;
        try {
            requestJson = JSON.writeValueAsString(body);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalArgumentException("The snapshot cannot be written as JSON: " + e.getMessage(), e);
        }
        String responseJson;
        lock.readLock().lock();
        try {
            ensureOpen();
            responseJson = api.evaluate(pointer, requestJson);
        } finally {
            lock.readLock().unlock();
        }
        try {
            return map(JSON.readTree(responseJson));
        } catch (java.io.IOException | RuntimeException e) {
            throw new AcsException("The engine returned a result that cannot be read: " + e.getMessage(), e);
        }
    }

    /**
     * The {@code policy_id} and annotator names of every intervention point, from the merged manifest, as JSON. Used to label telemetry.
     */
    public JsonNode policyLabels() {
        lock.readLock().lock();
        try {
            ensureOpen();
            return JSON.readTree(api.policyLabels(pointer));
        } catch (java.io.IOException e) {
            throw new AcsException("The engine returned policy labels that cannot be read: " + e.getMessage(), e);
        } finally {
            lock.readLock().unlock();
        }
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("The ACS runtime is closed");
        }
    }

    /** Frees the engine once evaluations in progress are done. Closing twice is harmless; evaluating afterwards throws. */
    @Override
    public void close() {
        lock.writeLock().lock();
        try {
            if (!closed) {
                closed = true;
                cleanable.clean();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    // ------------------------------------------------------------------ the engine's JSON to records

    static InterventionPointResult map(JsonNode raw) {
        Verdict verdict = mapVerdict(required(raw, "verdict"));
        boolean applied = raw.path("transformed_policy_target_applied").asBoolean(false);
        JsonNode transformed = raw.get("transformed_policy_target");
        if (!applied && transformed != null && !transformed.isNull()) {
            applied = true; // older engines only said so by sending the target
        }
        String enforced = text(raw, "enforced_identity");
        String input = text(raw, "input_identity");
        String action = text(raw, "action_identity");
        if (action == null) {
            action = enforced;
        }
        JsonNode policyInput = raw.get("policy_input");
        return new InterventionPointResult(
                verdict,
                applied && transformed != null ? transformed : null,
                policyInput == null || policyInput.isNull() ? null : policyInput,
                action,
                applied,
                input != null ? input : action,
                enforced != null ? enforced : action);
    }

    private static JsonNode required(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull()) {
            throw new IllegalArgumentException("missing '" + field + "'");
        }
        return value;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    private static Verdict mapVerdict(JsonNode raw) {
        List<String> labels = new ArrayList<>();
        JsonNode resultLabels = raw.get("result_labels");
        if (resultLabels != null && resultLabels.isArray()) {
            resultLabels.forEach(label -> labels.add(label.asText("")));
        }
        List<Warning> warnings = new ArrayList<>();
        JsonNode rawWarnings = raw.get("warnings");
        if (rawWarnings != null && rawWarnings.isArray()) {
            rawWarnings.forEach(w -> warnings.add(new Warning(text(w, "reason"), text(w, "message"))));
        }
        JsonNode approval = raw.get("approval");
        return new Verdict(
                Decision.fromWireName(raw.path("decision").asText("")),
                text(raw, "reason"),
                text(raw, "message"),
                mapTransform(raw.get("transform")),
                mapEvidence(raw.get("evidence")),
                labels,
                warnings,
                approval == null || approval.isNull() ? null : approval);
    }

    private static Transform mapTransform(JsonNode raw) {
        if (raw == null || raw.isNull()) {
            return null;
        }
        JsonNode value = raw.get("value");
        return new Transform(raw.path("path").asText(""), value == null ? null : value);
    }

    private static Evidence mapEvidence(JsonNode raw) {
        if (raw == null || raw.isNull()) {
            return null;
        }
        Map<String, String> pointers = null;
        JsonNode rawPointers = raw.get("verification_pointers");
        if (rawPointers != null && rawPointers.isObject()) {
            pointers = new LinkedHashMap<>();
            for (Map.Entry<String, JsonNode> entry : rawPointers.properties()) {
                if (entry.getValue().isTextual()) {
                    pointers.put(entry.getKey(), entry.getValue().asText());
                }
            }
        }
        JsonNode artefact = raw.get("artefact");
        return new Evidence(artefact != null && artefact.isTextual() ? artefact.asText() : null, pointers);
    }
}
