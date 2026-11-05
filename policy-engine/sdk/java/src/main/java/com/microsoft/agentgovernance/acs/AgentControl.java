// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The host API of the Agent Control Specification: ask the engine to decide at an intervention point ({@code evaluate*}), or let it
 * guard an action end to end ({@code run*}).
 *
 * <pre>{@code
 * try (AgentControl control = AgentControl.fromPath("manifest.yaml")) {
 *     ToolRunResult result = control.runTool("web_search", args, a -> search(a));
 *     use(result.value());
 * } catch (AgentControlBlockedException blocked) {
 *     // the engine denied the action; blocked.result().verdict().reason() says why
 * }
 * }</pre>
 *
 * <p>All values are Jackson {@link JsonNode}s: the snapshot the engine sees is JSON, and so is every answer. The class holds no decision
 * logic: whether an action may proceed, what is replaced and what needs approval is decided by the engine; this class carries it out.
 * It fails closed: a {@code deny}, a verdict it does not understand, an approval that cannot be given or does not match the action
 * all stop the action with an {@link AgentControlInterruptionException}.
 *
 * <p>Thread-safe, like the runtime under it.
 */
public final class AgentControl implements AutoCloseable {

    private static final ObjectMapper JSON = new ObjectMapper();

    /** An action the engine guards: given the (possibly transformed) value, does the work and returns its result. */
    @FunctionalInterface
    public interface Executor {
        JsonNode execute(JsonNode value) throws Exception;
    }

    /** The result of {@link #run}: the input and output guards. */
    public record RunResult(JsonNode value, InterventionPointResult inputResult, InterventionPointResult outputResult) {
    }

    /** The result of {@link #runModel}. */
    public record ModelRunResult(JsonNode value, InterventionPointResult preModelCallResult, InterventionPointResult postModelCallResult) {
    }

    /** The result of {@link #runTool}. */
    public record ToolRunResult(JsonNode value, InterventionPointResult preToolCallResult, InterventionPointResult postToolCallResult) {
    }

    /** Thrown for a failure inside the guarded action (it is not an engine decision). */
    public static final class ActionExecutionException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        ActionExecutionException(Throwable cause) {
            super("The guarded action failed: " + cause.getMessage(), cause);
        }
    }

    /**
     * Optional parts of a call.
     *
     * @param snapshot         members added to the snapshot next to the ones the call sets (ambient state of the agent)
     * @param mode             {@link EnforcementMode#ENFORCE} when null
     * @param approvalResolver overrides the resolver of the {@link AgentControl} for this call
     * @param toolCallId       identity of a tool call, kept the same on the {@code pre_tool_call} and {@code post_tool_call} of one call
     */
    public record Options(Map<String, JsonNode> snapshot, EnforcementMode mode, ApprovalResolver approvalResolver, String toolCallId) {

        public Options {
            snapshot = snapshot == null ? Map.of() : Map.copyOf(snapshot);
            mode = mode == null ? EnforcementMode.ENFORCE : mode;
            if (toolCallId != null && toolCallId.isEmpty()) {
                throw new IllegalArgumentException("toolCallId must be a non-empty string when provided");
            }
        }

        public static Options defaults() {
            return new Options(null, null, null, null);
        }

        public Options withSnapshot(Map<String, JsonNode> snapshot) {
            return new Options(snapshot, mode, approvalResolver, toolCallId);
        }

        public Options withMode(EnforcementMode mode) {
            return new Options(snapshot, mode, approvalResolver, toolCallId);
        }

        public Options withApprovalResolver(ApprovalResolver resolver) {
            return new Options(snapshot, mode, resolver, toolCallId);
        }

        public Options withToolCallId(String toolCallId) {
            return new Options(snapshot, mode, approvalResolver, toolCallId);
        }
    }

    private final AgentControlRuntime runtime;
    private final ApprovalResolver approvalResolver;

    /** @param approvalResolver consulted when the engine denies with an approval block; null = such a deny stands */
    public AgentControl(AgentControlRuntime runtime, ApprovalResolver approvalResolver) {
        this.runtime = Objects.requireNonNull(runtime, "runtime");
        this.approvalResolver = approvalResolver;
    }

    public AgentControl(AgentControlRuntime runtime) {
        this(runtime, null);
    }

    /** A control over the Rust engine with the bundled dispatchers (Rego policies need the OPA executable, see {@code ACS_OPA_PATH}). */
    public static AgentControl fromPath(String manifestPath) {
        return builder().manifestPath(manifestPath).build();
    }

    public static AgentControl fromYaml(String yaml) {
        return builder().manifestYaml(yaml).build();
    }

    public static AgentControl fromJson(String json) {
        return builder().manifestJson(json).build();
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Collects what a control over the Rust engine is built from. */
    public static final class Builder {
        private final NativeRuntime.Builder runtime = NativeRuntime.builder();
        private ApprovalResolver resolver;

        private Builder() {
        }

        public Builder manifestPath(String path) {
            runtime.manifestPath(path);
            return this;
        }

        public Builder manifestYaml(String yaml) {
            runtime.manifestYaml(yaml);
            return this;
        }

        public Builder manifestJson(String json) {
            runtime.manifestJson(json);
            return this;
        }

        public Builder manifestChain(List<String> yamls) {
            runtime.manifestChain(yamls);
            return this;
        }

        public Builder annotatorDispatcher(AnnotatorDispatcher annotator) {
            runtime.annotatorDispatcher(annotator);
            return this;
        }

        public Builder policyDispatcher(PolicyDispatcher policy) {
            runtime.policyDispatcher(policy);
            return this;
        }

        public Builder perfTelemetry(PerfTelemetry level) {
            runtime.perfTelemetry(level);
            return this;
        }

        public Builder opaPath(String opaPath) {
            runtime.opaPath(opaPath);
            return this;
        }

        public Builder approvalResolver(ApprovalResolver resolver) {
            this.resolver = resolver;
            return this;
        }

        public AgentControl build() {
            return new AgentControl(runtime.build(), resolver);
        }
    }

    /** Closes the runtime when it is {@link AutoCloseable} (the Rust engine is); a custom runtime is left to its owner otherwise. */
    @Override
    public void close() {
        if (runtime instanceof AutoCloseable closeable) {
            try {
                closeable.close();
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new AcsException("Cannot close the runtime: " + e.getMessage(), e);
            }
        }
    }

    // ------------------------------------------------------------------ evaluate

    public InterventionPointResult evaluate(InterventionPoint point, JsonNode snapshot, EnforcementMode mode) {
        return runtime.evaluate(new InterventionPointRequest(point, snapshot, mode));
    }

    public InterventionPointResult evaluate(InterventionPoint point, JsonNode snapshot) {
        return evaluate(point, snapshot, EnforcementMode.ENFORCE);
    }

    public InterventionPointResult evaluateAgentStartup(JsonNode agent, Options options) {
        return evaluate(InterventionPoint.AGENT_STARTUP, snapshot(options, "agent", agent), options.mode());
    }

    public InterventionPointResult evaluateInput(JsonNode input) {
        return evaluateInput(input, Options.defaults());
    }

    public InterventionPointResult evaluateInput(JsonNode input, Options options) {
        return evaluate(InterventionPoint.INPUT, snapshot(options, "input", input), options.mode());
    }

    public InterventionPointResult evaluateOutput(JsonNode output) {
        return evaluateOutput(output, Options.defaults());
    }

    public InterventionPointResult evaluateOutput(JsonNode output, Options options) {
        return evaluate(InterventionPoint.OUTPUT, snapshot(options, "output", output), options.mode());
    }

    public InterventionPointResult evaluatePreModelCall(JsonNode modelRequest, Options options) {
        return evaluate(InterventionPoint.PRE_MODEL_CALL, snapshot(options, "model_request", modelRequest), options.mode());
    }

    public InterventionPointResult evaluatePostModelCall(JsonNode modelResponse, Options options) {
        return evaluate(InterventionPoint.POST_MODEL_CALL, snapshot(options, "model_response", modelResponse), options.mode());
    }

    public InterventionPointResult evaluatePreToolCall(String toolName, JsonNode args, Options options) {
        requireName(toolName);
        return evaluate(InterventionPoint.PRE_TOOL_CALL, snapshot(options, "tool_call", toolCall(toolName, args, options.toolCallId())),
                options.mode());
    }

    public InterventionPointResult evaluatePostToolCall(String toolName, JsonNode args, JsonNode toolResult, Options options) {
        requireName(toolName);
        return evaluate(InterventionPoint.POST_TOOL_CALL, snapshot(options, "tool_call", toolCall(toolName, args, options.toolCallId()),
                "tool_result", toolResult), options.mode());
    }

    /**
     * @param summary the summary of the session the engine decides on at shutdown
     * @param reason  why the agent stops; may be null
     */
    public InterventionPointResult evaluateAgentShutdown(JsonNode summary, String reason, Options options) {
        return reason == null || reason.isBlank()
                ? evaluate(InterventionPoint.AGENT_SHUTDOWN, snapshot(options, "summary", summary), options.mode())
                : evaluate(InterventionPoint.AGENT_SHUTDOWN, snapshot(options, "summary", summary, "reason", JSON.getNodeFactory().textNode(reason)),
                        options.mode());
    }

    // ------------------------------------------------------------------ guard an action

    /** Guards an agent turn: {@code input} before the action, {@code output} after it. */
    public RunResult run(JsonNode input, Executor execute, Options options) {
        Objects.requireNonNull(execute, "execute");
        InterventionPointResult inputResult = evaluate(InterventionPoint.INPUT, snapshot(options, "input", input), options.mode());
        enforce(InterventionPoint.INPUT, inputResult, options);
        JsonNode effectiveInput = transformedOr(InterventionPoint.INPUT, inputResult, input, options.mode(), "input");

        JsonNode output = perform(execute, effectiveInput);
        InterventionPointResult outputResult = evaluate(InterventionPoint.OUTPUT,
                snapshot(options, "input", effectiveInput, "output", output), options.mode());
        enforce(InterventionPoint.OUTPUT, outputResult, options);
        return new RunResult(transformedOr(InterventionPoint.OUTPUT, outputResult, output, options.mode(), "output"), inputResult, outputResult);
    }

    public RunResult run(JsonNode input, Executor execute) {
        return run(input, execute, Options.defaults());
    }

    /**
     * Guards a model call: {@code pre_model_call} before it, {@code post_model_call} after. A request that asks for streaming
     * ({@code "stream": true}) is refused: this method guards one request and one response.
     */
    public ModelRunResult runModel(JsonNode modelRequest, Executor execute, Options options) {
        Objects.requireNonNull(execute, "execute");
        if (modelRequest != null && modelRequest.path("stream").asBoolean(false)) {
            throw new AgentControlBlockedException(InterventionPoint.PRE_MODEL_CALL, InterventionPointResult.of(Verdict.of(Decision.DENY,
                    "host_error:streaming_unsupported", "Streaming model requests are not guarded by runModel.")));
        }
        InterventionPointResult pre = evaluate(InterventionPoint.PRE_MODEL_CALL, snapshot(options, "model_request", modelRequest), options.mode());
        enforce(InterventionPoint.PRE_MODEL_CALL, pre, options);
        JsonNode effectiveRequest = transformedOr(InterventionPoint.PRE_MODEL_CALL, pre, modelRequest, options.mode(), "model_request");

        JsonNode response = perform(execute, effectiveRequest);
        InterventionPointResult post = evaluate(InterventionPoint.POST_MODEL_CALL,
                snapshot(options, "model_request", effectiveRequest, "model_response", response), options.mode());
        enforce(InterventionPoint.POST_MODEL_CALL, post, options);
        return new ModelRunResult(transformedOr(InterventionPoint.POST_MODEL_CALL, post, response, options.mode(), "model_response"), pre, post);
    }

    /**
     * Guards a tool call: {@code pre_tool_call} before it, {@code post_tool_call} after. The manifest must configure both points (give
     * {@code post_tool_call} an allow policy if nothing is to be checked afterwards), or the call fails closed once the tool has run.
     */
    public ToolRunResult runTool(String toolName, JsonNode args, Executor execute, Options options) {
        requireName(toolName);
        Objects.requireNonNull(execute, "execute");
        InterventionPointResult pre = evaluate(InterventionPoint.PRE_TOOL_CALL,
                snapshot(options, "tool_call", toolCall(toolName, args, options.toolCallId())), options.mode());
        enforce(InterventionPoint.PRE_TOOL_CALL, pre, options);
        JsonNode effectiveArgs = transformedOr(InterventionPoint.PRE_TOOL_CALL, pre, args, options.mode(), "tool_call.args");

        JsonNode toolResult = perform(execute, effectiveArgs);
        InterventionPointResult post = evaluate(InterventionPoint.POST_TOOL_CALL, snapshot(options,
                "tool_call", toolCall(toolName, effectiveArgs, options.toolCallId()), "tool_result", toolResult), options.mode());
        enforce(InterventionPoint.POST_TOOL_CALL, post, options);
        return new ToolRunResult(transformedOr(InterventionPoint.POST_TOOL_CALL, post, toolResult, options.mode(), "tool_result"), pre, post);
    }

    public ToolRunResult runTool(String toolName, JsonNode args, Executor execute) {
        return runTool(toolName, args, execute, Options.defaults());
    }

    /** Same as {@link #runTool}. */
    public ToolRunResult protectTool(String toolName, JsonNode args, Executor execute, Options options) {
        return runTool(toolName, args, execute, options);
    }

    // ------------------------------------------------------------------ enforcement

    private void enforce(InterventionPoint point, InterventionPointResult result, Options options) {
        if (options.mode() != EnforcementMode.ENFORCE) {
            return;
        }
        Decision decision = result.verdict().decision();
        // warn is retired and never returned, but it means "allow and record a warning": it still permits
        if (decision.permits()) {
            return;
        }
        // a deny that carries an approval block can be lifted by a person; so can the retired escalate. Any other deny is final.
        boolean liftable = decision == Decision.ESCALATE || decision == Decision.DENY && result.verdict().approval() != null;
        if (!liftable) {
            throw new AgentControlBlockedException(point, result);
        }
        ApprovalResolver resolver = options.approvalResolver() != null ? options.approvalResolver() : approvalResolver;
        if (resolver == null) {
            throw new AgentControlBlockedException(point, withVerdict(result, Verdict.of(Decision.DENY, "host_error:approval_unresolved",
                    "Approval requires a configured resolver.")));
        }
        String originalIdentity = result.actionIdentity();
        ApprovalResolution resolution;
        try {
            // the resolver gets a copy: whatever it does to it, the result that is enforced here is untouched
            resolution = resolver.resolve(point, copy(result));
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new AgentControlBlockedException(point, approvalResolverFailed(result), e);
        }
        if (resolution == null || resolution.outcome() == null) {
            throw new AgentControlBlockedException(point, approvalResolverFailed(result));
        }
        switch (resolution.outcome()) {
            case ALLOW -> requireApprovedIdentity(point, originalIdentity, resolution.actionIdentity());
            case SUSPEND -> {
                requireApprovedIdentity(point, originalIdentity, resolution.actionIdentity());
                throw new AgentControlSuspendedException(point, result, resolution.handle());
            }
            case DENY -> throw new AgentControlBlockedException(point, result);
            default -> throw new AgentControlBlockedException(point, approvalResolverFailed(result));
        }
    }

    /** An approval consents to one exact action: the identity the resolver names must be the one the engine reported. */
    private static void requireApprovedIdentity(InterventionPoint point, String originalIdentity, String approvedIdentity) {
        if (originalIdentity != null && approvedIdentity != null && originalIdentity.equals(approvedIdentity)) {
            return;
        }
        throw new AgentControlBlockedException(point, InterventionPointResult.of(
                Verdict.of(Decision.DENY, "host_error:approval_identity_mismatch", null)));
    }

    private static InterventionPointResult approvalResolverFailed(InterventionPointResult result) {
        return new InterventionPointResult(Verdict.of(Decision.DENY, "host_error:approval_resolver_failed", "Approval resolver failed closed."),
                null, result.policyInput(), result.actionIdentity(), false, null, null);
    }

    private static InterventionPointResult withVerdict(InterventionPointResult result, Verdict verdict) {
        return new InterventionPointResult(verdict, result.transformedPolicyTarget(), result.policyInput(), result.actionIdentity(),
                result.transformedPolicyTargetApplied(), result.inputIdentity(), result.enforcedIdentity());
    }

    private static InterventionPointResult copy(InterventionPointResult result) {
        return new InterventionPointResult(result.verdict(), deep(result.transformedPolicyTarget()), deep(result.policyInput()),
                result.actionIdentity(), result.transformedPolicyTargetApplied(), result.inputIdentity(), result.enforcedIdentity());
    }

    private static JsonNode deep(JsonNode node) {
        return node == null ? null : node.deepCopy();
    }

    // ------------------------------------------------------------------ transforms

    /**
     * What the host proceeds with: the replacement the engine produced for a {@code transform}, placed where the policy target was.
     *
     * <p>{@code valueRoot} is where {@code original} sits in the snapshot ({@code input}, {@code tool_call.args}, ...). A policy target
     * that is exactly that place replaces the whole value; one below it ({@code tool_call.args.query}) replaces that member only; one
     * anywhere else (the tool name, the whole snapshot) cannot be applied to this value, so the action is blocked rather than run on a
     * wrong value.
     */
    static JsonNode transformedOr(InterventionPoint point, InterventionPointResult result, JsonNode original, EnforcementMode mode,
                                  String valueRoot) {
        if (mode != EnforcementMode.ENFORCE || !result.verdict().decision().appliesTransform()) {
            return original;
        }
        JsonNode transformed = result.transformedPolicyTarget();
        if (!result.transformedPolicyTargetApplied() && transformed == null) {
            return original;
        }
        JsonNode replacement = transformed == null ? JSON.getNodeFactory().nullNode() : transformed.deepCopy();
        String target = snapshotPath(policyTargetPath(result));
        if (target == null || target.equals(valueRoot)) {
            return replacement;
        }
        String relative = null;
        if (target.startsWith(valueRoot + ".") || target.startsWith(valueRoot + "[")) {
            relative = target.substring(valueRoot.length());
        }
        if (relative != null && original != null) {
            JsonNode root = original.deepCopy();
            if (setRelative(root, relative, replacement)) {
                return root;
            }
        }
        throw new AgentControlBlockedException(point, withVerdict(result, Verdict.of(Decision.DENY, "host_error:transform_target_unsupported",
                "The transform replaces " + target + ", which is not part of the value the action receives (" + valueRoot + ").")));
    }

    /** {@code $.input.text} and {@code $snap.input.text} both become {@code input.text}; anything else is not a snapshot path. */
    static String snapshotPath(String path) {
        if (path == null) {
            return null;
        }
        if (path.startsWith("$.")) {
            return path.substring(2);
        }
        if (path.startsWith("$snap.")) {
            return path.substring(6);
        }
        return null;
    }

    private static String policyTargetPath(InterventionPointResult result) {
        JsonNode policyInput = result.policyInput();
        if (policyInput == null || !policyInput.isObject()) {
            return null;
        }
        JsonNode target = policyInput.get("policy_target");
        if (target == null || !target.isObject()) {
            return null;
        }
        JsonNode path = target.get("path");
        return path != null && path.isTextual() ? path.asText() : null;
    }

    private static boolean setRelative(JsonNode root, String path, JsonNode value) {
        List<Object> segments = segments(path);
        if (segments.isEmpty()) {
            return false;
        }
        JsonNode current = root;
        for (int i = 0; i < segments.size() - 1; i++) {
            current = child(current, segments.get(i));
            if (current == null) {
                return false;
            }
        }
        Object last = segments.get(segments.size() - 1);
        if (last instanceof String field && current instanceof ObjectNode object && object.has(field)) {
            object.set(field, value);
            return true;
        }
        if (last instanceof Integer index && current instanceof ArrayNode array && index >= 0 && index < array.size()) {
            array.set(index, value);
            return true;
        }
        return false;
    }

    private static JsonNode child(JsonNode node, Object segment) {
        if (segment instanceof String field && node instanceof ObjectNode object) {
            return object.get(field);
        }
        if (segment instanceof Integer index && node instanceof ArrayNode array && index >= 0 && index < array.size()) {
            return array.get(index);
        }
        return null;
    }

    private static List<Object> segments(String path) {
        List<Object> segments = new ArrayList<>();
        int index = 0;
        while (index < path.length()) {
            char c = path.charAt(index);
            if (c == '.') {
                index++;
                int start = index;
                while (index < path.length() && path.charAt(index) != '.' && path.charAt(index) != '[') {
                    index++;
                }
                if (start == index) {
                    return List.of();
                }
                segments.add(path.substring(start, index));
            } else if (c == '[') {
                int end = path.indexOf(']', index);
                if (end < 0) {
                    return List.of();
                }
                try {
                    segments.add(Integer.parseInt(path.substring(index + 1, end)));
                } catch (NumberFormatException e) {
                    return List.of();
                }
                index = end + 1;
            } else {
                return List.of();
            }
        }
        return segments;
    }

    // ------------------------------------------------------------------ snapshots

    private static JsonNode snapshot(Options options, String key, JsonNode value) {
        ObjectNode snapshot = ambient(options);
        snapshot.set(key, orNull(value));
        return snapshot;
    }

    private static JsonNode snapshot(Options options, String key1, JsonNode value1, String key2, JsonNode value2) {
        ObjectNode snapshot = ambient(options);
        snapshot.set(key1, orNull(value1));
        snapshot.set(key2, orNull(value2));
        return snapshot;
    }

    private static ObjectNode ambient(Options options) {
        ObjectNode snapshot = JSON.createObjectNode();
        for (Map.Entry<String, JsonNode> entry : new LinkedHashMap<>(options.snapshot()).entrySet()) {
            snapshot.set(entry.getKey(), orNull(entry.getValue()));
        }
        return snapshot;
    }

    private static JsonNode orNull(JsonNode value) {
        return value == null ? JSON.getNodeFactory().nullNode() : value.deepCopy();
    }

    private static ObjectNode toolCall(String name, JsonNode args, String id) {
        ObjectNode call = JSON.createObjectNode();
        call.put("name", name);
        call.set("args", orNull(args));
        if (id != null) {
            call.put("id", id);
        }
        return call;
    }

    private static void requireName(String toolName) {
        if (toolName == null || toolName.isBlank()) {
            throw new IllegalArgumentException("toolName must not be blank");
        }
    }

    private static JsonNode perform(Executor execute, JsonNode value) {
        try {
            JsonNode result = execute.execute(value);
            return result == null ? JSON.getNodeFactory().nullNode() : result;
        } catch (RuntimeException e) {
            throw e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ActionExecutionException(e);
        } catch (Exception e) {
            throw new ActionExecutionException(e);
        }
    }
}
