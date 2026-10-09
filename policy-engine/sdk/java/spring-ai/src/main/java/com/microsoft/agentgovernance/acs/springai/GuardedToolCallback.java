// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs.springai;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.agentgovernance.acs.AgentControl;
import com.microsoft.agentgovernance.acs.AgentControlBlockedException;
import java.util.Objects;
import java.util.function.Function;
import org.springframework.ai.chat.model.ToolContext;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.ToolDefinition;
import org.springframework.ai.tool.metadata.ToolMetadata;

/**
 * A Spring AI {@link ToolCallback} whose every call is guarded by the Agent Control Specification engine: {@code pre_tool_call} sees the
 * arguments before the tool runs and {@code post_tool_call} sees the result before the model does. The delegate runs only when the engine
 * allows it, on the arguments the engine allowed (a {@code transform} is applied).
 *
 * <p>What the model is told when the engine refuses is a {@code refusal} function of the exception (by default a short text that says the
 * call did not run and why), so that the model can carry on without the tool instead of the whole chat failing. An approval that is decided
 * elsewhere ({@code AgentControlSuspendedException}) is not caught: the caller owns that flow.
 *
 * <p>Tools that Spring AI builds from an MCP server are {@code ToolCallback}s too, so this class guards MCP tools as well; see
 * {@link GuardedToolCallbackProvider}.
 */
public final class GuardedToolCallback implements ToolCallback {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final ToolCallback delegate;
    private final AgentControl control;
    private final Function<AgentControlBlockedException, String> refusal;

    public GuardedToolCallback(AgentControl control, ToolCallback delegate) {
        this(control, delegate, GuardedToolCallback::defaultRefusal);
    }

    public GuardedToolCallback(AgentControl control, ToolCallback delegate, Function<AgentControlBlockedException, String> refusal) {
        this.control = Objects.requireNonNull(control, "control");
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.refusal = Objects.requireNonNull(refusal, "refusal");
    }

    @Override
    public ToolDefinition getToolDefinition() {
        return delegate.getToolDefinition();
    }

    @Override
    public ToolMetadata getToolMetadata() {
        return delegate.getToolMetadata();
    }

    @Override
    public String call(String toolInput) {
        return guarded(toolInput, delegate::call);
    }

    @Override
    public String call(String toolInput, ToolContext toolContext) {
        return guarded(toolInput, args -> delegate.call(args, toolContext));
    }

    private String guarded(String toolInput, Function<String, String> invoke) {
        JsonNode args = parseArguments(toolInput);
        try {
            AgentControl.ToolRunResult run = control.runTool(getToolDefinition().name(), args,
                    effective -> toResult(invoke.apply(effective.toString())));
            JsonNode value = run.value();
            return value != null && value.isTextual() ? value.asText() : String.valueOf(value);
        } catch (AgentControlBlockedException blocked) {
            return refusal.apply(blocked);
        }
    }

    /** The arguments Spring AI hands over are JSON text; an empty string is no arguments. Anything else that is not JSON is refused (fail closed). */
    static JsonNode parseArguments(String toolInput) {
        if (toolInput == null || toolInput.isBlank()) {
            return JSON.createObjectNode();
        }
        try {
            return JSON.readTree(toolInput);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("The tool arguments are not valid JSON, so the call is not evaluated and not run: "
                    + e.getOriginalMessage(), e);
        }
    }

    /** A tool answers with text; when the text is JSON the policy sees it as JSON, otherwise as a string. */
    static JsonNode toResult(String text) {
        if (text == null) {
            return JSON.getNodeFactory().nullNode();
        }
        String trimmed = text.strip();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            try {
                return JSON.readTree(trimmed);
            } catch (JsonProcessingException ignored) {
                // not JSON after all: the policy sees the text
            }
        }
        return JSON.getNodeFactory().textNode(text);
    }

    static String defaultRefusal(AgentControlBlockedException blocked) {
        String reason = blocked.result() == null || blocked.result().verdict() == null ? null : blocked.result().verdict().reason();
        return "NOT EXECUTED: the policy does not allow this call" + (reason == null || reason.isBlank() ? "" : " (" + reason + ")")
                + ". Carry on without it and say plainly that this data is not available.";
    }
}
