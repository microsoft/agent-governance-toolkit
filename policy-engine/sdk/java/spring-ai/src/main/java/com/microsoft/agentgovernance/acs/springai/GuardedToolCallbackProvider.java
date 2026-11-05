// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs.springai;

import com.microsoft.agentgovernance.acs.AgentControl;
import com.microsoft.agentgovernance.acs.AgentControlBlockedException;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.Function;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.ToolCallbackProvider;

/**
 * Guards every tool a {@link ToolCallbackProvider} offers. This is the MCP adapter: Spring AI's MCP client
 * ({@code SyncMcpToolCallbackProvider}, {@code AsyncMcpToolCallbackProvider}) is a {@code ToolCallbackProvider}, so
 *
 * <pre>{@code
 * ToolCallbackProvider guarded = new GuardedToolCallbackProvider(control, mcpToolCallbackProvider);
 * chatClient.prompt().toolCallbacks(guarded.getToolCallbacks())...
 * }</pre>
 *
 * makes every MCP tool call pass {@code pre_tool_call} and {@code post_tool_call}. The tools are listed from the delegate each time, so a
 * server whose tool list changes stays guarded. List the MCP tools in the manifest's {@code tools:}; the engine denies a tool it does not know.
 */
public final class GuardedToolCallbackProvider implements ToolCallbackProvider {

    private final AgentControl control;
    private final ToolCallbackProvider delegate;
    private final Function<AgentControlBlockedException, String> refusal;

    public GuardedToolCallbackProvider(AgentControl control, ToolCallbackProvider delegate) {
        this(control, delegate, GuardedToolCallback::defaultRefusal);
    }

    public GuardedToolCallbackProvider(AgentControl control, ToolCallbackProvider delegate,
                                       Function<AgentControlBlockedException, String> refusal) {
        this.control = Objects.requireNonNull(control, "control");
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.refusal = Objects.requireNonNull(refusal, "refusal");
    }

    @Override
    public ToolCallback[] getToolCallbacks() {
        return Arrays.stream(delegate.getToolCallbacks())
                .map(callback -> (ToolCallback) new GuardedToolCallback(control, callback, refusal))
                .toArray(ToolCallback[]::new);
    }

    /** Guards a fixed set of callbacks. */
    public static ToolCallback[] guard(AgentControl control, ToolCallback... callbacks) {
        return new GuardedToolCallbackProvider(control, ToolCallbackProvider.from(callbacks)).getToolCallbacks();
    }
}
