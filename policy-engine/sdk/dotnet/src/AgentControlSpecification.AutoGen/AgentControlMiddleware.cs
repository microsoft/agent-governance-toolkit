using AutoGen.Core;

namespace AgentControlSpecification.AutoGen;

public sealed class AgentControlMiddleware : IMiddleware
{
    private readonly AgentControl control;
    private readonly EnforcementMode mode;
    private readonly ApprovalResolver? approvalResolver;

    public AgentControlMiddleware(AgentControl control, EnforcementMode mode = EnforcementMode.Enforce, ApprovalResolver? approvalResolver = null)
    {
        this.control = control ?? throw new ArgumentNullException(nameof(control));
        this.mode = mode;
        this.approvalResolver = approvalResolver;
    }

    public string? Name => "AgentControlSpecification";

    public async Task<IMessage> InvokeAsync(MiddlewareContext context, IAgent agent, CancellationToken cancellationToken = default)
    {
        var last = context.Messages.LastOrDefault();
        if (last is ToolCallMessage toolCallMessage && toolCallMessage.ToolCalls.Count == 1)
        {
            var call = toolCallMessage.ToolCalls[0];
            var result = await control.ProtectToolAsync(
                call.FunctionName,
                call.FunctionArguments,
                async (_, ct) => await agent.GenerateReplyAsync(context.Messages, context.Options, ct).ConfigureAwait(false),
                string.IsNullOrWhiteSpace(call.ToolCallId) ? Guid.NewGuid().ToString("N") : call.ToolCallId,
                mode: mode,
                approvalResolver: approvalResolver,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            return result.Value;
        }

        var run = await control.RunAsync(
            last?.GetContent() ?? string.Empty,
            async (_, ct) => await agent.GenerateReplyAsync(context.Messages, context.Options, ct).ConfigureAwait(false),
            mode: mode,
            approvalResolver: approvalResolver,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        return run.Value;
    }
}

public static class AgentControlAutoGenExtensions
{
    public static MiddlewareAgent UseAgentControl(this IAgent agent, AgentControl control, EnforcementMode mode = EnforcementMode.Enforce, ApprovalResolver? approvalResolver = null)
    {
        ArgumentNullException.ThrowIfNull(agent);
        ArgumentNullException.ThrowIfNull(control);
        return new MiddlewareAgent(agent, agent.Name, [new AgentControlMiddleware(control, mode, approvalResolver)]);
    }

    public static MiddlewareAgent UseAgentControl(this MiddlewareAgent agent, AgentControl control, EnforcementMode mode = EnforcementMode.Enforce, ApprovalResolver? approvalResolver = null)
    {
        ArgumentNullException.ThrowIfNull(agent);
        agent.Use(new AgentControlMiddleware(control, mode, approvalResolver));
        return agent;
    }

    public static MiddlewareAgent AsGuarded(this IAgent agent, AgentControl control, EnforcementMode mode = EnforcementMode.Enforce, ApprovalResolver? approvalResolver = null) =>
        agent.UseAgentControl(control, mode, approvalResolver);

    public static MiddlewareAgent AsGuarded(this MiddlewareAgent agent, AgentControl control, EnforcementMode mode = EnforcementMode.Enforce, ApprovalResolver? approvalResolver = null) =>
        agent.UseAgentControl(control, mode, approvalResolver);
}
