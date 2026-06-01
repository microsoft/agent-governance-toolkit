using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using AgentControlSpecification.AI;

namespace AgentControlSpecification.AgentFramework;

public static class AgentControlAgentBuilderExtensions
{
    public static AIAgent UseAgentControl(this AIAgent agent, AgentControl control, EnforcementMode mode = EnforcementMode.Enforce, ApprovalResolver? approvalResolver = null)
    {
        ArgumentNullException.ThrowIfNull(agent);
        return agent.AsBuilder().UseAgentControl(control, mode, approvalResolver).Build();
    }

    public static AIAgent AsGuarded(this AIAgent agent, AgentControl control, EnforcementMode mode = EnforcementMode.Enforce, ApprovalResolver? approvalResolver = null) =>
        agent.UseAgentControl(control, mode, approvalResolver);

    public static AIAgentBuilder UseAgentControl(this AIAgentBuilder builder, AgentControl control, EnforcementMode mode = EnforcementMode.Enforce, ApprovalResolver? approvalResolver = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(control);
        builder.Use(async (messages, session, options, agent, ct) =>
        {
            var messageList = messages as IReadOnlyList<ChatMessage> ?? messages.ToList();
            var request = ChatRequestSnapshot.From(messageList, null);
            var result = await control.RunModelTurnAsync(
                messageList.LastOrDefault(message => message.Role == ChatRole.User)?.Text ?? string.Empty,
                request,
                async (effectiveRequest, token) => await agent.RunAsync(
                    effectiveRequest.ApplyMessages(messageList),
                    session,
                    options,
                    token).ConfigureAwait(false),
                mode: mode,
                approvalResolver: approvalResolver,
                cancellationToken: ct).ConfigureAwait(false);
            return result.Value;
        }, (messages, session, options, agent, ct) => agent.RunStreamingAsync(messages, session, options, ct));

        return builder;
    }

    public static AIAgentBuilder UseAgentControlFunctionInvocation(this AIAgentBuilder builder, AgentControl control, EnforcementMode mode = EnforcementMode.Enforce, ApprovalResolver? approvalResolver = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(control);
        builder.Use(async (_, context, next, ct) =>
        {
            var result = await control.ProtectToolAsync(
                context.Function.Name,
                context.Arguments.ToDictionary(pair => pair.Key, pair => pair.Value),
                async (_, token) => await next(context, token).ConfigureAwait(false),
                string.IsNullOrEmpty(context.CallContent?.CallId) ? null : context.CallContent!.CallId,
                mode: mode,
                approvalResolver: approvalResolver,
                cancellationToken: ct).ConfigureAwait(false);
            return result.Value!;
        });
        return builder;
    }
}
