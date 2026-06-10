using AutoGen.Core;
using System.Text.Json;

namespace AgentControlSpecification.AutoGen;

public sealed class AgentControlMiddleware : IMiddleware
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

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
            IMessage? reply = null;
            var result = await control.ProtectToolAsync(
                call.FunctionName,
                call.FunctionArguments,
                async (_, ct) =>
                {
                    reply = await agent.GenerateReplyAsync(context.Messages, context.Options, ct).ConfigureAwait(false);
                    return SerializeMessage(reply);
                },
                string.IsNullOrEmpty(call.ToolCallId) ? null : call.ToolCallId,
                mode: mode,
                approvalResolver: approvalResolver,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            return ApplyTransformedMessage(reply!, result.Value);
        }

        var modelRequest = JsonSerializer.SerializeToElement(context.Messages, JsonOptions);
        IMessage? modelReply = null;
        var run = await control.RunModelTurnAsync<string, JsonElement, JsonElement>(
            last?.GetContent() ?? string.Empty,
            modelRequest,
            async (_, ct) =>
            {
                modelReply = await agent.GenerateReplyAsync(context.Messages, context.Options, ct).ConfigureAwait(false);
                return SerializeMessage(modelReply);
            },
            response => response,
            mode: mode,
            approvalResolver: approvalResolver,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        return ApplyTransformedMessage(modelReply!, run.Value);
    }

    private static IMessage ApplyTransformedMessage(IMessage original, JsonElement transformed)
    {
        if (TryReadContent(transformed, out var content))
        {
            return WithContent(original, content);
        }

        return original;
    }

    private static JsonElement SerializeMessage(IMessage? message)
    {
        if (message is null)
        {
            return JsonSerializer.SerializeToElement<object?>(null, JsonOptions);
        }

        return JsonSerializer.SerializeToElement(message, message.GetType(), JsonOptions);
    }

    private static bool TryReadContent(JsonElement element, out string content)
    {
        if (element.ValueKind == JsonValueKind.String)
        {
            content = element.GetString() ?? string.Empty;
            return true;
        }

        if (element.ValueKind == JsonValueKind.Object)
        {
            if (element.TryGetProperty("content", out var lower) && lower.ValueKind == JsonValueKind.String)
            {
                content = lower.GetString() ?? string.Empty;
                return true;
            }

            if (element.TryGetProperty("Content", out var upper) && upper.ValueKind == JsonValueKind.String)
            {
                content = upper.GetString() ?? string.Empty;
                return true;
            }
        }

        content = string.Empty;
        return false;
    }

    private static IMessage WithContent(IMessage message, string content)
    {
        switch (message)
        {
            case TextMessage textMessage:
                textMessage.Content = content;
                return textMessage;
            case ToolCallMessage toolCallMessage:
                toolCallMessage.Content = content;
                return toolCallMessage;
            default:
                var property = message.GetType().GetProperty("Content");
                if (property?.CanWrite == true && property.PropertyType == typeof(string))
                {
                    property.SetValue(message, content);
                }
                return message;
        }
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
