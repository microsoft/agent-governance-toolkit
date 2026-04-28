// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections;
using System.Linq;
using AgentGovernance.Audit;
using AgentGovernance.Integration;
using AgentGovernance.Policy;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

namespace AgentGovernance.Extensions.Microsoft.Agents;

/// <summary>
/// Reusable Microsoft Agent Framework adapter that applies AGT governance as real MAF middleware.
/// </summary>
public sealed class AgentFrameworkGovernanceAdapter
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AgentFrameworkGovernanceAdapter"/> class.
    /// </summary>
    public AgentFrameworkGovernanceAdapter(
        GovernanceKernel kernel,
        AgentFrameworkGovernanceOptions? options = null)
    {
        Kernel = kernel ?? throw new ArgumentNullException(nameof(kernel));
        Options = options ?? new AgentFrameworkGovernanceOptions();
    }

    /// <summary>
    /// Gets the AGT governance kernel that backs this adapter.
    /// </summary>
    public GovernanceKernel Kernel { get; }

    /// <summary>
    /// Gets the adapter options controlling identifier and payload translation.
    /// </summary>
    public AgentFrameworkGovernanceOptions Options { get; }

    /// <summary>
    /// Applies run-level governance before the inner agent executes.
    /// </summary>
    public async Task<AgentResponse> RunAsync(
        IEnumerable<ChatMessage> messages,
        AgentSession? session,
        AgentRunOptions? options,
        AIAgent innerAgent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(messages);
        ArgumentNullException.ThrowIfNull(innerAgent);

        var agentId = ResolveAgentId(innerAgent, session);
        var agentName = ResolveAgentName(innerAgent);
        var inputText = ResolveInputText(messages);
        var sessionId = ResolveSessionId(session);

        var context = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
        {
            ["message"] = inputText,
            ["agent_name"] = agentName,
            ["message_count"] = messages.Count(),
            ["has_session"] = session is not null
        };

        var decision = Kernel.PolicyEngine.Evaluate(agentId, context);
        EmitRunDecision(agentId, sessionId, inputText, decision);
        Kernel.Metrics?.RecordDecision(
            decision.Allowed,
            agentId,
            "agent_run",
            decision.EvaluationMs,
            decision.RateLimited);

        if (!decision.Allowed)
        {
            return Options.BlockedRunResponseFactory?.Invoke(decision)
                ?? CreateBlockedRunResponse(decision);
        }

        return await innerAgent.RunAsync(messages, session, options, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Applies function-call governance before the inner tool executes.
    /// </summary>
    public async ValueTask<object?> InvokeFunctionAsync(
        AIAgent agent,
        FunctionInvocationContext context,
        Func<FunctionInvocationContext, CancellationToken, ValueTask<object?>> next,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(agent);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        var agentId = ResolveAgentId(agent, session: null);
        var decision = Kernel.EvaluateToolCall(
            agentId,
            context.Function.Name,
            ResolveToolArguments(context));

        if (!decision.Allowed)
        {
            context.Terminate = true;
            return Options.BlockedToolResultFactory?.Invoke(decision)
                ?? $"Blocked by governance policy: {decision.Reason}";
        }

        return await next(context, cancellationToken).ConfigureAwait(false);
    }

    private static AgentResponse CreateBlockedRunResponse(PolicyDecision decision)
    {
        return new AgentResponse(
        [
            new ChatMessage(ChatRole.Assistant, $"Blocked by governance policy: {decision.Reason}")
        ]);
    }

    private void EmitRunDecision(
        string agentId,
        string sessionId,
        string inputText,
        PolicyDecision decision)
    {
        if (!Kernel.AuditEnabled)
        {
            return;
        }

        var auditData = new Dictionary<string, object>
        {
            ["message"] = inputText,
            ["allowed"] = decision.Allowed,
            ["action"] = decision.Action,
            ["reason"] = decision.Reason,
            ["evaluation_ms"] = decision.EvaluationMs
        };

        Kernel.AuditEmitter.Emit(
            decision.Allowed ? GovernanceEventType.PolicyCheck : GovernanceEventType.PolicyViolation,
            agentId,
            sessionId,
            auditData,
            decision.MatchedRule ?? decision.PolicyName);
    }

    private string ResolveAgentId(AIAgent agent, AgentSession? session)
    {
        var resolved = Options.AgentIdResolver?.Invoke(agent, session);
        if (!string.IsNullOrWhiteSpace(resolved))
        {
            return resolved;
        }

        var agentName = ResolveAgentName(agent);
        if (!string.IsNullOrWhiteSpace(agentName))
        {
            return $"did:agentmesh:{Slugify(agentName)}";
        }

        return Options.DefaultAgentId;
    }

    private string ResolveAgentName(AIAgent agent)
    {
        var nameProperty = agent.GetType().GetProperty("Name");
        return nameProperty?.GetValue(agent) as string ?? "unknown-agent";
    }

    private string ResolveInputText(IEnumerable<ChatMessage> messages)
    {
        var resolved = Options.InputTextResolver?.Invoke(messages);
        if (!string.IsNullOrWhiteSpace(resolved))
        {
            return resolved;
        }

        foreach (var message in messages.Reverse())
        {
            if (!string.IsNullOrWhiteSpace(message.Text))
            {
                return message.Text;
            }
        }

        return string.Empty;
    }

    private Dictionary<string, object> ResolveToolArguments(FunctionInvocationContext context)
    {
        var resolved = Options.ToolArgumentsResolver?.Invoke(context);
        if (resolved is not null)
        {
            return resolved;
        }

        return NormalizeArguments(context.Arguments);
    }

    private static Dictionary<string, object> NormalizeArguments(object? arguments)
    {
        var normalized = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        if (arguments is null)
        {
            return normalized;
        }

        if (arguments is IDictionary genericDictionary)
        {
            foreach (DictionaryEntry entry in genericDictionary)
            {
                if (entry.Key is string key && entry.Value is not null)
                {
                    normalized[key] = entry.Value;
                }
            }

            return normalized;
        }

        normalized["arguments"] = arguments;
        return normalized;
    }

    private static string ResolveSessionId(AgentSession? session)
    {
        var idProperty = session?.GetType().GetProperty("Id");
        if (idProperty?.GetValue(session) is string sessionId && !string.IsNullOrWhiteSpace(sessionId))
        {
            return sessionId;
        }

        return $"maf-{Guid.NewGuid():N}"[..20];
    }

    private static string Slugify(string value)
    {
        var buffer = new char[value.Length];
        var cursor = 0;

        foreach (var ch in value)
        {
            buffer[cursor++] = char.IsLetterOrDigit(ch)
                ? char.ToLowerInvariant(ch)
                : '-';
        }

        return new string(buffer, 0, cursor).Trim('-');
    }
}
