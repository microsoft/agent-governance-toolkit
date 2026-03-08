// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Audit;
using AgentGovernance.Policy;

namespace AgentGovernance.Integration;

/// <summary>
/// The result of evaluating a tool call through the governance middleware.
/// </summary>
public sealed class ToolCallResult
{
    /// <summary>
    /// Whether the tool call is allowed to proceed.
    /// </summary>
    public bool Allowed { get; init; }

    /// <summary>
    /// Human-readable reason for the decision.
    /// </summary>
    public required string Reason { get; init; }

    /// <summary>
    /// The governance event generated for this evaluation (for audit logging).
    /// </summary>
    public required GovernanceEvent AuditEntry { get; init; }

    /// <summary>
    /// The underlying policy decision, if available.
    /// </summary>
    public PolicyDecision? PolicyDecision { get; init; }
}

/// <summary>
/// Middleware for integrating the governance engine with the Microsoft Agent Framework.
/// Agents call <see cref="EvaluateToolCall"/> before executing any tool to enforce
/// governance policies and emit audit events.
/// </summary>
/// <remarks>
/// <b>Usage with Microsoft Agent Framework:</b>
/// <code>
/// var middleware = new GovernanceMiddleware(engine, emitter);
/// var result = middleware.EvaluateToolCall("did:mesh:abc123", "file_write", new() { ["path"] = "/etc/config" });
/// if (!result.Allowed)
/// {
///     // Block the tool call and log the reason.
///     logger.Warn(result.Reason);
///     return;
/// }
/// // Proceed with the tool call.
/// </code>
/// </remarks>
public sealed class GovernanceMiddleware
{
    private readonly PolicyEngine _policyEngine;
    private readonly AuditEmitter _auditEmitter;

    /// <summary>
    /// Initializes a new <see cref="GovernanceMiddleware"/> instance.
    /// </summary>
    /// <param name="policyEngine">The policy engine to evaluate requests against.</param>
    /// <param name="auditEmitter">The audit emitter for publishing governance events.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="policyEngine"/> or <paramref name="auditEmitter"/> is <c>null</c>.
    /// </exception>
    public GovernanceMiddleware(PolicyEngine policyEngine, AuditEmitter auditEmitter)
    {
        ArgumentNullException.ThrowIfNull(policyEngine);
        ArgumentNullException.ThrowIfNull(auditEmitter);

        _policyEngine = policyEngine;
        _auditEmitter = auditEmitter;
    }

    /// <summary>
    /// Evaluates whether a tool call is permitted under the current governance policies.
    /// Emits the appropriate audit events.
    /// </summary>
    /// <param name="agentId">The DID of the agent requesting the tool call.</param>
    /// <param name="toolName">The name of the tool being called (e.g., "file_write", "http_request").</param>
    /// <param name="arguments">Optional arguments to the tool call, exposed to policy conditions.</param>
    /// <returns>A <see cref="ToolCallResult"/> indicating whether the call is allowed and why.</returns>
    public ToolCallResult EvaluateToolCall(
        string agentId,
        string toolName,
        Dictionary<string, object>? arguments = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);
        ArgumentException.ThrowIfNullOrWhiteSpace(toolName);

        // Build the evaluation context from the tool call parameters.
        var context = BuildContext(agentId, toolName, arguments);

        // Generate a session ID for correlating audit events.
        var sessionId = $"session-{Guid.NewGuid():N}"[..24];

        // Evaluate against the policy engine.
        var decision = _policyEngine.Evaluate(agentId, context);

        // Determine event type based on the decision.
        var eventType = decision.Allowed
            ? GovernanceEventType.PolicyCheck
            : GovernanceEventType.ToolCallBlocked;

        // Build the audit event.
        var auditEvent = new GovernanceEvent
        {
            Type = eventType,
            AgentId = agentId,
            SessionId = sessionId,
            PolicyName = decision.MatchedRule,
            Data = new Dictionary<string, object>
            {
                ["tool_name"] = toolName,
                ["allowed"] = decision.Allowed,
                ["action"] = decision.Action,
                ["reason"] = decision.Reason,
                ["evaluation_ms"] = decision.EvaluationMs
            }
        };

        // Add arguments to audit data if present.
        if (arguments is not null)
        {
            auditEvent.Data["arguments"] = arguments;
        }

        // Emit the audit event.
        _auditEmitter.Emit(auditEvent);

        // If denied, also emit a PolicyViolation event.
        if (!decision.Allowed)
        {
            _auditEmitter.Emit(
                GovernanceEventType.PolicyViolation,
                agentId,
                sessionId,
                new Dictionary<string, object>
                {
                    ["tool_name"] = toolName,
                    ["matched_rule"] = decision.MatchedRule ?? "(default deny)",
                    ["reason"] = decision.Reason
                },
                decision.MatchedRule);
        }

        return new ToolCallResult
        {
            Allowed = decision.Allowed,
            Reason = decision.Reason,
            AuditEntry = auditEvent,
            PolicyDecision = decision
        };
    }

    /// <summary>
    /// Builds the evaluation context dictionary from tool call parameters.
    /// The context includes the tool name, agent ID, and any additional arguments
    /// so that policy conditions can reference them.
    /// </summary>
    private static Dictionary<string, object> BuildContext(
        string agentId,
        string toolName,
        Dictionary<string, object>? arguments)
    {
        var context = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
        {
            ["tool_name"] = toolName,
            ["agent_did"] = agentId
        };

        // Merge arguments into the context so policy conditions can reference them directly.
        if (arguments is not null)
        {
            foreach (var (key, value) in arguments)
            {
                context.TryAdd(key, value);
            }
        }

        return context;
    }
}
