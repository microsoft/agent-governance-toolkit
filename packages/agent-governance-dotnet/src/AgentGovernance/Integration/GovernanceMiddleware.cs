// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Audit;
using AgentGovernance.Hypervisor;
using AgentGovernance.Policy;
using AgentGovernance.RateLimiting;
using AgentGovernance.Security;
using AgentGovernance.Telemetry;

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
    private Dictionary<string, PolicyRule>? _ruleLookupCache;
    private int _cachedPolicyCount = -1;
    private readonly RateLimiter? _rateLimiter;
    private readonly GovernanceMetrics? _metrics;
    private readonly RingEnforcer? _ringEnforcer;
    private readonly PromptInjectionDetector? _injectionDetector;

    /// <summary>
    /// Initializes a new <see cref="GovernanceMiddleware"/> instance.
    /// </summary>
    /// <param name="policyEngine">The policy engine to evaluate requests against.</param>
    /// <param name="auditEmitter">The audit emitter for publishing governance events.</param>
    /// <param name="rateLimiter">Optional rate limiter for enforcing rate-limit policies.</param>
    /// <param name="metrics">Optional metrics collector for OpenTelemetry export.</param>
    /// <param name="ringEnforcer">Optional execution ring enforcer for privilege-based access control.</param>
    /// <param name="injectionDetector">Optional prompt injection detector for scanning tool call arguments.</param>
    public GovernanceMiddleware(
        PolicyEngine policyEngine,
        AuditEmitter auditEmitter,
        RateLimiter? rateLimiter = null,
        GovernanceMetrics? metrics = null,
        RingEnforcer? ringEnforcer = null,
        PromptInjectionDetector? injectionDetector = null)
    {
        ArgumentNullException.ThrowIfNull(policyEngine);
        ArgumentNullException.ThrowIfNull(auditEmitter);

        _policyEngine = policyEngine;
        _auditEmitter = auditEmitter;
        _rateLimiter = rateLimiter;
        _metrics = metrics;
        _ringEnforcer = ringEnforcer;
        _injectionDetector = injectionDetector;
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

        // Prompt injection pre-check: scan argument values for injection patterns.
        if (_injectionDetector is not null && arguments is not null)
        {
            foreach (var (key, value) in arguments)
            {
                if (value is string strValue && !string.IsNullOrWhiteSpace(strValue))
                {
                    var detection = _injectionDetector.Detect(strValue);
                    if (detection.IsInjection)
                    {
                        var injectionEvent = new GovernanceEvent
                        {
                            Type = GovernanceEventType.ToolCallBlocked,
                            AgentId = agentId,
                            SessionId = sessionId,
                            Data = new Dictionary<string, object>
                            {
                                ["tool_name"] = toolName,
                                ["allowed"] = false,
                                ["action"] = "deny",
                                ["reason"] = $"Prompt injection detected in argument '{key}': {detection.InjectionType} ({detection.ThreatLevel})",
                                ["injection_type"] = detection.InjectionType.ToString(),
                                ["threat_level"] = detection.ThreatLevel.ToString()
                            }
                        };
                        _auditEmitter.Emit(injectionEvent);
                        _metrics?.RecordDecision(false, agentId, toolName, 0, false);

                        return new ToolCallResult
                        {
                            Allowed = false,
                            Reason = $"Prompt injection detected in argument '{key}': {detection.InjectionType}",
                            AuditEntry = injectionEvent
                        };
                    }
                }
            }
        }

        // Evaluate against the policy engine.
        var decision = _policyEngine.Evaluate(agentId, context);

        // Enforce rate limiting if the decision indicates a rate-limit policy.
        if (decision.RateLimited && decision.MatchedRule is not null)
        {
            if (_rateLimiter is not null)
            {
                // Find the matching rule to get the limit expression.
                var rule = FindMatchingRule(decision.MatchedRule);
                if (rule?.Limit is not null)
                {
                    var (maxCalls, window) = RateLimiter.ParseLimit(rule.Limit);
                    var rateLimitKey = $"{agentId}:{toolName}";
                    if (_rateLimiter.TryAcquire(rateLimitKey, maxCalls, window))
                    {
                        // Under the rate limit — allow the request.
                        decision = new PolicyDecision
                        {
                            Allowed = true,
                            Action = "rate_limit",
                            MatchedRule = decision.MatchedRule,
                            Reason = $"Allowed within rate limit: {rule.Limit} for tool '{toolName}'.",
                            RateLimited = true,
                            EvaluationMs = decision.EvaluationMs
                        };
                    }
                    else
                    {
                        decision = new PolicyDecision
                        {
                            Allowed = false,
                            Action = "rate_limited",
                            MatchedRule = decision.MatchedRule,
                            Reason = $"Rate limit exceeded: {rule.Limit} for tool '{toolName}'.",
                            RateLimited = true,
                            EvaluationMs = decision.EvaluationMs
                        };
                    }
                }
            }
            else
            {
                // No rate limiter configured — allow the request (lenient fallback).
                decision = new PolicyDecision
                {
                    Allowed = true,
                    Action = "rate_limit",
                    MatchedRule = decision.MatchedRule,
                    Reason = "Rate limit rule matched but no rate limiter configured; allowing by default.",
                    RateLimited = false,
                    EvaluationMs = decision.EvaluationMs
                };
            }
        }

        // Record metrics.
        _metrics?.RecordDecision(decision.Allowed, agentId, toolName, decision.EvaluationMs, decision.RateLimited);

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

    /// <summary>
    /// Searches loaded policies for a rule by name using a cached lookup.
    /// Cache is invalidated when the policy count changes.
    /// </summary>
    private PolicyRule? FindMatchingRule(string ruleName)
    {
        var policies = _policyEngine.ListPolicies();
        var currentCount = policies.Count;

        if (_ruleLookupCache is null || _cachedPolicyCount != currentCount)
        {
            var cache = new Dictionary<string, PolicyRule>(StringComparer.Ordinal);
            foreach (var policy in policies)
            {
                foreach (var rule in policy.Rules)
                {
                    cache.TryAdd(rule.Name, rule);
                }
            }
            _ruleLookupCache = cache;
            _cachedPolicyCount = currentCount;
        }

        return _ruleLookupCache.TryGetValue(ruleName, out var cached) ? cached : null;
    }
}
