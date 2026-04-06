// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using AgentGovernance.Audit;
using AgentGovernance.Integration;
using AgentGovernance.Mcp.Abstractions;
using AgentGovernance.Policy;
using AgentGovernance.RateLimiting;
using AgentGovernance.Telemetry;
using Microsoft.Extensions.Logging;

namespace AgentGovernance.Mcp;

/// <summary>
/// MCP governance gateway that intercepts tool calls through a 5-stage pipeline:
/// <list type="number">
///   <item><b>Deny-list</b> — Immediately block tools on the deny list.</item>
///   <item><b>Allow-list</b> — If an allow-list is configured, only permit listed tools.</item>
///   <item><b>Parameter sanitization</b> — Scan parameters for dangerous patterns (PII, shell injection).</item>
///   <item><b>Rate limiting</b> — Enforce per-agent call budgets.</item>
///   <item><b>Human approval</b> — Route sensitive tool calls through human-in-the-loop review.</item>
/// </list>
/// <para>
/// The gateway is <b>fail-closed</b>: any exception during pipeline evaluation results in denial.
/// Integrates with the existing <see cref="GovernanceKernel"/> policy engine and rate limiter.
/// </para>
/// </summary>
/// <remarks>
/// Ported from the Python <c>MCPGateway</c> in <c>agent_os/mcp_gateway.py</c>.
/// </remarks>
public sealed class McpGateway
{
    private readonly GovernanceKernel _kernel;
    private readonly HashSet<string> _deniedTools;
    private readonly HashSet<string> _allowedTools;
    private readonly HashSet<string> _sensitiveTools;
    private readonly bool _enableBuiltinSanitization;
    private readonly Func<string, string, Dictionary<string, object>, ApprovalStatus>? _approvalCallback;
    private readonly bool _requireHumanApproval;
    private readonly bool _enableCredentialRedaction;
    private readonly IMcpAuditSink _auditSink;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Maximum tool calls per agent before rate-limiting kicks in.
    /// Set to <c>0</c> or negative to disable budget-based rate limiting
    /// (the kernel's policy-based rate limiter still applies).
    /// When a <see cref="RateLimiter"/> is configured, this value is informational only —
    /// the limiter's <see cref="McpSlidingRateLimiter.MaxCallsPerWindow"/> controls the actual limit.
    /// </summary>
    public int MaxToolCallsPerAgent { get; init; } = 1000;

    /// <summary>
    /// Optional sliding-window rate limiter. When set, replaces the simple counter-based
    /// budget with a proper sliding window that automatically expires old calls.
    /// </summary>
    public McpSlidingRateLimiter? RateLimiter { get; set; }

    /// <summary>
    /// Optional <see cref="GovernanceMetrics"/> instance for recording
    /// telemetry from the MCP gateway pipeline.
    /// </summary>
    public GovernanceMetrics? Metrics { get; set; }

    /// <summary>
    /// Optional logger for recording gateway decisions and errors.
    /// When <c>null</c>, no logging occurs — the gateway operates silently.
    /// </summary>
    public ILogger<McpGateway>? Logger { get; set; }

    /// <summary>
    /// Initializes a new <see cref="McpGateway"/>.
    /// </summary>
    /// <param name="kernel">
    /// The <see cref="GovernanceKernel"/> whose policy engine and rate limiter will be used.
    /// </param>
    /// <param name="deniedTools">Tools that are always blocked, regardless of policy.</param>
    /// <param name="allowedTools">
    /// If non-empty, only these tools are permitted (allow-list mode).
    /// An empty or <c>null</c> list disables the allow-list filter.
    /// </param>
    /// <param name="sensitiveTools">Tools that require human approval even if policy allows them.</param>
    /// <param name="approvalCallback">
    /// Optional callback for human-in-the-loop approval.
    /// Signature: <c>(agentId, toolName, parameters) → ApprovalStatus</c>.
    /// </param>
    /// <param name="enableBuiltinSanitization">
    /// Whether to apply built-in dangerous-pattern sanitization (SSN, credit cards, shell injection).
    /// Defaults to <c>true</c>.
    /// </param>
    /// <param name="requireHumanApproval">
    /// When <c>true</c>, ALL tool calls require human approval (not just sensitive tools).
    /// Defaults to <c>false</c>.
    /// </param>
    /// <param name="enableCredentialRedaction">
    /// Whether to redact credentials before audit entries are stored.
    /// Defaults to <c>true</c>.
    /// </param>
    /// <param name="auditSink">The sink used to persist audit entries.</param>
    /// <param name="timeProvider">The clock used for audit timestamps.</param>
    public McpGateway(
        GovernanceKernel kernel,
        IEnumerable<string>? deniedTools = null,
        IEnumerable<string>? allowedTools = null,
        IEnumerable<string>? sensitiveTools = null,
        Func<string, string, Dictionary<string, object>, ApprovalStatus>? approvalCallback = null,
        bool enableBuiltinSanitization = true,
        bool requireHumanApproval = false,
        bool enableCredentialRedaction = true,
        IMcpAuditSink? auditSink = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(kernel);

        _kernel = kernel;
        _deniedTools = deniedTools is not null
            ? new HashSet<string>(deniedTools, StringComparer.OrdinalIgnoreCase)
            : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        _allowedTools = allowedTools is not null
            ? new HashSet<string>(allowedTools, StringComparer.OrdinalIgnoreCase)
            : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        _sensitiveTools = sensitiveTools is not null
            ? new HashSet<string>(sensitiveTools, StringComparer.OrdinalIgnoreCase)
            : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        _approvalCallback = approvalCallback;
        _enableBuiltinSanitization = enableBuiltinSanitization;
        _requireHumanApproval = requireHumanApproval;
        _enableCredentialRedaction = enableCredentialRedaction;
        _auditSink = auditSink ?? new InMemoryMcpAuditSink();
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Intercepts an MCP tool call and runs it through the 5-stage governance pipeline.
    /// </summary>
    /// <param name="agentId">The agent's DID.</param>
    /// <param name="toolName">Name of the MCP tool being called.</param>
    /// <param name="parameters">Parameters being passed to the tool.</param>
    /// <returns>
    /// A tuple of (allowed, reason). If <c>allowed</c> is <c>false</c>,
    /// the tool call should be blocked.
    /// </returns>
    public (bool Allowed, string Reason) InterceptToolCall(
        string agentId,
        string toolName,
        Dictionary<string, object> parameters)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);
        ArgumentException.ThrowIfNullOrWhiteSpace(toolName);
        parameters ??= new Dictionary<string, object>();

        var sw = Stopwatch.StartNew();
        Logger?.LogInformation("MCP tool call intercepted: {ToolName} by {AgentId}", toolName, agentId);

        try
        {
            var (allowed, reason, approvalStatus) = Evaluate(agentId, toolName, parameters);

            sw.Stop();
            var stage = DetermineStage(allowed, reason);
            var rateLimited = reason.Contains("exceeded call budget", StringComparison.OrdinalIgnoreCase)
                           || reason.Contains("rate limit", StringComparison.OrdinalIgnoreCase);
            Metrics?.RecordMcpDecision(allowed, agentId, toolName, sw.Elapsed.TotalMilliseconds, stage, rateLimited);

            if (allowed)
            {
                Logger?.LogInformation("MCP tool call allowed: {ToolName} for {AgentId}", toolName, agentId);
            }
            else
            {
                Logger?.LogWarning("MCP tool call denied: {ToolName} for {AgentId} - {Reason}", toolName, agentId, reason);
            }

            RecordAuditEntry(agentId, toolName, parameters, allowed, reason, approvalStatus);

            return (allowed, reason);
        }
        catch (Exception ex)
        {
            sw.Stop();
            Logger?.LogError(ex, "MCP gateway error for {ToolName} - failing closed", toolName);

            // Fail-closed: any exception → deny.
            var failReason = "Gateway error (fail-closed).";

            Metrics?.RecordMcpDecision(false, agentId, toolName, sw.Elapsed.TotalMilliseconds, "error");

            try
            {
                RecordAuditEntry(agentId, toolName, parameters, false, failReason, null);
            }
            catch (Exception auditEx)
            {
                Logger?.LogError(auditEx, "MCP audit sink failure while recording a fail-closed decision");
            }

            return (false, failReason);
        }
    }

    /// <summary>
    /// Returns a defensive copy of the audit log.
    /// </summary>
    public IReadOnlyList<McpAuditEntry> AuditLog
    {
        get
        {
            return _auditSink is InMemoryMcpAuditSink inMemoryAuditSink
                ? inMemoryAuditSink.GetSnapshot()
                : Array.Empty<McpAuditEntry>();
        }
    }

    /// <summary>
    /// Returns the current call count for an agent.
    /// When a sliding window <see cref="RateLimiter"/> is configured,
    /// returns the count of calls within the current window.
    /// </summary>
    public int GetAgentCallCount(string agentId)
    {
        if (RateLimiter is not null)
        {
            return RateLimiter.GetCallCount(agentId);
        }

        return 0;
    }

    /// <summary>
    /// Resets the call budget for a specific agent.
    /// </summary>
    public void ResetAgentBudget(string agentId)
    {
        if (RateLimiter is not null)
        {
            RateLimiter.Reset(agentId);
        }
    }

    /// <summary>
    /// Resets call budgets for all agents.
    /// </summary>
    public void ResetAllBudgets()
    {
        if (RateLimiter is not null)
        {
            RateLimiter.ResetAll();
        }
    }

    // ── 5-Stage Pipeline ─────────────────────────────────────────────────

    private (bool Allowed, string Reason, ApprovalStatus? Status) Evaluate(
        string agentId,
        string toolName,
        Dictionary<string, object> parameters)
    {
        // Stage 1: Deny-list check
        if (_deniedTools.Contains(toolName))
        {
            return (false, $"Tool '{toolName}' is on the deny list", null);
        }

        // Stage 2: Allow-list check (empty allow-list = all tools allowed)
        if (_allowedTools.Count > 0 && !_allowedTools.Contains(toolName))
        {
            return (false, $"Tool '{toolName}' is not on the allow list", null);
        }

        // Stage 3: Parameter sanitization
        var sanitizationResult = SanitizeParameters(parameters);
        if (!sanitizationResult.Clean)
        {
            return (false, $"Parameters matched dangerous pattern: {sanitizationResult.MatchedPattern}", null);
        }

        // Also evaluate through the kernel's policy engine for policy-based blocking.
        var policyResult = _kernel.EvaluateToolCall(agentId, toolName, parameters);
        if (!policyResult.Allowed)
        {
            return (false, policyResult.Reason, null);
        }

        // Stage 4: Rate limiting (sliding window or disabled)
        if (RateLimiter is not null)
        {
            // Peek — don't consume a permit yet (we may need human approval first).
            var remaining = RateLimiter.GetRemainingBudget(agentId);
            if (remaining <= 0)
            {
                return (false, $"Agent '{agentId}' exceeded call budget ({RateLimiter.MaxCallsPerWindow}/{RateLimiter.MaxCallsPerWindow})", null);
            }
        }

        // Stage 5: Human approval
        if (_requireHumanApproval || _sensitiveTools.Contains(toolName))
        {
            var approvalResult = EvaluateHumanApproval(agentId, toolName, parameters);
            // Only consume a rate-limit permit on approved calls
            if (approvalResult.Allowed && RateLimiter is not null)
            {
                if (!RateLimiter.TryAcquire(agentId))
                {
                    // Race: another thread consumed the last permit between check and acquire.
                    return (false, $"Agent '{agentId}' exceeded call budget ({RateLimiter.MaxCallsPerWindow}/{RateLimiter.MaxCallsPerWindow})", null);
                }
            }
            return approvalResult;
        }

        // Consume a rate-limit permit for calls that are allowed without human approval
        if (RateLimiter is not null)
        {
            if (!RateLimiter.TryAcquire(agentId))
            {
                return (false, $"Agent '{agentId}' exceeded call budget ({RateLimiter.MaxCallsPerWindow}/{RateLimiter.MaxCallsPerWindow})", null);
            }
        }

        return (true, "Allowed by policy", null);
    }

    private (bool Allowed, string Reason, ApprovalStatus? Status) EvaluateHumanApproval(
        string agentId,
        string toolName,
        Dictionary<string, object> parameters)
    {
        if (_approvalCallback is null)
        {
            return (false, "Awaiting human approval", ApprovalStatus.Pending);
        }

        try
        {
            var status = _approvalCallback(agentId, toolName, parameters);

            return status switch
            {
                ApprovalStatus.Approved => (true, "Approved by human reviewer", ApprovalStatus.Approved),
                ApprovalStatus.Denied => (false, "Human approval denied", ApprovalStatus.Denied),
                ApprovalStatus.Pending => (false, "Awaiting human approval", ApprovalStatus.Pending),
                _ => (false, "Unknown approval status — fail-closed", null)
            };
        }
        catch
        {
            // Fail-closed: approval callback error → deny.
            return (false, "Approval callback error — fail-closed", ApprovalStatus.Denied);
        }
    }

    private static string DetermineStage(bool allowed, string reason)
    {
        if (allowed)
            return "allowed";
        if (reason.Contains("deny list", StringComparison.OrdinalIgnoreCase))
            return "deny_list";
        if (reason.Contains("allow list", StringComparison.OrdinalIgnoreCase))
            return "allow_list";
        if (reason.Contains("dangerous pattern", StringComparison.OrdinalIgnoreCase)
            || reason.Contains("sanitiz", StringComparison.OrdinalIgnoreCase))
            return "sanitization";
        if (reason.Contains("exceeded call budget", StringComparison.OrdinalIgnoreCase)
            || reason.Contains("rate limit", StringComparison.OrdinalIgnoreCase))
            return "rate_limit";
        if (reason.Contains("approval", StringComparison.OrdinalIgnoreCase))
            return "approval";
        return "policy";
    }

    private static (bool Clean, string? MatchedPattern) SanitizeParameters(Dictionary<string, object> parameters)
    {
        if (parameters.Count == 0)
            return (true, null);

        string paramText;
        try
        {
            paramText = JsonSerializer.Serialize(parameters);
        }
        catch
        {
            paramText = string.Join(" ", parameters.Values.Select(v => v?.ToString() ?? string.Empty));
        }

        foreach (var (pattern, name) in SanitizationDefaults.AllPatterns)
        {
            try
            {
                if (pattern.IsMatch(paramText))
                {
                    return (false, name);
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // Fail-closed: regex timeout → deny.
                return (false, $"{name} (regex timeout)");
            }
        }

        return (true, null);
    }

    private void RecordAuditEntry(
        string agentId,
        string toolName,
        Dictionary<string, object> parameters,
        bool allowed,
        string reason,
        ApprovalStatus? approvalStatus)
    {
        var auditParameters = _enableCredentialRedaction
            ? CredentialRedactor.RedactDictionary(parameters)
            : new Dictionary<string, object>(parameters);

        _auditSink.RecordAsync(new McpAuditEntry
        {
            Timestamp = _timeProvider.GetUtcNow(),
            AgentId = agentId,
            ToolName = toolName,
            Parameters = auditParameters,
            Allowed = allowed,
            Reason = reason,
            ApprovalStatus = approvalStatus
        }).GetAwaiter().GetResult();
    }
}

/// <summary>
/// A single audit entry recorded by the <see cref="McpGateway"/>.
/// </summary>
public sealed class McpAuditEntry
{
    /// <summary>When the evaluation occurred.</summary>
    public DateTimeOffset Timestamp { get; init; }

    /// <summary>The agent's DID.</summary>
    public required string AgentId { get; init; }

    /// <summary>The tool that was called.</summary>
    public required string ToolName { get; init; }

    /// <summary>Parameters passed to the tool.</summary>
    public Dictionary<string, object> Parameters { get; init; } = new();

    /// <summary>Whether the call was allowed.</summary>
    public bool Allowed { get; init; }

    /// <summary>Reason for the decision.</summary>
    public required string Reason { get; init; }

    /// <summary>Human approval status, if applicable.</summary>
    public ApprovalStatus? ApprovalStatus { get; init; }
}
