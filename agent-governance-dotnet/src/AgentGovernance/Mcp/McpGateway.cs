// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

namespace AgentGovernance.Mcp;

/// <summary>
/// Gateway terminal status.
/// </summary>
public enum McpGatewayStatus
{
    /// <summary>Request is allowed to proceed.</summary>
    Allowed,
    /// <summary>Request was denied by policy.</summary>
    Denied,
    /// <summary>Request was rate-limited.</summary>
    RateLimited,
    /// <summary>Request requires human approval before proceeding.</summary>
    RequiresApproval
}

/// <summary>
/// Configuration for the MCP gateway.
/// </summary>
public sealed class McpGatewayConfig
{
    /// <summary>Tool names (or prefix patterns ending with *) that are always denied.</summary>
    public List<string> DenyList { get; init; } = [];

    /// <summary>
    /// Tool names (or prefix patterns ending with *) that are allowed.
    /// If non-empty, only tools matching this list are permitted.
    /// </summary>
    public List<string> AllowList { get; init; } = [];

    /// <summary>Tool names that require human approval before execution.</summary>
    public List<string> ApprovalRequiredTools { get; init; } = [];

    /// <summary>When true, approval-required tools are auto-approved.</summary>
    public bool AutoApprove { get; init; }

    /// <summary>When true, requests with suspicious payload findings are blocked.</summary>
    public bool BlockOnSuspiciousPayload { get; init; } = true;
}

/// <summary>
/// An MCP request to be evaluated by the gateway.
/// </summary>
public sealed class McpGatewayRequest
{
    /// <summary>Agent identifier (DID or other identifier).</summary>
    public required string AgentId { get; init; }

    /// <summary>Name of the tool being invoked.</summary>
    public required string ToolName { get; init; }

    /// <summary>Request payload as a text string (e.g., serialized JSON).</summary>
    public required string Payload { get; init; }
}

/// <summary>
/// Decision produced by the MCP gateway pipeline.
/// </summary>
public sealed class McpGatewayDecision
{
    /// <summary>Terminal status of the gateway decision.</summary>
    public required McpGatewayStatus Status { get; init; }

    /// <summary>Whether the request is allowed to proceed.</summary>
    public bool Allowed => Status == McpGatewayStatus.Allowed;

    /// <summary>Sanitized payload (credentials and threats neutralized).</summary>
    public required string SanitizedPayload { get; init; }

    /// <summary>Findings from payload sanitization.</summary>
    public required IReadOnlyList<McpResponseFinding> Findings { get; init; }

    /// <summary>Seconds until the rate limit resets (0 if not rate-limited).</summary>
    public int RetryAfterSeconds { get; init; }
}

/// <summary>
/// Gateway pipeline for governed MCP traffic.
/// Enforces deny-list → allow-list → payload sanitization → rate limiting → human approval.
/// Thread-safe.
/// </summary>
public sealed class McpGateway
{
    private readonly McpGatewayConfig _config;
    private readonly McpResponseSanitizer _sanitizer;
    private readonly RateLimiting.RateLimiter _rateLimiter;
    private readonly int _maxCallsPerMinute;

    /// <summary>
    /// Creates a new gateway with the specified configuration.
    /// </summary>
    /// <param name="config">Gateway configuration (deny/allow lists, approval tools).</param>
    /// <param name="sanitizer">Response sanitizer for payload inspection.</param>
    /// <param name="rateLimiter">Rate limiter for per-agent throttling.</param>
    /// <param name="maxCallsPerMinute">Maximum tool calls per agent per minute (default: 60).</param>
    public McpGateway(
        McpGatewayConfig config,
        McpResponseSanitizer? sanitizer = null,
        RateLimiting.RateLimiter? rateLimiter = null,
        int maxCallsPerMinute = 60)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _sanitizer = sanitizer ?? new McpResponseSanitizer();
        _rateLimiter = rateLimiter ?? new RateLimiting.RateLimiter();
        _maxCallsPerMinute = maxCallsPerMinute;
    }

    /// <summary>
    /// Evaluates an MCP request through the gateway pipeline.
    /// </summary>
    public McpGatewayDecision ProcessRequest(McpGatewayRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Sanitize payload
        var sanitized = _sanitizer.ScanText(request.Payload);

        // Deny list check
        if (MatchesAny(_config.DenyList, request.ToolName))
        {
            return MakeDecision(McpGatewayStatus.Denied, sanitized);
        }

        // Allow list check (if non-empty, tool must be in list)
        if (_config.AllowList.Count > 0 && !MatchesAny(_config.AllowList, request.ToolName))
        {
            return MakeDecision(McpGatewayStatus.Denied, sanitized);
        }

        // Block on suspicious payload
        if (_config.BlockOnSuspiciousPayload && sanitized.Findings.Count > 0)
        {
            return MakeDecision(McpGatewayStatus.Denied, sanitized);
        }

        // Rate limiting
        var rateLimitKey = $"{request.AgentId}:{request.ToolName}";
        if (!_rateLimiter.TryAcquire(rateLimitKey, _maxCallsPerMinute, TimeSpan.FromMinutes(1)))
        {
            return new McpGatewayDecision
            {
                Status = McpGatewayStatus.RateLimited,
                SanitizedPayload = sanitized.Sanitized,
                Findings = sanitized.Findings,
                RetryAfterSeconds = 60
            };
        }

        // Human approval check
        if (MatchesAny(_config.ApprovalRequiredTools, request.ToolName) && !_config.AutoApprove)
        {
            return MakeDecision(McpGatewayStatus.RequiresApproval, sanitized);
        }

        return MakeDecision(McpGatewayStatus.Allowed, sanitized);
    }

    private static McpGatewayDecision MakeDecision(McpGatewayStatus status, McpSanitizedResponse sanitized)
    {
        return new McpGatewayDecision
        {
            Status = status,
            SanitizedPayload = sanitized.Sanitized,
            Findings = sanitized.Findings
        };
    }

    private static bool MatchesAny(List<string> rules, string value)
    {
        return rules.Any(rule => MatchesRule(rule, value));
    }

    private static bool MatchesRule(string rule, string value)
    {
        if (rule.EndsWith('*'))
            return value.StartsWith(rule[..^1], StringComparison.Ordinal);
        return string.Equals(rule, value, StringComparison.Ordinal);
    }
}
