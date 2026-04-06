// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Mcp;
using AgentGovernance.Mcp.Abstractions;
using AgentGovernance.Telemetry;
using Microsoft.Extensions.Logging;

namespace AgentGovernance.Extensions;

/// <summary>
/// Configuration options for MCP governance integration.
/// </summary>
public sealed class McpGovernanceOptions
{
    /// <summary>
    /// Tools that are always blocked, regardless of policy.
    /// </summary>
    public List<string> DeniedTools { get; init; } = new();

    /// <summary>
    /// If non-empty, only these tools are permitted (allow-list mode).
    /// An empty list disables the allow-list filter.
    /// </summary>
    public List<string> AllowedTools { get; init; } = new();

    /// <summary>
    /// Tools that require human approval even if policy allows them.
    /// </summary>
    public List<string> SensitiveTools { get; init; } = new();

    /// <summary>
    /// Whether to apply built-in dangerous-pattern sanitization
    /// (SSN, credit cards, shell injection). Defaults to <c>true</c>.
    /// </summary>
    public bool EnableBuiltinSanitization { get; set; } = true;

    /// <summary>
    /// When <c>true</c>, all tool calls require human approval.
    /// Defaults to <c>false</c>.
    /// </summary>
    public bool RequireHumanApproval { get; set; } = false;

    /// <summary>
    /// Maximum tool calls per agent before budget-based rate limiting kicks in.
    /// Set to <c>0</c> or negative to disable. Defaults to <c>1000</c>.
    /// </summary>
    public int MaxToolCallsPerAgent { get; set; } = 1000;

    /// <summary>
    /// Optional custom tool-to-action-type mappings, merged on top of defaults.
    /// </summary>
    public Dictionary<string, ActionType>? CustomToolMappings { get; init; }

    /// <summary>
    /// Optional callback for human-in-the-loop approval.
    /// Signature: <c>(agentId, toolName, parameters) → ApprovalStatus</c>.
    /// </summary>
    public Func<string, string, Dictionary<string, object>, ApprovalStatus>? ApprovalCallback { get; init; }

    /// <summary>
    /// Whether to enable response scanning on tool outputs (§5/§12).
    /// Defaults to <c>true</c>.
    /// </summary>
    public bool EnableResponseScanning { get; set; } = true;

    /// <summary>
    /// Whether to enable credential redaction in audit logs (§10).
    /// Defaults to <c>true</c>.
    /// </summary>
    public bool EnableCredentialRedaction { get; set; } = true;

    /// <summary>
    /// Session TTL for the <see cref="McpSessionAuthenticator"/> (§6).
    /// Defaults to 1 hour. Set to <c>null</c> to disable session authentication.
    /// </summary>
    public TimeSpan? SessionTtl { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Maximum concurrent sessions per agent (§6). Defaults to 10.
    /// </summary>
    public int MaxSessionsPerAgent { get; set; } = 10;

    /// <summary>
    /// Shared secret for HMAC-SHA256 message signing (§7).
    /// When <c>null</c>, message signing is disabled.
    /// </summary>
    public byte[]? MessageSigningKey { get; set; }

    /// <summary>
    /// Replay window for message signing (§7). Defaults to 5 minutes.
    /// </summary>
    public TimeSpan MessageReplayWindow { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Duration of the sliding rate-limit window (§4).
    /// Calls older than this window are expired and no longer count against the budget.
    /// Defaults to 5 minutes.
    /// </summary>
    public TimeSpan RateLimitWindow { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The agent identity used for governance decisions in the official MCP SDK bridge.
    /// Defaults to <c>"did:mesh:default"</c>.
    /// </summary>
    public string AgentId { get; set; } = "did:mesh:default";
}

/// <summary>
/// Extension methods for registering MCP governance services.
/// Provides a <c>AddMcpGovernance</c> / <c>UseMcpGovernance</c> pattern
/// consistent with the existing SDK's DI conventions.
/// </summary>
/// <remarks>
/// <b>Usage:</b>
/// <code>
/// // Configure kernel with MCP governance
/// var (kernel, gateway, scanner, handler) = McpGovernanceExtensions.AddMcpGovernance(
///     kernelOptions: new GovernanceOptions
///     {
///         PolicyPaths = new() { "policies/default.yaml" }
///     },
///     mcpOptions: new McpGovernanceOptions
///     {
///         DeniedTools = new() { "rm_rf", "drop_database" },
///         SensitiveTools = new() { "send_email", "deploy_production" },
///         MaxToolCallsPerAgent = 500
///     },
///     agentId: "did:mesh:agent-001"
/// );
///
/// // Use the gateway to intercept tool calls
/// var (allowed, reason) = gateway.InterceptToolCall("did:mesh:agent-001", "file_read", args);
///
/// // Use the scanner to check tool definitions
/// var threats = scanner.ScanTool("file_read", "Read a file from disk", schema, "my-server");
///
/// // Use the handler for full JSON-RPC message routing
/// var response = handler.HandleMessage(jsonRpcMessage);
/// </code>
/// </remarks>
public static class McpGovernanceExtensions
{
    /// <summary>
    /// Creates and wires together a full MCP governance stack:
    /// <see cref="GovernanceKernel"/>, <see cref="McpGateway"/>,
    /// <see cref="McpSecurityScanner"/>, <see cref="McpMessageHandler"/>,
    /// <see cref="McpResponseScanner"/>, <see cref="McpSessionAuthenticator"/> (optional),
    /// and <see cref="McpMessageSigner"/> (optional).
    /// </summary>
    /// <param name="kernelOptions">
    /// Options for the <see cref="GovernanceKernel"/>. When <c>null</c>, uses defaults.
    /// </param>
    /// <param name="mcpOptions">
    /// Options for MCP-specific governance. When <c>null</c>, uses defaults.
    /// </param>
    /// <param name="agentId">
    /// Optional DID of the agent that will use the message handler.
    /// When <c>null</c>, uses <see cref="McpGovernanceOptions.AgentId"/>.
    /// </param>
    /// <param name="timeProvider">Optional clock used for MCP timestamps and expiry checks.</param>
    /// <param name="sessionStore">Optional session store for session authentication state.</param>
    /// <param name="nonceStore">Optional nonce store for replay protection state.</param>
    /// <param name="rateLimitStore">Optional rate-limit store for per-agent budget state.</param>
    /// <param name="auditSink">Optional audit sink for gateway audit entries.</param>
    /// <returns>
    /// A governance stack with all configured components.
    /// </returns>
    public static McpGovernanceStack AddMcpGovernance(
            GovernanceOptions? kernelOptions = null,
            McpGovernanceOptions? mcpOptions = null,
            string? agentId = null,
            TimeProvider? timeProvider = null,
            IMcpSessionStore? sessionStore = null,
            IMcpNonceStore? nonceStore = null,
            IMcpRateLimitStore? rateLimitStore = null,
            IMcpAuditSink? auditSink = null)
    {
        var opts = mcpOptions ?? new McpGovernanceOptions();
        var resolvedTimeProvider = timeProvider ?? TimeProvider.System;
        var resolvedSessionStore = sessionStore ?? new InMemoryMcpSessionStore();
        var resolvedNonceStore = nonceStore ?? new InMemoryMcpNonceStore();
        var resolvedRateLimitStore = rateLimitStore ?? new InMemoryMcpRateLimitStore();
        var resolvedAuditSink = auditSink ?? new InMemoryMcpAuditSink();
        var resolvedAgentId = agentId ?? opts.AgentId;

        var kernel = new GovernanceKernel(kernelOptions);

        var gateway = new McpGateway(
            kernel,
            deniedTools: opts.DeniedTools,
            allowedTools: opts.AllowedTools,
            sensitiveTools: opts.SensitiveTools,
            approvalCallback: opts.ApprovalCallback,
            enableCredentialRedaction: opts.EnableCredentialRedaction,
            enableBuiltinSanitization: opts.EnableBuiltinSanitization,
            requireHumanApproval: opts.RequireHumanApproval,
            auditSink: resolvedAuditSink,
            timeProvider: resolvedTimeProvider)
        {
            MaxToolCallsPerAgent = opts.MaxToolCallsPerAgent,
            RateLimiter = opts.MaxToolCallsPerAgent > 0
                ? new McpSlidingRateLimiter(resolvedRateLimitStore, resolvedTimeProvider)
                {
                    MaxCallsPerWindow = opts.MaxToolCallsPerAgent,
                    WindowSize = opts.RateLimitWindow
                }
                : null
        };

        var scanner = new McpSecurityScanner();

        var metrics = new GovernanceMetrics();
        gateway.Metrics = metrics;
        scanner.Metrics = metrics;

        var toolMapper = new McpToolMapper(opts.CustomToolMappings);

        var handler = new McpMessageHandler(gateway, toolMapper, resolvedAgentId);

        var responseScanner = opts.EnableResponseScanning ? new McpResponseScanner() : null;

        McpSessionAuthenticator? sessionAuth = null;
        if (opts.SessionTtl.HasValue)
        {
            sessionAuth = new McpSessionAuthenticator(resolvedSessionStore, resolvedTimeProvider)
            {
                SessionTtl = opts.SessionTtl.Value,
                MaxSessionsPerAgent = opts.MaxSessionsPerAgent
            };
        }

        McpMessageSigner? messageSigner = null;
        if (opts.MessageSigningKey is not null)
        {
            messageSigner = new McpMessageSigner(opts.MessageSigningKey, resolvedNonceStore, resolvedTimeProvider)
            {
                ReplayWindow = opts.MessageReplayWindow
            };
        }

        return new McpGovernanceStack
        {
            Kernel = kernel,
            Gateway = gateway,
            Scanner = scanner,
            Handler = handler,
            ResponseScanner = responseScanner,
            SessionAuthenticator = sessionAuth,
            MessageSigner = messageSigner,
            Metrics = metrics
        };
    }

    /// <summary>
    /// Convenience method that creates a gateway from an existing kernel.
    /// Use when you already have a <see cref="GovernanceKernel"/> and just
    /// need to add MCP gateway capabilities.
    /// </summary>
    /// <param name="kernel">An existing governance kernel.</param>
    /// <param name="mcpOptions">
    /// Options for MCP-specific governance. When <c>null</c>, uses defaults.
    /// </param>
    /// <param name="timeProvider">Optional clock used for MCP timestamps and expiry checks.</param>
    /// <param name="rateLimitStore">Optional rate-limit store for per-agent budget state.</param>
    /// <param name="auditSink">Optional audit sink for gateway audit entries.</param>
    /// <returns>A configured <see cref="McpGateway"/>.</returns>
    public static McpGateway UseMcpGovernance(
        GovernanceKernel kernel,
        McpGovernanceOptions? mcpOptions = null,
        TimeProvider? timeProvider = null,
        IMcpRateLimitStore? rateLimitStore = null,
        IMcpAuditSink? auditSink = null)
    {
        ArgumentNullException.ThrowIfNull(kernel);
        var opts = mcpOptions ?? new McpGovernanceOptions();
        var resolvedTimeProvider = timeProvider ?? TimeProvider.System;
        var resolvedRateLimitStore = rateLimitStore ?? new InMemoryMcpRateLimitStore();
        var resolvedAuditSink = auditSink ?? new InMemoryMcpAuditSink();

        return new McpGateway(
            kernel,
            deniedTools: opts.DeniedTools,
            allowedTools: opts.AllowedTools,
            sensitiveTools: opts.SensitiveTools,
            approvalCallback: opts.ApprovalCallback,
            enableCredentialRedaction: opts.EnableCredentialRedaction,
            enableBuiltinSanitization: opts.EnableBuiltinSanitization,
            requireHumanApproval: opts.RequireHumanApproval,
            auditSink: resolvedAuditSink,
            timeProvider: resolvedTimeProvider)
        {
            MaxToolCallsPerAgent = opts.MaxToolCallsPerAgent,
            RateLimiter = opts.MaxToolCallsPerAgent > 0
                ? new McpSlidingRateLimiter(resolvedRateLimitStore, resolvedTimeProvider)
                {
                    MaxCallsPerWindow = opts.MaxToolCallsPerAgent,
                    WindowSize = opts.RateLimitWindow
                }
                : null
        };
    }
}

/// <summary>
/// Contains all components of a fully wired MCP governance stack.
/// </summary>
public sealed class McpGovernanceStack
{
    /// <summary>The governance kernel (policy engine, rate limiter, audit).</summary>
    public required GovernanceKernel Kernel { get; init; }

    /// <summary>The 5-stage MCP gateway pipeline.</summary>
    public required McpGateway Gateway { get; init; }

    /// <summary>The tool definition security scanner.</summary>
    public required McpSecurityScanner Scanner { get; init; }

    /// <summary>The JSON-RPC message handler.</summary>
    public required McpMessageHandler Handler { get; init; }

    /// <summary>Response scanner for output validation (§5/§12). Null if disabled.</summary>
    public McpResponseScanner? ResponseScanner { get; init; }

    /// <summary>Session authenticator for agent identity binding (§6). Null if disabled.</summary>
    public McpSessionAuthenticator? SessionAuthenticator { get; init; }

    /// <summary>Message signer for integrity and replay protection (§7). Null if disabled.</summary>
    public McpMessageSigner? MessageSigner { get; init; }

    /// <summary>Shared <see cref="GovernanceMetrics"/> instance used by the gateway and scanner.</summary>
    public GovernanceMetrics? Metrics { get; init; }

    /// <summary>
    /// Optional <see cref="ILoggerFactory"/> for wiring loggers to individual components.
    /// When set, the stack propagates loggers to all components that support them.
    /// </summary>
    public ILoggerFactory? LoggerFactory
    {
        set
        {
            if (value is null) return;
            Gateway.Logger = value.CreateLogger<McpGateway>();
            Scanner.Logger = value.CreateLogger<McpSecurityScanner>();
            Handler.Logger = value.CreateLogger<McpMessageHandler>();
            if (ResponseScanner is not null)
                ResponseScanner.Logger = value.CreateLogger<McpResponseScanner>();
            if (SessionAuthenticator is not null)
                SessionAuthenticator.Logger = value.CreateLogger<McpSessionAuthenticator>();
            if (MessageSigner is not null)
                MessageSigner.Logger = value.CreateLogger<McpMessageSigner>();
            if (Gateway.RateLimiter is not null)
                Gateway.RateLimiter.Logger = value.CreateLogger<McpSlidingRateLimiter>();
            CredentialRedactor.Logger = value.CreateLogger("AgentGovernance.Mcp.CredentialRedactor");
        }
    }

    /// <summary>
    /// Deconstructs into the original 4-component tuple for backward compatibility.
    /// </summary>
    public void Deconstruct(
        out GovernanceKernel kernel,
        out McpGateway gateway,
        out McpSecurityScanner scanner,
        out McpMessageHandler handler)
    {
        kernel = Kernel;
        gateway = Gateway;
        scanner = Scanner;
        handler = Handler;
    }
}

/// <summary>
/// Recommended default tool lists for MCP governance, aligned with OWASP guidance.
/// Use these as a starting point — merge with your own lists as needed.
/// </summary>
/// <example>
/// <code>
/// var options = new McpGovernanceOptions
/// {
///     DeniedTools = McpGovernanceDefaults.DeniedTools.ToList(),
///     SensitiveTools = McpGovernanceDefaults.SensitiveTools.ToList()
/// };
/// </code>
/// </example>
public static class McpGovernanceDefaults
{
    /// <summary>
    /// Tools that should be blocked by default — destructive, irreversible, or
    /// high-risk operations that agents should never invoke without explicit override.
    /// </summary>
    public static IReadOnlyList<string> DeniedTools { get; } = new[]
    {
        // Filesystem destructive
        "rm_rf", "delete_recursive", "format_disk", "wipe_volume",
        // Database destructive
        "drop_database", "drop_table", "truncate_table",
        // Shell/process
        "exec_shell", "exec_command", "spawn_process", "run_arbitrary",
        // Credential/secret access
        "get_secrets", "export_credentials", "dump_env",
        // Network exfiltration
        "upload_file_external", "send_to_webhook",
    };

    /// <summary>
    /// Tools that should require human-in-the-loop approval — high-impact
    /// operations that are legitimate but need a human to confirm intent.
    /// </summary>
    public static IReadOnlyList<string> SensitiveTools { get; } = new[]
    {
        // Communication
        "send_email", "send_message", "post_to_channel",
        // Deployment
        "deploy_production", "deploy_staging", "rollback_deployment",
        // Data modification
        "write_file", "update_record", "delete_record",
        // Infrastructure
        "create_resource", "delete_resource", "modify_permissions",
        // Financial
        "submit_payment", "approve_expense", "transfer_funds",
    };
}
