// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Security.Claims;
using AgentGovernance.Hypervisor;
using AgentGovernance.Policy;
using AgentGovernance.Security;
using AgentGovernance.Sre;

namespace AgentGovernance.Extensions.ModelContextProtocol;

/// <summary>
/// Configures governance behavior for Model Context Protocol servers.
/// </summary>
public sealed class McpGovernanceOptions
{
    /// <summary>
    /// Gets the YAML policy files loaded into the governance kernel.
    /// </summary>
    public List<string> PolicyPaths { get; } = [];

    /// <summary>
    /// Gets or sets the conflict resolution strategy for policy evaluation.
    /// </summary>
    public ConflictResolutionStrategy ConflictStrategy { get; set; } = ConflictResolutionStrategy.PriorityFirstMatch;

    /// <summary>
    /// Gets or sets a value indicating whether audit emission is enabled.
    /// </summary>
    public bool EnableAudit { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether metrics are enabled.
    /// </summary>
    public bool EnableMetrics { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether execution rings are enabled.
    /// </summary>
    public bool EnableRings { get; set; }

    /// <summary>
    /// Gets or sets custom execution ring thresholds.
    /// </summary>
    public Dictionary<ExecutionRing, double>? RingThresholds { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether prompt-injection detection is enabled.
    /// </summary>
    public bool EnablePromptInjectionDetection { get; set; }

    /// <summary>
    /// Gets or sets the prompt-injection detector configuration.
    /// </summary>
    public DetectionConfig? PromptInjectionConfig { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the circuit breaker is enabled.
    /// </summary>
    public bool EnableCircuitBreaker { get; set; }

    /// <summary>
    /// Gets or sets the circuit-breaker configuration.
    /// </summary>
    public CircuitBreakerConfig? CircuitBreakerConfig { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether MCP requests must resolve to an authenticated agent identifier.
    /// </summary>
    public bool RequireAuthenticatedAgentId { get; set; } = true;

    /// <summary>
    /// Gets or sets a resolver that maps an authenticated principal to an agent identifier for policy evaluation.
    /// </summary>
    public Func<ClaimsPrincipal, string?>? AgentIdResolver { get; set; }

    /// <summary>
    /// Gets or sets the fallback agent identifier used only when anonymous requests are explicitly allowed.
    /// </summary>
    public string DefaultAgentId { get; set; } = "did:mcp:anonymous";

    /// <summary>
    /// Gets or sets the MCP server name used in MCP scanner findings.
    /// </summary>
    public string ServerName { get; set; } = "default";

    /// <summary>
    /// Gets or sets a value indicating whether tool definitions should be scanned when options are materialized.
    /// </summary>
    public bool ScanToolsOnStartup { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether unsafe tool definitions should fail server startup.
    /// </summary>
    public bool FailOnUnsafeTools { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether text tool results should be sanitized before returning to the client.
    /// </summary>
    public bool SanitizeResponses { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether fallback tool-call handlers should be governed.
    /// </summary>
    public bool GovernFallbackHandlers { get; set; } = true;

    internal GovernanceOptions ToGovernanceOptions()
    {
        return new GovernanceOptions
        {
            PolicyPaths = [.. PolicyPaths],
            ConflictStrategy = ConflictStrategy,
            EnableAudit = EnableAudit,
            EnableMetrics = EnableMetrics,
            EnableRings = EnableRings,
            RingThresholds = RingThresholds is null ? null : new Dictionary<ExecutionRing, double>(RingThresholds),
            EnablePromptInjectionDetection = EnablePromptInjectionDetection,
            PromptInjectionConfig = PromptInjectionConfig,
            EnableCircuitBreaker = EnableCircuitBreaker,
            CircuitBreakerConfig = CircuitBreakerConfig
        };
    }
}
