// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Audit;
using AgentGovernance.Integration;
using AgentGovernance.Policy;

namespace AgentGovernance;

/// <summary>
/// Configuration options for the <see cref="GovernanceKernel"/>.
/// </summary>
public sealed class GovernanceOptions
{
    /// <summary>
    /// List of file paths to YAML policy files to load at initialisation.
    /// </summary>
    public List<string> PolicyPaths { get; init; } = new();

    /// <summary>
    /// The conflict resolution strategy for the policy engine.
    /// Defaults to <see cref="ConflictResolutionStrategy.PriorityFirstMatch"/>.
    /// </summary>
    public ConflictResolutionStrategy ConflictStrategy { get; init; } =
        ConflictResolutionStrategy.PriorityFirstMatch;

    /// <summary>
    /// Whether to enable audit event emission.
    /// When <c>false</c>, the <see cref="AuditEmitter"/> is still created but events
    /// are not emitted from the middleware. Defaults to <c>true</c>.
    /// </summary>
    public bool EnableAudit { get; init; } = true;
}

/// <summary>
/// Main entry point and facade for the Agent Governance system.
/// Provides a simplified API that wires together the <see cref="PolicyEngine"/>,
/// <see cref="AuditEmitter"/>, and <see cref="GovernanceMiddleware"/>.
/// </summary>
/// <remarks>
/// <b>Quick start:</b>
/// <code>
/// var kernel = new GovernanceKernel(new GovernanceOptions
/// {
///     PolicyPaths = new() { "policies/default.yaml" },
///     ConflictStrategy = ConflictResolutionStrategy.DenyOverrides
/// });
///
/// var result = kernel.EvaluateToolCall("did:mesh:abc123", "file_write", new() { ["path"] = "/etc" });
/// if (!result.Allowed)
/// {
///     Console.WriteLine($"Blocked: {result.Reason}");
/// }
/// </code>
/// </remarks>
public sealed class GovernanceKernel
{
    /// <summary>
    /// The policy evaluation engine used by this kernel.
    /// </summary>
    public PolicyEngine PolicyEngine { get; }

    /// <summary>
    /// The audit event emitter used by this kernel.
    /// </summary>
    public AuditEmitter AuditEmitter { get; }

    /// <summary>
    /// The governance middleware that integrates the policy engine with agent tool calls.
    /// </summary>
    public GovernanceMiddleware Middleware { get; }

    /// <summary>
    /// Whether audit events are enabled.
    /// </summary>
    public bool AuditEnabled { get; }

    /// <summary>
    /// Initializes a new <see cref="GovernanceKernel"/> with optional configuration.
    /// Loads any policy files specified in <see cref="GovernanceOptions.PolicyPaths"/>.
    /// </summary>
    /// <param name="options">
    /// Configuration options. When <c>null</c>, uses default settings.
    /// </param>
    public GovernanceKernel(GovernanceOptions? options = null)
    {
        var opts = options ?? new GovernanceOptions();

        PolicyEngine = new PolicyEngine
        {
            ConflictStrategy = opts.ConflictStrategy
        };

        AuditEmitter = new AuditEmitter();
        AuditEnabled = opts.EnableAudit;
        Middleware = new GovernanceMiddleware(PolicyEngine, AuditEmitter);

        // Load any initial policy files.
        foreach (var path in opts.PolicyPaths)
        {
            PolicyEngine.LoadYamlFile(path);
        }
    }

    /// <summary>
    /// Loads a governance policy from a YAML file.
    /// </summary>
    /// <param name="yamlPath">Path to the YAML policy file.</param>
    public void LoadPolicy(string yamlPath)
    {
        PolicyEngine.LoadYamlFile(yamlPath);
    }

    /// <summary>
    /// Loads a governance policy from a YAML string.
    /// </summary>
    /// <param name="yaml">YAML content representing a policy document.</param>
    public void LoadPolicyFromYaml(string yaml)
    {
        PolicyEngine.LoadYaml(yaml);
    }

    /// <summary>
    /// Evaluates whether a tool call is permitted under the current governance policies.
    /// This is the primary method agents should call before executing any tool.
    /// </summary>
    /// <param name="agentId">The DID of the agent requesting the tool call.</param>
    /// <param name="toolName">The name of the tool being called.</param>
    /// <param name="args">Optional arguments to the tool call.</param>
    /// <returns>A <see cref="ToolCallResult"/> indicating whether the call is allowed.</returns>
    public ToolCallResult EvaluateToolCall(
        string agentId,
        string toolName,
        Dictionary<string, object>? args = null)
    {
        return Middleware.EvaluateToolCall(agentId, toolName, args);
    }

    /// <summary>
    /// Subscribes to a specific governance event type.
    /// </summary>
    /// <param name="type">The event type to listen for.</param>
    /// <param name="handler">The callback to invoke when a matching event is emitted.</param>
    public void OnEvent(GovernanceEventType type, Action<GovernanceEvent> handler)
    {
        AuditEmitter.On(type, handler);
    }

    /// <summary>
    /// Subscribes to all governance events (wildcard).
    /// </summary>
    /// <param name="handler">The callback to invoke for every emitted event.</param>
    public void OnAllEvents(Action<GovernanceEvent> handler)
    {
        AuditEmitter.OnAll(handler);
    }
}
