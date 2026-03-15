// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Audit;
using AgentGovernance.Hypervisor;
using AgentGovernance.Integration;
using AgentGovernance.Policy;
using AgentGovernance.RateLimiting;
using AgentGovernance.Security;
using AgentGovernance.Sre;
using AgentGovernance.Telemetry;

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

    /// <summary>
    /// Whether to enable OpenTelemetry metrics collection.
    /// Defaults to <c>true</c>.
    /// </summary>
    public bool EnableMetrics { get; init; } = true;

    /// <summary>
    /// Whether to enable execution ring enforcement.
    /// When enabled, tool calls are checked against the agent's trust-based ring before policy evaluation.
    /// Defaults to <c>false</c>.
    /// </summary>
    public bool EnableRings { get; init; } = false;

    /// <summary>
    /// Custom ring thresholds for execution ring assignment.
    /// Only used when <see cref="EnableRings"/> is <c>true</c>.
    /// When <c>null</c>, uses default thresholds.
    /// </summary>
    public Dictionary<ExecutionRing, double>? RingThresholds { get; init; }

    /// <summary>
    /// Whether to enable prompt injection detection on tool call arguments.
    /// When enabled, arguments are scanned for injection patterns before policy evaluation.
    /// Defaults to <c>false</c>.
    /// </summary>
    public bool EnablePromptInjectionDetection { get; init; } = false;

    /// <summary>
    /// Configuration for the prompt injection detector.
    /// Only used when <see cref="EnablePromptInjectionDetection"/> is <c>true</c>.
    /// </summary>
    public DetectionConfig? PromptInjectionConfig { get; init; }

    /// <summary>
    /// Whether to enable the circuit breaker for governance evaluations.
    /// Defaults to <c>false</c>.
    /// </summary>
    public bool EnableCircuitBreaker { get; init; } = false;

    /// <summary>
    /// Circuit breaker configuration.
    /// Only used when <see cref="EnableCircuitBreaker"/> is <c>true</c>.
    /// </summary>
    public CircuitBreakerConfig? CircuitBreakerConfig { get; init; }
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
public sealed class GovernanceKernel : IDisposable
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
    /// The rate limiter shared across all governance evaluations.
    /// </summary>
    public RateLimiter RateLimiter { get; }

    /// <summary>
    /// OpenTelemetry-compatible governance metrics. <c>null</c> when metrics are disabled.
    /// </summary>
    public GovernanceMetrics? Metrics { get; }

    /// <summary>
    /// Execution ring enforcer for privilege-based access control.
    /// <c>null</c> when ring enforcement is disabled.
    /// </summary>
    public RingEnforcer? Rings { get; }

    /// <summary>
    /// Prompt injection detector for scanning tool call inputs.
    /// <c>null</c> when prompt injection detection is disabled.
    /// </summary>
    public PromptInjectionDetector? InjectionDetector { get; }

    /// <summary>
    /// Circuit breaker for governance evaluation resilience.
    /// <c>null</c> when the circuit breaker is disabled.
    /// </summary>
    public CircuitBreaker? CircuitBreaker { get; }

    /// <summary>
    /// Saga orchestrator for multi-step transaction governance.
    /// Always available.
    /// </summary>
    public SagaOrchestrator SagaOrchestrator { get; }

    /// <summary>
    /// SLO engine for tracking governance service-level objectives.
    /// Always available — callers register SLO specs and record observations.
    /// </summary>
    public SloEngine SloEngine { get; }

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
        RateLimiter = new RateLimiter();
        Metrics = opts.EnableMetrics ? new GovernanceMetrics() : null;

        Rings = opts.EnableRings
            ? (opts.RingThresholds is not null ? new RingEnforcer(opts.RingThresholds) : new RingEnforcer())
            : null;

        InjectionDetector = opts.EnablePromptInjectionDetection
            ? (opts.PromptInjectionConfig is not null ? new PromptInjectionDetector(opts.PromptInjectionConfig) : new PromptInjectionDetector())
            : null;

        CircuitBreaker = opts.EnableCircuitBreaker
            ? (opts.CircuitBreakerConfig is not null ? new CircuitBreaker(opts.CircuitBreakerConfig) : new CircuitBreaker())
            : null;

        SagaOrchestrator = new SagaOrchestrator();
        SloEngine = new SloEngine();

        Middleware = new GovernanceMiddleware(PolicyEngine, AuditEmitter, RateLimiter, Metrics, Rings, InjectionDetector);

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

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        (Metrics as IDisposable)?.Dispose();
    }

    private bool _disposed;
}
