// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

namespace AgentGovernance.Hypervisor;

/// <summary>
/// Execution privilege levels inspired by CPU protection rings.
/// Lower values indicate higher privilege. Agents start at Ring 3 (Sandbox)
/// and earn their way up based on trust score.
/// </summary>
public enum ExecutionRing
{
    /// <summary>System-level — policy modification, kill switches. Typically reserved for human operators.</summary>
    Ring0 = 0,

    /// <summary>Trusted — full tool access with standard resource limits.</summary>
    Ring1 = 1,

    /// <summary>Standard — limited tool access, rate-limited.</summary>
    Ring2 = 2,

    /// <summary>Sandbox — heavily restricted, minimal permissions.</summary>
    Ring3 = 3
}

/// <summary>
/// Resource limits enforced per execution ring.
/// </summary>
public sealed class RingResourceLimits
{
    /// <summary>Maximum tool calls per minute.</summary>
    public int MaxCallsPerMinute { get; init; }

    /// <summary>Maximum execution time per tool call in seconds.</summary>
    public double MaxExecutionTimeSec { get; init; }

    /// <summary>Maximum memory usage in megabytes (advisory).</summary>
    public int MaxMemoryMb { get; init; }

    /// <summary>Whether the ring allows write operations.</summary>
    public bool AllowWrites { get; init; }

    /// <summary>Whether the ring allows network access.</summary>
    public bool AllowNetwork { get; init; }

    /// <summary>Whether the ring allows spawning sub-agents.</summary>
    public bool AllowDelegation { get; init; }

    /// <summary>Default resource limits for each ring level.</summary>
    public static readonly IReadOnlyDictionary<ExecutionRing, RingResourceLimits> Defaults =
        new Dictionary<ExecutionRing, RingResourceLimits>
        {
            [ExecutionRing.Ring0] = new()
            {
                MaxCallsPerMinute = int.MaxValue,
                MaxExecutionTimeSec = double.MaxValue,
                MaxMemoryMb = int.MaxValue,
                AllowWrites = true,
                AllowNetwork = true,
                AllowDelegation = true
            },
            [ExecutionRing.Ring1] = new()
            {
                MaxCallsPerMinute = 1000,
                MaxExecutionTimeSec = 300,
                MaxMemoryMb = 4096,
                AllowWrites = true,
                AllowNetwork = true,
                AllowDelegation = true
            },
            [ExecutionRing.Ring2] = new()
            {
                MaxCallsPerMinute = 100,
                MaxExecutionTimeSec = 60,
                MaxMemoryMb = 1024,
                AllowWrites = true,
                AllowNetwork = true,
                AllowDelegation = false
            },
            [ExecutionRing.Ring3] = new()
            {
                MaxCallsPerMinute = 10,
                MaxExecutionTimeSec = 5,
                MaxMemoryMb = 256,
                AllowWrites = false,
                AllowNetwork = false,
                AllowDelegation = false
            }
        };
}

/// <summary>
/// Result of an execution ring access check.
/// </summary>
public sealed record RingCheckResult(
    bool Allowed,
    ExecutionRing AgentRing,
    ExecutionRing RequiredRing,
    string Reason);

/// <summary>
/// Enforces execution ring privileges for agent operations.
/// Agents are assigned to rings based on trust score and can be promoted
/// or demoted dynamically.
/// </summary>
public sealed class RingEnforcer
{
    private readonly Dictionary<ExecutionRing, double> _thresholds;
    private readonly Dictionary<ExecutionRing, RingResourceLimits> _limits;

    /// <summary>
    /// Initializes a new <see cref="RingEnforcer"/> with configurable trust score thresholds.
    /// </summary>
    /// <param name="thresholds">
    /// Optional custom trust score thresholds for ring assignment.
    /// Keys are ring levels, values are minimum trust scores (0.0–1.0).
    /// Defaults: Ring0=0.95, Ring1=0.80, Ring2=0.60, Ring3=0.0.
    /// </param>
    /// <param name="limits">Optional custom resource limits per ring.</param>
    public RingEnforcer(
        Dictionary<ExecutionRing, double>? thresholds = null,
        Dictionary<ExecutionRing, RingResourceLimits>? limits = null)
    {
        _thresholds = thresholds ?? new Dictionary<ExecutionRing, double>
        {
            [ExecutionRing.Ring0] = 0.95,
            [ExecutionRing.Ring1] = 0.80,
            [ExecutionRing.Ring2] = 0.60,
            [ExecutionRing.Ring3] = 0.0
        };

        _limits = limits ?? new Dictionary<ExecutionRing, RingResourceLimits>(
            RingResourceLimits.Defaults);
    }

    /// <summary>
    /// Computes the execution ring for an agent based on their trust score.
    /// </summary>
    /// <param name="trustScore">Agent trust score (0.0–1.0).</param>
    /// <returns>The highest-privilege ring the agent qualifies for.</returns>
    public ExecutionRing ComputeRing(double trustScore)
    {
        if (trustScore >= _thresholds[ExecutionRing.Ring0]) return ExecutionRing.Ring0;
        if (trustScore >= _thresholds[ExecutionRing.Ring1]) return ExecutionRing.Ring1;
        if (trustScore >= _thresholds[ExecutionRing.Ring2]) return ExecutionRing.Ring2;
        return ExecutionRing.Ring3;
    }

    /// <summary>
    /// Checks whether an agent at a given trust score is permitted to perform
    /// an operation requiring the specified ring level.
    /// </summary>
    /// <param name="trustScore">Agent trust score (0.0–1.0).</param>
    /// <param name="requiredRing">The minimum ring required for the operation.</param>
    /// <returns>A <see cref="RingCheckResult"/> with the decision.</returns>
    public RingCheckResult Check(double trustScore, ExecutionRing requiredRing)
    {
        var agentRing = ComputeRing(trustScore);

        // Ring0 operations always require explicit elevation — never auto-granted.
        if (requiredRing == ExecutionRing.Ring0 && agentRing != ExecutionRing.Ring0)
        {
            return new RingCheckResult(false, agentRing, requiredRing,
                "Ring 0 operations require explicit elevation and are never auto-granted.");
        }

        // Lower ring value = higher privilege. Agent ring must be <= required ring.
        bool allowed = (int)agentRing <= (int)requiredRing;

        var reason = allowed
            ? $"Agent at {agentRing} has sufficient privilege for {requiredRing}."
            : $"Agent at {agentRing} lacks privilege for {requiredRing} (trust: {trustScore:F2}).";

        return new RingCheckResult(allowed, agentRing, requiredRing, reason);
    }

    /// <summary>
    /// Determines whether an agent should be demoted based on a drop in trust score.
    /// </summary>
    /// <param name="currentRing">The agent's current ring.</param>
    /// <param name="newTrustScore">The agent's updated trust score.</param>
    /// <returns><c>true</c> if the agent should be moved to a less-privileged ring.</returns>
    public bool ShouldDemote(ExecutionRing currentRing, double newTrustScore)
    {
        var computedRing = ComputeRing(newTrustScore);
        return (int)computedRing > (int)currentRing;
    }

    /// <summary>
    /// Returns the resource limits for a given ring.
    /// </summary>
    public RingResourceLimits GetLimits(ExecutionRing ring)
    {
        return _limits.TryGetValue(ring, out var limits)
            ? limits
            : RingResourceLimits.Defaults[ring];
    }
}
