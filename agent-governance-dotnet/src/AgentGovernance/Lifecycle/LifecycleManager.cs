// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace AgentGovernance.Lifecycle;

/// <summary>
/// Eight-state lifecycle model for governed agents.
/// </summary>
public enum LifecycleState
{
    /// <summary>Agent is being provisioned and is not yet ready.</summary>
    Provisioning,

    /// <summary>Agent is running and accepting work.</summary>
    Active,

    /// <summary>Agent is temporarily paused (e.g., policy hold).</summary>
    Suspended,

    /// <summary>Agent credentials or keys are being rotated.</summary>
    Rotating,

    /// <summary>Agent is running in a degraded capacity.</summary>
    Degraded,

    /// <summary>Agent is isolated due to a security or trust concern.</summary>
    Quarantined,

    /// <summary>Agent shutdown is in progress.</summary>
    Decommissioning,

    /// <summary>Agent has been fully decommissioned.</summary>
    Decommissioned
}

/// <summary>
/// Immutable record of a lifecycle state transition.
/// </summary>
/// <param name="AgentId">DID of the agent.</param>
/// <param name="FromState">Previous lifecycle state.</param>
/// <param name="ToState">New lifecycle state.</param>
/// <param name="Reason">Human-readable reason for the transition.</param>
/// <param name="Timestamp">UTC time of the transition.</param>
/// <param name="InitiatedBy">Identifier of the actor that initiated the transition.</param>
public record LifecycleEvent(
    string AgentId,
    LifecycleState FromState,
    LifecycleState ToState,
    string Reason,
    DateTimeOffset Timestamp,
    string InitiatedBy);

/// <summary>
/// Manages the lifecycle of a single governed agent using an eight-state
/// machine with validated transitions.
/// </summary>
public class LifecycleManager
{
    private static readonly Dictionary<LifecycleState, HashSet<LifecycleState>> ValidTransitions = new()
    {
        [LifecycleState.Provisioning] = new()
        {
            LifecycleState.Active,
            LifecycleState.Decommissioning
        },
        [LifecycleState.Active] = new()
        {
            LifecycleState.Suspended,
            LifecycleState.Rotating,
            LifecycleState.Degraded,
            LifecycleState.Quarantined,
            LifecycleState.Decommissioning
        },
        [LifecycleState.Suspended] = new()
        {
            LifecycleState.Active,
            LifecycleState.Quarantined,
            LifecycleState.Decommissioning
        },
        [LifecycleState.Rotating] = new()
        {
            LifecycleState.Active,
            LifecycleState.Degraded,
            LifecycleState.Decommissioning
        },
        [LifecycleState.Degraded] = new()
        {
            LifecycleState.Active,
            LifecycleState.Quarantined,
            LifecycleState.Decommissioning
        },
        [LifecycleState.Quarantined] = new()
        {
            LifecycleState.Active,
            LifecycleState.Decommissioning
        },
        [LifecycleState.Decommissioning] = new()
        {
            LifecycleState.Decommissioned
        },
        [LifecycleState.Decommissioned] = new()
    };

    private readonly string _agentId;
    private readonly List<LifecycleEvent> _events = new();
    private readonly object _lock = new();

    /// <summary>
    /// Creates a new <see cref="LifecycleManager"/> for the given agent.
    /// The agent starts in <see cref="LifecycleState.Provisioning"/>.
    /// </summary>
    /// <param name="agentId">DID of the agent to manage.</param>
    public LifecycleManager(string agentId)
    {
        _agentId = agentId;
        State = LifecycleState.Provisioning;
    }

    /// <summary>
    /// Current lifecycle state of the agent.
    /// </summary>
    public LifecycleState State { get; private set; }

    /// <summary>
    /// Immutable snapshot of all recorded lifecycle events.
    /// </summary>
    public IReadOnlyList<LifecycleEvent> Events
    {
        get
        {
            lock (_lock)
            {
                return _events.ToList().AsReadOnly();
            }
        }
    }

    /// <summary>
    /// Returns whether a transition from the current state to <paramref name="toState"/> is valid.
    /// </summary>
    public bool CanTransition(LifecycleState toState)
    {
        lock (_lock)
        {
            return ValidTransitions.TryGetValue(State, out var targets) && targets.Contains(toState);
        }
    }

    /// <summary>
    /// Transitions the agent to a new state if the transition is valid.
    /// </summary>
    /// <param name="toState">The target state.</param>
    /// <param name="reason">Human-readable reason for the transition.</param>
    /// <param name="initiatedBy">Identifier of the actor initiating the transition.</param>
    /// <returns>The recorded <see cref="LifecycleEvent"/>.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the transition is not allowed.</exception>
    public LifecycleEvent Transition(LifecycleState toState, string reason, string initiatedBy)
    {
        lock (_lock)
        {
            if (!ValidTransitions.TryGetValue(State, out var targets) || !targets.Contains(toState))
            {
                throw new InvalidOperationException(
                    $"Cannot transition from {State} to {toState}.");
            }

            var fromState = State;
            State = toState;

            var evt = new LifecycleEvent(_agentId, fromState, toState, reason, DateTimeOffset.UtcNow, initiatedBy);
            _events.Add(evt);
            return evt;
        }
    }

    // ── Convenience methods ──────────────────────────────────────

    /// <summary>
    /// Transitions the agent to <see cref="LifecycleState.Active"/>.
    /// </summary>
    public LifecycleEvent Activate(string reason = "Ready")
        => Transition(LifecycleState.Active, reason, "system");

    /// <summary>
    /// Transitions the agent to <see cref="LifecycleState.Suspended"/>.
    /// </summary>
    public LifecycleEvent Suspend(string reason)
        => Transition(LifecycleState.Suspended, reason, "system");

    /// <summary>
    /// Transitions the agent to <see cref="LifecycleState.Quarantined"/>.
    /// </summary>
    public LifecycleEvent Quarantine(string reason)
        => Transition(LifecycleState.Quarantined, reason, "system");

    /// <summary>
    /// Transitions the agent to <see cref="LifecycleState.Decommissioning"/>.
    /// </summary>
    public LifecycleEvent Decommission(string reason)
        => Transition(LifecycleState.Decommissioning, reason, "system");
}
