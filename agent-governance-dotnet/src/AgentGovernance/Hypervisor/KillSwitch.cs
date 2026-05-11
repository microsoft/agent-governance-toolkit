// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace AgentGovernance.Hypervisor;

/// <summary>
/// Reason an agent was terminated via the kill switch.
/// </summary>
public enum KillReason
{
    /// <summary>Agent violated a governance policy.</summary>
    PolicyViolation,

    /// <summary>Agent's trust score dropped below the acceptable threshold.</summary>
    TrustThreshold,

    /// <summary>A human operator manually triggered the kill.</summary>
    ManualOverride,

    /// <summary>Anomalous behaviour was detected by the monitoring system.</summary>
    AnomalyDetected,

    /// <summary>Agent exceeded resource consumption limits.</summary>
    ResourceExhaustion
}

/// <summary>
/// Immutable record of a single kill switch activation.
/// </summary>
/// <param name="AgentId">DID of the terminated agent.</param>
/// <param name="Reason">Why the agent was killed.</param>
/// <param name="Detail">Human-readable detail message.</param>
/// <param name="Timestamp">UTC time the kill occurred.</param>
public record KillEvent(string AgentId, KillReason Reason, string Detail, DateTimeOffset Timestamp);

/// <summary>
/// Agent kill switch that can be armed/disarmed.
/// When armed, calling <see cref="Kill"/> terminates the target agent,
/// records the event, and notifies subscribers.
/// </summary>
public class KillSwitch
{
    private readonly List<KillEvent> _history = new();
    private readonly object _lock = new();

    /// <summary>
    /// Whether the kill switch is currently armed. Only armed switches can kill agents.
    /// </summary>
    public bool IsArmed { get; private set; }

    /// <summary>
    /// Immutable snapshot of all recorded kill events.
    /// </summary>
    public IReadOnlyList<KillEvent> History
    {
        get
        {
            lock (_lock)
            {
                return _history.ToList().AsReadOnly();
            }
        }
    }

    /// <summary>
    /// Raised immediately after an agent is killed.
    /// </summary>
    public event EventHandler<KillEvent>? OnKill;

    /// <summary>
    /// Arms the kill switch, enabling <see cref="Kill"/> to terminate agents.
    /// </summary>
    public void Arm()
    {
        lock (_lock)
        {
            IsArmed = true;
        }
    }

    /// <summary>
    /// Disarms the kill switch. Subsequent calls to <see cref="Kill"/> will throw.
    /// </summary>
    public void Disarm()
    {
        lock (_lock)
        {
            IsArmed = false;
        }
    }

    /// <summary>
    /// Terminates the specified agent, records the event, and raises <see cref="OnKill"/>.
    /// </summary>
    /// <param name="agentId">DID of the agent to terminate.</param>
    /// <param name="reason">Reason for the kill.</param>
    /// <param name="detail">Human-readable detail message.</param>
    /// <returns>The recorded <see cref="KillEvent"/>.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the switch is not armed.</exception>
    public KillEvent Kill(string agentId, KillReason reason, string detail)
    {
        KillEvent killEvent;

        lock (_lock)
        {
            if (!IsArmed)
            {
                throw new InvalidOperationException("Kill switch is not armed.");
            }

            killEvent = new KillEvent(agentId, reason, detail, DateTimeOffset.UtcNow);
            _history.Add(killEvent);
        }

        OnKill?.Invoke(this, killEvent);
        return killEvent;
    }
}
