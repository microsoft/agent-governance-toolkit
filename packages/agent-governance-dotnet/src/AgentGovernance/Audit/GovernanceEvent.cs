// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

namespace AgentGovernance.Audit;

/// <summary>
/// Types of governance events emitted during agent operations.
/// </summary>
public enum GovernanceEventType
{
    /// <summary>A policy check was performed.</summary>
    PolicyCheck,

    /// <summary>A policy violation was detected (request denied).</summary>
    PolicyViolation,

    /// <summary>A tool call was blocked by the governance engine.</summary>
    ToolCallBlocked,

    /// <summary>A governance checkpoint was created.</summary>
    CheckpointCreated,

    /// <summary>A configuration or policy drift was detected.</summary>
    DriftDetected,

    /// <summary>An agent identity was verified.</summary>
    TrustVerified,

    /// <summary>An agent identity verification failed.</summary>
    TrustFailed,

    /// <summary>An agent was registered in the governance system.</summary>
    AgentRegistered
}

/// <summary>
/// Represents a single governance event emitted by the governance engine
/// or its components. Events are used for audit logging, monitoring,
/// and triggering downstream reactions via the <see cref="AuditEmitter"/>.
/// </summary>
public sealed class GovernanceEvent
{
    /// <summary>
    /// The type of governance event.
    /// </summary>
    public GovernanceEventType Type { get; init; }

    /// <summary>
    /// UTC timestamp of when the event occurred.
    /// </summary>
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// The decentralised identifier of the agent involved (e.g., "did:mesh:abc123").
    /// </summary>
    public required string AgentId { get; init; }

    /// <summary>
    /// The session identifier for correlating events within a single agent session.
    /// </summary>
    public required string SessionId { get; init; }

    /// <summary>
    /// The name of the policy that produced this event, if applicable.
    /// </summary>
    public string? PolicyName { get; init; }

    /// <summary>
    /// A unique identifier for this event instance.
    /// </summary>
    public string EventId { get; init; } = $"evt-{Guid.NewGuid():N}";

    /// <summary>
    /// Arbitrary data associated with this event.
    /// Keys and values depend on the <see cref="Type"/>.
    /// </summary>
    public Dictionary<string, object> Data { get; init; } = new();

    /// <inheritdoc />
    public override string ToString() =>
        $"[{Timestamp:O}] {Type} agent={AgentId} session={SessionId} policy={PolicyName ?? "(none)"}";
}
