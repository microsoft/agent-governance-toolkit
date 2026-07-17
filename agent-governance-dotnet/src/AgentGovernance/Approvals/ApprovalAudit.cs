// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace AgentGovernance.Approvals;

/// <summary>Lifecycle events emitted by the approval protocol.</summary>
public enum ApprovalAuditEventType
{
    /// <summary>A policy decision suspended execution.</summary>
    PolicyDecision,

    /// <summary>An approval request was opened.</summary>
    ApprovalRequested,

    /// <summary>An approval chain entry was appended.</summary>
    ApprovalChainEntry,

    /// <summary>An approval request reached a terminal resolution.</summary>
    ApprovalResolved,

    /// <summary>An approval request expired.</summary>
    ApprovalExpired,

    /// <summary>An approval request was cancelled.</summary>
    ApprovalCancelled,

    /// <summary>An allow resolution was consumed.</summary>
    ApprovalConsumed,

    /// <summary>Execution was released after successful validation.</summary>
    ExecutionAllowed,

    /// <summary>Execution was denied during validation.</summary>
    ExecutionDenied
}

/// <summary>A structured, linked approval audit record.</summary>
public sealed record ApprovalAuditEvent
{
    /// <summary>The audit event type.</summary>
    public required ApprovalAuditEventType Type { get; init; }

    /// <summary>The UTC event time.</summary>
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>The acting agent identifier.</summary>
    public string? AgentId { get; init; }

    /// <summary>The linked policy decision identifier.</summary>
    public string? PolicyDecisionId { get; init; }

    /// <summary>The linked approval request identifier.</summary>
    public string? ApprovalRequestId { get; init; }

    /// <summary>The linked approval resolution identifier.</summary>
    public string? ApprovalResolutionId { get; init; }

    /// <summary>The linked approval chain entry identifier.</summary>
    public string? ChainEntryId { get; init; }

    /// <summary>The bound action digest.</summary>
    public string? ActionDigest { get; init; }

    /// <summary>The bound policy version.</summary>
    public string? PolicyVersion { get; init; }

    /// <summary>The bound approval chain version.</summary>
    public string? ApprovalChainVersion { get; init; }

    /// <summary>The machine-readable event reason.</summary>
    public string? ReasonCode { get; init; }
}

/// <summary>Receives structured approval protocol audit records.</summary>
public interface IApprovalAuditSink
{
    /// <summary>Persists one approval audit record.</summary>
    void Write(ApprovalAuditEvent auditEvent);
}

/// <summary>A thread-safe in-memory approval audit sink for tests and local embedding.</summary>
public sealed class InMemoryApprovalAuditSink : IApprovalAuditSink
{
    private readonly object _sync = new();
    private readonly List<ApprovalAuditEvent> _events = new();

    /// <inheritdoc />
    public void Write(ApprovalAuditEvent auditEvent)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);
        lock (_sync)
        {
            _events.Add(auditEvent);
        }
    }

    /// <summary>Returns an immutable snapshot of recorded events.</summary>
    public IReadOnlyList<ApprovalAuditEvent> GetEvents()
    {
        lock (_sync)
        {
            return _events.ToList().AsReadOnly();
        }
    }
}
