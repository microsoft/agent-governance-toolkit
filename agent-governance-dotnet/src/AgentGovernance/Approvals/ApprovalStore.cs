// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace AgentGovernance.Approvals;

/// <summary>Persistence contract for approval requests, entries, and resolutions.</summary>
public interface IApprovalStore
{
    /// <summary>Persists a new policy decision and approval request.</summary>
    void SaveRequest(ApprovalPolicyDecisionRecord policyDecision, ApprovalRequest request);

    /// <summary>Attempts to load a policy decision and approval request.</summary>
    bool TryGetRequest(
        string approvalRequestId,
        out ApprovalPolicyDecisionRecord policyDecision,
        out ApprovalRequest request);

    /// <summary>Updates a request lifecycle status.</summary>
    bool TryUpdateStatus(string approvalRequestId, ApprovalStatus status, out ApprovalRequest request);

    /// <summary>Appends one tamper-evident approval entry.</summary>
    void AppendEntry(ApprovalChainEntry entry);

    /// <summary>Returns entries in append order.</summary>
    IReadOnlyList<ApprovalChainEntry> GetEntries(string approvalRequestId);

    /// <summary>Persists the terminal resolution for a request.</summary>
    void SaveResolution(ApprovalResolution resolution);

    /// <summary>Attempts to load the terminal resolution for a request.</summary>
    bool TryGetResolution(string approvalRequestId, out ApprovalResolution resolution);

    /// <summary>
    /// Atomically marks an allowed request as consumed. Returns <c>true</c> exactly once.
    /// </summary>
    bool TryConsume(string approvalRequestId, out ApprovalRequest request);
}

/// <summary>A thread-safe process-local reference implementation of <see cref="IApprovalStore"/>.</summary>
public sealed class InMemoryApprovalStore : IApprovalStore
{
    private readonly object _sync = new();
    private readonly Dictionary<string, StoreRecord> _records = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public void SaveRequest(ApprovalPolicyDecisionRecord policyDecision, ApprovalRequest request)
    {
        ArgumentNullException.ThrowIfNull(policyDecision);
        ArgumentNullException.ThrowIfNull(request);

        lock (_sync)
        {
            if (_records.ContainsKey(request.ApprovalRequestId))
            {
                throw new ApprovalProtocolException(
                    $"Approval request '{request.ApprovalRequestId}' already exists.");
            }

            _records.Add(request.ApprovalRequestId, new StoreRecord(policyDecision, request));
        }
    }

    /// <inheritdoc />
    public bool TryGetRequest(
        string approvalRequestId,
        out ApprovalPolicyDecisionRecord policyDecision,
        out ApprovalRequest request)
    {
        lock (_sync)
        {
            if (_records.TryGetValue(approvalRequestId, out var record))
            {
                policyDecision = record.PolicyDecision;
                request = record.Request;
                return true;
            }
        }

        policyDecision = null!;
        request = null!;
        return false;
    }

    /// <inheritdoc />
    public bool TryUpdateStatus(string approvalRequestId, ApprovalStatus status, out ApprovalRequest request)
    {
        lock (_sync)
        {
            if (!_records.TryGetValue(approvalRequestId, out var record))
            {
                request = null!;
                return false;
            }

            record.Request = record.Request with { Status = status };
            request = record.Request;
            return true;
        }
    }

    /// <inheritdoc />
    public void AppendEntry(ApprovalChainEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        lock (_sync)
        {
            if (!_records.TryGetValue(entry.ApprovalRequestId, out var record))
            {
                throw new ApprovalProtocolException(
                    $"Unknown approval request '{entry.ApprovalRequestId}'.");
            }

            record.Entries.Add(CopyEntry(entry));
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<ApprovalChainEntry> GetEntries(string approvalRequestId)
    {
        lock (_sync)
        {
            return _records.TryGetValue(approvalRequestId, out var record)
                ? record.Entries.Select(CopyEntry).ToList().AsReadOnly()
                : Array.Empty<ApprovalChainEntry>();
        }
    }

    /// <inheritdoc />
    public void SaveResolution(ApprovalResolution resolution)
    {
        ArgumentNullException.ThrowIfNull(resolution);

        lock (_sync)
        {
            if (!_records.TryGetValue(resolution.ApprovalRequestId, out var record))
            {
                throw new ApprovalProtocolException(
                    $"Unknown approval request '{resolution.ApprovalRequestId}'.");
            }

            record.Resolution = resolution;
        }
    }

    /// <inheritdoc />
    public bool TryGetResolution(string approvalRequestId, out ApprovalResolution resolution)
    {
        lock (_sync)
        {
            if (_records.TryGetValue(approvalRequestId, out var record) && record.Resolution is not null)
            {
                resolution = record.Resolution;
                return true;
            }
        }

        resolution = null!;
        return false;
    }

    /// <inheritdoc />
    public bool TryConsume(string approvalRequestId, out ApprovalRequest request)
    {
        lock (_sync)
        {
            if (!_records.TryGetValue(approvalRequestId, out var record))
            {
                request = null!;
                return false;
            }

            if (record.Request.Status != ApprovalStatus.Allowed)
            {
                request = record.Request;
                return false;
            }

            record.Request = record.Request with { Status = ApprovalStatus.Consumed };
            request = record.Request;
            return true;
        }
    }

    private static ApprovalChainEntry CopyEntry(ApprovalChainEntry entry) =>
        entry with { Roles = entry.Roles.ToArray() };

    private sealed class StoreRecord
    {
        internal StoreRecord(ApprovalPolicyDecisionRecord policyDecision, ApprovalRequest request)
        {
            PolicyDecision = policyDecision;
            Request = request;
        }

        internal ApprovalPolicyDecisionRecord PolicyDecision { get; }

        internal ApprovalRequest Request { get; set; }

        internal List<ApprovalChainEntry> Entries { get; } = new();

        internal ApprovalResolution? Resolution { get; set; }
    }
}
