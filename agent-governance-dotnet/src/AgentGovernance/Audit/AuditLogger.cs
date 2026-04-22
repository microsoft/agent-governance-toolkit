// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AgentGovernance.Audit;

/// <summary>
/// Represents a single entry in the hash-chain audit log.
/// Each entry contains a SHA-256 hash linking it to the previous entry,
/// forming a tamper-evident chain.
/// </summary>
public sealed class AuditEntry
{
    /// <summary>
    /// The sequence number of this entry in the log (zero-based).
    /// </summary>
    public long Seq { get; init; }

    /// <summary>
    /// UTC timestamp of when this entry was recorded.
    /// </summary>
    public DateTimeOffset Timestamp { get; init; }

    /// <summary>
    /// The decentralised identifier of the agent that performed the action.
    /// </summary>
    public required string AgentId { get; init; }

    /// <summary>
    /// The action that was performed (e.g., "tool_call", "policy_check").
    /// </summary>
    public required string Action { get; init; }

    /// <summary>
    /// The governance decision for this action (e.g., "allow", "deny").
    /// </summary>
    public required string Decision { get; init; }

    /// <summary>
    /// The SHA-256 hash of the previous entry, or an empty string for the genesis entry.
    /// </summary>
    public string PreviousHash { get; init; } = string.Empty;

    /// <summary>
    /// The SHA-256 hash of this entry, computed over the concatenation of
    /// <see cref="Seq"/>, <see cref="Timestamp"/>, <see cref="AgentId"/>,
    /// <see cref="Action"/>, <see cref="Decision"/>, and <see cref="PreviousHash"/>.
    /// </summary>
    public string Hash { get; init; } = string.Empty;
}

/// <summary>
/// A tamper-evident, hash-chain audit logger for governance actions.
/// Each logged entry includes a SHA-256 hash linking to the previous entry,
/// enabling full chain integrity verification.
/// <para>
/// This class is thread-safe. All mutations are protected by a lock.
/// </para>
/// </summary>
public sealed class AuditLogger
{
    private readonly List<AuditEntry> _entries = new();
    private readonly object _lock = new();

    /// <summary>
    /// Returns the number of entries in the audit log.
    /// </summary>
    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _entries.Count;
            }
        }
    }

    /// <summary>
    /// Appends a new entry to the hash-chain audit log.
    /// The entry's hash is computed from its fields and the previous entry's hash.
    /// </summary>
    /// <param name="agentId">The agent's decentralised identifier.</param>
    /// <param name="action">The action performed.</param>
    /// <param name="decision">The governance decision.</param>
    /// <returns>The newly created <see cref="AuditEntry"/>.</returns>
    public AuditEntry Log(string agentId, string action, string decision)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);
        ArgumentException.ThrowIfNullOrWhiteSpace(action);
        ArgumentException.ThrowIfNullOrWhiteSpace(decision);

        lock (_lock)
        {
            var seq = _entries.Count;
            var timestamp = DateTimeOffset.UtcNow;
            var previousHash = seq == 0 ? string.Empty : _entries[seq - 1].Hash;

            var hash = ComputeHash(seq, timestamp, agentId, action, decision, previousHash);

            var entry = new AuditEntry
            {
                Seq = seq,
                Timestamp = timestamp,
                AgentId = agentId,
                Action = action,
                Decision = decision,
                PreviousHash = previousHash,
                Hash = hash
            };

            _entries.Add(entry);
            return entry;
        }
    }

    /// <summary>
    /// Validates the integrity of the entire hash chain.
    /// Recomputes every hash and verifies that each entry's <see cref="AuditEntry.PreviousHash"/>
    /// matches the preceding entry's <see cref="AuditEntry.Hash"/>.
    /// </summary>
    /// <returns><c>true</c> if the chain is intact; otherwise <c>false</c>.</returns>
    public bool Verify()
    {
        lock (_lock)
        {
            for (var i = 0; i < _entries.Count; i++)
            {
                var entry = _entries[i];

                // Verify previous-hash linkage.
                var expectedPrevHash = i == 0 ? string.Empty : _entries[i - 1].Hash;
                if (entry.PreviousHash != expectedPrevHash)
                {
                    return false;
                }

                // Recompute and verify this entry's hash.
                var recomputed = ComputeHash(
                    entry.Seq, entry.Timestamp, entry.AgentId,
                    entry.Action, entry.Decision, entry.PreviousHash);

                if (entry.Hash != recomputed)
                {
                    return false;
                }
            }

            return true;
        }
    }

    /// <summary>
    /// Returns audit entries, optionally filtered by agent ID and/or action.
    /// </summary>
    /// <param name="agentId">When provided, only entries for this agent are returned.</param>
    /// <param name="action">When provided, only entries with this action are returned.</param>
    /// <returns>A read-only list of matching entries.</returns>
    public IReadOnlyList<AuditEntry> GetEntries(string? agentId = null, string? action = null)
    {
        lock (_lock)
        {
            IEnumerable<AuditEntry> query = _entries;

            if (agentId is not null)
            {
                query = query.Where(e => e.AgentId == agentId);
            }

            if (action is not null)
            {
                query = query.Where(e => e.Action == action);
            }

            return query.ToList().AsReadOnly();
        }
    }

    /// <summary>
    /// Serializes the entire audit log to a JSON string.
    /// </summary>
    /// <returns>A JSON array of all audit entries.</returns>
    public string ExportJson()
    {
        lock (_lock)
        {
            return JsonSerializer.Serialize(_entries, JsonOptions);
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    /// <summary>
    /// Computes the SHA-256 hash for an audit entry from its constituent fields.
    /// </summary>
    private static string ComputeHash(
        long seq, DateTimeOffset timestamp, string agentId,
        string action, string decision, string previousHash)
    {
        var payload = $"{seq}|{timestamp:O}|{agentId}|{action}|{decision}|{previousHash}";
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(payload));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
