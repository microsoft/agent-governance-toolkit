// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;

namespace AgentGovernance.Mcp.Abstractions;

/// <summary>
/// Stores MCP sessions keyed by their session token.
/// </summary>
public interface IMcpSessionStore
{
    /// <summary>
    /// Retrieves a session by token.
    /// </summary>
    /// <param name="sessionToken">The session token to look up.</param>
    /// <param name="cancellationToken">Cancels the store operation.</param>
    /// <returns>The stored session, or <c>null</c> when the token is unknown.</returns>
    Task<McpSession?> GetAsync(string sessionToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Stores or updates a session for the supplied token.
    /// </summary>
    /// <param name="sessionToken">The token associated with the session.</param>
    /// <param name="session">The session value to persist.</param>
    /// <param name="cancellationToken">Cancels the store operation.</param>
    Task SetAsync(string sessionToken, McpSession session, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a session by token.
    /// </summary>
    /// <param name="sessionToken">The session token to delete.</param>
    /// <param name="cancellationToken">Cancels the store operation.</param>
    /// <returns><c>true</c> when a session was removed; otherwise <c>false</c>.</returns>
    Task<bool> DeleteAsync(string sessionToken, CancellationToken cancellationToken = default);
}

/// <summary>
/// Stores seen MCP message nonces for replay protection.
/// </summary>
public interface IMcpNonceStore
{
    /// <summary>
    /// Checks whether a nonce is already present in the replay cache.
    /// </summary>
    /// <param name="nonce">The nonce to look up.</param>
    /// <param name="cancellationToken">Cancels the store operation.</param>
    /// <returns><c>true</c> when the nonce exists; otherwise <c>false</c>.</returns>
    Task<bool> ContainsAsync(string nonce, CancellationToken cancellationToken = default);

    /// <summary>
    /// Adds a nonce to the replay cache.
    /// </summary>
    /// <param name="nonce">The nonce to persist.</param>
    /// <param name="observedAt">The timestamp associated with the nonce.</param>
    /// <param name="cancellationToken">Cancels the store operation.</param>
    /// <returns><c>true</c> when the nonce was added; otherwise <c>false</c> if it already existed.</returns>
    Task<bool> AddAsync(string nonce, DateTimeOffset observedAt, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes nonce entries that are older than the provided cutoff.
    /// </summary>
    /// <param name="cutoff">The oldest permitted timestamp.</param>
    /// <param name="cancellationToken">Cancels the store operation.</param>
    /// <returns>The number of removed nonce entries.</returns>
    Task<int> CleanupAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default);
}

/// <summary>
/// Stores per-agent MCP rate-limit buckets.
/// </summary>
public interface IMcpRateLimitStore
{
    /// <summary>
    /// Retrieves the current bucket for an agent.
    /// </summary>
    /// <param name="agentId">The agent identifier.</param>
    /// <param name="cancellationToken">Cancels the store operation.</param>
    /// <returns>The stored bucket, or <c>null</c> when none exists.</returns>
    Task<McpRateLimitBucket?> GetBucketAsync(string agentId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Stores the current bucket for an agent.
    /// </summary>
    /// <param name="agentId">The agent identifier.</param>
    /// <param name="bucket">The bucket state to persist.</param>
    /// <param name="cancellationToken">Cancels the store operation.</param>
    Task SetBucketAsync(string agentId, McpRateLimitBucket bucket, CancellationToken cancellationToken = default);
}

/// <summary>
/// Receives MCP audit entries from the gateway pipeline.
/// </summary>
public interface IMcpAuditSink
{
    /// <summary>
    /// Records an audit entry.
    /// </summary>
    /// <param name="entry">The audit entry to persist.</param>
    /// <param name="cancellationToken">Cancels the sink operation.</param>
    Task RecordAsync(McpAuditEntry entry, CancellationToken cancellationToken = default);
}

/// <summary>
/// Serializable rate-limit bucket state for a single agent.
/// </summary>
public sealed class McpRateLimitBucket
{
    /// <summary>
    /// Initializes an empty rate-limit bucket.
    /// </summary>
    public McpRateLimitBucket()
        : this(Array.Empty<DateTimeOffset>())
    {
    }

    /// <summary>
    /// Initializes a bucket from an existing sequence of timestamps.
    /// </summary>
    /// <param name="timestamps">The timestamps currently recorded for the bucket.</param>
    public McpRateLimitBucket(IEnumerable<DateTimeOffset> timestamps)
    {
        ArgumentNullException.ThrowIfNull(timestamps);
        Timestamps = timestamps.OrderBy(timestamp => timestamp).ToArray();
    }

    /// <summary>
    /// The timestamps currently recorded in the bucket, ordered from oldest to newest.
    /// </summary>
    public IReadOnlyList<DateTimeOffset> Timestamps { get; init; }
}

/// <summary>
/// In-memory default implementation of <see cref="IMcpSessionStore"/>.
/// </summary>
public sealed class InMemoryMcpSessionStore : IMcpSessionStore
{
    private readonly ConcurrentDictionary<string, McpSession> _sessions = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public Task<McpSession?> GetAsync(string sessionToken, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _sessions.TryGetValue(sessionToken, out var session);
        return Task.FromResult(session);
    }

    /// <inheritdoc />
    public Task SetAsync(string sessionToken, McpSession session, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionToken);
        ArgumentNullException.ThrowIfNull(session);

        _sessions[sessionToken] = session;
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<bool> DeleteAsync(string sessionToken, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(_sessions.TryRemove(sessionToken, out _));
    }
}

/// <summary>
/// In-memory default implementation of <see cref="IMcpNonceStore"/>.
/// </summary>
public sealed class InMemoryMcpNonceStore : IMcpNonceStore
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _nonces = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public Task<bool> ContainsAsync(string nonce, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(_nonces.ContainsKey(nonce));
    }

    /// <inheritdoc />
    public Task<bool> AddAsync(string nonce, DateTimeOffset observedAt, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(_nonces.TryAdd(nonce, observedAt));
    }

    /// <inheritdoc />
    public Task<int> CleanupAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var toRemove = _nonces
            .Where(kv => kv.Value <= cutoff)
            .Select(kv => kv.Key)
            .ToList();

        foreach (var nonce in toRemove)
        {
            _nonces.TryRemove(nonce, out _);
        }

        return Task.FromResult(toRemove.Count);
    }
}

/// <summary>
/// In-memory default implementation of <see cref="IMcpRateLimitStore"/>.
/// </summary>
public sealed class InMemoryMcpRateLimitStore : IMcpRateLimitStore
{
    private readonly ConcurrentDictionary<string, McpRateLimitBucket> _buckets = new(StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc />
    public Task<McpRateLimitBucket?> GetBucketAsync(string agentId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_buckets.TryGetValue(agentId, out var bucket))
        {
            return Task.FromResult<McpRateLimitBucket?>(null);
        }

        return Task.FromResult<McpRateLimitBucket?>(new McpRateLimitBucket(bucket.Timestamps));
    }

    /// <inheritdoc />
    public Task SetBucketAsync(string agentId, McpRateLimitBucket bucket, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);
        ArgumentNullException.ThrowIfNull(bucket);

        _buckets[agentId] = new McpRateLimitBucket(bucket.Timestamps);
        return Task.CompletedTask;
    }
}

/// <summary>
/// In-memory default implementation of <see cref="IMcpAuditSink"/>.
/// </summary>
public sealed class InMemoryMcpAuditSink : IMcpAuditSink
{
    private readonly object _lock = new();
    private readonly List<McpAuditEntry> _entries = new();

    /// <inheritdoc />
    public Task RecordAsync(McpAuditEntry entry, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(entry);

        lock (_lock)
        {
            _entries.Add(CloneEntry(entry));
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Returns a defensive snapshot of the stored audit entries.
    /// </summary>
    /// <returns>A read-only copy of the stored entries.</returns>
    public IReadOnlyList<McpAuditEntry> GetSnapshot()
    {
        lock (_lock)
        {
            return _entries.Select(CloneEntry).ToList().AsReadOnly();
        }
    }

    private static McpAuditEntry CloneEntry(McpAuditEntry entry)
    {
        return new McpAuditEntry
        {
            Timestamp = entry.Timestamp,
            AgentId = entry.AgentId,
            ToolName = entry.ToolName,
            Parameters = new Dictionary<string, object>(entry.Parameters),
            Allowed = entry.Allowed,
            Reason = entry.Reason,
            ApprovalStatus = entry.ApprovalStatus
        };
    }
}
