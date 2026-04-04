// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Collections.Concurrent;
using AgentGovernance.Mcp.Abstractions;
using Microsoft.Extensions.Logging;

namespace AgentGovernance.Mcp;

/// <summary>
/// A thread-safe sliding window rate limiter for per-agent MCP tool call budgets.
/// </summary>
/// <remarks>
/// Each agent maintains a queue of call timestamps. When <see cref="TryAcquire"/>
/// is called, expired entries (older than <see cref="WindowSize"/>) are pruned and
/// the call is allowed only if the remaining count is below <see cref="MaxCallsPerWindow"/>.
/// <para>
/// Thread safety is achieved via per-agent locking — agents do not contend with each other.
/// </para>
/// </remarks>
public sealed class McpSlidingRateLimiter
{
    private readonly IMcpRateLimitStore _rateLimitStore;
    private readonly ConcurrentDictionary<string, object> _bucketLocks = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _trackedAgents = new(StringComparer.OrdinalIgnoreCase);
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a new limiter with in-memory persistence and the system clock.
    /// </summary>
    public McpSlidingRateLimiter()
        : this(new InMemoryMcpRateLimitStore(), TimeProvider.System)
    {
    }

    /// <summary>
    /// Initializes a new limiter with explicit persistence and clock dependencies.
    /// </summary>
    /// <param name="rateLimitStore">The store used to persist bucket state.</param>
    /// <param name="timeProvider">The clock used for sliding-window calculations.</param>
    public McpSlidingRateLimiter(IMcpRateLimitStore rateLimitStore, TimeProvider? timeProvider = null)
    {
        _rateLimitStore = rateLimitStore ?? throw new ArgumentNullException(nameof(rateLimitStore));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Maximum number of calls an agent may make within a single sliding window.
    /// Defaults to <c>100</c>.
    /// </summary>
    public int MaxCallsPerWindow { get; init; } = 100;

    /// <summary>
    /// The duration of the sliding window. Defaults to 5 minutes.
    /// </summary>
    public TimeSpan WindowSize { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Optional logger for recording rate limit events.
    /// When <c>null</c>, no logging occurs — the limiter operates silently.
    /// </summary>
    public ILogger<McpSlidingRateLimiter>? Logger { get; set; }

    /// <summary>
    /// Attempts to acquire a call permit for the specified agent.
    /// Returns <c>true</c> if the agent is under the rate limit (and records the call),
    /// or <c>false</c> if the agent has exhausted its budget for the current window.
    /// </summary>
    /// <param name="agentId">The agent's identifier (e.g., a DID).</param>
    /// <returns><c>true</c> if the call is permitted; <c>false</c> if rate-limited.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="agentId"/> is null or whitespace.</exception>
    public bool TryAcquire(string agentId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);

        var bucketLock = _bucketLocks.GetOrAdd(agentId, _ => new object());
        _trackedAgents[agentId] = 0;

        var now = _timeProvider.GetUtcNow();
        var cutoff = now - WindowSize;

        lock (bucketLock)
        {
            var timestamps = GetBucketTimestamps(agentId);
            PruneExpired(timestamps, cutoff);

            if (timestamps.Count >= MaxCallsPerWindow)
            {
                Logger?.LogWarning("MCP rate limit exceeded for {AgentId}: {Used}/{Max} in window", agentId, timestamps.Count, MaxCallsPerWindow);
                return false;
            }

            timestamps.Add(now);
            SaveBucket(agentId, timestamps);
            return true;
        }
    }

    /// <summary>
    /// Returns the number of calls the agent can still make within the current window.
    /// </summary>
    /// <param name="agentId">The agent's identifier.</param>
    /// <returns>Remaining call budget (≥ 0).</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="agentId"/> is null or whitespace.</exception>
    public int GetRemainingBudget(string agentId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);

        var bucketLock = _bucketLocks.GetOrAdd(agentId, _ => new object());
        lock (bucketLock)
        {
            var timestamps = GetBucketTimestamps(agentId);
            if (timestamps.Count == 0)
            {
                return MaxCallsPerWindow;
            }

            PruneExpired(timestamps, _timeProvider.GetUtcNow() - WindowSize);
            SaveBucket(agentId, timestamps);
            return Math.Max(0, MaxCallsPerWindow - timestamps.Count);
        }
    }

    /// <summary>
    /// Returns the number of calls recorded in the current window for the specified agent.
    /// </summary>
    /// <param name="agentId">The agent's identifier.</param>
    /// <returns>Current call count within the window.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="agentId"/> is null or whitespace.</exception>
    public int GetCallCount(string agentId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);

        var bucketLock = _bucketLocks.GetOrAdd(agentId, _ => new object());
        lock (bucketLock)
        {
            var timestamps = GetBucketTimestamps(agentId);
            if (timestamps.Count == 0)
            {
                return 0;
            }

            PruneExpired(timestamps, _timeProvider.GetUtcNow() - WindowSize);
            SaveBucket(agentId, timestamps);
            return timestamps.Count;
        }
    }

    /// <summary>
    /// Clears all recorded call timestamps for the specified agent.
    /// </summary>
    /// <param name="agentId">The agent's identifier.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="agentId"/> is null or whitespace.</exception>
    public void Reset(string agentId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);

        var bucketLock = _bucketLocks.GetOrAdd(agentId, _ => new object());
        lock (bucketLock)
        {
            SaveBucket(agentId, []);
            _trackedAgents.TryRemove(agentId, out _);
        }
    }

    /// <summary>
    /// Clears all recorded call timestamps for all agents.
    /// </summary>
    public void ResetAll()
    {
        var keys = _trackedAgents.Keys.ToArray();
        foreach (var key in keys)
        {
            Reset(key);
        }
    }

    /// <summary>
    /// Removes expired timestamps from all agents and returns the total number removed.
    /// Call periodically to reclaim memory for long-lived limiter instances.
    /// </summary>
    /// <returns>The total number of expired entries removed across all agents.</returns>
    public int CleanupExpired()
    {
        var cutoff = _timeProvider.GetUtcNow() - WindowSize;
        int totalRemoved = 0;

        foreach (var agentId in _trackedAgents.Keys.ToArray())
        {
            var bucketLock = _bucketLocks.GetOrAdd(agentId, _ => new object());
            lock (bucketLock)
            {
                var timestamps = GetBucketTimestamps(agentId);
                int before = timestamps.Count;
                PruneExpired(timestamps, cutoff);
                SaveBucket(agentId, timestamps);
                totalRemoved += before - timestamps.Count;

                if (timestamps.Count == 0)
                {
                    _trackedAgents.TryRemove(agentId, out _);
                }
            }
        }

        return totalRemoved;
    }

    private List<DateTimeOffset> GetBucketTimestamps(string agentId)
    {
        return _rateLimitStore.GetBucketAsync(agentId).GetAwaiter().GetResult()?.Timestamps.ToList()
            ?? [];
    }

    private void SaveBucket(string agentId, List<DateTimeOffset> timestamps)
    {
        _rateLimitStore.SetBucketAsync(agentId, new McpRateLimitBucket(timestamps)).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Removes timestamps that are older than <paramref name="cutoff"/>.
    /// Because timestamps are recorded in chronological order, only the oldest prefix can expire.
    /// </summary>
    private static void PruneExpired(List<DateTimeOffset> timestamps, DateTimeOffset cutoff)
    {
        int removeCount = 0;
        while (removeCount < timestamps.Count && timestamps[removeCount] <= cutoff)
        {
            removeCount++;
        }

        if (removeCount > 0)
        {
            timestamps.RemoveRange(0, removeCount);
        }
    }
}
