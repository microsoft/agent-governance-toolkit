// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Collections.Concurrent;

namespace AgentGovernance.RateLimiting;

/// <summary>
/// Thread-safe sliding window rate limiter for governance policy enforcement.
/// Tracks call counts per key (agent + scope) within configurable time windows.
/// </summary>
public sealed class RateLimiter
{
    private const int MaxTrackedKeys = 50_000;
    private readonly ConcurrentDictionary<string, CallWindow> _windows = new();

    /// <summary>
    /// Checks whether a call is permitted under the rate limit and records it if so.
    /// </summary>
    /// <param name="key">
    /// A composite key identifying the rate-limit scope (e.g., "did:agentmesh:abc123:file_write").
    /// </param>
    /// <param name="maxCalls">Maximum number of calls allowed within the window.</param>
    /// <param name="window">The sliding time window duration.</param>
    /// <returns><c>true</c> if the call is within limits; <c>false</c> if rate-limited.</returns>
    public bool TryAcquire(string key, int maxCalls, TimeSpan window)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        if (maxCalls <= 0) throw new ArgumentOutOfRangeException(nameof(maxCalls));
        if (window <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(window));

        var callWindow = _windows.GetOrAdd(key, _ => new CallWindow());

        // Prevent unbounded dictionary growth: prune stale keys when at capacity.
        if (_windows.Count > MaxTrackedKeys)
        {
            PruneStaleKeys(window);
        }

        return callWindow.TryRecord(maxCalls, window);
    }

    /// <summary>
    /// Returns the current call count for a key within the specified window.
    /// </summary>
    public int GetCurrentCount(string key, TimeSpan window)
    {
        if (_windows.TryGetValue(key, out var callWindow))
        {
            return callWindow.CountWithin(window);
        }
        return 0;
    }

    /// <summary>
    /// Removes all tracked state. Useful for testing.
    /// </summary>
    public void Reset() => _windows.Clear();

    private void PruneStaleKeys(TimeSpan window)
    {
        foreach (var kvp in _windows)
        {
            if (kvp.Value.CountWithin(window) == 0)
            {
                _windows.TryRemove(kvp.Key, out _);
            }
        }
    }

    /// <summary>
    /// Parses a rate-limit expression like "100/minute", "50/hour", "10/second".
    /// </summary>
    /// <param name="limitExpression">The limit expression string.</param>
    /// <returns>A tuple of (maxCalls, window).</returns>
    /// <exception cref="FormatException">Thrown when the expression cannot be parsed.</exception>
    public static (int MaxCalls, TimeSpan Window) ParseLimit(string limitExpression)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(limitExpression);

        var parts = limitExpression.Trim().Split('/');
        if (parts.Length != 2 || !int.TryParse(parts[0].Trim(), out var maxCalls) || maxCalls <= 0)
        {
            throw new FormatException($"Invalid rate-limit expression: '{limitExpression}'. Expected format: '100/minute'.");
        }

        var unit = parts[1].Trim().ToLowerInvariant();
        var window = unit switch
        {
            "s" or "sec" or "second" => TimeSpan.FromSeconds(1),
            "m" or "min" or "minute" => TimeSpan.FromMinutes(1),
            "h" or "hr" or "hour" => TimeSpan.FromHours(1),
            "d" or "day" => TimeSpan.FromDays(1),
            _ => throw new FormatException($"Unknown time unit: '{unit}'. Use second, minute, hour, or day.")
        };

        return (maxCalls, window);
    }

    /// <summary>
    /// Sliding window implemented as a lock-protected queue of timestamps.
    /// </summary>
    private sealed class CallWindow
    {
        private readonly object _lock = new();
        private readonly Queue<long> _timestamps = new();

        public bool TryRecord(int maxCalls, TimeSpan window)
        {
            lock (_lock)
            {
                Prune(window);

                if (_timestamps.Count >= maxCalls)
                {
                    return false;
                }

                _timestamps.Enqueue(Environment.TickCount64);
                return true;
            }
        }

        public int CountWithin(TimeSpan window)
        {
            lock (_lock)
            {
                Prune(window);
                return _timestamps.Count;
            }
        }

        private void Prune(TimeSpan window)
        {
            var cutoff = Environment.TickCount64 - (long)window.TotalMilliseconds;
            while (_timestamps.Count > 0 && _timestamps.Peek() < cutoff)
            {
                _timestamps.Dequeue();
            }
        }
    }
}
