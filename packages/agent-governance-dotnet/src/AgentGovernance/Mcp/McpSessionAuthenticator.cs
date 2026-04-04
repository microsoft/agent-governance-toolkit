// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Security.Cryptography;
using AgentGovernance.Mcp.Abstractions;
using Microsoft.Extensions.Logging;

namespace AgentGovernance.Mcp;

/// <summary>
/// Authenticates MCP sessions by binding agent identities to cryptographic session tokens.
/// Implements OWASP MCP Security Cheat Sheet §6: sessions are bound to user/agent context,
/// validated on each request, and expire after a configurable TTL.
/// <para>
/// Prevents rate-limiter bypass via agent ID spoofing by requiring authenticated sessions.
/// Session IDs are cryptographically random (not sequential or predictable).
/// </para>
/// </summary>
public sealed class McpSessionAuthenticator
{
    private readonly IMcpSessionStore _sessionStore;
    private readonly ConcurrentDictionary<string, string> _trackedSessions = new(StringComparer.Ordinal);
    private readonly object _sessionLock = new();
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a new authenticator with in-memory storage and the system clock.
    /// </summary>
    public McpSessionAuthenticator()
        : this(new InMemoryMcpSessionStore(), TimeProvider.System)
    {
    }

    /// <summary>
    /// Initializes a new authenticator with explicit persistence and clock dependencies.
    /// </summary>
    /// <param name="sessionStore">The session store used for token persistence.</param>
    /// <param name="timeProvider">The clock used for session timestamps and expiry checks.</param>
    public McpSessionAuthenticator(IMcpSessionStore sessionStore, TimeProvider? timeProvider = null)
    {
        _sessionStore = sessionStore ?? throw new ArgumentNullException(nameof(sessionStore));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>Session TTL. Defaults to 1 hour.</summary>
    public TimeSpan SessionTtl { get; init; } = TimeSpan.FromHours(1);

    /// <summary>Maximum concurrent sessions per agent. Defaults to 10.</summary>
    public int MaxSessionsPerAgent { get; init; } = 10;

    /// <summary>
    /// Optional logger for recording session lifecycle events.
    /// When <c>null</c>, no logging occurs — the authenticator operates silently.
    /// </summary>
    public ILogger<McpSessionAuthenticator>? Logger { get; set; }

    /// <summary>
    /// Creates a new authenticated session for an agent.
    /// </summary>
    /// <param name="agentId">The agent's DID (e.g., "did:mesh:agent-001").</param>
    /// <param name="userId">Optional user context to bind the session to.</param>
    /// <returns>
    /// A session token that must be presented with each request,
    /// or <c>null</c> when session persistence fails and the authenticator fails closed.
    /// </returns>
    /// <exception cref="ArgumentException">If agentId is null or whitespace.</exception>
    /// <exception cref="InvalidOperationException">If agent has exceeded max concurrent sessions.</exception>
    public string? CreateSession(string agentId, string? userId = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);

        // Lock to prevent TOCTOU race between count check and add
        lock (_sessionLock)
        {
            var now = _timeProvider.GetUtcNow();
            var activeSessions = GetTrackedSessions(now, removeExpired: true);
            if (activeSessions is null)
            {
                return null;
            }

            // Check max sessions per agent
            var agentSessionCount = activeSessions.Count(session => string.Equals(session.Session.AgentId, agentId, StringComparison.Ordinal));
            if (agentSessionCount >= MaxSessionsPerAgent)
                throw new InvalidOperationException($"Agent '{agentId}' has exceeded maximum concurrent sessions ({MaxSessionsPerAgent}).");

            // Generate cryptographic session token
            var tokenBytes = RandomNumberGenerator.GetBytes(32);
            var token = Convert.ToBase64String(tokenBytes);

            var session = new McpSession
            {
                Token = token,
                AgentId = agentId,
                UserId = userId,
                CreatedAt = now,
                ExpiresAt = now.Add(SessionTtl),
                // Composite key for rate limiting: userId:agentId or just agentId
                RateLimitKey = userId is not null ? $"{userId}:{agentId}" : agentId
            };

            if (!TrySetSession(session))
            {
                return null;
            }

            _trackedSessions[token] = agentId;
            Logger?.LogInformation("MCP session created for {AgentId}", agentId);
            return token;
        }
    }

    /// <summary>
    /// Validates a request against an existing session.
    /// </summary>
    /// <param name="agentId">The agent's DID claiming this session.</param>
    /// <param name="sessionToken">The session token to validate.</param>
    /// <returns>The authenticated session, or <c>null</c> if validation fails.</returns>
    public McpSession? ValidateRequest(string agentId, string sessionToken)
    {
        if (string.IsNullOrWhiteSpace(agentId) || string.IsNullOrWhiteSpace(sessionToken))
        {
            Logger?.LogWarning("MCP session validation failed for {AgentId}: {Reason}", agentId ?? "(null)", "missing agentId or sessionToken");
            return null;
        }

        if (!TryGetSession(sessionToken, "validating request", out var session))
        {
            Logger?.LogWarning("MCP session validation failed for {AgentId}: {Reason}", agentId, "session store unavailable");
            return null;
        }

        if (session is null)
        {
            _trackedSessions.TryRemove(sessionToken, out _);
            Logger?.LogWarning("MCP session validation failed for {AgentId}: {Reason}", agentId, "session token not found");
            return null;
        }

        _trackedSessions[sessionToken] = session.AgentId;

        // Check agent ID matches (prevent token theft)
        if (!string.Equals(session.AgentId, agentId, StringComparison.Ordinal))
        {
            Logger?.LogWarning("MCP session validation failed for {AgentId}: {Reason}", agentId, "agent ID mismatch");
            return null;
        }

        // Check expiry
        if (session.IsExpiredAt(_timeProvider.GetUtcNow()))
        {
            Logger?.LogWarning("MCP session validation failed for {AgentId}: {Reason}", agentId, "session expired");
            if (TryDeleteSession(sessionToken, "removing expired session", out _))
            {
                _trackedSessions.TryRemove(sessionToken, out _);
            }

            return null;
        }

        return session;
    }

    /// <summary>
    /// Revokes a session token immediately.
    /// </summary>
    /// <param name="sessionToken">The token to revoke.</param>
    /// <returns><c>true</c> if the session was found and removed; otherwise <c>false</c>.</returns>
    public bool RevokeSession(string sessionToken)
    {
        if (!TryDeleteSession(sessionToken, "revoking session", out var removed))
        {
            return false;
        }

        if (removed)
        {
            _trackedSessions.TryRemove(sessionToken, out _);
        }

        return removed;
    }

    /// <summary>
    /// Revokes all sessions for an agent.
    /// </summary>
    /// <param name="agentId">The agent whose sessions should be revoked.</param>
    /// <returns>The number of sessions revoked.</returns>
    public int RevokeAllSessions(string agentId)
    {
        lock (_sessionLock)
        {
            var now = _timeProvider.GetUtcNow();
            var trackedSessions = GetTrackedSessions(now, removeExpired: false);
            if (trackedSessions is null)
            {
                return 0;
            }

            var toRemove = trackedSessions
                .Where(session => string.Equals(session.Session.AgentId, agentId, StringComparison.Ordinal))
                .Select(session => session.Token)
                .ToList();

            foreach (var token in toRemove)
            {
                if (TryDeleteSession(token, "revoking all sessions", out var removed) && removed)
                {
                    _trackedSessions.TryRemove(token, out _);
                }
            }

            return toRemove.Count;
        }
    }

    /// <summary>
    /// Removes expired sessions from the cache.
    /// </summary>
    /// <returns>The number of expired sessions removed.</returns>
    public int CleanupExpiredSessions()
    {
        lock (_sessionLock)
        {
            var now = _timeProvider.GetUtcNow();
            var trackedSessions = GetTrackedSessions(now, removeExpired: false);
            if (trackedSessions is null)
            {
                return 0;
            }

            var expired = trackedSessions
                .Where(session => session.Session.IsExpiredAt(now))
                .ToList();

            var removedCount = 0;
            foreach (var sessionEntry in expired)
            {
                if (TryDeleteSession(sessionEntry.Token, "cleaning up expired sessions", out var removed) && removed)
                {
                    _trackedSessions.TryRemove(sessionEntry.Token, out _);
                    Logger?.LogDebug("MCP session expired for {AgentId}", sessionEntry.Session.AgentId);
                    removedCount++;
                }
            }

            return removedCount;
        }
    }

    /// <summary>
    /// Gets the count of active (non-expired) sessions.
    /// </summary>
    public int ActiveSessionCount
    {
        get
        {
            lock (_sessionLock)
            {
                return GetTrackedSessions(_timeProvider.GetUtcNow(), removeExpired: true)?.Count ?? 0;
            }
        }
    }

    private bool TrySetSession(McpSession session)
    {
        try
        {
            _sessionStore.SetAsync(session.Token, session).GetAwaiter().GetResult();
            return true;
        }
        catch (Exception ex)
        {
            Logger?.LogError(ex, "MCP session store write failed for {AgentId}", session.AgentId);
            return false;
        }
    }

    private bool TryGetSession(string token, string operation, out McpSession? session)
    {
        try
        {
            session = _sessionStore.GetAsync(token).GetAwaiter().GetResult();
            return true;
        }
        catch (Exception ex)
        {
            Logger?.LogError(ex, "MCP session store read failed while {Operation}", operation);
            session = null;
            return false;
        }
    }

    private bool TryDeleteSession(string token, string operation, out bool removed)
    {
        try
        {
            removed = _sessionStore.DeleteAsync(token).GetAwaiter().GetResult();
            return true;
        }
        catch (Exception ex)
        {
            Logger?.LogError(ex, "MCP session store delete failed while {Operation}", operation);
            removed = false;
            return false;
        }
    }

    private List<(string Token, McpSession Session)>? GetTrackedSessions(DateTimeOffset now, bool removeExpired)
    {
        var sessions = new List<(string Token, McpSession Session)>();
        foreach (var token in _trackedSessions.Keys.ToList())
        {
            if (!TryGetSession(token, "enumerating tracked sessions", out var session))
            {
                return null;
            }

            if (session is null)
            {
                _trackedSessions.TryRemove(token, out _);
                continue;
            }

            if (removeExpired && session.IsExpiredAt(now))
            {
                if (!TryDeleteSession(token, "removing expired tracked session", out _))
                {
                    return null;
                }

                _trackedSessions.TryRemove(token, out _);
                continue;
            }

            _trackedSessions[token] = session.AgentId;
            sessions.Add((token, session));
        }

        return sessions;
    }
}

/// <summary>
/// Represents an authenticated MCP session bound to an agent identity.
/// </summary>
public sealed class McpSession
{
    /// <summary>Cryptographic session token.</summary>
    public required string Token { get; init; }

    /// <summary>The agent's DID this session is bound to.</summary>
    public required string AgentId { get; init; }

    /// <summary>Optional user context (for user:agent binding).</summary>
    public string? UserId { get; init; }

    /// <summary>When the session was created.</summary>
    public DateTimeOffset CreatedAt { get; init; }

    /// <summary>When the session expires.</summary>
    public DateTimeOffset ExpiresAt { get; init; }

    /// <summary>
    /// Composite key for rate limiting. Format: "userId:agentId" or just "agentId".
    /// </summary>
    public required string RateLimitKey { get; init; }

    /// <summary>Whether this session has expired.</summary>
    public bool IsExpired => IsExpiredAt(TimeProvider.System.GetUtcNow());

    /// <summary>
    /// Determines whether the session is expired at the supplied time.
    /// </summary>
    /// <param name="currentTime">The time to compare against <see cref="ExpiresAt"/>.</param>
    /// <returns><c>true</c> when the session has expired; otherwise <c>false</c>.</returns>
    public bool IsExpiredAt(DateTimeOffset currentTime) => currentTime >= ExpiresAt;
}
