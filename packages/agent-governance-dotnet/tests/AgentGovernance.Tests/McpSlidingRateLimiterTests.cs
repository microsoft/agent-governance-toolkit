// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Reflection;
using AgentGovernance.Mcp;
using AgentGovernance.Mcp.Abstractions;
using Xunit;

namespace AgentGovernance.Tests;

public class McpSlidingRateLimiterTests
{
    private static int GetBucketLockCount(McpSlidingRateLimiter limiter)
    {
        var field = typeof(McpSlidingRateLimiter).GetField("_bucketLocks", BindingFlags.Instance | BindingFlags.NonPublic);
        var bucketLocks = Assert.IsAssignableFrom<System.Collections.IDictionary>(field?.GetValue(limiter));
        return bucketLocks.Count;
    }

    // ── TryAcquire basics ────────────────────────────────────────────────

    [Fact]
    public void TryAcquire_UnderLimit_ReturnsTrue()
    {
        var limiter = new McpSlidingRateLimiter { MaxCallsPerWindow = 5 };

        Assert.True(limiter.TryAcquire("agent-1"));
        Assert.True(limiter.TryAcquire("agent-1"));
        Assert.True(limiter.TryAcquire("agent-1"));
    }

    [Fact]
    public void TryAcquire_AtLimit_ReturnsFalse()
    {
        var limiter = new McpSlidingRateLimiter { MaxCallsPerWindow = 3 };

        Assert.True(limiter.TryAcquire("agent-1"));
        Assert.True(limiter.TryAcquire("agent-1"));
        Assert.True(limiter.TryAcquire("agent-1"));

        // 4th call should be denied
        Assert.False(limiter.TryAcquire("agent-1"));
        Assert.False(limiter.TryAcquire("agent-1")); // still denied
    }

    [Fact]
    public void TryAcquire_SingleCallLimit_WorksCorrectly()
    {
        var limiter = new McpSlidingRateLimiter { MaxCallsPerWindow = 1 };

        Assert.True(limiter.TryAcquire("agent-1"));
        Assert.False(limiter.TryAcquire("agent-1"));
    }

    // ── Window expiry ────────────────────────────────────────────────────

    [Fact]
    public void TryAcquire_AfterWindowExpires_AllowsAgain()
    {
        var timeProvider = new ManualTimeProvider(DateTimeOffset.Parse("2024-01-01T00:00:00Z"));
        var limiter = new McpSlidingRateLimiter(new InMemoryMcpRateLimitStore(), timeProvider)
        {
            MaxCallsPerWindow = 2,
            WindowSize = TimeSpan.FromMilliseconds(100)
        };

        Assert.True(limiter.TryAcquire("agent-1"));
        Assert.True(limiter.TryAcquire("agent-1"));
        Assert.False(limiter.TryAcquire("agent-1"));

        timeProvider.Advance(TimeSpan.FromMilliseconds(150));

        // Should be allowed again
        Assert.True(limiter.TryAcquire("agent-1"));
        Assert.True(limiter.TryAcquire("agent-1"));
        Assert.False(limiter.TryAcquire("agent-1"));
    }

    [Fact]
    public void TryAcquire_PartialWindowExpiry_SlidesCorrectly()
    {
        var timeProvider = new ManualTimeProvider(DateTimeOffset.Parse("2024-01-01T00:00:00Z"));
        var limiter = new McpSlidingRateLimiter(new InMemoryMcpRateLimitStore(), timeProvider)
        {
            MaxCallsPerWindow = 2,
            WindowSize = TimeSpan.FromMilliseconds(100)
        };

        // Fill the window
        Assert.True(limiter.TryAcquire("agent-1"));
        Assert.True(limiter.TryAcquire("agent-1"));
        Assert.False(limiter.TryAcquire("agent-1"));

        timeProvider.Advance(TimeSpan.FromMilliseconds(150));

        // Make one call
        Assert.True(limiter.TryAcquire("agent-1"));

        // Should still have one more available
        Assert.True(limiter.TryAcquire("agent-1"));
        Assert.False(limiter.TryAcquire("agent-1"));
    }

    // ── Per-agent isolation ──────────────────────────────────────────────

    [Fact]
    public void TryAcquire_DifferentAgents_IndependentBudgets()
    {
        var limiter = new McpSlidingRateLimiter { MaxCallsPerWindow = 1 };

        Assert.True(limiter.TryAcquire("agent-A"));
        Assert.False(limiter.TryAcquire("agent-A"));

        // Agent B is independent
        Assert.True(limiter.TryAcquire("agent-B"));
        Assert.False(limiter.TryAcquire("agent-B"));
    }

    [Fact]
    public void TryAcquire_AgentId_CaseInsensitive()
    {
        var limiter = new McpSlidingRateLimiter { MaxCallsPerWindow = 1 };

        Assert.True(limiter.TryAcquire("Agent-A"));
        Assert.False(limiter.TryAcquire("agent-a")); // same agent, different case
    }

    // ── GetRemainingBudget ───────────────────────────────────────────────

    [Fact]
    public void GetRemainingBudget_UnknownAgent_ReturnsMax()
    {
        var limiter = new McpSlidingRateLimiter { MaxCallsPerWindow = 10 };

        Assert.Equal(10, limiter.GetRemainingBudget("unknown"));
    }

    [Fact]
    public void GetRemainingBudget_AfterCalls_ReturnsCorrectCount()
    {
        var limiter = new McpSlidingRateLimiter { MaxCallsPerWindow = 5 };

        limiter.TryAcquire("agent-1");
        limiter.TryAcquire("agent-1");
        limiter.TryAcquire("agent-1");

        Assert.Equal(2, limiter.GetRemainingBudget("agent-1"));
    }

    [Fact]
    public void GetRemainingBudget_AtLimit_ReturnsZero()
    {
        var limiter = new McpSlidingRateLimiter { MaxCallsPerWindow = 2 };

        limiter.TryAcquire("agent-1");
        limiter.TryAcquire("agent-1");

        Assert.Equal(0, limiter.GetRemainingBudget("agent-1"));
    }

    [Fact]
    public void GetRemainingBudget_AfterExpiry_RestoresToMax()
    {
        var timeProvider = new ManualTimeProvider(DateTimeOffset.Parse("2024-01-01T00:00:00Z"));
        var limiter = new McpSlidingRateLimiter(new InMemoryMcpRateLimitStore(), timeProvider)
        {
            MaxCallsPerWindow = 3,
            WindowSize = TimeSpan.FromMilliseconds(80)
        };

        limiter.TryAcquire("agent-1");
        limiter.TryAcquire("agent-1");
        Assert.Equal(1, limiter.GetRemainingBudget("agent-1"));

        timeProvider.Advance(TimeSpan.FromMilliseconds(120));

        Assert.Equal(3, limiter.GetRemainingBudget("agent-1"));
    }

    // ── GetCallCount ─────────────────────────────────────────────────────

    [Fact]
    public void GetCallCount_UnknownAgent_ReturnsZero()
    {
        var limiter = new McpSlidingRateLimiter();
        Assert.Equal(0, limiter.GetCallCount("unknown"));
    }

    [Fact]
    public void GetCallCount_ReturnsAccurateCount()
    {
        var limiter = new McpSlidingRateLimiter { MaxCallsPerWindow = 10 };

        limiter.TryAcquire("agent-1");
        limiter.TryAcquire("agent-1");

        Assert.Equal(2, limiter.GetCallCount("agent-1"));
    }

    // ── Reset ────────────────────────────────────────────────────────────

    [Fact]
    public void Reset_ClearsSingleAgent()
    {
        var limiter = new McpSlidingRateLimiter { MaxCallsPerWindow = 1 };

        limiter.TryAcquire("agent-A");
        limiter.TryAcquire("agent-B");

        Assert.False(limiter.TryAcquire("agent-A"));
        Assert.False(limiter.TryAcquire("agent-B"));

        limiter.Reset("agent-A");

        // Agent A should be restored, B still blocked
        Assert.True(limiter.TryAcquire("agent-A"));
        Assert.False(limiter.TryAcquire("agent-B"));
    }

    [Fact]
    public void Reset_UnknownAgent_DoesNotThrow()
    {
        var limiter = new McpSlidingRateLimiter();
        limiter.Reset("nonexistent"); // should be a no-op
    }

    // ── ResetAll ─────────────────────────────────────────────────────────

    [Fact]
    public void ResetAll_ClearsAllAgents()
    {
        var limiter = new McpSlidingRateLimiter { MaxCallsPerWindow = 1 };

        limiter.TryAcquire("agent-A");
        limiter.TryAcquire("agent-B");
        limiter.TryAcquire("agent-C");

        limiter.ResetAll();

        Assert.True(limiter.TryAcquire("agent-A"));
        Assert.True(limiter.TryAcquire("agent-B"));
        Assert.True(limiter.TryAcquire("agent-C"));
    }

    [Fact]
    public void ResetAll_EmptyLimiter_DoesNotThrow()
    {
        var limiter = new McpSlidingRateLimiter();
        limiter.ResetAll(); // no-op
    }

    // ── CleanupExpired ───────────────────────────────────────────────────

    [Fact]
    public void CleanupExpired_RemovesOldEntries()
    {
        var timeProvider = new ManualTimeProvider(DateTimeOffset.Parse("2024-01-01T00:00:00Z"));
        var limiter = new McpSlidingRateLimiter(new InMemoryMcpRateLimitStore(), timeProvider)
        {
            MaxCallsPerWindow = 100,
            WindowSize = TimeSpan.FromMilliseconds(80)
        };

        limiter.TryAcquire("agent-1");
        limiter.TryAcquire("agent-1");
        limiter.TryAcquire("agent-2");

        timeProvider.Advance(TimeSpan.FromMilliseconds(120));

        int removed = limiter.CleanupExpired();

        Assert.Equal(3, removed);
        Assert.Equal(0, limiter.GetCallCount("agent-1"));
        Assert.Equal(0, limiter.GetCallCount("agent-2"));
    }

    [Fact]
    public void CleanupExpired_KeepsRecentEntries()
    {
        var limiter = new McpSlidingRateLimiter
        {
            MaxCallsPerWindow = 100,
            WindowSize = TimeSpan.FromMinutes(5) // long window
        };

        limiter.TryAcquire("agent-1");
        limiter.TryAcquire("agent-1");

        int removed = limiter.CleanupExpired();

        Assert.Equal(0, removed);
        Assert.Equal(2, limiter.GetCallCount("agent-1"));
    }

    [Fact]
    public void CleanupExpired_EmptyLimiter_ReturnsZero()
    {
        var limiter = new McpSlidingRateLimiter();
        Assert.Equal(0, limiter.CleanupExpired());
    }

    [Fact]
    public void CleanupExpired_EvictsInactiveLockEntries()
    {
        var timeProvider = new ManualTimeProvider(DateTimeOffset.Parse("2024-01-01T00:00:00Z"));
        var limiter = new McpSlidingRateLimiter(new InMemoryMcpRateLimitStore(), timeProvider)
        {
            WindowSize = TimeSpan.FromMilliseconds(50),
            LockEntryTtl = TimeSpan.FromMilliseconds(1),
            LockSweepInterval = TimeSpan.Zero
        };

        limiter.TryAcquire("agent-1");
        Assert.Equal(1, GetBucketLockCount(limiter));

        timeProvider.Advance(TimeSpan.FromMilliseconds(100));

        limiter.CleanupExpired();

        Assert.Equal(0, GetBucketLockCount(limiter));
    }

    // ── Thread safety ────────────────────────────────────────────────────

    [Fact]
    public void TryAcquire_ConcurrentAccess_DoesNotExceedLimit()
    {
        const int maxCalls = 50;
        var limiter = new McpSlidingRateLimiter
        {
            MaxCallsPerWindow = maxCalls,
            WindowSize = TimeSpan.FromMinutes(5)
        };

        int totalAllowed = 0;
        var tasks = new Task[10];

        for (int t = 0; t < tasks.Length; t++)
        {
            tasks[t] = Task.Run(() =>
            {
                for (int i = 0; i < maxCalls; i++)
                {
                    if (limiter.TryAcquire("agent-shared"))
                    {
                        Interlocked.Increment(ref totalAllowed);
                    }
                }
            });
        }

        Task.WaitAll(tasks);

        // Exactly maxCalls should have been allowed, no more
        Assert.Equal(maxCalls, totalAllowed);
    }

    [Fact]
    public void TryAcquire_ConcurrentDifferentAgents_AllGetFullBudget()
    {
        const int maxCalls = 10;
        var limiter = new McpSlidingRateLimiter
        {
            MaxCallsPerWindow = maxCalls,
            WindowSize = TimeSpan.FromMinutes(5)
        };

        var agentCounts = new int[5];
        var tasks = new Task[agentCounts.Length];

        for (int a = 0; a < agentCounts.Length; a++)
        {
            int agentIndex = a;
            tasks[a] = Task.Run(() =>
            {
                for (int i = 0; i < maxCalls + 5; i++) // try more than allowed
                {
                    if (limiter.TryAcquire($"agent-{agentIndex}"))
                    {
                        Interlocked.Increment(ref agentCounts[agentIndex]);
                    }
                }
            });
        }

        Task.WaitAll(tasks);

        // Each agent should get exactly maxCalls
        foreach (var count in agentCounts)
        {
            Assert.Equal(maxCalls, count);
        }
    }

    // ── Argument validation ──────────────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void TryAcquire_NullOrEmptyAgentId_Throws(string? agentId)
    {
        var limiter = new McpSlidingRateLimiter();
        Assert.ThrowsAny<ArgumentException>(() => limiter.TryAcquire(agentId!));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void GetRemainingBudget_NullOrEmptyAgentId_Throws(string? agentId)
    {
        var limiter = new McpSlidingRateLimiter();
        Assert.ThrowsAny<ArgumentException>(() => limiter.GetRemainingBudget(agentId!));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void GetCallCount_NullOrEmptyAgentId_Throws(string? agentId)
    {
        var limiter = new McpSlidingRateLimiter();
        Assert.ThrowsAny<ArgumentException>(() => limiter.GetCallCount(agentId!));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Reset_NullOrEmptyAgentId_Throws(string? agentId)
    {
        var limiter = new McpSlidingRateLimiter();
        Assert.ThrowsAny<ArgumentException>(() => limiter.Reset(agentId!));
    }

    // ── Default configuration ────────────────────────────────────────────

    [Fact]
    public void Defaults_AreCorrect()
    {
        var limiter = new McpSlidingRateLimiter();

        Assert.Equal(100, limiter.MaxCallsPerWindow);
        Assert.Equal(TimeSpan.FromMinutes(5), limiter.WindowSize);
    }
}
