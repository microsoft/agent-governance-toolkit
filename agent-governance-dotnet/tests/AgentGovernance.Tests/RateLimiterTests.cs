// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.RateLimiting;
using Xunit;

namespace AgentGovernance.Tests;

public class RateLimiterTests
{
    [Fact]
    public void TryAcquire_WithinLimit_ReturnsTrue()
    {
        var limiter = new RateLimiter();
        for (int i = 0; i < 5; i++)
        {
            Assert.True(limiter.TryAcquire("agent:tool", 5, TimeSpan.FromMinutes(1)));
        }
    }

    [Fact]
    public void TryAcquire_ExceedsLimit_ReturnsFalse()
    {
        var limiter = new RateLimiter();
        for (int i = 0; i < 3; i++)
        {
            Assert.True(limiter.TryAcquire("agent:tool", 3, TimeSpan.FromMinutes(1)));
        }
        Assert.False(limiter.TryAcquire("agent:tool", 3, TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void TryAcquire_DifferentKeys_IndependentLimits()
    {
        var limiter = new RateLimiter();
        Assert.True(limiter.TryAcquire("agent1:tool", 1, TimeSpan.FromMinutes(1)));
        Assert.False(limiter.TryAcquire("agent1:tool", 1, TimeSpan.FromMinutes(1)));

        // Different key should still be allowed.
        Assert.True(limiter.TryAcquire("agent2:tool", 1, TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void GetCurrentCount_ReturnsAccurateCount()
    {
        var limiter = new RateLimiter();
        limiter.TryAcquire("key", 10, TimeSpan.FromMinutes(1));
        limiter.TryAcquire("key", 10, TimeSpan.FromMinutes(1));
        limiter.TryAcquire("key", 10, TimeSpan.FromMinutes(1));

        Assert.Equal(3, limiter.GetCurrentCount("key", TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void GetCurrentCount_UnknownKey_ReturnsZero()
    {
        var limiter = new RateLimiter();
        Assert.Equal(0, limiter.GetCurrentCount("unknown", TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void Reset_ClearsAllState()
    {
        var limiter = new RateLimiter();
        limiter.TryAcquire("key", 1, TimeSpan.FromMinutes(1));
        Assert.False(limiter.TryAcquire("key", 1, TimeSpan.FromMinutes(1)));

        limiter.Reset();
        Assert.True(limiter.TryAcquire("key", 1, TimeSpan.FromMinutes(1)));
    }

    [Theory]
    [InlineData("100/minute", 100, 60_000)]
    [InlineData("50/hour", 50, 3_600_000)]
    [InlineData("10/second", 10, 1_000)]
    [InlineData("5/day", 5, 86_400_000)]
    [InlineData("200/min", 200, 60_000)]
    [InlineData("30/h", 30, 3_600_000)]
    [InlineData("1000/s", 1000, 1_000)]
    public void ParseLimit_ValidExpressions_ParsesCorrectly(string expr, int expectedMax, double expectedWindowMs)
    {
        var (maxCalls, window) = RateLimiter.ParseLimit(expr);
        Assert.Equal(expectedMax, maxCalls);
        Assert.Equal(expectedWindowMs, window.TotalMilliseconds);
    }

    [Theory]
    [InlineData("")]
    [InlineData("100")]
    [InlineData("abc/minute")]
    [InlineData("0/minute")]
    [InlineData("-5/hour")]
    [InlineData("100/fortnight")]
    public void ParseLimit_InvalidExpressions_Throws(string expr)
    {
        if (string.IsNullOrEmpty(expr))
        {
            Assert.ThrowsAny<ArgumentException>(() => RateLimiter.ParseLimit(expr));
        }
        else
        {
            Assert.ThrowsAny<Exception>(() => RateLimiter.ParseLimit(expr));
        }
    }

    [Fact]
    public void TryAcquire_InvalidArgs_Throws()
    {
        var limiter = new RateLimiter();
        Assert.ThrowsAny<ArgumentException>(() => limiter.TryAcquire("", 5, TimeSpan.FromMinutes(1)));
        Assert.Throws<ArgumentOutOfRangeException>(() => limiter.TryAcquire("key", 0, TimeSpan.FromMinutes(1)));
        Assert.Throws<ArgumentOutOfRangeException>(() => limiter.TryAcquire("key", 5, TimeSpan.Zero));
    }
}
