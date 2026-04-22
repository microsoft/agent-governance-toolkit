// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.RateLimiting;
using Xunit;

namespace AgentGovernance.Tests;

public class RateLimiterAdvancedTests
{
    [Fact]
    public void TryAcquire_ExactlyAtLimit_LastCallSucceeds()
    {
        var limiter = new RateLimiter();
        for (int i = 0; i < 5; i++)
            Assert.True(limiter.TryAcquire("key", 5, TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void TryAcquire_OneOverLimit_Fails()
    {
        var limiter = new RateLimiter();
        for (int i = 0; i < 5; i++)
            limiter.TryAcquire("key", 5, TimeSpan.FromMinutes(1));
        Assert.False(limiter.TryAcquire("key", 5, TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void TryAcquire_LimitOfOne_SecondCallFails()
    {
        var limiter = new RateLimiter();
        Assert.True(limiter.TryAcquire("key", 1, TimeSpan.FromMinutes(1)));
        Assert.False(limiter.TryAcquire("key", 1, TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void TryAcquire_LimitOfZero_ThrowsArgumentOutOfRange()
    {
        var limiter = new RateLimiter();
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            limiter.TryAcquire("key", 0, TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void TryAcquire_NegativeLimit_ThrowsArgumentOutOfRange()
    {
        var limiter = new RateLimiter();
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            limiter.TryAcquire("key", -1, TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void TryAcquire_ZeroWindow_ThrowsArgumentOutOfRange()
    {
        var limiter = new RateLimiter();
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            limiter.TryAcquire("key", 10, TimeSpan.Zero));
    }

    [Fact]
    public void TryAcquire_DifferentKeys_Independent()
    {
        var limiter = new RateLimiter();
        Assert.True(limiter.TryAcquire("a", 1, TimeSpan.FromMinutes(1)));
        Assert.True(limiter.TryAcquire("b", 1, TimeSpan.FromMinutes(1)));
        Assert.False(limiter.TryAcquire("a", 1, TimeSpan.FromMinutes(1)));
        Assert.True(limiter.TryAcquire("c", 1, TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void TryAcquire_ManyDistinctKeys_AllIndependent()
    {
        var limiter = new RateLimiter();
        for (int i = 0; i < 100; i++)
            Assert.True(limiter.TryAcquire($"key-{i}", 1, TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void GetCurrentCount_NoAcquisitions_Zero()
    {
        var limiter = new RateLimiter();
        Assert.Equal(0, limiter.GetCurrentCount("x", TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void GetCurrentCount_AfterAcquisitions_Correct()
    {
        var limiter = new RateLimiter();
        for (int i = 0; i < 3; i++)
            limiter.TryAcquire("key", 10, TimeSpan.FromMinutes(1));
        Assert.Equal(3, limiter.GetCurrentCount("key", TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void Reset_ClearsAllKeys()
    {
        var limiter = new RateLimiter();
        limiter.TryAcquire("a", 10, TimeSpan.FromMinutes(1));
        limiter.TryAcquire("b", 10, TimeSpan.FromMinutes(1));
        limiter.Reset();
        Assert.Equal(0, limiter.GetCurrentCount("a", TimeSpan.FromMinutes(1)));
        Assert.Equal(0, limiter.GetCurrentCount("b", TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void Reset_AllowsNewAcquisitions()
    {
        var limiter = new RateLimiter();
        limiter.TryAcquire("key", 1, TimeSpan.FromMinutes(1));
        Assert.False(limiter.TryAcquire("key", 1, TimeSpan.FromMinutes(1)));
        limiter.Reset();
        Assert.True(limiter.TryAcquire("key", 1, TimeSpan.FromMinutes(1)));
    }

    [Theory]
    [InlineData("10/second", 10, 1)]
    [InlineData("100/minute", 100, 60)]
    [InlineData("5000/hour", 5000, 3600)]
    [InlineData("100000/day", 100000, 86400)]
    public void ParseLimit_ValidExpressions_Parsed(string expr, int expectedMax, int expectedSec)
    {
        var (max, window) = RateLimiter.ParseLimit(expr);
        Assert.Equal(expectedMax, max);
        Assert.Equal(expectedSec, (int)window.TotalSeconds);
    }

    [Theory]
    [InlineData("")]
    [InlineData("invalid")]
    [InlineData("10")]
    [InlineData("abc/minute")]
    [InlineData("10/nanosecond")]
    public void ParseLimit_InvalidExpressions_Throws(string expr)
    {
        Assert.ThrowsAny<Exception>(() => RateLimiter.ParseLimit(expr));
    }

    [Fact]
    public async Task TryAcquire_ConcurrentCalls_ThreadSafe()
    {
        var limiter = new RateLimiter();
        int maxCalls = 100;
        int successCount = 0;
        var tasks = Enumerable.Range(0, 200).Select(_ => Task.Run(() =>
        {
            if (limiter.TryAcquire("key", maxCalls, TimeSpan.FromMinutes(1)))
                Interlocked.Increment(ref successCount);
        })).ToArray();
        await Task.WhenAll(tasks);
        Assert.Equal(maxCalls, successCount);
    }

    [Fact]
    public void TryAcquire_HighLimit_AllSucceed()
    {
        var limiter = new RateLimiter();
        for (int i = 0; i < 10000; i++)
            Assert.True(limiter.TryAcquire("key", 10000, TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void TryAcquire_AfterFailure_StillFails()
    {
        var limiter = new RateLimiter();
        limiter.TryAcquire("key", 1, TimeSpan.FromMinutes(1));
        for (int i = 0; i < 10; i++)
            Assert.False(limiter.TryAcquire("key", 1, TimeSpan.FromMinutes(1)));
    }
}
