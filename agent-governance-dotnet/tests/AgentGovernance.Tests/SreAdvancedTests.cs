// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Sre;
using Xunit;

namespace AgentGovernance.Tests;

public class CircuitBreakerAdvancedTests
{
    [Fact]
    public void RecordFailure_ConsecutiveFailures_OpensAtThreshold()
    {
        var cb = new CircuitBreaker(new CircuitBreakerConfig { FailureThreshold = 5 });
        for (int i = 0; i < 4; i++) { cb.RecordFailure(); Assert.Equal(CircuitState.Closed, cb.State); }
        cb.RecordFailure();
        Assert.Equal(CircuitState.Open, cb.State);
    }

    [Fact]
    public void RecordSuccess_ResetsFailureCount()
    {
        var cb = new CircuitBreaker(new CircuitBreakerConfig { FailureThreshold = 3 });
        cb.RecordFailure(); cb.RecordFailure();
        cb.RecordSuccess();
        Assert.Equal(0, cb.FailureCount);
    }

    [Fact]
    public void RecordFailure_InterleavedWithSuccess_ResetsCount()
    {
        var cb = new CircuitBreaker(new CircuitBreakerConfig { FailureThreshold = 3 });
        cb.RecordFailure(); cb.RecordFailure(); cb.RecordSuccess(); cb.RecordFailure(); cb.RecordFailure();
        Assert.Equal(CircuitState.Closed, cb.State);
        Assert.Equal(2, cb.FailureCount);
    }

    [Fact]
    public async Task ExecuteAsync_Open_ThrowsException()
    {
        var cb = new CircuitBreaker(new CircuitBreakerConfig { FailureThreshold = 1 });
        cb.RecordFailure();
        await Assert.ThrowsAsync<CircuitBreakerOpenException>(() => cb.ExecuteAsync(async () => "x"));
    }

    [Fact]
    public async Task ExecuteAsync_Open_ActionNeverExecuted()
    {
        var cb = new CircuitBreaker(new CircuitBreakerConfig { FailureThreshold = 1 });
        cb.RecordFailure();
        bool executed = false;
        try { await cb.ExecuteAsync(async () => { executed = true; return 0; }); } catch { }
        Assert.False(executed);
    }

    [Fact]
    public async Task ExecuteAsync_Success_RecordsSuccess()
    {
        var cb = new CircuitBreaker(new CircuitBreakerConfig { FailureThreshold = 3 });
        cb.RecordFailure(); cb.RecordFailure();
        Assert.Equal(42, await cb.ExecuteAsync(async () => 42));
        Assert.Equal(0, cb.FailureCount);
    }

    [Fact]
    public async Task ExecuteAsync_Failure_RecordsAndRethrows()
    {
        var cb = new CircuitBreaker(new CircuitBreakerConfig { FailureThreshold = 5 });
        await Assert.ThrowsAsync<ArgumentException>(() => cb.ExecuteAsync<int>(async () => throw new ArgumentException()));
        Assert.Equal(1, cb.FailureCount);
    }

    [Fact]
    public void Reset_FromOpen_ReturnsToClosed()
    {
        var cb = new CircuitBreaker(new CircuitBreakerConfig { FailureThreshold = 1 });
        cb.RecordFailure();
        cb.Reset();
        Assert.Equal(CircuitState.Closed, cb.State);
        Assert.Equal(0, cb.FailureCount);
    }

    [Fact]
    public async Task Reset_AllowsNewExecutions()
    {
        var cb = new CircuitBreaker(new CircuitBreakerConfig { FailureThreshold = 1 });
        cb.RecordFailure(); cb.Reset();
        Assert.Equal("ok", await cb.ExecuteAsync(async () => "ok"));
    }

    [Fact]
    public async Task RecordFailure_ConcurrentCalls_StateConsistent()
    {
        var cb = new CircuitBreaker(new CircuitBreakerConfig { FailureThreshold = 100 });
        await Task.WhenAll(Enumerable.Range(0, 100).Select(_ => Task.Run(() => cb.RecordFailure())));
        Assert.Equal(CircuitState.Open, cb.State);
    }

    [Fact]
    public void Exception_HasRetryAfter()
    {
        var ex = new CircuitBreakerOpenException(TimeSpan.FromMinutes(2));
        Assert.Equal(TimeSpan.FromMinutes(2), ex.RetryAfter);
    }
}

public class SloEngineAdvancedTests
{
    [Theory]
    [InlineData(ComparisonOp.GreaterThanOrEqual, 100, 100, true)]
    [InlineData(ComparisonOp.GreaterThanOrEqual, 100, 99, false)]
    [InlineData(ComparisonOp.LessThanOrEqual, 100, 100, true)]
    [InlineData(ComparisonOp.LessThanOrEqual, 100, 101, false)]
    [InlineData(ComparisonOp.GreaterThan, 100, 100, false)]
    [InlineData(ComparisonOp.GreaterThan, 100, 101, true)]
    [InlineData(ComparisonOp.LessThan, 100, 100, false)]
    [InlineData(ComparisonOp.LessThan, 100, 99, true)]
    public void SliSpec_AllComparisons(ComparisonOp op, double threshold, double value, bool expected)
    {
        Assert.Equal(expected, new SliSpec { Metric = "m", Threshold = threshold, Comparison = op }.IsSatisfied(value));
    }

    [Fact]
    public void Tracker_AllGood_100Pct() { var t = MakeTracker(); for (int i = 0; i < 100; i++) t.Record(99.5); Assert.Equal(100.0, t.CurrentSli()); Assert.True(t.IsMet()); }

    [Fact]
    public void Tracker_AllBad_0Pct() { var t = MakeTracker(); for (int i = 0; i < 100; i++) t.Record(50); Assert.Equal(0.0, t.CurrentSli()); Assert.False(t.IsMet()); }

    [Fact]
    public void Tracker_ExactlyAtTarget_IsMet()
    {
        var t = MakeTracker(90.0);
        for (int i = 0; i < 90; i++) t.Record(99.5);
        for (int i = 0; i < 10; i++) t.Record(50);
        Assert.True(t.IsMet());
    }

    [Fact]
    public void Tracker_BudgetDecreases()
    {
        var t = MakeTracker();
        for (int i = 0; i < 100; i++) t.Record(99.5);
        var full = t.RemainingBudget();
        t.Record(50);
        Assert.True(t.RemainingBudget() < full);
    }

    [Fact]
    public void Tracker_BurnRateAlerts()
    {
        var slo = new SloSpec
        {
            Name = "test",
            Sli = new SliSpec { Metric = "m", Threshold = 99.0 },
            Target = 99.0,
            Window = TimeSpan.FromMinutes(5),
            ErrorBudgetPolicy = new ErrorBudgetPolicy
            {
                Thresholds = new() { new BurnRateThreshold { Name = "warn", Rate = 1.0, Severity = BurnRateSeverity.Warning } }
            }
        };
        var t = new ErrorBudgetTracker(slo);
        for (int i = 0; i < 20; i++) t.Record(50);
        Assert.NotEmpty(t.CheckBurnRateAlerts());
    }

    [Fact]
    public void Tracker_NullSlo_Throws() => Assert.Throws<ArgumentNullException>(() => new ErrorBudgetTracker(null!));

    [Fact]
    public void SloEngine_Register_Duplicate_Throws()
    {
        var e = new SloEngine();
        e.Register(new SloSpec { Name = "x", Sli = new SliSpec { Metric = "m", Threshold = 99 } });
        Assert.Throws<InvalidOperationException>(() => e.Register(new SloSpec { Name = "x", Sli = new SliSpec { Metric = "m", Threshold = 99 } }));
    }

    [Fact]
    public void SloEngine_Get_Unknown_Null() => Assert.Null(new SloEngine().Get("nope"));

    [Fact]
    public void SloEngine_Get_CaseInsensitive()
    {
        var e = new SloEngine();
        e.Register(new SloSpec { Name = "My-SLO", Sli = new SliSpec { Metric = "m", Threshold = 99 } });
        Assert.NotNull(e.Get("my-slo"));
    }

    [Fact]
    public void SloEngine_All_ReturnsAll()
    {
        var e = new SloEngine();
        e.Register(new SloSpec { Name = "a", Sli = new SliSpec { Metric = "m", Threshold = 99 } });
        e.Register(new SloSpec { Name = "b", Sli = new SliSpec { Metric = "m", Threshold = 99 } });
        Assert.Equal(2, e.All().Count);
    }

    [Fact]
    public void SloEngine_Violations_OnlyFailed()
    {
        var e = new SloEngine();
        var good = e.Register(new SloSpec { Name = "good", Sli = new SliSpec { Metric = "m", Threshold = 99 }, Target = 99, Window = TimeSpan.FromMinutes(5) });
        for (int i = 0; i < 100; i++) good.Record(99.5);
        var bad = e.Register(new SloSpec { Name = "bad", Sli = new SliSpec { Metric = "m", Threshold = 99 }, Target = 99, Window = TimeSpan.FromMinutes(5) });
        for (int i = 0; i < 10; i++) bad.Record(50);
        Assert.Single(e.Violations());
        Assert.Contains("bad", e.Violations());
    }

    [Fact]
    public void SloEngine_Register_Null_Throws() => Assert.Throws<ArgumentNullException>(() => new SloEngine().Register(null!));

    private static ErrorBudgetTracker MakeTracker(double target = 99.0) =>
        new(new SloSpec { Name = "t", Sli = new SliSpec { Metric = "m", Threshold = 99 }, Target = target, Window = TimeSpan.FromMinutes(5) });
}
