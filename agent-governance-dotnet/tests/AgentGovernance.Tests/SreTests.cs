// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Sre;
using Xunit;

namespace AgentGovernance.Tests;

public class CircuitBreakerTests
{
    [Fact]
    public void InitialState_IsClosed()
    {
        var cb = new CircuitBreaker();
        Assert.Equal(CircuitState.Closed, cb.State);
    }

    [Fact]
    public void RecordFailure_BelowThreshold_StaysClosed()
    {
        var cb = new CircuitBreaker(new CircuitBreakerConfig { FailureThreshold = 3 });
        cb.RecordFailure();
        cb.RecordFailure();
        Assert.Equal(CircuitState.Closed, cb.State);
    }

    [Fact]
    public void RecordFailure_AtThreshold_OpensCircuit()
    {
        var cb = new CircuitBreaker(new CircuitBreakerConfig { FailureThreshold = 3 });
        cb.RecordFailure();
        cb.RecordFailure();
        cb.RecordFailure();
        Assert.Equal(CircuitState.Open, cb.State);
    }

    [Fact]
    public void Open_RejectsRequests()
    {
        var cb = new CircuitBreaker(new CircuitBreakerConfig { FailureThreshold = 1 });
        cb.RecordFailure();
        Assert.Equal(CircuitState.Open, cb.State);

        Assert.Throws<CircuitBreakerOpenException>(() =>
            cb.ExecuteAsync(async () => "ok").GetAwaiter().GetResult());
    }

    [Fact]
    public void RecordSuccess_InClosed_ResetsFailureCount()
    {
        var cb = new CircuitBreaker(new CircuitBreakerConfig { FailureThreshold = 3 });
        cb.RecordFailure();
        cb.RecordFailure();
        cb.RecordSuccess();
        Assert.Equal(0, cb.FailureCount);
        Assert.Equal(CircuitState.Closed, cb.State);
    }

    [Fact]
    public async Task ExecuteAsync_Success_ReturnsResult()
    {
        var cb = new CircuitBreaker();
        var result = await cb.ExecuteAsync(async () => 42);
        Assert.Equal(42, result);
    }

    [Fact]
    public async Task ExecuteAsync_Failure_RecordsAndRethrows()
    {
        var cb = new CircuitBreaker(new CircuitBreakerConfig { FailureThreshold = 5 });
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => cb.ExecuteAsync<int>(async () => throw new InvalidOperationException("boom")));
        Assert.Equal(1, cb.FailureCount);
    }

    [Fact]
    public void Reset_ReturnsToClosedState()
    {
        var cb = new CircuitBreaker(new CircuitBreakerConfig { FailureThreshold = 1 });
        cb.RecordFailure();
        Assert.Equal(CircuitState.Open, cb.State);

        cb.Reset();
        Assert.Equal(CircuitState.Closed, cb.State);
        Assert.Equal(0, cb.FailureCount);
    }

    [Fact]
    public void CircuitBreakerOpenException_HasRetryAfter()
    {
        var ex = new CircuitBreakerOpenException(TimeSpan.FromSeconds(30));
        Assert.Equal(30, ex.RetryAfter.TotalSeconds);
        Assert.Contains("30", ex.Message);
    }

    [Fact]
    public async Task ExecuteAsync_OperationCanceledException_DoesNotRecordFailure()
    {
        // Regression: ExecuteAsync<T> previously caught all exceptions and
        // recorded them as failures before re-throwing. That treated caller
        // cancellation as a service failure -- a burst of cancelled requests
        // (e.g. a downstream request timeout, a shutdown signal, an upstream
        // client disconnect) would trip the breaker open against a perfectly
        // healthy dependency. Cancellation should propagate without touching
        // the failure counter.

        var cb = new CircuitBreaker(new CircuitBreakerConfig { FailureThreshold = 3 });

        for (var i = 0; i < 5; i++)
        {
            await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            {
                await cb.ExecuteAsync<int>(() => throw new OperationCanceledException());
            });
        }

        Assert.Equal(CircuitState.Closed, cb.State);
        Assert.Equal(0, cb.FailureCount);
    }

    [Fact]
    public async Task ExecuteAsync_Void_OperationCanceledException_DoesNotRecordFailure()
    {
        // Same property as the generic overload, exercising the void Task path.
        var cb = new CircuitBreaker(new CircuitBreakerConfig { FailureThreshold = 3 });

        for (var i = 0; i < 5; i++)
        {
            await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            {
                await cb.ExecuteAsync(() => throw new OperationCanceledException());
            });
        }

        Assert.Equal(CircuitState.Closed, cb.State);
        Assert.Equal(0, cb.FailureCount);
    }

    [Fact]
    public async Task ExecuteAsync_TaskCanceledException_DoesNotRecordFailure()
    {
        // TaskCanceledException inherits from OperationCanceledException -- the
        // same flow-through must apply (it's what HttpClient + CancellationToken
        // throw when an HTTP call is cancelled).
        var cb = new CircuitBreaker(new CircuitBreakerConfig { FailureThreshold = 3 });

        for (var i = 0; i < 5; i++)
        {
            await Assert.ThrowsAsync<TaskCanceledException>(async () =>
            {
                await cb.ExecuteAsync<int>(() => throw new TaskCanceledException());
            });
        }

        Assert.Equal(CircuitState.Closed, cb.State);
        Assert.Equal(0, cb.FailureCount);
    }

    [Fact]
    public async Task ExecuteAsync_NonCancellationException_StillRecordsFailure()
    {
        // Sanity check: the OperationCanceledException carve-out must not
        // swallow real exceptions. InvalidOperationException etc. should still
        // count against the breaker.
        var cb = new CircuitBreaker(new CircuitBreakerConfig { FailureThreshold = 3 });

        for (var i = 0; i < 3; i++)
        {
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            {
                await cb.ExecuteAsync<int>(() => throw new InvalidOperationException("downstream failure"));
            });
        }

        Assert.Equal(CircuitState.Open, cb.State);
        Assert.Equal(3, cb.FailureCount);
    }
}

public class SloEngineTests
{
    [Fact]
    public void SliSpec_IsSatisfied_GreaterThanOrEqual()
    {
        var sli = new SliSpec { Metric = "compliance_rate", Threshold = 99.0, Comparison = ComparisonOp.GreaterThanOrEqual };
        Assert.True(sli.IsSatisfied(99.5));
        Assert.True(sli.IsSatisfied(99.0));
        Assert.False(sli.IsSatisfied(98.9));
    }

    [Fact]
    public void SliSpec_IsSatisfied_LessThanOrEqual()
    {
        var sli = new SliSpec { Metric = "latency_ms", Threshold = 100.0, Comparison = ComparisonOp.LessThanOrEqual };
        Assert.True(sli.IsSatisfied(50));
        Assert.True(sli.IsSatisfied(100));
        Assert.False(sli.IsSatisfied(101));
    }

    [Fact]
    public void ErrorBudgetTracker_AllGoodEvents_SloMet()
    {
        var slo = new SloSpec
        {
            Name = "safety",
            Sli = new SliSpec { Metric = "compliance", Threshold = 99.0 },
            Target = 99.0,
            Window = TimeSpan.FromMinutes(5)
        };

        var tracker = new ErrorBudgetTracker(slo);
        for (int i = 0; i < 100; i++)
        {
            tracker.Record(99.5); // All good
        }

        Assert.True(tracker.IsMet());
        Assert.Equal(100.0, tracker.CurrentSli());
    }

    [Fact]
    public void ErrorBudgetTracker_TooManyBadEvents_SloNotMet()
    {
        var slo = new SloSpec
        {
            Name = "safety",
            Sli = new SliSpec { Metric = "compliance", Threshold = 99.0 },
            Target = 99.0,
            Window = TimeSpan.FromMinutes(5)
        };

        var tracker = new ErrorBudgetTracker(slo);
        // 90 good, 10 bad → 90% SLI, below 99% target
        for (int i = 0; i < 90; i++) tracker.Record(99.5);
        for (int i = 0; i < 10; i++) tracker.Record(50.0);

        Assert.False(tracker.IsMet());
        Assert.Equal(90.0, tracker.CurrentSli());
    }

    [Fact]
    public void ErrorBudgetTracker_RemainingBudget_Decreases()
    {
        var slo = new SloSpec
        {
            Name = "safety",
            Sli = new SliSpec { Metric = "compliance", Threshold = 99.0 },
            Target = 99.0,
            Window = TimeSpan.FromMinutes(5)
        };

        var tracker = new ErrorBudgetTracker(slo);
        for (int i = 0; i < 100; i++) tracker.Record(99.5);

        var fullBudget = tracker.TotalErrorBudget();
        Assert.True(fullBudget > 0);
        Assert.Equal(fullBudget, tracker.RemainingBudget());

        // Add a bad event.
        tracker.Record(50.0);
        Assert.True(tracker.RemainingBudget() < fullBudget);
    }

    [Fact]
    public void ErrorBudgetTracker_BurnRateAlerts_Triggered()
    {
        var slo = new SloSpec
        {
            Name = "safety",
            Sli = new SliSpec { Metric = "compliance", Threshold = 99.0 },
            Target = 99.0,
            Window = TimeSpan.FromMinutes(5),
            ErrorBudgetPolicy = new ErrorBudgetPolicy
            {
                Thresholds = new()
                {
                    new BurnRateThreshold { Name = "warning", Rate = 1.0, Severity = BurnRateSeverity.Warning },
                    new BurnRateThreshold { Name = "critical", Rate = 5.0, Severity = BurnRateSeverity.Critical }
                }
            }
        };

        var tracker = new ErrorBudgetTracker(slo);
        // Generate lots of bad events to create high burn rate.
        for (int i = 0; i < 50; i++) tracker.Record(99.5);
        for (int i = 0; i < 10; i++) tracker.Record(50.0);

        var alerts = tracker.CheckBurnRateAlerts();
        Assert.NotEmpty(alerts);
    }

    [Fact]
    public void ErrorBudgetTracker_NoEvents_SloMet()
    {
        var slo = new SloSpec
        {
            Name = "safety",
            Sli = new SliSpec { Metric = "compliance", Threshold = 99.0 },
            Target = 99.0,
            Window = TimeSpan.FromMinutes(5)
        };

        var tracker = new ErrorBudgetTracker(slo);
        Assert.True(tracker.IsMet());
        Assert.Equal(100.0, tracker.CurrentSli());
    }
}
