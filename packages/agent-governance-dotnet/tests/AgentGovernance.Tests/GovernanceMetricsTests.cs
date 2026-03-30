// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Diagnostics.Metrics;
using AgentGovernance.Telemetry;
using Xunit;

namespace AgentGovernance.Tests;

// Serialize metrics tests to avoid .NET Meter global state interference
// when multiple test classes create GovernanceMetrics instances in parallel.
[Collection("MetricsTests")]
public class GovernanceMetricsTests : IDisposable
{
    private readonly GovernanceMetrics _metrics = new();

    [Fact]
    public void MeterName_IsAgentGovernance()
    {
        Assert.Equal("AgentGovernance", GovernanceMetrics.MeterName);
    }

    [Fact]
    public void RecordDecision_AllowedIncrementsCounters()
    {
        long policyBefore = 0, policyAfter = 0;
        long allowedBefore = 0, allowedAfter = 0;
        long blockedBefore = 0, blockedAfter = 0;

        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == GovernanceMetrics.MeterName)
                listener.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
        {
            if (instrument.Name == "agent_governance.policy_decisions") policyAfter += measurement;
            if (instrument.Name == "agent_governance.tool_calls_allowed") allowedAfter += measurement;
            if (instrument.Name == "agent_governance.tool_calls_blocked") blockedAfter += measurement;
        });
        listener.Start();

        policyBefore = policyAfter;
        allowedBefore = allowedAfter;
        blockedBefore = blockedAfter;

        _metrics.RecordDecision(allowed: true, "did:mesh:test", "file_read", 0.05);
        listener.RecordObservableInstruments();

        Assert.Equal(1, policyAfter - policyBefore);
        Assert.Equal(1, allowedAfter - allowedBefore);
        Assert.Equal(0, blockedAfter - blockedBefore);
    }

    [Fact]
    public void RecordDecision_DeniedIncrementsBlockedCounter()
    {
        long blockedBefore = 0;
        long blockedAfter = 0;

        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == GovernanceMetrics.MeterName)
                listener.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
        {
            if (instrument.Name == "agent_governance.tool_calls_blocked") blockedAfter += measurement;
        });
        listener.Start();
        listener.RecordObservableInstruments();

        // Capture baseline AFTER listener processes any existing measurements
        blockedBefore = blockedAfter;

        _metrics.RecordDecision(allowed: false, "did:mesh:test", "shell_exec", 0.02);
        listener.RecordObservableInstruments();

        Assert.Equal(1, blockedAfter - blockedBefore);
    }

    [Fact]
    public void RecordDecision_RateLimitedIncrementsRateLimitCounter()
    {
        long rateBefore = 0, rateAfter = 0;

        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == GovernanceMetrics.MeterName)
                listener.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
        {
            if (instrument.Name == "agent_governance.rate_limit_hits") rateAfter += measurement;
        });
        listener.Start();

        rateBefore = rateAfter;

        _metrics.RecordDecision(allowed: false, "did:mesh:test", "api_call", 0.01, rateLimited: true);
        listener.RecordObservableInstruments();

        Assert.Equal(1, rateAfter - rateBefore);
    }

    [Fact]
    public void RecordDecision_RecordsLatencyHistogram()
    {
        double latency = -1;
        bool captured = false;

        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == GovernanceMetrics.MeterName)
                listener.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<double>((instrument, measurement, tags, state) =>
        {
            if (instrument.Name == "agent_governance.evaluation_latency_ms" && !captured)
            {
                // Skip measurements from other test instances; capture only after our flag is set
            }
        });
        listener.Start();

        // Replace callback now that baseline noise is subscribed
        listener.SetMeasurementEventCallback<double>((instrument, measurement, tags, state) =>
        {
            if (instrument.Name == "agent_governance.evaluation_latency_ms")
            {
                latency = measurement;
                captured = true;
            }
        });

        _metrics.RecordDecision(allowed: true, "did:mesh:test", "search", 0.087);

        Assert.Equal(0.087, latency, precision: 5);
    }

    [Fact]
    public void RegisterTrustScoreGauge_ReportsValues()
    {
        double observedScore = 0;

        _metrics.RegisterTrustScoreGauge(() => new[]
        {
            new Measurement<double>(850.0, new KeyValuePair<string, object?>("agent_id", "did:mesh:test"))
        });

        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == GovernanceMetrics.MeterName)
                listener.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<double>((instrument, measurement, tags, state) =>
        {
            if (instrument.Name == "agent_governance.trust_score") observedScore = measurement;
        });
        listener.Start();
        listener.RecordObservableInstruments();

        Assert.Equal(850.0, observedScore);
    }

    [Fact]
    public void RegisterActiveAgentsGauge_ReportsCount()
    {
        int observedCount = 0;

        _metrics.RegisterActiveAgentsGauge(() => 42);

        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == GovernanceMetrics.MeterName)
                listener.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<int>((instrument, measurement, tags, state) =>
        {
            if (instrument.Name == "agent_governance.active_agents") observedCount = measurement;
        });
        listener.Start();
        listener.RecordObservableInstruments();

        Assert.Equal(42, observedCount);
    }

    public void Dispose() => _metrics.Dispose();
}
