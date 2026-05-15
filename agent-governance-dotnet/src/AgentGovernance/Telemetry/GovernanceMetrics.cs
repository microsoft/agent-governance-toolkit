// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Diagnostics.Metrics;

namespace AgentGovernance.Telemetry;

/// <summary>
/// Configures tag emission for <see cref="GovernanceMetrics"/>.
/// </summary>
/// <remarks>
/// In production deployments the raw <c>agent_id</c> and <c>tool_name</c> tag
/// dimensions can blow up the cardinality of the underlying meter aggregation
/// tables — Prometheus and similar exporters allocate a distinct time-series
/// per unique tag combination, so an environment with thousands of agents and
/// dozens of tools produces tens of thousands of series per counter.
///
/// The safe defaults are: do NOT emit <c>agent_id</c> or <c>tool_name</c> as
/// tags. Opt in to either dimension explicitly, and prefer the
/// <see cref="AgentIdBucket"/> / <see cref="ToolNameBucket"/> hooks so that
/// raw identifiers are reduced to a bounded label set before becoming a tag.
/// </remarks>
public sealed class GovernanceMetricsOptions
{
    /// <summary>
    /// When <c>true</c>, includes an <c>agent_id</c> tag on per-decision metrics.
    /// Default: <c>false</c> (raw <c>agent_id</c> is unbounded in cardinality).
    /// </summary>
    public bool IncludeAgentIdTag { get; init; }

    /// <summary>
    /// When <c>true</c>, includes a <c>tool_name</c> tag on per-decision metrics.
    /// Default: <c>false</c> (tool registries are typically bounded, but
    /// dynamically-named MCP tools can still grow without limit).
    /// </summary>
    public bool IncludeToolNameTag { get; init; }

    /// <summary>
    /// Optional bucketing function applied to <c>agent_id</c> before it is
    /// emitted as a tag (only consulted when <see cref="IncludeAgentIdTag"/>
    /// is <c>true</c>). Use this to map raw agent identifiers to a small,
    /// bounded label set (e.g. tenant prefix, hash mod N).
    /// </summary>
    public Func<string, string>? AgentIdBucket { get; init; }

    /// <summary>
    /// Optional bucketing function applied to <c>tool_name</c> before it is
    /// emitted as a tag (only consulted when <see cref="IncludeToolNameTag"/>
    /// is <c>true</c>).
    /// </summary>
    public Func<string, string>? ToolNameBucket { get; init; }
}

/// <summary>
/// OpenTelemetry-compatible metrics for governance operations using
/// <see cref="System.Diagnostics.Metrics"/>. Consumers can collect these
/// metrics with any OTEL-compatible exporter (Prometheus, Azure Monitor, etc.).
/// </summary>
/// <remarks>
/// <b>Usage with OpenTelemetry:</b>
/// <code>
/// using var meterProvider = Sdk.CreateMeterProviderBuilder()
///     .AddMeter(GovernanceMetrics.MeterName)
///     .AddPrometheusExporter()
///     .Build();
/// </code>
///
/// <b>Tag cardinality:</b> by default only the <c>decision</c> tag is emitted
/// on per-call metrics. Pass a <see cref="GovernanceMetricsOptions"/> to opt
/// into <c>agent_id</c> and / or <c>tool_name</c>, and supply bucketing
/// functions if the raw values would exceed the exporter's cardinality budget.
/// </remarks>
public sealed class GovernanceMetrics : IDisposable
{
    /// <summary>
    /// The meter name used for all governance metrics.
    /// Register this with your OTEL MeterProvider to collect metrics.
    /// </summary>
    public const string MeterName = "AgentGovernance";

    private readonly Meter _meter;
    private readonly GovernanceMetricsOptions _options;

    /// <summary>Total policy evaluation decisions (allowed + denied).</summary>
    public Counter<long> PolicyDecisions { get; }

    /// <summary>Tool calls blocked by policy.</summary>
    public Counter<long> ToolCallsBlocked { get; }

    /// <summary>Tool calls allowed by policy.</summary>
    public Counter<long> ToolCallsAllowed { get; }

    /// <summary>Requests rejected by rate limiting.</summary>
    public Counter<long> RateLimitHits { get; }

    /// <summary>Governance evaluation latency in milliseconds.</summary>
    public Histogram<double> EvaluationLatency { get; }

    /// <summary>Current agent trust score (0–1000).</summary>
    public ObservableGauge<double>? TrustScore { get; private set; }

    /// <summary>Number of active agents being tracked.</summary>
    public ObservableGauge<int>? ActiveAgents { get; private set; }

    /// <summary>Audit events emitted.</summary>
    public Counter<long> AuditEvents { get; }

    /// <summary>
    /// Initializes a new <see cref="GovernanceMetrics"/> instance with the
    /// default low-cardinality tag policy (only <c>decision</c> is emitted).
    /// </summary>
    public GovernanceMetrics() : this(new GovernanceMetricsOptions()) { }

    /// <summary>
    /// Initializes a new <see cref="GovernanceMetrics"/> instance with explicit
    /// tag-emission options.
    /// </summary>
    /// <param name="options">Controls which high-cardinality fields are emitted as tags.</param>
    public GovernanceMetrics(GovernanceMetricsOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
        _meter = new Meter(MeterName, "1.0.0");

        PolicyDecisions = _meter.CreateCounter<long>(
            "agent_governance.policy_decisions",
            description: "Total policy evaluation decisions");

        ToolCallsBlocked = _meter.CreateCounter<long>(
            "agent_governance.tool_calls_blocked",
            description: "Tool calls blocked by governance policy");

        ToolCallsAllowed = _meter.CreateCounter<long>(
            "agent_governance.tool_calls_allowed",
            description: "Tool calls allowed by governance policy");

        RateLimitHits = _meter.CreateCounter<long>(
            "agent_governance.rate_limit_hits",
            description: "Requests rejected by rate limiting");

        EvaluationLatency = _meter.CreateHistogram<double>(
            "agent_governance.evaluation_latency_ms",
            unit: "ms",
            description: "Governance evaluation latency in milliseconds");

        AuditEvents = _meter.CreateCounter<long>(
            "agent_governance.audit_events",
            description: "Total audit events emitted");
    }

    /// <summary>
    /// Registers an observable gauge for agent trust scores.
    /// The callback is invoked each time metrics are collected.
    /// </summary>
    /// <param name="observeValues">
    /// Callback that returns current trust scores as (value, tags) measurements.
    /// </param>
    public void RegisterTrustScoreGauge(Func<IEnumerable<Measurement<double>>> observeValues)
    {
        TrustScore = _meter.CreateObservableGauge(
            "agent_governance.trust_score",
            observeValues,
            description: "Current agent trust score (0-1000)");
    }

    /// <summary>
    /// Registers an observable gauge for active agent count.
    /// </summary>
    /// <param name="observeValue">Callback that returns the current active agent count.</param>
    public void RegisterActiveAgentsGauge(Func<int> observeValue)
    {
        ActiveAgents = _meter.CreateObservableGauge(
            "agent_governance.active_agents",
            observeValue,
            description: "Number of active agents being tracked");
    }

    /// <summary>
    /// Records a policy decision with the appropriate metric tags.
    /// </summary>
    /// <param name="allowed">Whether the decision was allow or deny.</param>
    /// <param name="agentId">The agent DID.</param>
    /// <param name="toolName">The tool name.</param>
    /// <param name="evaluationMs">Evaluation time in milliseconds.</param>
    /// <param name="rateLimited">Whether the request was rate-limited.</param>
    public void RecordDecision(bool allowed, string agentId, string toolName, double evaluationMs, bool rateLimited = false)
    {
        var tags = BuildDecisionTags(allowed, agentId, toolName);

        PolicyDecisions.Add(1, tags);

        if (allowed)
            ToolCallsAllowed.Add(1, tags);
        else
            ToolCallsBlocked.Add(1, tags);

        if (rateLimited)
            RateLimitHits.Add(1, tags);

        EvaluationLatency.Record(evaluationMs, tags);
    }

    private KeyValuePair<string, object?>[] BuildDecisionTags(bool allowed, string agentId, string toolName)
    {
        var capacity = 1
            + (_options.IncludeAgentIdTag ? 1 : 0)
            + (_options.IncludeToolNameTag ? 1 : 0);
        var tags = new KeyValuePair<string, object?>[capacity];
        var idx = 0;
        tags[idx++] = new KeyValuePair<string, object?>("decision", allowed ? "allow" : "deny");
        if (_options.IncludeAgentIdTag)
        {
            var value = _options.AgentIdBucket is null ? agentId : _options.AgentIdBucket(agentId);
            tags[idx++] = new KeyValuePair<string, object?>("agent_id", value);
        }
        if (_options.IncludeToolNameTag)
        {
            var value = _options.ToolNameBucket is null ? toolName : _options.ToolNameBucket(toolName);
            tags[idx++] = new KeyValuePair<string, object?>("tool_name", value);
        }
        return tags;
    }

    /// <inheritdoc />
    public void Dispose() => _meter.Dispose();
}
