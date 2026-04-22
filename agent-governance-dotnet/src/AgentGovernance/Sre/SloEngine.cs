// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

namespace AgentGovernance.Sre;

/// <summary>
/// Comparison operator for SLI threshold evaluation.
/// </summary>
public enum ComparisonOp
{
    /// <summary>Less than or equal.</summary>
    LessThanOrEqual,

    /// <summary>Greater than or equal.</summary>
    GreaterThanOrEqual,

    /// <summary>Less than.</summary>
    LessThan,

    /// <summary>Greater than.</summary>
    GreaterThan
}

/// <summary>
/// Service Level Indicator specification — the metric and threshold that define what "good" means.
/// </summary>
public sealed class SliSpec
{
    /// <summary>Name of the metric being measured (e.g., "policy_compliance_rate").</summary>
    public required string Metric { get; init; }

    /// <summary>Threshold value for the SLI.</summary>
    public double Threshold { get; init; }

    /// <summary>Comparison operator for evaluating the metric against the threshold.</summary>
    public ComparisonOp Comparison { get; init; } = ComparisonOp.GreaterThanOrEqual;

    /// <summary>
    /// Evaluates whether a metric value satisfies this SLI.
    /// </summary>
    public bool IsSatisfied(double value) => Comparison switch
    {
        ComparisonOp.LessThanOrEqual => value <= Threshold,
        ComparisonOp.GreaterThanOrEqual => value >= Threshold,
        ComparisonOp.LessThan => value < Threshold,
        ComparisonOp.GreaterThan => value > Threshold,
        _ => false
    };
}

/// <summary>
/// Severity of an error budget burn rate alert.
/// </summary>
public enum BurnRateSeverity
{
    /// <summary>Elevated burn rate that should be investigated.</summary>
    Warning,
    /// <summary>Dangerously high burn rate requiring immediate attention.</summary>
    Critical,
    /// <summary>Extreme burn rate triggering on-call page.</summary>
    Page
}

/// <summary>
/// A burn rate threshold that triggers an alert when error budget consumption
/// exceeds a specified rate.
/// </summary>
public sealed class BurnRateThreshold
{
    /// <summary>Name of this threshold level.</summary>
    public required string Name { get; init; }

    /// <summary>
    /// Burn rate multiplier. A rate of 1.0 means consuming the budget evenly over
    /// the SLO window. A rate of 10.0 means consuming 10x faster than sustainable.
    /// </summary>
    public double Rate { get; init; } = 1.0;

    /// <summary>Severity level for alerts triggered by this threshold.</summary>
    public BurnRateSeverity Severity { get; init; } = BurnRateSeverity.Warning;

    /// <summary>Evaluation window in seconds.</summary>
    public int WindowSeconds { get; init; } = 3600;
}

/// <summary>
/// Error budget policy defining when and how to alert on budget consumption.
/// </summary>
public sealed class ErrorBudgetPolicy
{
    /// <summary>Burn rate thresholds that trigger alerts at different severity levels.</summary>
    public List<BurnRateThreshold> Thresholds { get; init; } = new();
}

/// <summary>
/// Service Level Objective specification defining reliability targets for an agent.
/// </summary>
public sealed class SloSpec
{
    /// <summary>Unique name for this SLO.</summary>
    public required string Name { get; init; }

    /// <summary>Human-readable description.</summary>
    public string? Description { get; init; }

    /// <summary>Service or agent this SLO applies to.</summary>
    public string? Service { get; init; }

    /// <summary>The SLI that measures this SLO.</summary>
    public required SliSpec Sli { get; init; }

    /// <summary>Target percentage (0–100). For example, 99.9 means 99.9% of events must satisfy the SLI.</summary>
    public double Target { get; init; } = 99.0;

    /// <summary>Rolling time window for evaluation.</summary>
    public TimeSpan Window { get; init; } = TimeSpan.FromHours(1);

    /// <summary>Error budget policy with burn rate thresholds.</summary>
    public ErrorBudgetPolicy? ErrorBudgetPolicy { get; init; }

    /// <summary>Optional labels for filtering and grouping.</summary>
    public Dictionary<string, string> Labels { get; init; } = new();
}

/// <summary>
/// Tracks error budget consumption for a single SLO over a rolling window.
/// </summary>
public sealed class ErrorBudgetTracker
{
    private readonly SloSpec _slo;
    private readonly object _lock = new();
    private readonly Queue<(long Ticks, bool Good)> _events = new();

    /// <summary>
    /// Initializes a new tracker for the specified SLO.
    /// </summary>
    public ErrorBudgetTracker(SloSpec slo)
    {
        _slo = slo ?? throw new ArgumentNullException(nameof(slo));
    }

    /// <summary>
    /// Records an event (good or bad) for error budget tracking.
    /// </summary>
    /// <param name="metricValue">The observed metric value.</param>
    public void Record(double metricValue)
    {
        var good = _slo.Sli.IsSatisfied(metricValue);
        lock (_lock)
        {
            _events.Enqueue((Environment.TickCount64, good));
            Prune();
        }
    }

    /// <summary>
    /// Returns the current SLI value as a percentage (0–100) within the window.
    /// </summary>
    public double CurrentSli()
    {
        lock (_lock)
        {
            Prune();
            if (_events.Count == 0) return 100.0;

            var goodCount = _events.Count(e => e.Good);
            return (double)goodCount / _events.Count * 100.0;
        }
    }

    /// <summary>
    /// Returns the total error budget as the allowed number of bad events.
    /// </summary>
    public double TotalErrorBudget()
    {
        lock (_lock)
        {
            Prune();
            var total = Math.Max(_events.Count, 1);
            return total * (100.0 - _slo.Target) / 100.0;
        }
    }

    /// <summary>
    /// Returns the remaining error budget (can be negative if budget is exhausted).
    /// </summary>
    public double RemainingBudget()
    {
        lock (_lock)
        {
            Prune();
            if (_events.Count == 0) return TotalErrorBudget();

            var badCount = _events.Count(e => !e.Good);
            return TotalErrorBudget() - badCount;
        }
    }

    /// <summary>
    /// Returns the current burn rate. A rate of 1.0 means consuming budget at the
    /// sustainable rate. Values above 1.0 indicate faster-than-sustainable consumption.
    /// </summary>
    public double BurnRate()
    {
        lock (_lock)
        {
            Prune();
            if (_events.Count == 0) return 0.0;

            var totalBudget = TotalErrorBudget();
            if (totalBudget <= 0) return 0.0;

            var badCount = _events.Count(e => !e.Good);
            return badCount / totalBudget;
        }
    }

    /// <summary>
    /// Checks whether the SLO is currently being met.
    /// </summary>
    public bool IsMet() => CurrentSli() >= _slo.Target;

    /// <summary>
    /// Checks error budget burn rate thresholds and returns any triggered alerts.
    /// </summary>
    public IReadOnlyList<BurnRateThreshold> CheckBurnRateAlerts()
    {
        var policy = _slo.ErrorBudgetPolicy;
        if (policy is null) return Array.Empty<BurnRateThreshold>();

        var currentBurnRate = BurnRate();
        return policy.Thresholds
            .Where(t => currentBurnRate >= t.Rate)
            .OrderByDescending(t => t.Rate)
            .ToList()
            .AsReadOnly();
    }

    /// <summary>Total events in the current window.</summary>
    public int EventCount { get { lock (_lock) { Prune(); return _events.Count; } } }

    private void Prune()
    {
        var cutoff = Environment.TickCount64 - (long)_slo.Window.TotalMilliseconds;
        while (_events.Count > 0 && _events.Peek().Ticks < cutoff)
        {
            _events.Dequeue();
        }
    }
}

/// <summary>
/// Facade for managing multiple SLO trackers across agents and services.
/// </summary>
public sealed class SloEngine
{
    private readonly Dictionary<string, ErrorBudgetTracker> _trackers = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    /// <summary>
    /// Registers an SLO and creates a budget tracker for it.
    /// </summary>
    public ErrorBudgetTracker Register(SloSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        lock (_lock)
        {
            if (_trackers.ContainsKey(spec.Name))
                throw new InvalidOperationException($"SLO '{spec.Name}' is already registered.");

            var tracker = new ErrorBudgetTracker(spec);
            _trackers[spec.Name] = tracker;
            return tracker;
        }
    }

    /// <summary>
    /// Gets a registered SLO tracker by name. Returns <c>null</c> if not found.
    /// </summary>
    public ErrorBudgetTracker? Get(string name)
    {
        lock (_lock)
        {
            return _trackers.GetValueOrDefault(name);
        }
    }

    /// <summary>
    /// Returns all registered SLO trackers.
    /// </summary>
    public IReadOnlyDictionary<string, ErrorBudgetTracker> All()
    {
        lock (_lock)
        {
            return new Dictionary<string, ErrorBudgetTracker>(_trackers);
        }
    }

    /// <summary>
    /// Returns all SLOs that are currently not being met.
    /// </summary>
    public IReadOnlyList<string> Violations()
    {
        lock (_lock)
        {
            return _trackers
                .Where(kv => !kv.Value.IsMet())
                .Select(kv => kv.Key)
                .ToList()
                .AsReadOnly();
        }
    }
}
