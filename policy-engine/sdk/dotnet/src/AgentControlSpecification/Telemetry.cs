// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Text;
using System.Text.Json;

namespace AgentControlSpecification;

public enum TelemetryEventType
{
    Decision,
    AnnotatorDispatch,
    PolicyEvaluation,
    EvaluationTiming,
    InterventionPointTransformed,
    AnnotatorFailed,
    PolicyFailed,
}

public static class TelemetryEventTypeExtensions
{
    public static string ToWireName(this TelemetryEventType eventType) => eventType switch
    {
        TelemetryEventType.Decision => "decision",
        TelemetryEventType.AnnotatorDispatch => "annotator_dispatch",
        TelemetryEventType.PolicyEvaluation => "policy_evaluation",
        TelemetryEventType.EvaluationTiming => "evaluation_timing",
        TelemetryEventType.InterventionPointTransformed => "intervention_point.transformed",
        TelemetryEventType.AnnotatorFailed => "annotator_failed",
        TelemetryEventType.PolicyFailed => "policy_failed",
        _ => throw new ArgumentOutOfRangeException(nameof(eventType), eventType, "Unknown Agent Control Specification telemetry event type."),
    };
}

public static class TelemetryRedaction
{
    private const int MaxReasonCodeUtf8Bytes = 96;

    public static string? SafeReasonCode(string? reason)
    {
        if (reason is null)
        {
            return null;
        }

        return IsIdentifierReasonCode(reason) ? reason : "policy_reason";
    }

    public static string? ErrorClassFor(string? reason) =>
        reason is not null && reason.StartsWith("runtime_error:", StringComparison.Ordinal)
            ? "runtime_error"
            : null;

    private static bool IsIdentifierReasonCode(string reason)
    {
        if (reason.Length == 0 || Encoding.UTF8.GetByteCount(reason) > MaxReasonCodeUtf8Bytes)
        {
            return false;
        }

        foreach (var ch in reason)
        {
            if (ch > 0x7f)
            {
                return false;
            }

            var isAllowed =
                (ch >= 'A' && ch <= 'Z') ||
                (ch >= 'a' && ch <= 'z') ||
                (ch >= '0' && ch <= '9') ||
                ch is '_' or '-' or '.' or ':' or '/';
            if (!isAllowed)
            {
                return false;
            }
        }

        return true;
    }
}

public sealed record TelemetryEvent
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public TelemetryEvent(
        TelemetryEventType eventType,
        InterventionPoint interventionPoint,
        Decision? decision = null,
        string? reasonCode = null,
        string? errorClass = null,
        string? policyId = null,
        IReadOnlyList<string>? annotators = null,
        EnforcementMode? enforcementMode = null,
        double? durationMs = null,
        string? evidenceArtefact = null,
        IReadOnlyList<string>? evidenceVerificationPointerKeys = null,
        string? actionIdentity = null,
        IReadOnlyDictionary<string, string>? metadata = null)
    {
        EventType = eventType;
        InterventionPoint = interventionPoint;
        Decision = decision;
        ReasonCode = reasonCode;
        ErrorClass = errorClass;
        PolicyId = policyId;
        Annotators = CopyList(annotators);
        EnforcementMode = enforcementMode;
        DurationMs = durationMs;
        EvidenceArtefact = evidenceArtefact;
        EvidenceVerificationPointerKeys = CopyList(evidenceVerificationPointerKeys);
        ActionIdentity = actionIdentity;
        Metadata = metadata is null
            ? new Dictionary<string, string>(StringComparer.Ordinal)
            : new Dictionary<string, string>(metadata, StringComparer.Ordinal);
    }

    public TelemetryEventType EventType { get; init; }

    public InterventionPoint InterventionPoint { get; init; }

    public Decision? Decision { get; init; }

    public string? ReasonCode { get; init; }

    public string? ErrorClass { get; init; }

    public string? PolicyId { get; init; }

    public IReadOnlyList<string> Annotators { get; init; }

    public EnforcementMode? EnforcementMode { get; init; }

    public double? DurationMs { get; init; }

    public string? EvidenceArtefact { get; init; }

    public IReadOnlyList<string> EvidenceVerificationPointerKeys { get; init; }

    public string? ActionIdentity { get; init; }

    public IReadOnlyDictionary<string, string> Metadata { get; init; }

    public static TelemetryEvent FromResult(
        InterventionPoint interventionPoint,
        EnforcementMode? mode,
        InterventionPointResult result,
        double? durationMs,
        string? policyId = null,
        IReadOnlyList<string>? annotators = null)
    {
        var verdict = result.Verdict;
        var evidence = verdict.Evidence;
        var pointerKeys = evidence?.VerificationPointers is null
            ? Array.Empty<string>()
            : evidence.VerificationPointers.Keys.OrderBy(key => key, StringComparer.Ordinal).ToArray();
        var resolvedAnnotators = annotators ?? AnnotatorNamesFromResult(result.PolicyInput);

        return new TelemetryEvent(
            TelemetryEventType.Decision,
            interventionPoint,
            verdict.Decision,
            TelemetryRedaction.SafeReasonCode(verdict.Reason),
            TelemetryRedaction.ErrorClassFor(verdict.Reason),
            policyId,
            resolvedAnnotators,
            mode,
            durationMs,
            evidence?.Artefact,
            pointerKeys,
            result.ActionIdentity,
            new Dictionary<string, string>(StringComparer.Ordinal));
    }

    // Sorted annotator names from the result policy input, used when the caller
    // has no manifest-configured annotator list (for example a from_url or YAML
    // manifest source). Mirrors the Python and Node host layers; reads the
    // annotation KEYS only, never the annotator output values.
    private static IReadOnlyList<string> AnnotatorNamesFromResult(JsonElement? policyInput)
    {
        if (policyInput is not JsonElement element || element.ValueKind != JsonValueKind.Object)
        {
            return Array.Empty<string>();
        }

        if (!element.TryGetProperty("annotations", out var annotations) ||
            annotations.ValueKind != JsonValueKind.Object)
        {
            return Array.Empty<string>();
        }

        return annotations
            .EnumerateObject()
            .Select(property => property.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();
    }

    public IReadOnlyDictionary<string, object?> ToDictionary() => new Dictionary<string, object?>(StringComparer.Ordinal)
    {
        ["event_type"] = EventType.ToWireName(),
        ["intervention_point"] = InterventionPoint.ToWireName(),
        ["decision"] = Decision?.ToWireName(),
        ["reason_code"] = ReasonCode,
        ["error_class"] = ErrorClass,
        ["policy_id"] = PolicyId,
        ["annotators"] = (Annotators ?? Array.Empty<string>()).ToArray(),
        ["enforcement_mode"] = EnforcementMode?.ToWireName(),
        ["duration_ms"] = DurationMs,
        ["evidence_artefact"] = EvidenceArtefact,
        ["evidence_verification_pointer_keys"] = (EvidenceVerificationPointerKeys ?? Array.Empty<string>()).ToArray(),
        ["action_identity"] = ActionIdentity,
        ["metadata"] = Metadata is null
            ? new Dictionary<string, string>(StringComparer.Ordinal)
            : new Dictionary<string, string>(Metadata, StringComparer.Ordinal),
    };

    public string ToJsonString() => JsonSerializer.Serialize(ToDictionary(), JsonOptions);

    private static IReadOnlyList<string> CopyList(IReadOnlyList<string>? values) =>
        values is null ? Array.Empty<string>() : values.ToArray();
}

public interface ITelemetrySink
{
    void Emit(TelemetryEvent telemetryEvent);

    void ForceFlush();

    void Shutdown();
}

public sealed class InMemoryTelemetrySink : ITelemetrySink
{
    public List<TelemetryEvent> Events { get; } = [];

    public void Emit(TelemetryEvent telemetryEvent) => Events.Add(telemetryEvent);

    public void ForceFlush()
    {
    }

    public void Shutdown()
    {
    }

    public void Clear() => Events.Clear();
}

public sealed class JsonStdoutTelemetrySink : ITelemetrySink
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly TextWriter writer;

    public JsonStdoutTelemetrySink(TextWriter? writer = null)
    {
        this.writer = writer ?? Console.Out;
    }

    public void Emit(TelemetryEvent telemetryEvent) =>
        writer.WriteLine(JsonSerializer.Serialize(telemetryEvent.ToDictionary(), JsonOptions));

    public void ForceFlush() => writer.Flush();

    public void Shutdown() => ForceFlush();
}

public sealed class MultiSink : ITelemetrySink
{
    private readonly ITelemetrySink[] sinks;

    public MultiSink(params ITelemetrySink[] sinks)
        : this((IEnumerable<ITelemetrySink>)sinks)
    {
    }

    public MultiSink(IEnumerable<ITelemetrySink> sinks)
    {
        ArgumentNullException.ThrowIfNull(sinks);
        this.sinks = sinks.Select(sink => sink ?? throw new ArgumentException("Telemetry sink collection must not contain null.", nameof(sinks))).ToArray();
    }

    public IReadOnlyList<ITelemetrySink> Sinks => sinks;

    public void Emit(TelemetryEvent telemetryEvent)
    {
        foreach (var sink in sinks)
        {
            try
            {
                sink.Emit(telemetryEvent);
            }
            catch (Exception exception) when (!TelemetryExceptions.IsFatal(exception))
            {
                Trace.TraceWarning($"ACS telemetry sink {sink.GetType().Name} raised during emit: {exception}");
            }
        }
    }

    public void ForceFlush()
    {
        foreach (var sink in sinks)
        {
            try
            {
                sink.ForceFlush();
            }
            catch (Exception exception) when (!TelemetryExceptions.IsFatal(exception))
            {
                Trace.TraceWarning($"ACS telemetry sink {sink.GetType().Name} raised during force flush: {exception}");
            }
        }
    }

    public void Shutdown()
    {
        foreach (var sink in sinks)
        {
            try
            {
                sink.Shutdown();
            }
            catch (Exception exception) when (!TelemetryExceptions.IsFatal(exception))
            {
                Trace.TraceWarning($"ACS telemetry sink {sink.GetType().Name} raised during shutdown: {exception}");
            }
        }
    }
}

// Fatal CLR exceptions must propagate even from the best-effort telemetry and
// manifest-indexing paths that are otherwise designed never to be load-bearing.
// Everything else is caught so a sink or a malformed manifest cannot break the
// host. This mirrors the Python `except Exception` (which excludes the
// fatal `BaseException` interrupts) and the Rust catch_unwind isolation.
internal static class TelemetryExceptions
{
    public static bool IsFatal(Exception exception) =>
        exception is OutOfMemoryException or StackOverflowException;
}

public sealed class OtelMetricsTelemetrySink : ITelemetrySink, IDisposable
{
    public const string DefaultOtelMeterName = "agent_control_specification";

    private static readonly string[] DecisionWireStrings = ["allow", "deny", "warn", "escalate", "transform"];
    private readonly Meter meter;
    private readonly Dictionary<string, Counter<double>> decisionCounters = new(StringComparer.Ordinal);
    private readonly Histogram<double> durationHistogram;
    private bool disposed;

    public OtelMetricsTelemetrySink(string meterName = DefaultOtelMeterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(meterName);
        MeterName = meterName;
        meter = new Meter(meterName);
        foreach (var decision in DecisionWireStrings)
        {
            decisionCounters[decision] = meter.CreateCounter<double>($"acs_intervention_{decision}_total");
        }

        durationHistogram = meter.CreateHistogram<double>("acs_intervention_duration_ms");
    }

    public string MeterName { get; }

    public void Emit(TelemetryEvent telemetryEvent)
    {
        if (disposed)
        {
            return;
        }

        // Record one increment and one duration sample per evaluation. Only the
        // base decision event records metrics, matching the Rust OTel sink, so a
        // non-decision event fed in directly cannot double-count.
        if (telemetryEvent.EventType != TelemetryEventType.Decision)
        {
            return;
        }

        var tags = MetricTags(telemetryEvent);
        if (telemetryEvent.Decision is not null)
        {
            var decision = telemetryEvent.Decision.Value.ToWireName();
            if (decisionCounters.TryGetValue(decision, out var counter))
            {
                counter.Add(1.0, tags);
            }
        }

        if (telemetryEvent.DurationMs is not null)
        {
            durationHistogram.Record(telemetryEvent.DurationMs.Value, tags);
        }
    }

    public void ForceFlush()
    {
    }

    public void Shutdown() => Dispose();

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        meter.Dispose();
        disposed = true;
    }

    private static TagList MetricTags(TelemetryEvent telemetryEvent)
    {
        var tags = new TagList
        {
            { "event_type", telemetryEvent.EventType.ToWireName() },
            { "intervention_point", telemetryEvent.InterventionPoint.ToWireName() },
        };
        AddIfPresent(ref tags, "enforcement_mode", telemetryEvent.EnforcementMode?.ToWireName());
        AddIfPresent(ref tags, "decision", telemetryEvent.Decision?.ToWireName());
        AddIfPresent(ref tags, "reason_code", telemetryEvent.ReasonCode);
        AddIfPresent(ref tags, "error_class", telemetryEvent.ErrorClass);
        AddIfPresent(ref tags, "policy_id", telemetryEvent.PolicyId);
        if (telemetryEvent.Annotators.Count > 0)
        {
            tags.Add("annotators", string.Join(",", telemetryEvent.Annotators));
        }

        AddIfPresent(ref tags, "evidence_artefact", telemetryEvent.EvidenceArtefact);
        if (telemetryEvent.EvidenceVerificationPointerKeys.Count > 0)
        {
            tags.Add("evidence_verification_pointer_keys", string.Join(",", telemetryEvent.EvidenceVerificationPointerKeys));
        }

        return tags;
    }

    private static void AddIfPresent(ref TagList tags, string key, string? value)
    {
        if (value is not null)
        {
            tags.Add(key, value);
        }
    }
}
