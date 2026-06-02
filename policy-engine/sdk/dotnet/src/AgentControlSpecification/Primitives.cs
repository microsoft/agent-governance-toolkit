using System.Text.Json;

namespace AgentControlSpecification;

public enum InterventionPoint
{
    AgentStartup,
    Input,
    PreModelCall,
    PostModelCall,
    PreToolCall,
    PostToolCall,
    Output,
    AgentShutdown,
}

public static class InterventionPointExtensions
{
    public static string ToWireName(this InterventionPoint interventionPoint) => interventionPoint switch
    {
        InterventionPoint.AgentStartup => "agent_startup",
        InterventionPoint.Input => "input",
        InterventionPoint.PreModelCall => "pre_model_call",
        InterventionPoint.PostModelCall => "post_model_call",
        InterventionPoint.PreToolCall => "pre_tool_call",
        InterventionPoint.PostToolCall => "post_tool_call",
        InterventionPoint.Output => "output",
        InterventionPoint.AgentShutdown => "agent_shutdown",
        _ => throw new ArgumentOutOfRangeException(nameof(interventionPoint), interventionPoint, "Unknown Agent Control Specification intervention point."),
    };

    public static InterventionPoint FromWireName(string value) => value switch
    {
        "agent_startup" => InterventionPoint.AgentStartup,
        "input" => InterventionPoint.Input,
        "pre_model_call" => InterventionPoint.PreModelCall,
        "post_model_call" => InterventionPoint.PostModelCall,
        "pre_tool_call" => InterventionPoint.PreToolCall,
        "post_tool_call" => InterventionPoint.PostToolCall,
        "output" => InterventionPoint.Output,
        "agent_shutdown" => InterventionPoint.AgentShutdown,
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown Agent Control Specification intervention point."),
    };

    public static bool IsToolInterventionPoint(this InterventionPoint interventionPoint) =>
        interventionPoint is InterventionPoint.PreToolCall or InterventionPoint.PostToolCall;
}

public enum EnforcementMode
{
    Enforce,
    EvaluateOnly,
}

public static class EnforcementModeExtensions
{
    public static string ToWireName(this EnforcementMode mode) => mode switch
    {
        EnforcementMode.Enforce => "enforce",
        EnforcementMode.EvaluateOnly => "evaluate_only",
        _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unknown Agent Control Specification enforcement mode."),
    };
}

public enum Decision
{
    Allow,
    Deny,
    Warn,
    Escalate,
    Transform,
}

public enum PerfTelemetry
{
    Off = 0,
    External = 1,
    Full = 2,
}

public static class DecisionExtensions
{
    public static string ToWireName(this Decision decision) => decision switch
    {
        Decision.Allow => "allow",
        Decision.Deny => "deny",
        Decision.Warn => "warn",
        Decision.Escalate => "escalate",
        Decision.Transform => "transform",
        _ => throw new ArgumentOutOfRangeException(nameof(decision), decision, "Unknown Agent Control Specification decision."),
    };

    public static Decision FromWireName(string value) => value switch
    {
        "allow" => Decision.Allow,
        "deny" => Decision.Deny,
        "warn" => Decision.Warn,
        "escalate" => Decision.Escalate,
        "transform" => Decision.Transform,
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown Agent Control Specification decision."),
    };

    /// <summary>
    /// Deprecated. Use <see cref="AppliesTransform(Decision)"/> when deciding
    /// whether to consume
    /// <see cref="InterventionPointResult.TransformedPolicyTarget"/>, or
    /// <see cref="Permits(Decision)"/> when checking whether the action
    /// proceeds. AGT D1 removed the effects[] surface and only the
    /// <c>Transform</c> decision mutates the policy target, so this helper now
    /// returns the same value as <see cref="AppliesTransform(Decision)"/>.
    /// </summary>
    [Obsolete("AGT D1 removed effects[]; use AppliesTransform (only Transform mutates) or Permits (action proceeds).")]
    public static bool AppliesEffects(this Decision decision) =>
        decision.AppliesTransform();

    /// <summary>
    /// True only for <c>Transform</c>, the sole mutating decision per AGT D1.
    /// Use this to decide whether to consume
    /// <see cref="InterventionPointResult.TransformedPolicyTarget"/>.
    /// </summary>
    public static bool AppliesTransform(this Decision decision) =>
        decision is Decision.Transform;

    /// <summary>
    /// True for decisions whose execution side proceeds with the action
    /// (<c>Allow</c>, <c>Warn</c>, <c>Transform</c>). Mirrors
    /// <c>Decision::permits</c> in the Rust core.
    /// </summary>
    public static bool Permits(this Decision decision) =>
        decision is Decision.Allow or Decision.Warn or Decision.Transform;
}

/// <summary>
/// AGT D1.1 single-target replacement payload. Present on a verdict only when
/// <see cref="Verdict.Decision"/> is <see cref="Decision.Transform"/>. The
/// runtime applies <see cref="Value"/> at <see cref="Path"/> rooted at
/// <c>$policy_target</c> before the action proceeds.
/// </summary>
public sealed record Transform(string Path, object? Value);

/// <summary>
/// AGT D2 opaque evidence payload that high-assurance dispatchers MAY attach
/// to a verdict. The runtime propagates the payload verbatim. The total
/// serialized size is bounded by AGT-EVIDENCE-1.0 §2 (4 KiB) at the
/// dispatcher boundary, not at this SDK shape.
/// </summary>
public sealed record Evidence(
    string? Artefact = null,
    IReadOnlyDictionary<string, string>? VerificationPointers = null);

public sealed record Verdict(
    Decision Decision,
    string? Reason = null,
    string? Message = null,
    Transform? Transform = null,
    Evidence? Evidence = null,
    IReadOnlyList<string>? ResultLabels = null);

public sealed record InterventionPointRequest(
    InterventionPoint InterventionPoint,
    JsonElement Snapshot,
    EnforcementMode Mode = EnforcementMode.Enforce);

/// <summary>
/// Result of a single intervention-point evaluation. Per AGT D1.4 the action
/// identity is bisected: <see cref="InputIdentity"/> pins what the policy
/// actually saw, <see cref="EnforcedIdentity"/> pins what the host will carry
/// out (equal to <see cref="InputIdentity"/> for non-transform decisions).
/// <see cref="ActionIdentity"/> is the pre-bisection alias that maps to
/// <see cref="EnforcedIdentity"/>.
/// </summary>
public sealed record InterventionPointResult(
    Verdict Verdict,
    JsonElement? TransformedPolicyTarget = null,
    JsonElement? PolicyInput = null,
    string? ActionIdentity = null,
    bool TransformedPolicyTargetApplied = false,
    string? InputIdentity = null,
    string? EnforcedIdentity = null);

public sealed record RunResult<TValue>(
    TValue Value,
    InterventionPointResult InputResult,
    InterventionPointResult OutputResult);

public sealed record ModelRunResult<TValue>(
    TValue Value,
    InterventionPointResult PreModelCallResult,
    InterventionPointResult PostModelCallResult);

public sealed record ToolRunResult<TValue>(
    TValue Value,
    InterventionPointResult PreToolCallResult,
    InterventionPointResult PostToolCallResult);

public sealed record ModelTurnRunResult<TValue>(
    TValue Value,
    InterventionPointResult InputResult,
    InterventionPointResult PreModelCallResult,
    InterventionPointResult PostModelCallResult,
    InterventionPointResult OutputResult);

public enum ApprovalOutcome
{
    Allow,
    Deny,
    Suspend,
}

public sealed record ApprovalResolution(ApprovalOutcome Outcome, JsonElement? Handle = null, string? ActionIdentity = null)
{
    public static ApprovalResolution Allow(string actionIdentity) => new(ApprovalOutcome.Allow, ActionIdentity: actionIdentity);

    public static ApprovalResolution Deny() => new(ApprovalOutcome.Deny);

    public static ApprovalResolution Suspend(JsonElement? handle = null, string? actionIdentity = null) => new(ApprovalOutcome.Suspend, handle, actionIdentity);
}

public delegate ValueTask<ApprovalResolution> ApprovalResolver(
    InterventionPoint interventionPoint,
    InterventionPointResult result,
    CancellationToken cancellationToken);

public abstract class AgentControlInterruptionException : InvalidOperationException
{
    protected AgentControlInterruptionException(
        string message,
        InterventionPoint interventionPoint,
        InterventionPointResult result,
        Exception? innerException = null)
        : base(message, innerException)
    {
        InterventionPoint = interventionPoint;
        Result = result;
    }

    public InterventionPoint InterventionPoint { get; }

    public InterventionPointResult Result { get; }
}

public sealed class AgentControlBlockedException : AgentControlInterruptionException
{
    public AgentControlBlockedException(
        InterventionPoint interventionPoint,
        InterventionPointResult result,
        Exception? innerException = null)
        : base(BuildMessage(interventionPoint, result), interventionPoint, result, innerException)
    {
    }

    private static string BuildMessage(InterventionPoint interventionPoint, InterventionPointResult result)
    {
        var reason = string.IsNullOrWhiteSpace(result.Verdict.Reason)
            ? string.Empty
            : $" ({result.Verdict.Reason})";
        return $"Agent Control Specification blocked {interventionPoint.ToWireName()}{reason}.";
    }
}

public sealed class AgentControlSuspendedException : AgentControlInterruptionException
{
    public AgentControlSuspendedException(
        InterventionPoint interventionPoint,
        InterventionPointResult result,
        JsonElement? handle = null)
        : base(BuildMessage(interventionPoint, result), interventionPoint, result)
    {
        Handle = handle;
    }

    public JsonElement? Handle { get; }

    private static string BuildMessage(InterventionPoint interventionPoint, InterventionPointResult result)
    {
        var reason = string.IsNullOrWhiteSpace(result.Verdict.Reason)
            ? string.Empty
            : $" ({result.Verdict.Reason})";
        return $"Agent Control Specification suspended {interventionPoint.ToWireName()} pending approval{reason}.";
    }
}
