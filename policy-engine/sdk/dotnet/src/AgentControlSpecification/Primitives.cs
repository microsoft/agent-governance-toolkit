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
        _ => throw new ArgumentOutOfRangeException(nameof(decision), decision, "Unknown Agent Control Specification decision."),
    };

    public static Decision FromWireName(string value) => value switch
    {
        "allow" => Decision.Allow,
        "deny" => Decision.Deny,
        "warn" => Decision.Warn,
        "escalate" => Decision.Escalate,
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown Agent Control Specification decision."),
    };

    public static bool AppliesEffects(this Decision decision) =>
        decision is Decision.Allow or Decision.Warn or Decision.Escalate;
}

public sealed record Verdict(
    Decision Decision,
    string? Reason = null,
    string? Message = null,
    IReadOnlyList<JsonElement>? Effects = null,
    IReadOnlyList<string>? ResultLabels = null);

public sealed record InterventionPointRequest(
    InterventionPoint InterventionPoint,
    JsonElement Snapshot,
    EnforcementMode Mode = EnforcementMode.Enforce);

public sealed record InterventionPointResult(
    Verdict Verdict,
    JsonElement? TransformedPolicyTarget = null,
    JsonElement? PolicyInput = null,
    string? ActionIdentity = null);

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
