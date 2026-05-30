using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace AgentControlSpecification;

public sealed class AgentControl
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly JsonSerializerOptions CanonicalJsonOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };
    private readonly IAgentControlRuntime runtime;
    private readonly ApprovalResolver? approvalResolver;

    public AgentControl(IAgentControlRuntime runtime, ApprovalResolver? approvalResolver = null)
    {
        this.runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        this.approvalResolver = approvalResolver;
    }

    public static AgentControl FromNative(
        object manifest,
        IAnnotatorDispatcher? annotatorDispatcher = null,
        IPolicyDispatcher? policyDispatcher = null,
        ApprovalResolver? approvalResolver = null,
        PerfTelemetry perfTelemetry = PerfTelemetry.Off) =>
        new(new NativeAgentControlRuntime(manifest, annotatorDispatcher, policyDispatcher, perfTelemetry), approvalResolver);

    public static AgentControl FromPath(
        string path,
        IAnnotatorDispatcher? annotatorDispatcher = null,
        IPolicyDispatcher? policyDispatcher = null,
        ApprovalResolver? approvalResolver = null,
        PerfTelemetry perfTelemetry = PerfTelemetry.Off) =>
        new(NativeAgentControlRuntime.FromPath(path, annotatorDispatcher, policyDispatcher, perfTelemetry), approvalResolver);

    public static AgentControl FromManifestChain(
        IReadOnlyList<string> manifests,
        IAnnotatorDispatcher? annotatorDispatcher = null,
        IPolicyDispatcher? policyDispatcher = null,
        ApprovalResolver? approvalResolver = null,
        PerfTelemetry perfTelemetry = PerfTelemetry.Off) =>
        new(NativeAgentControlRuntime.FromManifestChain(manifests, annotatorDispatcher, policyDispatcher, perfTelemetry), approvalResolver);

    public ValueTask<InterventionPointResult> EvaluateInterventionPointAsync(
        InterventionPoint interventionPoint,
        JsonElement snapshot,
        EnforcementMode mode = EnforcementMode.Enforce,
        CancellationToken cancellationToken = default) =>
        runtime.EvaluateInterventionPointAsync(new InterventionPointRequest(interventionPoint, snapshot, mode), cancellationToken);

    public ValueTask<InterventionPointResult> EvaluateAgentStartupAsync<TAgent>(
        TAgent agent,
        IReadOnlyDictionary<string, object?>? metadata = null,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        CancellationToken cancellationToken = default) =>
        metadata is null
            ? EvaluateInterventionPointAsync(
                InterventionPoint.AgentStartup,
                BuildSnapshot(snapshot, ("agent", agent)),
                mode,
                cancellationToken)
            : EvaluateInterventionPointAsync(
                InterventionPoint.AgentStartup,
                BuildSnapshot(snapshot, ("agent", agent), ("metadata", metadata)),
                mode,
                cancellationToken);

    public ValueTask<InterventionPointResult> EvaluateInputAsync<TInput>(
        TInput input,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        CancellationToken cancellationToken = default) =>
        EvaluateInterventionPointAsync(
            InterventionPoint.Input,
            BuildSnapshot(snapshot, ("input", input)),
            mode,
            cancellationToken);

    public ValueTask<InterventionPointResult> EvaluateOutputAsync<TOutput>(
        TOutput output,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        CancellationToken cancellationToken = default) =>
        EvaluateInterventionPointAsync(
            InterventionPoint.Output,
            BuildSnapshot(snapshot, ("output", output)),
            mode,
            cancellationToken);

    public ValueTask<InterventionPointResult> EvaluatePreModelCallAsync<TRequest>(
        TRequest modelRequest,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        CancellationToken cancellationToken = default) =>
        EvaluateInterventionPointAsync(
            InterventionPoint.PreModelCall,
            BuildSnapshot(snapshot, ("model_request", modelRequest)),
            mode,
            cancellationToken);

    public ValueTask<InterventionPointResult> EvaluatePostModelCallAsync<TResponse>(
        TResponse modelResponse,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        CancellationToken cancellationToken = default) =>
        EvaluateInterventionPointAsync(
            InterventionPoint.PostModelCall,
            BuildSnapshot(snapshot, ("model_response", modelResponse)),
            mode,
            cancellationToken);

    public ValueTask<InterventionPointResult> EvaluatePreToolCallAsync<TArgs>(
        string toolName,
        TArgs args,
        string? toolCallId = null,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(toolName);
        var requiredToolCallId = RequireToolCallId(toolCallId);
        return EvaluateInterventionPointAsync(
            InterventionPoint.PreToolCall,
            BuildSnapshot(snapshot, ("tool_call", ToolCall(toolName, args, requiredToolCallId))),
            mode,
            cancellationToken);
    }

    public ValueTask<InterventionPointResult> EvaluatePostToolCallAsync<TArgs, TOutput>(
        string toolName,
        TArgs args,
        TOutput toolResult,
        string? toolCallId = null,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(toolName);
        var requiredToolCallId = RequireToolCallId(toolCallId);
        return EvaluateInterventionPointAsync(
            InterventionPoint.PostToolCall,
            BuildSnapshot(
                snapshot,
                ("tool_call", ToolCall(toolName, args, requiredToolCallId)),
                ("tool_result", toolResult)),
            mode,
            cancellationToken);
    }

    public ValueTask<InterventionPointResult> EvaluateAgentShutdownAsync(
        object? agent,
        string? reason = null,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        CancellationToken cancellationToken = default) =>
        string.IsNullOrWhiteSpace(reason)
            ? EvaluateInterventionPointAsync(
                InterventionPoint.AgentShutdown,
                BuildSnapshot(snapshot, ("agent", agent)),
                mode,
                cancellationToken)
            : EvaluateInterventionPointAsync(
                InterventionPoint.AgentShutdown,
                BuildSnapshot(snapshot, ("agent", agent), ("reason", reason)),
                mode,
                cancellationToken);

    public ValueTask<InterventionPointResult> EvaluateAgentShutdownAsync(
        IReadOnlyDictionary<string, object?> fullSnapshot,
        string? reason = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(fullSnapshot);
        return string.IsNullOrWhiteSpace(reason)
            ? EvaluateInterventionPointAsync(InterventionPoint.AgentShutdown, BuildSnapshot(fullSnapshot), mode, cancellationToken)
            : EvaluateInterventionPointAsync(
                InterventionPoint.AgentShutdown,
                BuildSnapshot(fullSnapshot, ("reason", reason)),
                mode,
                cancellationToken);
    }

    public async ValueTask<RunResult<TOutput>> RunAsync<TInput, TOutput>(
        TInput input,
        Func<TInput, CancellationToken, ValueTask<TOutput>> execute,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(execute);
        var inputResult = await EvaluateInterventionPointAsync(
            InterventionPoint.Input,
            BuildSnapshot(snapshot, ("input", input)),
            mode,
            cancellationToken).ConfigureAwait(false);
        await EnforceAsync(InterventionPoint.Input, inputResult, mode, approvalResolver, cancellationToken).ConfigureAwait(false);
        var effectiveInput = TransformedOr(inputResult, input, mode);

        var output = await execute(effectiveInput, cancellationToken).ConfigureAwait(false);
        var outputResult = await EvaluateInterventionPointAsync(
            InterventionPoint.Output,
            BuildSnapshot(snapshot, ("input", effectiveInput), ("output", output)),
            mode,
            cancellationToken).ConfigureAwait(false);
        await EnforceAsync(InterventionPoint.Output, outputResult, mode, approvalResolver, cancellationToken).ConfigureAwait(false);

        return new RunResult<TOutput>(
            TransformedOr(outputResult, output, mode),
            inputResult,
            outputResult);
    }

    public async ValueTask<ModelRunResult<TResponse>> RunModelAsync<TRequest, TResponse>(
        TRequest modelRequest,
        Func<TRequest, CancellationToken, ValueTask<TResponse>> execute,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(execute);
        var preModelCallResult = await EvaluateInterventionPointAsync(
            InterventionPoint.PreModelCall,
            BuildSnapshot(snapshot, ("model_request", modelRequest)),
            mode,
            cancellationToken).ConfigureAwait(false);
        await EnforceAsync(InterventionPoint.PreModelCall, preModelCallResult, mode, approvalResolver, cancellationToken).ConfigureAwait(false);
        var effectiveRequest = TransformedOr(preModelCallResult, modelRequest, mode);

        var modelResponse = await execute(effectiveRequest, cancellationToken).ConfigureAwait(false);
        var postModelCallResult = await EvaluateInterventionPointAsync(
            InterventionPoint.PostModelCall,
            BuildSnapshot(
                snapshot,
                ("model_request", effectiveRequest),
                ("model_response", modelResponse)),
            mode,
            cancellationToken).ConfigureAwait(false);
        await EnforceAsync(InterventionPoint.PostModelCall, postModelCallResult, mode, approvalResolver, cancellationToken).ConfigureAwait(false);

        return new ModelRunResult<TResponse>(
            TransformedOr(postModelCallResult, modelResponse, mode),
            preModelCallResult,
            postModelCallResult);
    }

    public async ValueTask<ModelTurnRunResult<TResponse>> RunModelTurnAsync<TInput, TRequest, TResponse>(
        TInput input,
        TRequest modelRequest,
        Func<TRequest, CancellationToken, ValueTask<TResponse>> execute,
        Func<TResponse, object?>? outputSelector = null,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(execute);
        var inputResult = await EvaluateInterventionPointAsync(
            InterventionPoint.Input,
            BuildSnapshot(snapshot, ("input", input)),
            mode,
            cancellationToken).ConfigureAwait(false);
        await EnforceAsync(InterventionPoint.Input, inputResult, mode, approvalResolver, cancellationToken).ConfigureAwait(false);
        var effectiveInput = TransformedOr(inputResult, input, mode);

        var preModelCallResult = await EvaluateInterventionPointAsync(
            InterventionPoint.PreModelCall,
            BuildSnapshot(snapshot, ("input", effectiveInput), ("model_request", modelRequest)),
            mode,
            cancellationToken).ConfigureAwait(false);
        await EnforceAsync(InterventionPoint.PreModelCall, preModelCallResult, mode, approvalResolver, cancellationToken).ConfigureAwait(false);
        var effectiveRequest = TransformedOr(preModelCallResult, modelRequest, mode);

        var modelResponse = await execute(effectiveRequest, cancellationToken).ConfigureAwait(false);
        var postModelCallResult = await EvaluateInterventionPointAsync(
            InterventionPoint.PostModelCall,
            BuildSnapshot(
                snapshot,
                ("input", effectiveInput),
                ("model_request", effectiveRequest),
                ("model_response", modelResponse)),
            mode,
            cancellationToken).ConfigureAwait(false);
        await EnforceAsync(InterventionPoint.PostModelCall, postModelCallResult, mode, approvalResolver, cancellationToken).ConfigureAwait(false);
        var effectiveResponse = TransformedOr(postModelCallResult, modelResponse, mode);

        var outputResult = await EvaluateInterventionPointAsync(
            InterventionPoint.Output,
            BuildSnapshot(
                snapshot,
                ("input", effectiveInput),
                ("model_request", effectiveRequest),
                ("model_response", effectiveResponse),
                ("output", outputSelector?.Invoke(effectiveResponse) ?? effectiveResponse)),
            mode,
            cancellationToken).ConfigureAwait(false);
        await EnforceAsync(InterventionPoint.Output, outputResult, mode, approvalResolver, cancellationToken).ConfigureAwait(false);

        return new ModelTurnRunResult<TResponse>(
            TransformedOr(outputResult, effectiveResponse, mode),
            inputResult,
            preModelCallResult,
            postModelCallResult,
            outputResult);
    }

    public async ValueTask<ToolRunResult<TOutput>> RunToolAsync<TArgs, TOutput>(
        string toolName,
        TArgs args,
        Func<TArgs, CancellationToken, ValueTask<TOutput>> execute,
        string? toolCallId = null,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(toolName);
        ArgumentNullException.ThrowIfNull(execute);
        var requiredToolCallId = RequireToolCallId(toolCallId);
        var preToolCallResult = await EvaluateInterventionPointAsync(
            InterventionPoint.PreToolCall,
            BuildSnapshot(snapshot, ("tool_call", ToolCall(toolName, args, requiredToolCallId))),
            mode,
            cancellationToken).ConfigureAwait(false);
        await EnforceAsync(InterventionPoint.PreToolCall, preToolCallResult, mode, approvalResolver, cancellationToken).ConfigureAwait(false);
        var effectiveArgs = TransformedOr(preToolCallResult, args, mode);

        var toolResult = await execute(effectiveArgs, cancellationToken).ConfigureAwait(false);
        var postToolCallResult = await EvaluateInterventionPointAsync(
            InterventionPoint.PostToolCall,
            BuildSnapshot(
                snapshot,
                ("tool_call", ToolCall(toolName, effectiveArgs, requiredToolCallId)),
                ("tool_result", toolResult)),
            mode,
            cancellationToken).ConfigureAwait(false);
        await EnforceAsync(InterventionPoint.PostToolCall, postToolCallResult, mode, approvalResolver, cancellationToken).ConfigureAwait(false);

        return new ToolRunResult<TOutput>(
            TransformedOr(postToolCallResult, toolResult, mode),
            preToolCallResult,
            postToolCallResult);
    }

    public ValueTask<ToolRunResult<TOutput>> ProtectToolAsync<TArgs, TOutput>(
        string toolName,
        TArgs args,
        Func<TArgs, CancellationToken, ValueTask<TOutput>> execute,
        string? toolCallId = null,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null,
        CancellationToken cancellationToken = default) =>
        RunToolAsync(toolName, args, execute, toolCallId, snapshot, mode, approvalResolver, cancellationToken);

    public async ValueTask<InterventionPointResult> AgentStartupAsync<TAgent>(
        TAgent agent,
        IReadOnlyDictionary<string, object?>? metadata = null,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null,
        CancellationToken cancellationToken = default)
    {
        var result = await EvaluateAgentStartupAsync(agent, metadata, snapshot, mode, cancellationToken)
            .ConfigureAwait(false);
        await EnforceAsync(InterventionPoint.AgentStartup, result, mode, approvalResolver, cancellationToken)
            .ConfigureAwait(false);
        return result;
    }

    public async ValueTask<InterventionPointResult> AgentShutdownAsync(
        object? summary,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null,
        CancellationToken cancellationToken = default)
    {
        var result = await EvaluateInterventionPointAsync(
            InterventionPoint.AgentShutdown,
            BuildSnapshot(snapshot, ("summary", summary)),
            mode,
            cancellationToken).ConfigureAwait(false);
        await EnforceAsync(InterventionPoint.AgentShutdown, result, mode, approvalResolver, cancellationToken)
            .ConfigureAwait(false);
        return result;
    }

    /// <summary>
    /// Framework-agnostic session seam: enforces <c>agent_startup</c> before
    /// <paramref name="body"/> runs and <c>agent_shutdown</c> after it completes
    /// cleanly. Shutdown is skipped when <paramref name="body"/> throws, so an
    /// in-session error is never masked by the shutdown verdict. Set
    /// <see cref="GuardedSession.Summary"/> inside the body to supply the
    /// shutdown target.
    /// </summary>
    public async ValueTask<TOutput> RunSessionAsync<TAgent, TOutput>(
        TAgent agent,
        Func<GuardedSession, CancellationToken, ValueTask<TOutput>> body,
        IReadOnlyDictionary<string, object?>? metadata = null,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(body);
        await AgentStartupAsync(agent, metadata, snapshot, mode, approvalResolver, cancellationToken)
            .ConfigureAwait(false);
        var session = new GuardedSession();
        var output = await body(session, cancellationToken).ConfigureAwait(false);
        await AgentShutdownAsync(session.Summary, snapshot, mode, approvalResolver, cancellationToken)
            .ConfigureAwait(false);
        return output;
    }

    private async ValueTask EnforceAsync(
        InterventionPoint interventionPoint,
        InterventionPointResult result,
        EnforcementMode mode,
        ApprovalResolver? approvalResolver,
        CancellationToken cancellationToken)
    {
        if (mode != EnforcementMode.Enforce)
        {
            return;
        }

        var decision = result.Verdict.Decision;
        if (decision == Decision.Deny)
        {
            throw new AgentControlBlockedException(interventionPoint, result);
        }

        if (decision != Decision.Escalate)
        {
            return;
        }

        var resolver = approvalResolver ?? this.approvalResolver;
        if (resolver is null)
        {
            throw new AgentControlBlockedException(interventionPoint, result);
        }

        var originalIdentity = result.ActionIdentity;
        ApprovalResolution resolution;
        try
        {
            resolution = await resolver(interventionPoint, result, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new AgentControlBlockedException(interventionPoint, ApprovalResolverFailedResult(), exception);
        }

        if (resolution is null)
        {
            throw new AgentControlBlockedException(interventionPoint, ApprovalResolverFailedResult());
        }

        switch (resolution.Outcome)
        {
            case ApprovalOutcome.Allow:
                RequireApprovedIdentity(interventionPoint, result, originalIdentity, resolution.ActionIdentity);
                return;
            case ApprovalOutcome.Suspend:
                RequireApprovedIdentity(interventionPoint, result, originalIdentity, resolution.ActionIdentity);
                throw new AgentControlSuspendedException(interventionPoint, result, resolution.Handle);
            case ApprovalOutcome.Deny:
                throw new AgentControlBlockedException(interventionPoint, result);
            default:
                throw new AgentControlBlockedException(interventionPoint, ApprovalResolverFailedResult());
        }
    }

    private static InterventionPointResult ApprovalResolverFailedResult() =>
        new(new Verdict(
            Decision.Deny,
            Reason: "runtime_error:approval_resolver_failed",
            Message: "Approval resolver failed closed."));

    private static void RequireApprovedIdentity(
        InterventionPoint interventionPoint,
        InterventionPointResult result,
        string? originalIdentity,
        string? approvedIdentity)
    {
        var currentIdentity = result.PolicyInput.HasValue ? ActionIdentity(result.PolicyInput.Value) : null;
        if (originalIdentity is not null
            && currentIdentity is not null
            && approvedIdentity is not null
            && originalIdentity == currentIdentity
            && currentIdentity == approvedIdentity)
        {
            return;
        }

        throw new AgentControlBlockedException(
            interventionPoint,
            new InterventionPointResult(
                new Verdict(Decision.Deny, Reason: "runtime_error:approval_action_mismatch")));
    }

    public static string ActionIdentity(JsonElement policyInput)
    {
        var canonical = CanonicalJson(policyInput);
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return "sha256:" + Convert.ToHexString(digest).ToLowerInvariant();
    }

    private static string CanonicalJson(JsonElement value)
    {
        return value.ValueKind switch
        {
            JsonValueKind.Object => "{" + string.Join(",", value.EnumerateObject()
                .OrderBy(property => property.Name, StringComparer.Ordinal)
                .Select(property => JsonSerializer.Serialize(property.Name, CanonicalJsonOptions) + ":" + CanonicalJson(property.Value))) + "}",
            JsonValueKind.Array => "[" + string.Join(",", value.EnumerateArray().Select(CanonicalJson)) + "]",
            JsonValueKind.String => JsonSerializer.Serialize(value.GetString(), CanonicalJsonOptions),
            JsonValueKind.Number => value.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Null => "null",
            _ => "null",
        };
    }

    private static T TransformedOr<T>(InterventionPointResult result, T fallback, EnforcementMode mode)
    {
        if (mode != EnforcementMode.Enforce || !result.Verdict.Decision.AppliesEffects())
        {
            return fallback;
        }

        if (!result.TransformedPolicyTarget.HasValue || result.TransformedPolicyTarget.Value.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
        {
            return fallback;
        }

        return JsonSerializer.Deserialize<T>(result.TransformedPolicyTarget.Value.GetRawText(), JsonOptions)!;
    }

    private static JsonElement BuildSnapshot(
        IReadOnlyDictionary<string, object?>? ambient,
        params (string Key, object? Value)[] fields)
    {
        var envelope = ambient is null
            ? new Dictionary<string, object?>()
            : new Dictionary<string, object?>(ambient);
        foreach (var field in fields)
        {
            envelope[field.Key] = field.Value;
        }

        return JsonSerializer.SerializeToElement(envelope, JsonOptions);
    }

    private static Dictionary<string, object?> ToolCall<TArgs>(string name, TArgs args, string id) =>
        new()
        {
            ["id"] = id,
            ["name"] = name,
            ["args"] = args,
        };

    private static string RequireToolCallId(string? id)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            throw new ArgumentException("toolCallId is required for tool intervention point snapshots.", nameof(id));
        }

        return id;
    }
}

/// <summary>
/// Mutable session handle passed to <see cref="AgentControl.RunSessionAsync"/>.
/// Assign <see cref="Summary"/> inside the session body to supply the
/// <c>agent_shutdown</c> policy target.
/// </summary>
public sealed class GuardedSession
{
    public object? Summary { get; set; } = new Dictionary<string, object?>();
}
