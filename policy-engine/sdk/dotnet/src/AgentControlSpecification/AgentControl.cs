using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AgentControlSpecification;

public sealed class AgentControl
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
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

    /// <summary>
    /// Async counterpart to <see cref="FromPath"/>. Native runtime construction
    /// still happens off the calling thread so a manifest with a large bundle
    /// or many <c>extends</c> rolls do not stall an async caller. Mirrors the
    /// Rust SDK's <c>AgentControl::from_path</c> ergonomics.
    /// </summary>
    public static ValueTask<AgentControl> FromPathAsync(
        string path,
        IAnnotatorDispatcher? annotatorDispatcher = null,
        IPolicyDispatcher? policyDispatcher = null,
        ApprovalResolver? approvalResolver = null,
        PerfTelemetry perfTelemetry = PerfTelemetry.Off,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        cancellationToken.ThrowIfCancellationRequested();
        return new ValueTask<AgentControl>(Task.Run(
            () => FromPath(path, annotatorDispatcher, policyDispatcher, approvalResolver, perfTelemetry),
            cancellationToken));
    }

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
        var normalizedToolCallId = NormalizeToolCallId(toolCallId);
        return EvaluateInterventionPointAsync(
            InterventionPoint.PreToolCall,
            BuildSnapshot(snapshot, ("tool_call", ToolCall(toolName, args, normalizedToolCallId))),
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
        var normalizedToolCallId = NormalizeToolCallId(toolCallId);
        return EvaluateInterventionPointAsync(
            InterventionPoint.PostToolCall,
            BuildSnapshot(
                snapshot,
                ("tool_call", ToolCall(toolName, args, normalizedToolCallId)),
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
                BuildSnapshot(snapshot, ("summary", agent)),
                mode,
                cancellationToken)
            : EvaluateInterventionPointAsync(
                InterventionPoint.AgentShutdown,
                BuildSnapshot(snapshot, ("summary", agent), ("reason", reason)),
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
        return await RunModelCoreAsync(
            modelRequest,
            execute,
            snapshot,
            mode,
            approvalResolver,
            cancellationToken,
            rejectStreamingRequests: true).ConfigureAwait(false);
    }

    internal async ValueTask<ModelRunResult<TResponse>> RunModelCoreAsync<TRequest, TResponse>(
        TRequest modelRequest,
        Func<TRequest, CancellationToken, ValueTask<TResponse>> execute,
        IReadOnlyDictionary<string, object?>? snapshot,
        EnforcementMode mode,
        ApprovalResolver? approvalResolver,
        CancellationToken cancellationToken,
        bool rejectStreamingRequests)
    {
        ArgumentNullException.ThrowIfNull(execute);
        if (rejectStreamingRequests)
        {
            RejectStreamingModelRequest(modelRequest);
        }

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
        RejectStreamingModelRequest(modelRequest);

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
        var normalizedToolCallId = NormalizeToolCallId(toolCallId);
        var preToolCallResult = await EvaluateInterventionPointAsync(
            InterventionPoint.PreToolCall,
            BuildSnapshot(snapshot, ("tool_call", ToolCall(toolName, args, normalizedToolCallId))),
            mode,
            cancellationToken).ConfigureAwait(false);
        await EnforceAsync(InterventionPoint.PreToolCall, preToolCallResult, mode, approvalResolver, cancellationToken).ConfigureAwait(false);
        var effectiveArgs = TransformedOr(preToolCallResult, args, mode);

        var toolResult = await execute(effectiveArgs, cancellationToken).ConfigureAwait(false);
        var postToolCallResult = await EvaluateInterventionPointAsync(
            InterventionPoint.PostToolCall,
            BuildSnapshot(
                snapshot,
                ("tool_call", ToolCall(toolName, effectiveArgs, normalizedToolCallId)),
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
            throw new AgentControlBlockedException(interventionPoint, ApprovalResolverFailedResult(result), exception);
        }

        if (resolution is null)
        {
            throw new AgentControlBlockedException(interventionPoint, ApprovalResolverFailedResult(result));
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
                throw new AgentControlBlockedException(interventionPoint, ApprovalResolverFailedResult(result));
        }
    }

    private static void RejectStreamingModelRequest<TRequest>(TRequest modelRequest)
    {
        if (!IsExplicitStreamingRequest(modelRequest))
        {
            return;
        }

        throw new AgentControlBlockedException(
            InterventionPoint.PreModelCall,
            new InterventionPointResult(
                new Verdict(
                    Decision.Deny,
                    Reason: "runtime_error:streaming_unsupported",
                    Message: "Streaming model requests are not guarded by RunModelAsync; use RunModelStreamAsync for SSE buffering.")));
    }

    private static bool IsExplicitStreamingRequest<TRequest>(TRequest modelRequest)
    {
        if (modelRequest is null)
        {
            return false;
        }

        var request = JsonSerializer.SerializeToElement(modelRequest, JsonOptions);
        return request.ValueKind == JsonValueKind.Object
            && request.TryGetProperty("stream", out var stream)
            && stream.ValueKind == JsonValueKind.True;
    }

    private static InterventionPointResult ApprovalResolverFailedResult(InterventionPointResult result) =>
        new(
            new Verdict(
                Decision.Deny,
                Reason: "runtime_error:approval_resolver_failed",
                Message: "Approval resolver failed closed."),
            PolicyInput: result.PolicyInput,
            ActionIdentity: result.ActionIdentity);

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
                .OrderBy(property => property.Name, UnicodeScalarStringComparer.Instance)
                .Select(property => QuoteJsonString(property.Name) + ":" + CanonicalJson(property.Value))) + "}",
            JsonValueKind.Array => "[" + string.Join(",", value.EnumerateArray().Select(CanonicalJson)) + "]",
            JsonValueKind.String => QuoteJsonString(value.GetString() ?? string.Empty),
            JsonValueKind.Number => value.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Null => "null",
            _ => "null",
        };
    }

    private static string QuoteJsonString(string value)
    {
        var builder = new StringBuilder(value.Length + 2);
        builder.Append('"');
        foreach (var ch in value)
        {
            builder.Append(ch switch
            {
                '"' => "\\\"",
                '\\' => "\\\\",
                '\b' => "\\b",
                '\f' => "\\f",
                '\n' => "\\n",
                '\r' => "\\r",
                '\t' => "\\t",
                _ when ch < 0x20 => $"\\u{(int)ch:x4}",
                _ => ch,
            });
        }
        builder.Append('"');
        return builder.ToString();
    }

    private sealed class UnicodeScalarStringComparer : IComparer<string>
    {
        public static readonly UnicodeScalarStringComparer Instance = new();

        public int Compare(string? x, string? y)
        {
            if (ReferenceEquals(x, y))
            {
                return 0;
            }

            if (x is null)
            {
                return -1;
            }

            if (y is null)
            {
                return 1;
            }

            var left = x.EnumerateRunes().GetEnumerator();
            var right = y.EnumerateRunes().GetEnumerator();
            while (true)
            {
                var hasLeft = left.MoveNext();
                var hasRight = right.MoveNext();
                if (!hasLeft || !hasRight)
                {
                    return hasLeft == hasRight ? 0 : hasLeft ? 1 : -1;
                }

                var comparison = left.Current.Value.CompareTo(right.Current.Value);
                if (comparison != 0)
                {
                    return comparison;
                }
            }
        }
    }

    private static T TransformedOr<T>(InterventionPointResult result, T fallback, EnforcementMode mode)
    {
        if (mode != EnforcementMode.Enforce || !result.Verdict.Decision.AppliesTransform())
        {
            return fallback;
        }

        var hasTransformedPolicyTarget =
            result.TransformedPolicyTargetApplied ||
            (result.TransformedPolicyTarget.HasValue
                && result.TransformedPolicyTarget.Value.ValueKind != JsonValueKind.Undefined);
        if (!hasTransformedPolicyTarget)
        {
            return fallback;
        }

        var transformedJson = result.TransformedPolicyTarget?.GetRawText() ?? "null";
        if (TrySpliceNestedPolicyTarget(result, fallback, transformedJson, out var spliced))
        {
            return spliced;
        }

        return JsonSerializer.Deserialize<T>(transformedJson, JsonOptions)!;
    }

    private static bool TrySpliceNestedPolicyTarget<T>(
        InterventionPointResult result,
        T fallback,
        string transformedJson,
        out T spliced)
    {
        spliced = fallback;
        var relativePath = RelativeSnapshotPath(PolicyTargetPath(result));
        if (relativePath is null || relativePath.Length == 0)
        {
            return false;
        }

        var root = JsonSerializer.SerializeToNode(fallback, JsonOptions);
        var transformed = JsonNode.Parse(transformedJson);
        if (root is null || !SetRelativeJsonPath(root, relativePath, transformed))
        {
            return false;
        }

        spliced = root.Deserialize<T>(JsonOptions)!;
        return true;
    }

    private static string? PolicyTargetPath(InterventionPointResult result)
    {
        if (!result.PolicyInput.HasValue ||
            result.PolicyInput.Value.ValueKind != JsonValueKind.Object ||
            !result.PolicyInput.Value.TryGetProperty("policy_target", out var policyTarget) ||
            policyTarget.ValueKind != JsonValueKind.Object ||
            !policyTarget.TryGetProperty("path", out var path) ||
            path.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        return path.GetString();
    }

    private static string? RelativeSnapshotPath(string? path)
    {
        string rest;
        if (path is null)
        {
            return null;
        }
        else if (path.StartsWith("$.", StringComparison.Ordinal))
        {
            rest = path[2..];
        }
        else if (path.StartsWith("$snap.", StringComparison.Ordinal))
        {
            rest = path[6..];
        }
        else
        {
            return null;
        }

        var firstSegmentEnd = rest.Length;
        var dot = rest.IndexOf('.', StringComparison.Ordinal);
        var bracket = rest.IndexOf('[', StringComparison.Ordinal);
        if (dot >= 0)
        {
            firstSegmentEnd = Math.Min(firstSegmentEnd, dot);
        }
        if (bracket >= 0)
        {
            firstSegmentEnd = Math.Min(firstSegmentEnd, bracket);
        }

        return firstSegmentEnd == rest.Length ? string.Empty : rest[firstSegmentEnd..];
    }

    private static bool SetRelativeJsonPath(JsonNode root, string path, JsonNode? value)
    {
        var segments = RelativePathSegments(path);
        if (segments.Count == 0)
        {
            return false;
        }

        var current = root;
        foreach (var segment in segments.Take(segments.Count - 1))
        {
            current = segment switch
            {
                string field when current is JsonObject obj && obj[field] is not null => obj[field]!,
                int index when current is JsonArray array && index >= 0 && index < array.Count && array[index] is not null => array[index]!,
                _ => null,
            };
            if (current is null)
            {
                return false;
            }
        }

        return segments[^1] switch
        {
            string field when current is JsonObject obj && obj.ContainsKey(field) => SetObjectValue(obj, field, value),
            int index when current is JsonArray array && index >= 0 && index < array.Count => SetArrayValue(array, index, value),
            _ => false,
        };
    }

    private static List<object> RelativePathSegments(string path)
    {
        var segments = new List<object>();
        var index = 0;
        while (index < path.Length)
        {
            if (path[index] == '.')
            {
                index++;
                var start = index;
                while (index < path.Length && path[index] != '.' && path[index] != '[')
                {
                    index++;
                }
                if (start == index)
                {
                    return [];
                }
                segments.Add(path[start..index]);
            }
            else if (path[index] == '[')
            {
                var end = path.IndexOf(']', index);
                if (end < 0 || !int.TryParse(path[(index + 1)..end], out var arrayIndex))
                {
                    return [];
                }
                segments.Add(arrayIndex);
                index = end + 1;
            }
            else
            {
                return [];
            }
        }

        return segments;
    }

    private static bool SetObjectValue(JsonObject obj, string field, JsonNode? value)
    {
        obj[field] = value;
        return true;
    }

    private static bool SetArrayValue(JsonArray array, int index, JsonNode? value)
    {
        array[index] = value;
        return true;
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

    private static Dictionary<string, object?> ToolCall<TArgs>(string name, TArgs args, string? id)
    {
        var toolCall = new Dictionary<string, object?>
        {
            ["name"] = name,
            ["args"] = args,
        };
        if (id is not null)
        {
            toolCall["id"] = id;
        }

        return toolCall;
    }

    private static string? NormalizeToolCallId(string? id)
    {
        if (id is null)
        {
            return null;
        }

        if (id.Length == 0)
        {
            throw new ArgumentException("toolCallId must be a non-empty string when provided.", nameof(id));
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
