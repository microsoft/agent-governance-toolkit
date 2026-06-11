using System.Runtime.InteropServices;
using System.Text.Json;
using AgentControlSpecification.Interop;

namespace AgentControlSpecification;

public interface IAnnotatorDispatcher
{
    ValueTask<JsonElement> DispatchAsync(
        string annotatorName,
        JsonElement annotatorConfig,
        JsonElement preliminaryPolicyInput,
        CancellationToken cancellationToken = default);
}

public interface IPolicyDispatcher
{
    ValueTask<JsonElement> EvaluateAsync(
        JsonElement preparedInvocation,
        CancellationToken cancellationToken = default);
}

public interface IAgentControlRuntime
{
    ValueTask<InterventionPointResult> EvaluateInterventionPointAsync(
        InterventionPointRequest request,
        CancellationToken cancellationToken = default);
}

public sealed class NativeAgentControlRuntime : IAgentControlRuntime, IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    // Single source of truth for the annotator timeout sentinel that the host
    // dispatcher signals back to the native runtime. It must match the core
    // reserved reason `runtime_error:annotation_timeout`.
    private const string AnnotationTimeoutReason = "runtime_error:annotation_timeout";
    private readonly IAnnotatorDispatcher? annotatorDispatcher;
    private readonly IPolicyDispatcher? policyDispatcher;
    private readonly AcsRuntimeHandle handle;

    public NativeAgentControlRuntime(
        object manifest,
        IAnnotatorDispatcher? annotatorDispatcher = null,
        IPolicyDispatcher? policyDispatcher = null,
        PerfTelemetry perfTelemetry = PerfTelemetry.Off)
        : this(
            annotatorDispatcher,
            policyDispatcher,
            (annotatorCallback, policyCallback, freeResultCallback) =>
                BuildRuntime(ManifestToString(manifest ?? throw new ArgumentNullException(nameof(manifest))), annotatorCallback, policyCallback, freeResultCallback, perfTelemetry))
    {
    }

    private NativeAgentControlRuntime(
        IAnnotatorDispatcher? annotatorDispatcher,
        IPolicyDispatcher? policyDispatcher,
        Func<NativeMethods.AcsAnnotatorCallback?, NativeMethods.AcsPolicyCallback?, NativeMethods.AcsFreeResultCallback, AcsRuntimeHandle> build)
    {
        this.annotatorDispatcher = annotatorDispatcher;
        this.policyDispatcher = policyDispatcher;

        // A null dispatcher opts into the bundled native default (OPA policy /
        // classifier annotator) supplied by the Rust core.
        var annotatorCallback = annotatorDispatcher is null
            ? null
            : new NativeMethods.AcsAnnotatorCallback(DispatchAnnotator);
        var policyCallback = policyDispatcher is null
            ? null
            : new NativeMethods.AcsPolicyCallback(EvaluatePolicy);
        var freeResultCallback = new NativeMethods.AcsFreeResultCallback(FreeResult);
        handle = build(annotatorCallback, policyCallback, freeResultCallback);
    }

    public static NativeAgentControlRuntime FromPath(
        string path,
        IAnnotatorDispatcher? annotatorDispatcher = null,
        IPolicyDispatcher? policyDispatcher = null,
        PerfTelemetry perfTelemetry = PerfTelemetry.Off)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return new NativeAgentControlRuntime(
            annotatorDispatcher,
            policyDispatcher,
            (annotatorCallback, policyCallback, freeResultCallback) =>
                BuildRuntimeFromPath(path, annotatorCallback, policyCallback, freeResultCallback, perfTelemetry));
    }

    public static NativeAgentControlRuntime FromManifestChain(
        IReadOnlyList<string> manifests,
        IAnnotatorDispatcher? annotatorDispatcher = null,
        IPolicyDispatcher? policyDispatcher = null,
        PerfTelemetry perfTelemetry = PerfTelemetry.Off)
    {
        ArgumentNullException.ThrowIfNull(manifests);
        if (manifests.Count == 0)
        {
            throw new ArgumentException("Manifest chain must not be empty.", nameof(manifests));
        }

        return new NativeAgentControlRuntime(
            annotatorDispatcher,
            policyDispatcher,
            (annotatorCallback, policyCallback, freeResultCallback) =>
                BuildRuntimeFromManifestChain(manifests, annotatorCallback, policyCallback, freeResultCallback, perfTelemetry));
    }

    public ValueTask<InterventionPointResult> EvaluateInterventionPointAsync(
        InterventionPointRequest request,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return new ValueTask<InterventionPointResult>(Task.Run(() => EvaluateCore(request), cancellationToken));
    }

    public void Dispose() => handle.Dispose();

    private static AcsRuntimeHandle BuildRuntime(
        string manifest,
        NativeMethods.AcsAnnotatorCallback? annotatorCallback,
        NativeMethods.AcsPolicyCallback? policyCallback,
        NativeMethods.AcsFreeResultCallback freeResultCallback,
        PerfTelemetry perfTelemetry)
    {
        return BuildRuntimeFromBuilder(
            () =>
            {
                var builder = NativeMethods.AcsBuilderFromYaml(manifest, out var err);
                return (builder, err);
            },
            annotatorCallback,
            policyCallback,
            freeResultCallback,
            perfTelemetry);
    }

    private static AcsRuntimeHandle BuildRuntimeFromPath(
        string path,
        NativeMethods.AcsAnnotatorCallback? annotatorCallback,
        NativeMethods.AcsPolicyCallback? policyCallback,
        NativeMethods.AcsFreeResultCallback freeResultCallback,
        PerfTelemetry perfTelemetry)
    {
        return BuildRuntimeFromBuilder(
            () =>
            {
                var builder = NativeMethods.AcsBuilderFromPath(path, out var err);
                return (builder, err);
            },
            annotatorCallback,
            policyCallback,
            freeResultCallback,
            perfTelemetry);
    }

    private static AcsRuntimeHandle BuildRuntimeFromManifestChain(
        IReadOnlyList<string> manifests,
        NativeMethods.AcsAnnotatorCallback? annotatorCallback,
        NativeMethods.AcsPolicyCallback? policyCallback,
        NativeMethods.AcsFreeResultCallback freeResultCallback,
        PerfTelemetry perfTelemetry)
    {
        return WithNativeStringArray(manifests, (array, count) =>
            BuildRuntimeFromBuilder(
                () =>
                {
                    var builder = NativeMethods.AcsBuilderFromYamlChain(array, count, out var err);
                    return (builder, err);
                },
                annotatorCallback,
                policyCallback,
                freeResultCallback,
                perfTelemetry));
    }

    private static AcsRuntimeHandle BuildRuntimeFromBuilder(
        Func<(IntPtr Builder, IntPtr Error)> createBuilder,
        NativeMethods.AcsAnnotatorCallback? annotatorCallback,
        NativeMethods.AcsPolicyCallback? policyCallback,
        NativeMethods.AcsFreeResultCallback freeResultCallback,
        PerfTelemetry perfTelemetry)
    {
        var builder = IntPtr.Zero;
        var buildConsumesBuilder = false;
        try
        {
            if (policyCallback is null)
            {
                NativeEnvironment.SyncOpaEnvironment();
            }

            var created = createBuilder();
            builder = created.Builder;
            ThrowIfNativeFailed(builder, created.Error, "create ACS builder");

            IntPtr err;
            int code;
            if (annotatorCallback is null)
            {
                code = NativeMethods.AcsBuilderEnableDefaultAnnotatorDispatcher(builder, out err);
                ThrowIfNativeFailed(code, err, "enable default ACS annotator dispatcher");
            }
            else
            {
                code = NativeMethods.AcsBuilderRegisterAnnotatorDispatcher(
                    builder,
                    annotatorCallback,
                    freeResultCallback,
                    IntPtr.Zero,
                    out err);
                ThrowIfNativeFailed(code, err, "register ACS annotator dispatcher");
            }

            if (policyCallback is null)
            {
                code = NativeMethods.AcsBuilderEnableDefaultPolicyDispatcher(builder, out err);
                ThrowIfNativeFailed(code, err, "enable default ACS policy dispatcher");
            }
            else
            {
                code = NativeMethods.AcsBuilderRegisterPolicyDispatcher(
                    builder,
                    policyCallback,
                    freeResultCallback,
                    IntPtr.Zero,
                    out err);
                ThrowIfNativeFailed(code, err, "register ACS policy dispatcher");
            }

            code = NativeMethods.AcsBuilderSetPerfTelemetry(builder, (int)perfTelemetry, out err);
            ThrowIfNativeFailed(code, err, "set ACS perf telemetry");

            var runtime = NativeMethods.AcsBuilderBuild(builder, out err);
            buildConsumesBuilder = true;
            ThrowIfNativeFailed(runtime, err, "build ACS runtime");
            return AcsRuntimeHandle.FromExisting(runtime, annotatorCallback, policyCallback, freeResultCallback);
        }
        finally
        {
            if (builder != IntPtr.Zero && !buildConsumesBuilder)
            {
                NativeMethods.AcsBuilderFree(builder);
            }
        }
    }

    private static T WithNativeStringArray<T>(IReadOnlyList<string> values, Func<IntPtr, nuint, T> action)
    {
        var stringPointers = new IntPtr[values.Count];
        var arrayPtr = IntPtr.Zero;
        try
        {
            for (var index = 0; index < values.Count; index++)
            {
                stringPointers[index] = Marshal.StringToCoTaskMemUTF8(values[index]);
            }

            arrayPtr = Marshal.AllocCoTaskMem(IntPtr.Size * values.Count);
            for (var index = 0; index < stringPointers.Length; index++)
            {
                Marshal.WriteIntPtr(arrayPtr, index * IntPtr.Size, stringPointers[index]);
            }

            return action(arrayPtr, (nuint)values.Count);
        }
        finally
        {
            if (arrayPtr != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(arrayPtr);
            }

            foreach (var pointer in stringPointers)
            {
                if (pointer != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(pointer);
                }
            }
        }
    }

    private InterventionPointResult EvaluateCore(InterventionPointRequest request)
    {
        var requestJson = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["intervention_point"] = InterventionPointWireValue(request.InterventionPoint),
            ["mode"] = EnforcementModeWireValue(request.Mode),
            ["snapshot"] = request.Snapshot,
        }, JsonOptions);

        var result = NativeMethods.AcsRuntimeEvaluate(handle.DangerousGetPointer(), requestJson, out var err);
        ThrowIfNativeFailed(result, err, "evaluate ACS intervention point");
        try
        {
            var json = Marshal.PtrToStringUTF8(result)
                ?? throw new InvalidOperationException("ACS native evaluate returned a null or non-UTF8 result string.");
            using var document = JsonDocument.Parse(json);
            return MapResult(document.RootElement);
        }
        finally
        {
            NativeMethods.AcsFreeString(result);
        }
    }

    private static object InterventionPointWireValue(InterventionPoint interventionPoint) => interventionPoint switch
    {
        InterventionPoint.AgentStartup => "agent_startup",
        InterventionPoint.Input => "input",
        InterventionPoint.PreModelCall => "pre_model_call",
        InterventionPoint.PostModelCall => "post_model_call",
        InterventionPoint.PreToolCall => "pre_tool_call",
        InterventionPoint.PostToolCall => "post_tool_call",
        InterventionPoint.Output => "output",
        InterventionPoint.AgentShutdown => "agent_shutdown",
        _ => (int)interventionPoint,
    };

    private static object EnforcementModeWireValue(EnforcementMode mode) => mode switch
    {
        EnforcementMode.Enforce => "enforce",
        EnforcementMode.EvaluateOnly => "evaluate_only",
        _ => (int)mode,
    };

    private IntPtr DispatchAnnotator(
        IntPtr annotatorNamePtr,
        IntPtr annotatorJsonPtr,
        IntPtr preliminaryPolicyInputJsonPtr,
        IntPtr userData)
    {
        try
        {
            var annotatorName = ReadNativeCallbackString(annotatorNamePtr, nameof(annotatorNamePtr));
            var annotatorJson = ReadNativeCallbackString(annotatorJsonPtr, nameof(annotatorJsonPtr));
            var preliminaryJson = ReadNativeCallbackString(preliminaryPolicyInputJsonPtr, nameof(preliminaryPolicyInputJsonPtr));
            var annotatorConfig = ParseJsonElement(annotatorJson);
            var preliminaryPolicyInput = ParseJsonElement(preliminaryJson);
            var result = annotatorDispatcher!
                .DispatchAsync(annotatorName, annotatorConfig, preliminaryPolicyInput)
                .AsTask()
                .GetAwaiter()
                .GetResult();
            return Marshal.StringToCoTaskMemUTF8(result.GetRawText());
        }
        catch (Exception exception) when (exception.Message.Contains(AnnotationTimeoutReason, StringComparison.Ordinal))
        {
            return Marshal.StringToCoTaskMemUTF8(AnnotationTimeoutReason);
        }
        catch
        {
            return IntPtr.Zero;
        }
    }

    private IntPtr EvaluatePolicy(IntPtr preparedInvocationJsonPtr, IntPtr userData)
    {
        try
        {
            var invocationJson = ReadNativeCallbackString(preparedInvocationJsonPtr, nameof(preparedInvocationJsonPtr));
            var invocation = ParseJsonElement(invocationJson);
            var result = policyDispatcher!
                .EvaluateAsync(invocation)
                .AsTask()
                .GetAwaiter()
                .GetResult();
            return Marshal.StringToCoTaskMemUTF8(result.GetRawText());
        }
        catch
        {
            return IntPtr.Zero;
        }
    }

    private static InterventionPointResult MapResult(JsonElement raw)
    {
        var verdict = MapVerdict(raw.GetProperty("verdict"));
        var transformedPolicyTargetApplied =
            raw.TryGetProperty("transformed_policy_target_applied", out var appliedElement)
                && appliedElement.ValueKind == JsonValueKind.True;
        if (!transformedPolicyTargetApplied
            && raw.TryGetProperty("transformed_policy_target", out var legacyTransformed)
            && legacyTransformed.ValueKind != JsonValueKind.Null
            && legacyTransformed.ValueKind != JsonValueKind.Undefined)
        {
            transformedPolicyTargetApplied = true;
        }

        // AGT D1.4: the FFI surfaces both `input_identity` and
        // `enforced_identity` alongside the back-compat `action_identity`
        // alias (which equals `enforced_identity`). We populate every slot
        // we can so audit consumers see the bisected pair without losing
        // the single-identity shape older callers depend on.
        var enforcedIdentity = OptionalString(raw, "enforced_identity");
        var inputIdentity = OptionalString(raw, "input_identity");
        var actionIdentity = OptionalString(raw, "action_identity") ?? enforcedIdentity;
        return new InterventionPointResult(
            verdict,
            OptionalTransformedPolicyTarget(raw, transformedPolicyTargetApplied),
            OptionalElement(raw, "policy_input"),
            actionIdentity,
            transformedPolicyTargetApplied,
            inputIdentity ?? actionIdentity,
            enforcedIdentity ?? actionIdentity);
    }

    private static Verdict MapVerdict(JsonElement raw)
    {
        var resultLabels = raw.TryGetProperty("result_labels", out var labelsElement) && labelsElement.ValueKind == JsonValueKind.Array
            ? labelsElement.EnumerateArray().Select(label => label.GetString() ?? string.Empty).ToArray()
            : Array.Empty<string>();
        return new Verdict(
            DecisionExtensions.FromWireName(raw.GetProperty("decision").GetString() ?? string.Empty),
            OptionalString(raw, "reason"),
            OptionalString(raw, "message"),
            MapTransform(raw),
            MapEvidence(raw),
            resultLabels);
    }

    private static Transform? MapTransform(JsonElement raw)
    {
        if (!raw.TryGetProperty("transform", out var transformElement) || transformElement.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return null;
        }

        var path = transformElement.GetProperty("path").GetString() ?? string.Empty;
        object? value = null;
        if (transformElement.TryGetProperty("value", out var valueElement) && valueElement.ValueKind != JsonValueKind.Undefined)
        {
            value = valueElement.Clone();
        }

        return new Transform(path, value);
    }

    private static Evidence? MapEvidence(JsonElement raw)
    {
        if (!raw.TryGetProperty("evidence", out var evidenceElement) || evidenceElement.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return null;
        }

        string? artefact = null;
        if (evidenceElement.TryGetProperty("artefact", out var artefactElement) && artefactElement.ValueKind == JsonValueKind.String)
        {
            artefact = artefactElement.GetString();
        }

        Dictionary<string, string>? pointers = null;
        if (evidenceElement.TryGetProperty("verification_pointers", out var pointersElement)
            && pointersElement.ValueKind == JsonValueKind.Object)
        {
            pointers = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var property in pointersElement.EnumerateObject())
            {
                if (property.Value.ValueKind == JsonValueKind.String)
                {
                    pointers[property.Name] = property.Value.GetString() ?? string.Empty;
                }
            }
        }

        return new Evidence(artefact, pointers);
    }

    private static JsonElement? OptionalElement(JsonElement raw, string propertyName)
    {
        if (!raw.TryGetProperty(propertyName, out var value) || value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return null;
        }

        return value.Clone();
    }

    private static JsonElement? OptionalTransformedPolicyTarget(JsonElement raw, bool applied)
    {
        if (!applied || !raw.TryGetProperty("transformed_policy_target", out var value) || value.ValueKind == JsonValueKind.Undefined)
        {
            return null;
        }

        return value.Clone();
    }

    private static string? OptionalString(JsonElement raw, string propertyName) =>
        raw.TryGetProperty(propertyName, out var value) && value.ValueKind != JsonValueKind.Null
            ? value.GetString()
            : null;

    private static JsonElement ParseJsonElement(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.Clone();
    }

    private static string ManifestToString(object manifest) => manifest switch
    {
        string text => text,
        JsonElement json => json.GetRawText(),
        _ => JsonSerializer.Serialize(manifest, JsonOptions),
    };

    private static string ReadNativeCallbackString(IntPtr value, string name) =>
        Marshal.PtrToStringUTF8(value)
        ?? throw new InvalidOperationException($"ACS native callback argument {name} was null or non-UTF8.");

    private static void FreeResult(IntPtr ptr, IntPtr userData)
    {
        if (ptr != IntPtr.Zero)
        {
            Marshal.FreeCoTaskMem(ptr);
        }
    }

    private static void ThrowIfNativeFailed(IntPtr result, IntPtr err, string operation)
    {
        var error = TakeNativeError(err);
        if (result == IntPtr.Zero)
        {
            throw new InvalidOperationException($"Failed to {operation}: {error ?? "native call returned null without an error"}.");
        }
    }

    private static void ThrowIfNativeFailed(int result, IntPtr err, string operation)
    {
        var error = TakeNativeError(err);
        if (result != 0)
        {
            throw new InvalidOperationException($"Failed to {operation}: {error ?? $"native call returned code {result}"}.");
        }
    }

    private static string? TakeNativeError(IntPtr err)
    {
        if (err == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            return Marshal.PtrToStringUTF8(err);
        }
        finally
        {
            NativeMethods.AcsFreeString(err);
        }
    }
}
