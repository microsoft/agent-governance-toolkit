using System.Text.Json;

namespace AgentControlSpecification;

public interface IFullCoverageAgentAdapter<TAgent>
{
    TAgent Guard(TAgent agent, AgentControl control);
}

public interface IModelCallMiddleware
{
    ValueTask<InterventionPointResult> PreModelCallAsync(
        JsonElement modelRequestSnapshot,
        CancellationToken cancellationToken = default);

    ValueTask<InterventionPointResult> PostModelCallAsync(
        JsonElement modelResponseSnapshot,
        CancellationToken cancellationToken = default);
}

public interface IAgentControlChatClient<TRequest, TResponse>
{
    ValueTask<TResponse> GetResponseAsync(
        TRequest request,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        CancellationToken cancellationToken = default);
}

public sealed class AgentControlDelegatingChatClient<TRequest, TResponse> :
    IAgentControlChatClient<TRequest, TResponse>
{
    private readonly IAgentControlChatClient<TRequest, TResponse> inner;
    private readonly AgentControl control;
    private readonly EnforcementMode mode;
    private readonly ApprovalResolver? approvalResolver;

    public AgentControlDelegatingChatClient(
        IAgentControlChatClient<TRequest, TResponse> inner,
        AgentControl control,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null)
    {
        this.inner = inner ?? throw new ArgumentNullException(nameof(inner));
        this.control = control ?? throw new ArgumentNullException(nameof(control));
        this.mode = mode;
        this.approvalResolver = approvalResolver;
    }

    public async ValueTask<TResponse> GetResponseAsync(
        TRequest request,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        CancellationToken cancellationToken = default)
    {
        var result = await control.RunModelAsync<TRequest, TResponse>(
            request,
            (effectiveRequest, ct) => inner.GetResponseAsync(effectiveRequest, snapshot, ct),
            snapshot,
            mode,
            approvalResolver,
            cancellationToken).ConfigureAwait(false);

        return result.Value;
    }
}

public static class AgentControlChatClientExtensions
{
    public static AgentControlDelegatingChatClient<TRequest, TResponse> UseAgentControl<TRequest, TResponse>(
        this IAgentControlChatClient<TRequest, TResponse> client,
        AgentControl control,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null) =>
        new(client, control, mode, approvalResolver);
}

public interface IAgentControlToolInvocationFilter<TArgs, TOutput>
{
    ValueTask<ToolRunResult<TOutput>> InvokeAsync(
        string toolName,
        TArgs args,
        Func<TArgs, CancellationToken, ValueTask<TOutput>> next,
        string? toolCallId = null,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null,
        CancellationToken cancellationToken = default);
}

public sealed class AgentControlToolInvocationFilter<TArgs, TOutput> :
    IAgentControlToolInvocationFilter<TArgs, TOutput>
{
    private readonly AgentControl control;

    public AgentControlToolInvocationFilter(AgentControl control)
    {
        this.control = control ?? throw new ArgumentNullException(nameof(control));
    }

    public ValueTask<ToolRunResult<TOutput>> InvokeAsync(
        string toolName,
        TArgs args,
        Func<TArgs, CancellationToken, ValueTask<TOutput>> next,
        string? toolCallId = null,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null,
        CancellationToken cancellationToken = default) =>
        control.ProtectToolAsync(
            toolName,
            args,
            next,
            toolCallId,
            snapshot,
            mode,
            approvalResolver,
            cancellationToken);
}

public interface IAgentControlFunctionInvocationContext<TArgs, TOutput>
{
    string FunctionName { get; }

    TArgs Arguments { get; set; }

    TOutput? Result { get; set; }

    string? ToolCallId { get; }

    IReadOnlyDictionary<string, object?>? Snapshot { get; }
}

public sealed class AgentControlSemanticKernelFunctionFilter<TArgs, TOutput>
{
    private readonly AgentControl control;
    private readonly EnforcementMode mode;
    private readonly ApprovalResolver? approvalResolver;

    public AgentControlSemanticKernelFunctionFilter(
        AgentControl control,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null)
    {
        this.control = control ?? throw new ArgumentNullException(nameof(control));
        this.mode = mode;
        this.approvalResolver = approvalResolver;
    }

    public async ValueTask InvokeAsync(
        IAgentControlFunctionInvocationContext<TArgs, TOutput> context,
        Func<IAgentControlFunctionInvocationContext<TArgs, TOutput>, CancellationToken, ValueTask> next,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);
        ArgumentException.ThrowIfNullOrWhiteSpace(context.FunctionName);

        var result = await control.ProtectToolAsync(
            context.FunctionName,
            context.Arguments,
            async (effectiveArgs, ct) =>
            {
                context.Arguments = effectiveArgs;
                await next(context, ct).ConfigureAwait(false);
                return context.Result!;
            },
            context.ToolCallId,
            context.Snapshot,
            mode,
            approvalResolver,
            cancellationToken).ConfigureAwait(false);

        context.Result = result.Value;
    }
}

public interface IAgentControlAgentMiddleware<TInput, TOutput>
{
    ValueTask<RunResult<TOutput>> InvokeAsync(
        TInput input,
        Func<TInput, CancellationToken, ValueTask<TOutput>> next,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null,
        CancellationToken cancellationToken = default);
}

public sealed class AgentControlAgentMiddleware<TInput, TOutput> :
    IAgentControlAgentMiddleware<TInput, TOutput>
{
    private readonly AgentControl control;

    public AgentControlAgentMiddleware(AgentControl control)
    {
        this.control = control ?? throw new ArgumentNullException(nameof(control));
    }

    public ValueTask<RunResult<TOutput>> InvokeAsync(
        TInput input,
        Func<TInput, CancellationToken, ValueTask<TOutput>> next,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null,
        CancellationToken cancellationToken = default) =>
        control.RunAsync(input, next, snapshot, mode, approvalResolver, cancellationToken);
}

public interface IAgentControlAgentInvocationContext<TInput, TOutput>
{
    TInput Input { get; set; }

    TOutput? Output { get; set; }

    IReadOnlyDictionary<string, object?>? Snapshot { get; }
}

public sealed class AgentControlAutoGenMiddleware<TInput, TOutput>
{
    private readonly AgentControl control;
    private readonly EnforcementMode mode;
    private readonly ApprovalResolver? approvalResolver;

    public AgentControlAutoGenMiddleware(
        AgentControl control,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null)
    {
        this.control = control ?? throw new ArgumentNullException(nameof(control));
        this.mode = mode;
        this.approvalResolver = approvalResolver;
    }

    public async ValueTask InvokeAsync(
        IAgentControlAgentInvocationContext<TInput, TOutput> context,
        Func<IAgentControlAgentInvocationContext<TInput, TOutput>, CancellationToken, ValueTask> next,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        var result = await control.RunAsync(
            context.Input,
            async (effectiveInput, ct) =>
            {
                context.Input = effectiveInput;
                await next(context, ct).ConfigureAwait(false);
                return context.Output!;
            },
            context.Snapshot,
            mode,
            approvalResolver,
            cancellationToken).ConfigureAwait(false);

        context.Output = result.Value;
    }
}

// Microsoft Agent Framework (the unified successor to Semantic Kernel and
// AutoGen) exposes two middleware seams. Function-calling middleware wraps a
// tool/function invocation and maps onto the pre_tool_call and post_tool_call
// intervention points; agent-run middleware wraps an agent turn and maps onto
// the input and output intervention points. These duck-typed adapters let an
// integrator bind those seams to ACS without this SDK taking a dependency on
// the Agent Framework packages: bind the Agent Framework FunctionInvocationContext
// to IAgentControlFunctionInvocationContext, and the agent-run context to
// IAgentControlAgentInvocationContext.
public sealed class AgentControlAgentFrameworkFunctionMiddleware<TArgs, TOutput>
{
    private readonly AgentControl control;
    private readonly EnforcementMode mode;
    private readonly ApprovalResolver? approvalResolver;

    public AgentControlAgentFrameworkFunctionMiddleware(
        AgentControl control,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null)
    {
        this.control = control ?? throw new ArgumentNullException(nameof(control));
        this.mode = mode;
        this.approvalResolver = approvalResolver;
    }

    public async ValueTask InvokeAsync(
        IAgentControlFunctionInvocationContext<TArgs, TOutput> context,
        Func<IAgentControlFunctionInvocationContext<TArgs, TOutput>, CancellationToken, ValueTask> next,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);
        ArgumentException.ThrowIfNullOrWhiteSpace(context.FunctionName);

        var result = await control.ProtectToolAsync(
            context.FunctionName,
            context.Arguments,
            async (effectiveArgs, ct) =>
            {
                context.Arguments = effectiveArgs;
                await next(context, ct).ConfigureAwait(false);
                return context.Result!;
            },
            context.ToolCallId,
            context.Snapshot,
            mode,
            approvalResolver,
            cancellationToken).ConfigureAwait(false);

        context.Result = result.Value;
    }
}

public sealed class AgentControlAgentFrameworkRunMiddleware<TInput, TOutput>
{
    private readonly AgentControl control;
    private readonly EnforcementMode mode;
    private readonly ApprovalResolver? approvalResolver;

    public AgentControlAgentFrameworkRunMiddleware(
        AgentControl control,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null)
    {
        this.control = control ?? throw new ArgumentNullException(nameof(control));
        this.mode = mode;
        this.approvalResolver = approvalResolver;
    }

    public async ValueTask InvokeAsync(
        IAgentControlAgentInvocationContext<TInput, TOutput> context,
        Func<IAgentControlAgentInvocationContext<TInput, TOutput>, CancellationToken, ValueTask> next,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        var result = await control.RunAsync(
            context.Input,
            async (effectiveInput, ct) =>
            {
                context.Input = effectiveInput;
                await next(context, ct).ConfigureAwait(false);
                return context.Output!;
            },
            context.Snapshot,
            mode,
            approvalResolver,
            cancellationToken).ConfigureAwait(false);

        context.Output = result.Value;
    }
}

public static class AgentControlFrameworkAdapters
{
    public static AgentControlSemanticKernelFunctionFilter<TArgs, TOutput> SemanticKernelFunctionFilter<TArgs, TOutput>(
        AgentControl control,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null) =>
        new(control, mode, approvalResolver);

    public static AgentControlAutoGenMiddleware<TInput, TOutput> AutoGenMiddleware<TInput, TOutput>(
        AgentControl control,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null) =>
        new(control, mode, approvalResolver);

    public static AgentControlAgentFrameworkFunctionMiddleware<TArgs, TOutput> AgentFrameworkFunctionMiddleware<TArgs, TOutput>(
        AgentControl control,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null) =>
        new(control, mode, approvalResolver);

    public static AgentControlAgentFrameworkRunMiddleware<TInput, TOutput> AgentFrameworkRunMiddleware<TInput, TOutput>(
        AgentControl control,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null) =>
        new(control, mode, approvalResolver);
}

public sealed class UnsupportedFrameworkAdapter<TAgent> : IFullCoverageAgentAdapter<TAgent>
{
    public UnsupportedFrameworkAdapter(string frameworkName)
    {
        FrameworkName = string.IsNullOrWhiteSpace(frameworkName)
            ? throw new ArgumentException("Framework name is required.", nameof(frameworkName))
            : frameworkName;
    }

    public string FrameworkName { get; }

    public TAgent Guard(TAgent agent, AgentControl control) =>
        throw new AgentControlBlockedException(
            InterventionPoint.Input,
            new InterventionPointResult(new Verdict(
                Decision.Deny,
                Reason: "runtime_error:adapter_unsupported",
                Message:
                    $"Package-specific full-coverage {FrameworkName} adapter is not wired in this no-dependency SDK surface; " +
                    "use AgentControl.RunAsync(), AgentControl.RunModelAsync(), AgentControl.ProtectToolAsync(), " +
                    "or the no-dependency duck-typed adapter shapes.")));
}
