using System.Reflection;
using System.Text.Json;
using Microsoft.Extensions.AI;

namespace AgentControlSpecification.AI;

public sealed class AgentControlAIFunction : AIFunction
{
    private readonly AIFunction inner;
    private readonly AgentControl control;
    private readonly EnforcementMode mode;
    private readonly ApprovalResolver? approvalResolver;

    public AgentControlAIFunction(AIFunction inner, AgentControl control, EnforcementMode mode = EnforcementMode.Enforce, ApprovalResolver? approvalResolver = null)
    {
        this.inner = inner ?? throw new ArgumentNullException(nameof(inner));
        this.control = control ?? throw new ArgumentNullException(nameof(control));
        this.mode = mode;
        this.approvalResolver = approvalResolver;
    }

    public AIFunction InnerFunction => inner;

    public override MethodInfo? UnderlyingMethod => inner.UnderlyingMethod;

    public override JsonSerializerOptions JsonSerializerOptions => inner.JsonSerializerOptions;

    public override JsonElement JsonSchema => inner.JsonSchema;

    public override JsonElement? ReturnJsonSchema => inner.ReturnJsonSchema;

    public override string Name => inner.Name;

    public override string Description => inner.Description;

    public override IReadOnlyDictionary<string, object?> AdditionalProperties => inner.AdditionalProperties;

    protected override async ValueTask<object?> InvokeCoreAsync(AIFunctionArguments arguments, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        var args = arguments.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        var result = await control.ProtectToolAsync<IReadOnlyDictionary<string, object?>, object?>(
            Name,
            args,
            async (effectiveArgs, ct) => await inner.InvokeAsync(BuildArgs(effectiveArgs, arguments), ct).ConfigureAwait(false),
            toolCallId: null,
            snapshot: null,
            mode: mode,
            approvalResolver: approvalResolver,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        return result.Value;
    }

    private static AIFunctionArguments BuildArgs(IReadOnlyDictionary<string, object?> args, AIFunctionArguments original)
    {
        var rebuilt = new AIFunctionArguments(args.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal))
        {
            Services = original.Services,
            Context = original.Context,
        };
        return rebuilt;
    }
}
