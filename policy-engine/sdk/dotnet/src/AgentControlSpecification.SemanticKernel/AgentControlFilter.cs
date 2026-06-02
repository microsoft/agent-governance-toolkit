using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.SemanticKernel;
using Microsoft.SemanticKernel.ChatCompletion;
using AgentControlSpecification.AI;

namespace AgentControlSpecification.SemanticKernel;

public sealed class AgentControlFilter : IAutoFunctionInvocationFilter
{
    private readonly AgentControlSemanticKernelFunctionFilter<Dictionary<string, object?>, object?> inner;

    public AgentControlFilter(AgentControl control, EnforcementMode mode = EnforcementMode.Enforce, ApprovalResolver? approvalResolver = null)
    {
        inner = new AgentControlSemanticKernelFunctionFilter<Dictionary<string, object?>, object?>(control, mode, approvalResolver);
    }

    public Task OnAutoFunctionInvocationAsync(AutoFunctionInvocationContext context, Func<AutoFunctionInvocationContext, Task> next) =>
        inner.InvokeAsync(new Context(context), async (_, _) => await next(context).ConfigureAwait(false), context.CancellationToken).AsTask();

    private sealed class Context : IAgentControlFunctionInvocationContext<Dictionary<string, object?>, object?>
    {
        private readonly AutoFunctionInvocationContext context;
        public Context(AutoFunctionInvocationContext context) => this.context = context;
        public string FunctionName => context.Function.Name;
        public Dictionary<string, object?> Arguments
        {
            get => (context.Arguments ?? []).ToDictionary(pair => pair.Key, pair => pair.Value);
            set
            {
                if (context.Arguments is null) throw new InvalidOperationException("Semantic Kernel invocation arguments are required.");
                foreach (var pair in value) context.Arguments[pair.Key] = pair.Value;
            }
        }
        public object? Result { get => context.Result?.GetValue<object?>(); set => context.Result = new FunctionResult(context.Function, value); }
        public string? ToolCallId => context.ToolCallId;
        public IReadOnlyDictionary<string, object?>? Snapshot => null;
    }
}

public static class KernelBuilderExtensions
{
    public static IKernelBuilder UseAgentControl(this IKernelBuilder builder, AgentControl control, EnforcementMode mode = EnforcementMode.Enforce, ApprovalResolver? approvalResolver = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(control);
        builder.Services.TryAddSingleton(control);
        builder.Services.AddSingleton<IAutoFunctionInvocationFilter>(_ => new AgentControlFilter(control, mode, approvalResolver));
        DecorateChatClients(builder.Services, control, mode, approvalResolver);
        DecorateChatCompletionServices(builder.Services, control, mode, approvalResolver);
        return builder;
    }

    public static IKernelBuilder AsGuarded(this IKernelBuilder builder, AgentControl control, EnforcementMode mode = EnforcementMode.Enforce, ApprovalResolver? approvalResolver = null) =>
        builder.UseAgentControl(control, mode, approvalResolver);

    private static void DecorateChatClients(IServiceCollection services, AgentControl control, EnforcementMode mode, ApprovalResolver? approvalResolver)
    {
        for (var i = 0; i < services.Count; i++)
        {
            var descriptor = services[i];
            if (descriptor.ServiceType != typeof(Microsoft.Extensions.AI.IChatClient)) continue;
            services[i] = new ServiceDescriptor(typeof(Microsoft.Extensions.AI.IChatClient), sp =>
            {
                var inner = (Microsoft.Extensions.AI.IChatClient)(descriptor.ImplementationInstance ?? descriptor.ImplementationFactory?.Invoke(sp) ?? ActivatorUtilities.CreateInstance(sp, descriptor.ImplementationType!));
                return inner is AgentControlChatClient ? inner : new AgentControlChatClient(inner, control, mode, approvalResolver);
            }, descriptor.Lifetime);
        }
    }

    private static void DecorateChatCompletionServices(IServiceCollection services, AgentControl control, EnforcementMode mode, ApprovalResolver? approvalResolver)
    {
        for (var i = 0; i < services.Count; i++)
        {
            var descriptor = services[i];
            if (descriptor.ServiceType != typeof(IChatCompletionService)) continue;
            services[i] = new ServiceDescriptor(typeof(IChatCompletionService), sp =>
            {
                var inner = (IChatCompletionService)(descriptor.ImplementationInstance ?? descriptor.ImplementationFactory?.Invoke(sp) ?? ActivatorUtilities.CreateInstance(sp, descriptor.ImplementationType!));
                return inner is AgentControlChatCompletionService ? inner : new AgentControlChatCompletionService(inner, control, mode, approvalResolver);
            }, descriptor.Lifetime);
        }
    }
}
