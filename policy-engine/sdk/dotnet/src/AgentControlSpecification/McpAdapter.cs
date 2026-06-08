namespace AgentControlSpecification;

public interface IAgentControlMcpToolProvider<TArgs, TResult>
{
    ValueTask<ToolRunResult<TResult>> CallToolAsync(
        string toolName,
        TArgs arguments,
        string? toolCallId = null,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null,
        CancellationToken cancellationToken = default);
}

public sealed class AgentControlMcpToolProvider<TArgs, TResult> :
    IAgentControlMcpToolProvider<TArgs, TResult>
{
    private readonly AgentControl control;
    private readonly Func<TArgs, CancellationToken, ValueTask<TResult>> execute;

    public AgentControlMcpToolProvider(
        AgentControl control,
        Func<TArgs, CancellationToken, ValueTask<TResult>> execute)
    {
        this.control = control ?? throw new ArgumentNullException(nameof(control));
        this.execute = execute ?? throw new ArgumentNullException(nameof(execute));
    }

    public ValueTask<ToolRunResult<TResult>> CallToolAsync(
        string toolName,
        TArgs arguments,
        string? toolCallId = null,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null,
        CancellationToken cancellationToken = default) =>
        control.ProtectToolAsync(
            toolName,
            arguments,
            execute,
            toolCallId,
            snapshot,
            mode,
            approvalResolver,
            cancellationToken);
}
