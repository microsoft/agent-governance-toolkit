using System.Runtime.CompilerServices;
using Microsoft.SemanticKernel;
using Microsoft.SemanticKernel.ChatCompletion;

namespace AgentControlSpecification.SemanticKernel;

public sealed class AgentControlChatCompletionService : IChatCompletionService
{
    private readonly IChatCompletionService inner;
    private readonly AgentControl control;
    private readonly EnforcementMode mode;
    private readonly ApprovalResolver? approvalResolver;

    public AgentControlChatCompletionService(IChatCompletionService inner, AgentControl control, EnforcementMode mode = EnforcementMode.Enforce, ApprovalResolver? approvalResolver = null)
    {
        this.inner = inner ?? throw new ArgumentNullException(nameof(inner));
        this.control = control ?? throw new ArgumentNullException(nameof(control));
        this.mode = mode;
        this.approvalResolver = approvalResolver;
    }

    public IReadOnlyDictionary<string, object?> Attributes => inner.Attributes;

    public async Task<IReadOnlyList<ChatMessageContent>> GetChatMessageContentsAsync(ChatHistory chatHistory, PromptExecutionSettings? executionSettings = null, Kernel? kernel = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(chatHistory);
        var request = SemanticKernelChatRequestSnapshot.From(chatHistory, executionSettings);
        var result = await control.RunModelTurnAsync(
            LastUserText(chatHistory),
            request,
            async (_, ct) => SemanticKernelChatResponseSnapshot.From(await inner.GetChatMessageContentsAsync(chatHistory, executionSettings, kernel, ct).ConfigureAwait(false)),
            response => response.AssistantText,
            mode: mode,
            approvalResolver: approvalResolver,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        return result.Value.ToChatMessageContents();
    }

    public async IAsyncEnumerable<StreamingChatMessageContent> GetStreamingChatMessageContentsAsync(ChatHistory chatHistory, PromptExecutionSettings? executionSettings = null, Kernel? kernel = null, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var messages = await GetChatMessageContentsAsync(chatHistory, executionSettings, kernel, cancellationToken).ConfigureAwait(false);
        foreach (var message in messages)
        {
            yield return new StreamingChatMessageContent(message.Role, message.Content) { ModelId = message.ModelId };
        }
    }

    private static string LastUserText(ChatHistory history) =>
        history.LastOrDefault(message => message.Role == AuthorRole.User)?.Content ?? string.Empty;
}

public sealed record SemanticKernelChatRequestSnapshot(IReadOnlyList<SemanticKernelChatMessageSnapshot> Messages, string? ModelId)
{
    public static SemanticKernelChatRequestSnapshot From(ChatHistory history, PromptExecutionSettings? settings) =>
        new(history.Select(SemanticKernelChatMessageSnapshot.From).ToList(), settings?.ModelId);
}

public sealed record SemanticKernelChatResponseSnapshot(IReadOnlyList<SemanticKernelChatMessageSnapshot> Messages)
{
    public string AssistantText => string.Concat(Messages.Where(message => message.Role == AuthorRole.Assistant.Label).Select(message => message.Content));

    public IReadOnlyList<ChatMessageContent> ToChatMessageContents() =>
        Messages.Select(message => new ChatMessageContent(new AuthorRole(message.Role), message.Content) { ModelId = message.ModelId }).ToList();

    public static SemanticKernelChatResponseSnapshot From(IReadOnlyList<ChatMessageContent> messages) =>
        new(messages.Select(SemanticKernelChatMessageSnapshot.From).ToList());
}

public sealed record SemanticKernelChatMessageSnapshot(string Role, string? Content, string? ModelId)
{
    public static SemanticKernelChatMessageSnapshot From(ChatMessageContent message) =>
        new(message.Role.Label, message.Content, message.ModelId);
}
