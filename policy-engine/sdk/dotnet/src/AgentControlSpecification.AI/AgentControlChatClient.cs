using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;
using Microsoft.Extensions.AI;

namespace AgentControlSpecification.AI;

public sealed class AgentControlChatClient : DelegatingChatClient
{
    private readonly AgentControl control;
    private readonly EnforcementMode mode;
    private readonly ApprovalResolver? approvalResolver;

    public AgentControlChatClient(IChatClient innerClient, AgentControl control, EnforcementMode mode = EnforcementMode.Enforce, ApprovalResolver? approvalResolver = null)
        : base(innerClient)
    {
        this.control = control ?? throw new ArgumentNullException(nameof(control));
        this.mode = mode;
        this.approvalResolver = approvalResolver;
    }

    public override async Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
    {
        var messageList = messages as IReadOnlyList<ChatMessage> ?? messages.ToList();
        var request = ChatRequestSnapshot.From(messageList, options);
        var result = await control.RunModelTurnAsync(
            LastUserText(messageList),
            request,
            async (_, ct) => ChatResponseSnapshot.From(await base.GetResponseAsync(messageList, options, ct).ConfigureAwait(false)),
            response => response.Text,
            mode: mode,
            approvalResolver: approvalResolver,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        return result.Value.Response;
    }

    public override async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var response = await GetResponseAsync(messages, options, cancellationToken).ConfigureAwait(false);
        foreach (var update in response.ToChatResponseUpdates())
        {
            yield return update;
        }
    }

    private static string LastUserText(IReadOnlyList<ChatMessage> messages) =>
        messages.LastOrDefault(message => message.Role == ChatRole.User)?.Text ?? string.Empty;
}

public static class AgentControlChatClientBuilderExtensions
{
    public static ChatClientBuilder UseAgentControl(this ChatClientBuilder builder, AgentControl control, EnforcementMode mode = EnforcementMode.Enforce, ApprovalResolver? approvalResolver = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(control);
        return builder.Use(inner => new AgentControlChatClient(inner, control, mode, approvalResolver));
    }

    public static IChatClient UseAgentControl(this IChatClient client, AgentControl control, EnforcementMode mode = EnforcementMode.Enforce, ApprovalResolver? approvalResolver = null) =>
        new AgentControlChatClient(client, control, mode, approvalResolver);

    public static IChatClient AsGuarded(this IChatClient client, AgentControl control, EnforcementMode mode = EnforcementMode.Enforce, ApprovalResolver? approvalResolver = null) =>
        client.UseAgentControl(control, mode, approvalResolver);

    public static AIFunction AsGuarded(this AIFunction function, AgentControl control, EnforcementMode mode = EnforcementMode.Enforce, ApprovalResolver? approvalResolver = null) =>
        function is AgentControlAIFunction ? function : new AgentControlAIFunction(function, control, mode, approvalResolver);

    public static IEnumerable<AITool> AsGuarded(this IEnumerable<AITool> tools, AgentControl control, EnforcementMode mode = EnforcementMode.Enforce, ApprovalResolver? approvalResolver = null) =>
        tools.Select(tool => tool is AIFunction function ? function.AsGuarded(control, mode, approvalResolver) : tool);
}

public sealed record ChatRequestSnapshot(IReadOnlyList<ChatMessageSnapshot> Messages, ChatOptionsSnapshot Options)
{
    public static ChatRequestSnapshot From(IReadOnlyList<ChatMessage> messages, ChatOptions? options) =>
        new(messages.Select(ChatMessageSnapshot.From).ToList(), ChatOptionsSnapshot.From(options));
}

public sealed record ChatMessageSnapshot(string Role, string Text, string? AuthorName)
{
    public static ChatMessageSnapshot From(ChatMessage message) =>
        new(message.Role.ToString(), message.Text ?? string.Empty, message.AuthorName);
}

public sealed record ChatOptionsSnapshot(string? Instructions, string? ModelId, IReadOnlyList<string> Tools)
{
    public static ChatOptionsSnapshot From(ChatOptions? options) =>
        new(options?.Instructions, options?.ModelId, options?.Tools?.Select(tool => tool.Name).ToList() ?? []);
}

public sealed class ChatResponseSnapshot
{
    public ChatResponseSnapshot(string text, string? responseId, IReadOnlyList<ChatMessageSnapshot> messages)
    {
        Text = text;
        ResponseId = responseId;
        Messages = messages;
    }

    [JsonIgnore]
    public string Text { get; }

    public string? ResponseId { get; }

    [JsonIgnore]
    public IReadOnlyList<ChatMessageSnapshot> Messages { get; }

    [JsonIgnore]
    public ChatResponse Response => new(Messages.Select(message => new ChatMessage(new ChatRole(message.Role), message.Text)).ToList());

    public static ChatResponseSnapshot From(ChatResponse response) =>
        new(response.Text ?? string.Empty, response.ResponseId, response.Messages.Select(ChatMessageSnapshot.From).ToList());
}
