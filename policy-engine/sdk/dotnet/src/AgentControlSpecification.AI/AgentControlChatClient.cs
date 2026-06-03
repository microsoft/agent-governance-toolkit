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
            async (effectiveRequest, ct) =>
            {
                var innerResponse = await base.GetResponseAsync(
                    effectiveRequest.ApplyMessages(messageList),
                    effectiveRequest.ApplyOptions(options),
                    ct).ConfigureAwait(false);
                return ChatResponseSnapshot.From(innerResponse);
            },
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

    public IReadOnlyList<ChatMessage> ApplyMessages(IReadOnlyList<ChatMessage> original)
    {
        if (Messages.Count == original.Count && Messages.Select((message, index) => message.Matches(original[index])).All(match => match))
        {
            return original;
        }

        var applied = new List<ChatMessage>(Messages.Count);
        var originalIndex = 0;
        for (var messageIndex = 0; messageIndex < Messages.Count; messageIndex++)
        {
            var snapshot = Messages[messageIndex];
            var exactMatch = FindExactMatch(original, snapshot, originalIndex);
            if (exactMatch >= 0)
            {
                applied.Add(original[exactMatch]);
                originalIndex = exactMatch + 1;
                continue;
            }

            if (originalIndex < original.Count
                && snapshot.HasSameEnvelope(original[originalIndex])
                && !HasFutureExactMatch(original[originalIndex], messageIndex + 1))
            {
                applied.Add(snapshot.ApplyTo(original[originalIndex]));
                originalIndex++;
                continue;
            }

            applied.Add(snapshot.ToChatMessage());
        }

        return applied;
    }

    public ChatOptions? ApplyOptions(ChatOptions? original) => Options.ApplyTo(original);

    private int FindExactMatch(IReadOnlyList<ChatMessage> original, ChatMessageSnapshot snapshot, int startIndex)
    {
        for (var index = startIndex; index < original.Count; index++)
        {
            if (snapshot.Matches(original[index]))
            {
                return index;
            }
        }

        return -1;
    }

    private bool HasFutureExactMatch(ChatMessage original, int startIndex)
    {
        for (var index = startIndex; index < Messages.Count; index++)
        {
            if (Messages[index].Matches(original))
            {
                return true;
            }
        }

        return false;
    }
}

public sealed record ChatMessageSnapshot(string Role, string Text, string? AuthorName)
{
    public static ChatMessageSnapshot From(ChatMessage message) =>
        new(message.Role.ToString(), message.Text ?? string.Empty, message.AuthorName);

    public bool Matches(ChatMessage message) =>
        string.Equals(message.Role.ToString(), Role, StringComparison.Ordinal) &&
        string.Equals(message.Text ?? string.Empty, Text, StringComparison.Ordinal) &&
        string.Equals(message.AuthorName, AuthorName, StringComparison.Ordinal);

    public bool HasSameEnvelope(ChatMessage message) =>
        string.Equals(message.Role.ToString(), Role, StringComparison.Ordinal) &&
        string.Equals(message.AuthorName, AuthorName, StringComparison.Ordinal);

    public ChatMessage ToChatMessage()
    {
        var message = new ChatMessage(new ChatRole(Role), Text)
        {
            AuthorName = AuthorName,
        };
        return message;
    }

    public ChatMessage ApplyTo(ChatMessage original)
    {
        var message = original.Clone();
        message.Role = new ChatRole(Role);
        message.AuthorName = AuthorName;
        if (!string.Equals(message.Text ?? string.Empty, Text, StringComparison.Ordinal))
        {
            message.Contents = ReplaceTextContent(message.Contents, Text);
        }

        return message;
    }

    private static IList<AIContent> ReplaceTextContent(IList<AIContent> originalContents, string text)
    {
        var contents = new List<AIContent>(originalContents.Count + 1);
        var replaced = false;
        foreach (var content in originalContents)
        {
            if (content is TextContent)
            {
                if (!replaced)
                {
                    contents.Add(new TextContent(text));
                    replaced = true;
                }

                continue;
            }

            contents.Add(content);
        }

        if (!replaced)
        {
            contents.Insert(0, new TextContent(text));
        }

        return contents;
    }
}

public sealed record ChatOptionsSnapshot(string? Instructions, string? ModelId, IReadOnlyList<string> Tools)
{
    public static ChatOptionsSnapshot From(ChatOptions? options) =>
        new(options?.Instructions, options?.ModelId, options?.Tools?.Select(tool => tool.Name).ToList() ?? []);

    public ChatOptions? ApplyTo(ChatOptions? original)
    {
        if (original is null && Instructions is null && ModelId is null && Tools.Count == 0)
        {
            return null;
        }

        var options = original?.Clone() ?? new ChatOptions();
        options.Instructions = Instructions;
        options.ModelId = ModelId;
        var toolNames = Tools.ToHashSet(StringComparer.Ordinal);
        options.Tools = original?.Tools is null
            ? []
            : original.Tools.Where(tool => toolNames.Contains(tool.Name)).ToList();
        return options;
    }
}

public sealed class ChatResponseSnapshot
{
    private readonly ChatResponse? originalResponse;

    public ChatResponseSnapshot(string text, string? responseId, IReadOnlyList<ChatMessageSnapshot> messages)
        : this(text, responseId, messages, null)
    {
    }

    private ChatResponseSnapshot(string text, string? responseId, IReadOnlyList<ChatMessageSnapshot> messages, ChatResponse? originalResponse)
    {
        Text = text;
        ResponseId = responseId;
        Messages = messages;
        this.originalResponse = originalResponse;
    }

    public string Text { get; }

    public string? ResponseId { get; }

    public IReadOnlyList<ChatMessageSnapshot> Messages { get; }

    [JsonIgnore]
    public ChatResponse Response
    {
        get
        {
            if (originalResponse is not null && MessagesMatch(originalResponse.Messages))
            {
                return originalResponse;
            }

            return new(Messages.Select(message => message.ToChatMessage()).ToList())
            {
                ResponseId = ResponseId,
            };
        }
    }

    public static ChatResponseSnapshot From(ChatResponse response) =>
        new(response.Text ?? string.Empty, response.ResponseId, response.Messages.Select(ChatMessageSnapshot.From).ToList(), response);

    private bool MessagesMatch(IList<ChatMessage> messages) =>
        Messages.Count == messages.Count &&
        Messages.Select((message, index) => message.Matches(messages[index])).All(match => match);
}
