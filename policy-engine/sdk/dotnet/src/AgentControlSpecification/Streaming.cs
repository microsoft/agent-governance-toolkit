using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace AgentControlSpecification;

public sealed record StreamingLimits(int? MaxStreamBytes = null, int? MaxStreamEvents = null);

public sealed record ModelStreamRunResult(
    JsonElement Value,
    InterventionPointResult PreModelCallResult,
    InterventionPointResult PostModelCallResult,
    byte[] Bytes,
    JsonElement AssembledResponse,
    byte[] OriginalBytes);

public static class AgentControlStreamingExtensions
{
    public const int DefaultMaxStreamBytes = 8 * 1024 * 1024;
    public const int DefaultMaxStreamEvents = 10_000;

    public static async ValueTask<ModelStreamRunResult> RunModelStreamAsync<TRequest>(
        this AgentControl control,
        TRequest modelRequest,
        Func<TRequest, CancellationToken, ValueTask<byte[]>> execute,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null,
        StreamingLimits? limits = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(control);
        ArgumentNullException.ThrowIfNull(execute);

        byte[]? originalBytes = null;
        JsonElement? assembledResponse = null;
        try
        {
            var modelRun = await control.RunModelCoreAsync<TRequest, JsonElement>(
                modelRequest,
                async (effectiveRequest, ct) =>
                {
                    originalBytes = CopyBytes(await execute(effectiveRequest, ct).ConfigureAwait(false));
                    assembledResponse = AgentControlStreaming.AssembleSseStream(originalBytes, limits);
                    return assembledResponse.Value;
                },
                snapshot,
                mode,
                approvalResolver,
                cancellationToken,
                rejectStreamingRequests: false).ConfigureAwait(false);

            if (originalBytes is null || !assembledResponse.HasValue)
            {
                throw new StreamingUnsupportedException("Streaming response contained no data chunks.");
            }

            var transformed = modelRun.PostModelCallResult.TransformedPolicyTarget.HasValue
                && modelRun.PostModelCallResult.Verdict.Decision.AppliesTransform();
            var bytes = transformed
                ? AgentControlStreaming.SynthesizeSseStream(modelRun.Value, assembledResponse.Value)
                : CopyBytes(originalBytes);

            return new ModelStreamRunResult(
                modelRun.Value,
                modelRun.PreModelCallResult,
                modelRun.PostModelCallResult,
                bytes,
                assembledResponse.Value.Clone(),
                CopyBytes(originalBytes));
        }
        catch (AgentControlInterruptionException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw FailClosed(
                exception is StreamingUnsupportedException ? exception.Message : "Streaming response failed closed.",
                exception);
        }
    }

    public static async ValueTask<ModelStreamRunResult> RunModelStreamAsync<TRequest>(
        this AgentControl control,
        TRequest modelRequest,
        Func<TRequest, CancellationToken, IAsyncEnumerable<byte[]>> execute,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        EnforcementMode mode = EnforcementMode.Enforce,
        ApprovalResolver? approvalResolver = null,
        StreamingLimits? limits = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(execute);
        return await control.RunModelStreamAsync(
            modelRequest,
            async (effectiveRequest, ct) => await AgentControlStreaming.CollectStreamBytesAsync(execute(effectiveRequest, ct), limits, ct).ConfigureAwait(false),
            snapshot,
            mode,
            approvalResolver,
            limits,
            cancellationToken).ConfigureAwait(false);
    }

    private static byte[] CopyBytes(byte[] bytes)
    {
        var copy = new byte[bytes.Length];
        Buffer.BlockCopy(bytes, 0, copy, 0, bytes.Length);
        return copy;
    }

    private static AgentControlBlockedException FailClosed(string message, Exception exception) =>
        new(
            InterventionPoint.PostModelCall,
            new InterventionPointResult(new Verdict(Decision.Deny, Reason: "runtime_error:streaming_unsupported", Message: message)),
            exception);
}

public static class AgentControlStreaming
{
    private const string Done = "[DONE]";
    private const string DataField = "data:";
    private const string CommentPrefix = ":";
    private const string ChunkObject = "chat.completion.chunk";
    private const string CompletionObject = "chat.completion";
    private const string AssistantRole = "assistant";
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions CanonicalJsonOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };
    private static readonly HashSet<string> KnownChoiceKeys = ["index", "delta", "finish_reason"];
    private static readonly HashSet<string> KnownDeltaKeys = ["role", "content", "tool_calls"];
    private static readonly string[] PassthroughChunkKeys = ["id", "created", "model"];

    public static async ValueTask<byte[]> CollectStreamBytesAsync(
        IAsyncEnumerable<byte[]> stream,
        StreamingLimits? limits = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var maxBytes = MaxStreamBytes(limits);
        var parts = new List<byte[]>();
        var total = 0;
        await foreach (var part in stream.WithCancellation(cancellationToken).ConfigureAwait(false))
        {
            if (part is null)
            {
                throw new StreamingUnsupportedException("Streaming response chunks must be bytes.");
            }

            total += part.Length;
            if (total > maxBytes)
            {
                throw new StreamingUnsupportedException("Streaming response exceeded the buffering byte limit.");
            }

            parts.Add(part);
        }

        var output = new byte[total];
        var offset = 0;
        foreach (var part in parts)
        {
            Buffer.BlockCopy(part, 0, output, offset, part.Length);
            offset += part.Length;
        }

        return output;
    }

    public static JsonElement AssembleSseStream(byte[] raw, StreamingLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(raw);
        if (raw.Length > MaxStreamBytes(limits))
        {
            throw new StreamingUnsupportedException("Streaming response exceeded the buffering byte limit.");
        }

        var chunks = ParseSseChunks(raw, limits);
        if (chunks.Count == 0)
        {
            throw new StreamingUnsupportedException("Streaming response contained no data chunks.");
        }

        var content = new StringBuilder();
        JsonElement? finishReason = null;
        var toolCalls = new SortedDictionary<int, ToolCallAccumulator>();
        var template = new Dictionary<string, JsonElement>();

        foreach (var chunk in chunks)
        {
            if (template.Count == 0)
            {
                foreach (var key in PassthroughChunkKeys)
                {
                    if (chunk.TryGetProperty(key, out var property))
                    {
                        template[key] = property.Clone();
                    }
                }
            }

            var choicesRaw = chunk.TryGetProperty("choices", out var choicesElement) && choicesElement.ValueKind != JsonValueKind.Null
                ? choicesElement
                : default;
            if (choicesRaw.ValueKind != JsonValueKind.Array && choicesRaw.ValueKind != JsonValueKind.Undefined)
            {
                throw new StreamingUnsupportedException("Streaming chunk choices must be a list.");
            }

            if (choicesRaw.ValueKind == JsonValueKind.Undefined || choicesRaw.GetArrayLength() == 0)
            {
                continue;
            }

            if (choicesRaw.GetArrayLength() > 1)
            {
                throw new StreamingUnsupportedException("Multi-choice streaming responses are not guarded.");
            }

            var choice = choicesRaw[0];
            if (choice.ValueKind != JsonValueKind.Object)
            {
                throw new StreamingUnsupportedException("Streaming choice must be an object.");
            }

            var choiceIndex = choice.TryGetProperty("index", out var indexElement) ? ReadInt(indexElement, "Multi-choice streaming responses are not guarded.") : 0;
            if (choiceIndex != 0)
            {
                throw new StreamingUnsupportedException("Multi-choice streaming responses are not guarded.");
            }

            if (CarriesUnrepresentedData(choice, KnownChoiceKeys))
            {
                throw new StreamingUnsupportedException("Streaming choice carried unsupported fields.");
            }

            var delta = choice.TryGetProperty("delta", out var deltaElement) && deltaElement.ValueKind != JsonValueKind.Null
                ? deltaElement
                : default;
            if (delta.ValueKind != JsonValueKind.Object && delta.ValueKind != JsonValueKind.Undefined)
            {
                throw new StreamingUnsupportedException("Streaming choice delta must be an object.");
            }

            if (delta.ValueKind == JsonValueKind.Undefined)
            {
                delta = EmptyObject();
            }

            if (CarriesUnrepresentedData(delta, KnownDeltaKeys))
            {
                throw new StreamingUnsupportedException("Streaming delta carried unsupported fields.");
            }

            if (delta.TryGetProperty("content", out var piece) && piece.ValueKind != JsonValueKind.Null)
            {
                if (piece.ValueKind != JsonValueKind.String)
                {
                    throw new StreamingUnsupportedException("Streaming delta content must be a string.");
                }

                content.Append(piece.GetString());
            }

            if (delta.TryGetProperty("tool_calls", out var fragments))
            {
                MergeToolCallFragments(fragments, toolCalls);
            }

            if (choice.TryGetProperty("finish_reason", out var finish) && finish.ValueKind != JsonValueKind.Null)
            {
                finishReason = finish.Clone();
            }
        }

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            foreach (var key in PassthroughChunkKeys)
            {
                if (template.TryGetValue(key, out var value))
                {
                    writer.WritePropertyName(key);
                    value.WriteTo(writer);
                }
            }

            writer.WriteString("object", CompletionObject);
            writer.WritePropertyName("choices");
            writer.WriteStartArray();
            writer.WriteStartObject();
            writer.WriteNumber("index", 0);
            writer.WritePropertyName("message");
            writer.WriteStartObject();
            writer.WriteString("role", AssistantRole);
            writer.WriteString("content", content.ToString());
            if (toolCalls.Count > 0)
            {
                writer.WritePropertyName("tool_calls");
                writer.WriteStartArray();
                foreach (var toolCall in toolCalls.Values)
                {
                    toolCall.WriteTo(writer);
                }

                writer.WriteEndArray();
            }

            writer.WriteEndObject();
            writer.WritePropertyName("finish_reason");
            if (finishReason.HasValue)
            {
                finishReason.Value.WriteTo(writer);
            }
            else
            {
                writer.WriteNullValue();
            }

            writer.WriteEndObject();
            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return JsonDocument.Parse(stream.ToArray()).RootElement.Clone();
    }

    private static void WriteSynthesizedToolCall(Utf8JsonWriter writer, JsonElement toolCall, int order)
    {
        if (toolCall.ValueKind != JsonValueKind.Object)
        {
            throw new StreamingUnsupportedException("Transformed streaming tool_call must be an object.");
        }

        writer.WriteStartObject();
        var wroteIndex = false;
        foreach (var property in toolCall.EnumerateObject())
        {
            if (property.NameEquals("index"))
            {
                if (property.Value.ValueKind != JsonValueKind.Number
                    || !property.Value.TryGetInt32(out var existing)
                    || existing != order)
                {
                    throw new StreamingUnsupportedException("Transformed streaming tool_call index must match its order.");
                }

                writer.WriteNumber("index", order);
                wroteIndex = true;
                continue;
            }

            property.WriteTo(writer);
        }

        if (!wroteIndex)
        {
            writer.WriteNumber("index", order);
        }

        writer.WriteEndObject();
    }

    public static byte[] SynthesizeSseStream(JsonElement response, JsonElement template)
    {
        if (response.ValueKind != JsonValueKind.Object)
        {
            throw new StreamingUnsupportedException("Transformed streaming response must be an object.");
        }

        if (!response.TryGetProperty("choices", out var choices) || choices.ValueKind != JsonValueKind.Array || choices.GetArrayLength() != 1 || choices[0].ValueKind != JsonValueKind.Object)
        {
            throw new StreamingUnsupportedException("Transformed streaming response must carry a choice.");
        }

        var choice = choices[0];
        if (choice.TryGetProperty("index", out var indexElement) && ReadInt(indexElement, "Transformed streaming response must carry one zero-index choice.") != 0)
        {
            throw new StreamingUnsupportedException("Transformed streaming response must carry one zero-index choice.");
        }

        var message = choice.TryGetProperty("message", out var messageElement) && messageElement.ValueKind != JsonValueKind.Null
            ? messageElement
            : default;
        if (message.ValueKind != JsonValueKind.Object && message.ValueKind != JsonValueKind.Undefined)
        {
            throw new StreamingUnsupportedException("Transformed streaming choice must carry a message.");
        }

        if (message.ValueKind == JsonValueKind.Undefined)
        {
            message = EmptyObject();
        }

        if (message.TryGetProperty("content", out var content) && content.ValueKind != JsonValueKind.Null && content.ValueKind != JsonValueKind.String)
        {
            throw new StreamingUnsupportedException("Transformed streaming content must be a string.");
        }

        var hasToolCalls = message.TryGetProperty("tool_calls", out var toolCalls) && toolCalls.ValueKind != JsonValueKind.Null;
        if (hasToolCalls && toolCalls.ValueKind != JsonValueKind.Array)
        {
            throw new StreamingUnsupportedException("Transformed streaming tool_calls must be a list.");
        }

        var finishReason = choice.TryGetProperty("finish_reason", out var finish) && finish.ValueKind != JsonValueKind.Null
            ? finish
            : default;

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
        {
            writer.WriteStartObject();
            foreach (var key in PassthroughChunkKeys)
            {
                if (template.ValueKind == JsonValueKind.Object && template.TryGetProperty(key, out var value))
                {
                    writer.WritePropertyName(key);
                    value.WriteTo(writer);
                }
            }

            writer.WriteString("object", ChunkObject);
            writer.WritePropertyName("choices");
            writer.WriteStartArray();
            writer.WriteStartObject();
            writer.WriteNumber("index", 0);
            writer.WritePropertyName("delta");
            writer.WriteStartObject();
            writer.WriteString("role", AssistantRole);
            if (content.ValueKind == JsonValueKind.String)
            {
                writer.WriteString("content", content.GetString());
            }

            if (hasToolCalls && toolCalls.GetArrayLength() > 0)
            {
                writer.WritePropertyName("tool_calls");
                writer.WriteStartArray();
                var order = 0;
                foreach (var toolCall in toolCalls.EnumerateArray())
                {
                    WriteSynthesizedToolCall(writer, toolCall, order);
                    order++;
                }
                writer.WriteEndArray();
            }

            writer.WriteEndObject();
            writer.WritePropertyName("finish_reason");
            if (finishReason.ValueKind != JsonValueKind.Undefined)
            {
                finishReason.WriteTo(writer);
            }
            else
            {
                writer.WriteStringValue(hasToolCalls && toolCalls.GetArrayLength() > 0 ? "tool_calls" : "stop");
            }

            writer.WriteEndObject();
            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetBytes($"data: {Encoding.UTF8.GetString(stream.ToArray())}\n\ndata: {Done}\n\n");
    }

    private static List<JsonElement> ParseSseChunks(byte[] raw, StreamingLimits? limits)
    {
        string text;
        try
        {
            text = StrictUtf8.GetString(raw).Replace("\r\n", "\n", StringComparison.Ordinal).Replace("\r", "\n", StringComparison.Ordinal);
        }
        catch (DecoderFallbackException exception)
        {
            throw new StreamingUnsupportedException("Streaming response contained malformed UTF-8.", exception);
        }

        var chunks = new List<JsonElement>();
        var done = false;
        foreach (var block in text.Split("\n\n", StringSplitOptions.None))
        {
            var data = EventData(block);
            if (data is null)
            {
                continue;
            }

            if (done)
            {
                throw new StreamingUnsupportedException("Streaming response sent data after [DONE].");
            }

            if (data == Done)
            {
                done = true;
                continue;
            }

            if (chunks.Count >= MaxStreamEvents(limits))
            {
                throw new StreamingUnsupportedException("Streaming response exceeded the buffered event limit.");
            }

            try
            {
                using var document = JsonDocument.Parse(data);
                if (document.RootElement.ValueKind != JsonValueKind.Object)
                {
                    throw new StreamingUnsupportedException("Streaming SSE chunk must be a JSON object.");
                }

                chunks.Add(document.RootElement.Clone());
            }
            catch (JsonException exception)
            {
                throw new StreamingUnsupportedException("Streaming response contained malformed SSE JSON.", exception);
            }
        }

        if (!done)
        {
            throw new StreamingUnsupportedException("Streaming response terminated before [DONE].");
        }

        return chunks;
    }

    private static string? EventData(string block)
    {
        var dataLines = new List<string>();
        foreach (var line in block.Split('\n'))
        {
            if (line.Length == 0 || line.StartsWith(CommentPrefix, StringComparison.Ordinal))
            {
                continue;
            }

            if (line.StartsWith(DataField, StringComparison.Ordinal))
            {
                var data = line[DataField.Length..];
                if (data.StartsWith(' '))
                {
                    data = data[1..];
                }

                dataLines.Add(data);
            }
        }

        return dataLines.Count == 0 ? null : string.Join("\n", dataLines);
    }

    private static void MergeToolCallFragments(JsonElement fragments, SortedDictionary<int, ToolCallAccumulator> accumulators)
    {
        if (fragments.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
        {
            return;
        }

        if (fragments.ValueKind != JsonValueKind.Array)
        {
            throw new StreamingUnsupportedException("Streaming tool_calls must be a list.");
        }

        if (fragments.GetArrayLength() == 0)
        {
            return;
        }

        foreach (var fragment in fragments.EnumerateArray())
        {
            if (fragment.ValueKind != JsonValueKind.Object)
            {
                throw new StreamingUnsupportedException("Streaming tool_call fragment must be an object.");
            }

            if (!fragment.TryGetProperty("index", out var indexElement) || indexElement.ValueKind != JsonValueKind.Number || !indexElement.TryGetInt32(out var index))
            {
                throw new StreamingUnsupportedException("Streaming tool_call fragments require an integer index.");
            }

            if (!accumulators.TryGetValue(index, out var accumulator))
            {
                accumulator = new ToolCallAccumulator();
                accumulators[index] = accumulator;
            }

            accumulator.Merge(fragment);
        }
    }

    private static bool CarriesUnrepresentedData(JsonElement mapping, HashSet<string> known) =>
        mapping.EnumerateObject().Any(property => !known.Contains(property.Name) && !IsEmptyRepresentedValue(property.Value));

    private static bool IsEmptyRepresentedValue(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.Null or JsonValueKind.Undefined => true,
        JsonValueKind.String => value.GetString() == string.Empty,
        JsonValueKind.Array => value.GetArrayLength() == 0,
        JsonValueKind.Object => !value.EnumerateObject().Any(),
        _ => false,
    };

    private static int ReadInt(JsonElement element, string message)
    {
        if (element.ValueKind == JsonValueKind.Number && element.TryGetInt32(out var value))
        {
            return value;
        }

        throw new StreamingUnsupportedException(message);
    }

    private static JsonElement EmptyObject() => JsonSerializer.SerializeToElement(new Dictionary<string, object?>(), CanonicalJsonOptions);

    private static int MaxStreamBytes(StreamingLimits? limits) => limits?.MaxStreamBytes ?? AgentControlStreamingExtensions.DefaultMaxStreamBytes;

    private static int MaxStreamEvents(StreamingLimits? limits) => limits?.MaxStreamEvents ?? AgentControlStreamingExtensions.DefaultMaxStreamEvents;

    private sealed class ToolCallAccumulator
    {
        private string? id;
        private string? type;
        private string? name;
        private readonly StringBuilder arguments = new();

        public void Merge(JsonElement fragment)
        {
            if (fragment.TryGetProperty("id", out var idElement))
            {
                id = MergeScalar(id, idElement);
            }

            if (fragment.TryGetProperty("type", out var typeElement))
            {
                type = MergeScalar(type, typeElement);
            }

            var function = fragment.TryGetProperty("function", out var functionElement) && functionElement.ValueKind != JsonValueKind.Null
                ? functionElement
                : default;
            if (function.ValueKind != JsonValueKind.Object && function.ValueKind != JsonValueKind.Undefined)
            {
                throw new StreamingUnsupportedException("Streaming tool_call.function must be an object.");
            }

            if (function.ValueKind == JsonValueKind.Undefined)
            {
                function = EmptyObject();
            }

            if (function.TryGetProperty("name", out var nameElement))
            {
                name = MergeScalar(name, nameElement);
            }

            if (function.TryGetProperty("arguments", out var argumentsElement) && argumentsElement.ValueKind != JsonValueKind.Null)
            {
                if (argumentsElement.ValueKind != JsonValueKind.String)
                {
                    throw new StreamingUnsupportedException("Streaming tool_call arguments must be strings.");
                }

                arguments.Append(argumentsElement.GetString());
            }
        }

        public void WriteTo(Utf8JsonWriter writer)
        {
            writer.WriteStartObject();
            writer.WriteString("id", id ?? string.Empty);
            writer.WriteString("type", type ?? "function");
            writer.WritePropertyName("function");
            writer.WriteStartObject();
            writer.WriteString("name", name ?? string.Empty);
            writer.WriteString("arguments", arguments.ToString());
            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        private static string? MergeScalar(string? current, JsonElement incoming)
        {
            if (incoming.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
            {
                return current;
            }

            if (incoming.ValueKind != JsonValueKind.String)
            {
                throw new StreamingUnsupportedException("Streaming tool_call metadata must be strings.");
            }

            var value = incoming.GetString();
            if (current is not null && current != value)
            {
                throw new StreamingUnsupportedException("Streaming tool_call metadata changed mid-stream.");
            }

            return value;
        }
    }
}

public sealed class StreamingUnsupportedException : InvalidOperationException
{
    public StreamingUnsupportedException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
