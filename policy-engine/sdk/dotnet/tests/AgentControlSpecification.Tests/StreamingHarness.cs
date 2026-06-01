using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AgentControlSpecification;

internal static class StreamingHarness
{
    private const string CodingAssistantManifest = """
agent_control_specification_version: 0.3.1-beta
policies:
  coding_policy:
    type: custom
    adapter: coding_assistant_policy
intervention_points:
  pre_model_call:
    policy:
      id: coding_policy
    policy_target: $snap.model_request
  post_model_call:
    policy:
      id: coding_policy
    policy_target: $snap.model_response
    annotations:
      first:
        from: $snap.model_response
      second:
        from: $snap.model_response
  pre_tool_call:
    policy:
      id: coding_policy
    policy_target: $snap.tool_call
  post_tool_call:
    policy:
      id: coding_policy
    policy_target: $snap.tool_result
annotators:
  first:
    type: classifier
  second:
    type: classifier
""";

    public static async Task RunAsync()
    {
        await RunCodingAssistantScenarioAsync();
        await RunStreamingConformanceAsync();
        Console.WriteLine("AgentControlSpecification streaming coding-assistant use-case tests passed.");
        Console.WriteLine("AgentControlSpecification streaming conformance tests passed.");
    }

    private static async Task RunCodingAssistantScenarioAsync()
    {
        var annotator = new OrderingAnnotator();
        var policy = new CodingAssistantPolicy();
        var control = AgentControl.FromNative(CodingAssistantManifest, annotator, policy, AllowApproval());
        var inputBytes = SseText("safe SECRET", "stop");
        var streamResult = await control.RunModelStreamAsync(
            new ModelRequest("write code"),
            (_, _) => ValueTask.FromResult(inputBytes));
        AssertEqual(Decision.Allow, streamResult.PreModelCallResult.Verdict.Decision, "streaming pre_model_call should allow safe requests.");
        AssertEqual(Decision.Transform, streamResult.PostModelCallResult.Verdict.Decision, "streaming post_model_call should transform on redaction.");
        AssertEqual("safe [REDACTED]", ExtractContent(streamResult.Value), "streaming transform should redact model output.");
        Assert(!inputBytes.SequenceEqual(streamResult.Bytes), "transform should synthesize replacement bytes.");
        AssertEqual("first,second", string.Join(',', annotator.Calls), "annotators should dispatch in manifest order.");

        ToolArgs? toolSaw = null;
        var toolResult = await control.RunToolAsync<ToolArgs, string>(
            "shell",
            new ToolArgs(ExtractContent(streamResult.Value)),
            (args, _) =>
            {
                toolSaw = args;
                return ValueTask.FromResult($"ran:{args.Command}");
            },
            "tool-redacted");
        AssertEqual("safe [REDACTED]", toolSaw?.Command, "tool should receive redacted model output.");
        AssertEqual(Decision.Allow, toolResult.PreToolCallResult.Verdict.Decision, "redacted shell command should be allowed.");
        AssertEqual(Decision.Allow, toolResult.PostToolCallResult.Verdict.Decision, "post_tool_call should allow benign results.");

        var explicitStreamingUpstreamCalls = 0;
        try
        {
            await new AgentControl(new ThrowingRuntime()).RunModelAsync(
                new Dictionary<string, object?> { ["stream"] = true, ["messages"] = Array.Empty<object>() },
                (_, _) =>
                {
                    explicitStreamingUpstreamCalls++;
                    return ValueTask.FromResult(new Dictionary<string, object?> { ["ok"] = true });
                });
            throw new InvalidOperationException("explicit streaming RunModelAsync request should fail closed.");
        }
        catch (AgentControlBlockedException ex)
        {
            AssertEqual(InterventionPoint.PreModelCall, ex.InterventionPoint, "explicit streaming RunModelAsync request should block at pre_model_call.");
            AssertEqual("runtime_error:streaming_unsupported", ex.Result.Verdict.Reason, "explicit streaming RunModelAsync request should use streaming unsupported.");
            AssertEqual(0, explicitStreamingUpstreamCalls, "explicit streaming RunModelAsync request should not invoke upstream.");
        }

        var explicitStreamingRequest = new Dictionary<string, object?> { ["stream"] = true, ["messages"] = Array.Empty<object>() };
        var bufferedStream = await new AgentControl(new DelegateRuntime(_ => AllowResult())).RunModelStreamAsync(
            explicitStreamingRequest,
            (_, _) => ValueTask.FromResult(SseText("buffered", "stop")));
        AssertEqual("buffered", ExtractContent(bufferedStream.Value), "RunModelStreamAsync should support explicit streaming requests.");

        var mcp = new AgentControlMcpToolProvider<ToolArgs, string>(control, (args, _) => ValueTask.FromResult(args.Command));
        try
        {
            await mcp.CallToolAsync("shell", new ToolArgs("rm -rf /"), "tool-danger");
            throw new InvalidOperationException("dangerous MCP command should be denied.");
        }
        catch (AgentControlBlockedException ex)
        {
            AssertEqual(InterventionPoint.PreToolCall, ex.InterventionPoint, "MCP deny should happen before the tool executes.");
            AssertEqual(Decision.Deny, ex.Result.Verdict.Decision, "dangerous MCP command should deny.");
        }

        var sensitive = await control.RunToolAsync<ToolArgs, string>(
            "shell",
            new ToolArgs("deploy-production"),
            (args, _) => ValueTask.FromResult(args.Command),
            "tool-escalate-allow");
        AssertEqual("deploy-production", sensitive.Value, "approved sensitive action should continue.");
        AssertEqual(Decision.Escalate, sensitive.PreToolCallResult.Verdict.Decision, "sensitive action should escalate.");

        var rejectedControl = AgentControl.FromNative(CodingAssistantManifest, new OrderingAnnotator(), new CodingAssistantPolicy(), DenyApproval());
        try
        {
            await rejectedControl.RunToolAsync<ToolArgs, string>(
                "shell",
                new ToolArgs("deploy-production"),
                (args, _) => ValueTask.FromResult(args.Command),
                "tool-escalate-deny");
            throw new InvalidOperationException("rejected sensitive action should deny.");
        }
        catch (AgentControlBlockedException ex)
        {
            AssertEqual(InterventionPoint.PreToolCall, ex.InterventionPoint, "approval rejection should block at pre_tool_call.");
        }

        await AssertStreamingBlockedAsync(
            new AgentControl(new ThrowingRuntime()),
            "policy invocation failure should fail closed for streaming.");
        // AGT D1: invalid transform payloads must fail closed; a Transform
        // verdict with `choices` shaped as a string cannot be re-synthesized
        // as an SSE response.
        await AssertStreamingBlockedAsync(
            new AgentControl(new DelegateRuntime(_ => new InterventionPointResult(
                new Verdict(Decision.Transform, Transform: new Transform("$policy_target", JsonSerializer.SerializeToElement(new { choices = "bad" }))),
                JsonSerializer.SerializeToElement(new { choices = "bad" })))),
            "invalid transformed policy output should fail closed for streaming.");
        try
        {
            await new AgentControl(new DelegateRuntime(request => request.InterventionPoint == InterventionPoint.PostModelCall ? EscalateResult(request) : AllowResult()), ThrowingApproval())
                .RunModelStreamAsync(new ModelRequest("write code"), (_, _) => ValueTask.FromResult(SseText("ok", "stop")));
            throw new InvalidOperationException("approval callback failure should block streaming.");
        }
        catch (AgentControlBlockedException ex)
        {
            AssertEqual(InterventionPoint.PostModelCall, ex.InterventionPoint, "approval callback failure should block at post_model_call.");
            Assert(ex.InnerException is InvalidOperationException { Message: "approval failed" }, "approval callback failure should preserve the cause.");
        }

        try
        {
            await new AgentControl(
                    new DelegateRuntime(request => request.InterventionPoint == InterventionPoint.PostModelCall ? EscalateResult(request) : AllowResult()),
                    (_, result, _) => ValueTask.FromResult(ApprovalResolution.Suspend(JsonSerializer.SerializeToElement(new { ticket = "T-stream" }), result.ActionIdentity!)))
                .RunModelStreamAsync(new ModelRequest("write code"), (_, _) => ValueTask.FromResult(SseText("ok", "stop")));
            throw new InvalidOperationException("suspended streaming escalation should surface suspension.");
        }
        catch (AgentControlSuspendedException ex)
        {
            AssertEqual(InterventionPoint.PostModelCall, ex.InterventionPoint, "streaming suspension should report post_model_call.");
            AssertEqual("T-stream", ex.Handle!.Value.GetProperty("ticket").GetString(), "streaming suspension handle should round-trip.");
        }

        var cycle = new Dictionary<string, object?>();
        cycle["self"] = cycle;
        await AssertStreamingBlockedAsync(
            new AgentControl(new DelegateRuntime(_ => AllowResult())),
            "request serialization failure should fail closed for streaming.",
            cycle);
        await AssertStreamingBlockedAsync(
            new AgentControl(new DelegateRuntime(_ => AllowResult())),
            "stream failure should fail closed for streaming.",
            new ModelRequest("write code"),
            (_, _) => throw new InvalidOperationException("upstream stream terminated early"));

        var concurrentControl = new AgentControl(new DelegateRuntime(request =>
        {
            if (request.InterventionPoint != InterventionPoint.PostModelCall)
            {
                return AllowResult();
            }

            var content = request.Snapshot.GetProperty("model_response").GetProperty("choices")[0].GetProperty("message").GetProperty("content").GetString();
            return content == "SECRET" ? WarnRedactedCompletion() : AllowResult();
        }));
        var allowBytes = SseText("plain", "stop");
        var redactBytes = SseText("SECRET", "stop");
        var firstTask = concurrentControl.RunModelStreamAsync(new ModelRequest("a"), (_, _) => ValueTask.FromResult(allowBytes)).AsTask();
        var secondTask = concurrentControl.RunModelStreamAsync(new ModelRequest("b"), (_, _) => ValueTask.FromResult(redactBytes)).AsTask();
        await Task.WhenAll(firstTask, secondTask);
        Assert(allowBytes.SequenceEqual(firstTask.Result.Bytes), "concurrent allow stream should re-emit its own bytes.");
        Assert(!redactBytes.SequenceEqual(secondTask.Result.Bytes), "concurrent transformed stream should not reuse the allow buffer.");
        AssertEqual("plain", ExtractContent(firstTask.Result.Value), "concurrent allow value should stay isolated.");
        AssertEqual("[REDACTED]", ExtractContent(secondTask.Result.Value), "concurrent transform value should stay isolated.");
    }

    private static async Task RunStreamingConformanceAsync()
    {
        var root = FindRepoRoot();
        var streamingRoot = Path.Combine(root, "tests", "conformance", "streaming");
        using var manifest = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(streamingRoot, "manifest.json")));
        var limitsElement = manifest.RootElement.GetProperty("limits");
        AssertEqual(AgentControlStreamingExtensions.DefaultMaxStreamBytes, limitsElement.GetProperty("max_stream_bytes").GetInt32(), "default byte limit should match manifest.");
        AssertEqual(AgentControlStreamingExtensions.DefaultMaxStreamEvents, limitsElement.GetProperty("max_stream_events").GetInt32(), "default event limit should match manifest.");

        foreach (var testCase in manifest.RootElement.GetProperty("assemble").EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString() ?? string.Empty;
            var input = await File.ReadAllBytesAsync(Path.Combine(streamingRoot, testCase.GetProperty("input").GetString() ?? string.Empty));
            if (testCase.GetProperty("outcome").GetString() == "ok")
            {
                var assembled = AgentControlStreaming.AssembleSseStream(input);
                AssertJsonEqual(testCase.GetProperty("assembled"), assembled, $"{name} assembled JSON should match fixture.");
                var result = await new AgentControl(new DelegateRuntime(_ => AllowResult())).RunModelStreamAsync(new ModelRequest(name), (_, _) => ValueTask.FromResult(input));
                Assert(input.SequenceEqual(result.Bytes), $"{name} allow should re-emit input bytes.");
                Assert(input.SequenceEqual(result.OriginalBytes), $"{name} should preserve original bytes.");
                AssertJsonEqual(testCase.GetProperty("assembled"), result.AssembledResponse, $"{name} result assembled JSON should match fixture.");
            }
            else
            {
                try
                {
                    AgentControlStreaming.AssembleSseStream(input);
                    throw new InvalidOperationException($"{name} should fail closed during assembly.");
                }
                catch (Exception ex) when (ex is StreamingUnsupportedException && ex.Message == testCase.GetProperty("error_message").GetString())
                {
                }

                try
                {
                    await new AgentControl(new DelegateRuntime(_ => AllowResult())).RunModelStreamAsync(new ModelRequest(name), (_, _) => ValueTask.FromResult(input));
                    throw new InvalidOperationException($"{name} should block through RunModelStreamAsync.");
                }
                catch (AgentControlBlockedException ex)
                {
                    AssertEqual("runtime_error:streaming_unsupported", ex.Result.Verdict.Reason, $"{name} should use streaming unsupported reason.");
                    AssertEqual(testCase.GetProperty("error_message").GetString(), ex.Result.Verdict.Message, $"{name} should preserve the parser error message.");
                }
            }
        }

        foreach (var testCase in manifest.RootElement.GetProperty("synthesize").EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString() ?? string.Empty;
            var actual = AgentControlStreaming.SynthesizeSseStream(testCase.GetProperty("response"), testCase.GetProperty("template"));
            var expected = await File.ReadAllBytesAsync(Path.Combine(streamingRoot, testCase.GetProperty("expected_output").GetString() ?? string.Empty));
            Assert(expected.SequenceEqual(actual), $"{name} synthesized bytes should match fixture.");
        }

        AssertThrowsStreamingUnsupported(
            () => AgentControlStreaming.AssembleSseStream(Encoding.UTF8.GetBytes("data: {}\n\n"), new StreamingLimits(MaxStreamBytes: 3)),
            "Streaming response exceeded the buffering byte limit.");
        AssertThrowsStreamingUnsupported(
            () => AgentControlStreaming.AssembleSseStream(Encoding.UTF8.GetBytes("data: {}\n\n"), new StreamingLimits(MaxStreamEvents: 0)),
            "Streaming response exceeded the buffered event limit.");
    }

    private static async Task AssertStreamingBlockedAsync(
        AgentControl control,
        string message,
        object? request = null,
        Func<object, CancellationToken, ValueTask<byte[]>>? execute = null)
    {
        try
        {
            await control.RunModelStreamAsync(
                request ?? new ModelRequest("write code"),
                execute ?? ((_, _) => ValueTask.FromResult(SseText("ok", "stop"))));
            throw new InvalidOperationException(message);
        }
        catch (AgentControlBlockedException ex)
        {
            AssertEqual(InterventionPoint.PostModelCall, ex.InterventionPoint, message);
            AssertEqual("runtime_error:streaming_unsupported", ex.Result.Verdict.Reason, message);
        }
    }

    private static void AssertThrowsStreamingUnsupported(Action action, string message)
    {
        try
        {
            action();
            throw new InvalidOperationException($"Expected streaming unsupported error {message}.");
        }
        catch (Exception ex) when (ex is StreamingUnsupportedException && ex.Message == message)
        {
        }
    }

    private static byte[] SseText(string content, string finishReason) => Encoding.UTF8.GetBytes(
        $"data: {{\"id\":\"cmpl-1\",\"created\":1,\"model\":\"gpt-x\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\",\"content\":{JsonSerializer.Serialize(content)}}},\"finish_reason\":null}}]}}\n\n" +
        $"data: {{\"id\":\"cmpl-1\",\"created\":1,\"model\":\"gpt-x\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":{JsonSerializer.Serialize(finishReason)}}}]}}\n\n" +
        "data: [DONE]\n\n");

    private static string ExtractContent(JsonElement completion) =>
        completion.GetProperty("choices")[0].GetProperty("message").GetProperty("content").GetString() ?? string.Empty;

    private static InterventionPointResult AllowResult() => new(new Verdict(Decision.Allow));

    private static InterventionPointResult WarnRedactedCompletion()
    {
        var transformed = JsonSerializer.SerializeToElement(new
        {
            id = "cmpl-1",
            created = 1,
            model = "gpt-x",
            @object = "chat.completion",
            choices = new[]
            {
                new
                {
                    index = 0,
                    message = new { role = "assistant", content = "[REDACTED]" },
                    finish_reason = "stop",
                },
            },
        });
        // AGT D1: only Transform may rewrite the policy target; `warn`+effects
        // was the upstream-ACS pattern and is no longer valid.
        return new InterventionPointResult(
            new Verdict(Decision.Transform, Transform: new Transform("$policy_target", transformed)),
            transformed);
    }

    private static InterventionPointResult EscalateResult(InterventionPointRequest request)
    {
        var policyInput = JsonSerializer.SerializeToElement(new Dictionary<string, object?>
        {
            ["intervention_point"] = request.InterventionPoint.ToWireName(),
            ["snapshot"] = request.Snapshot,
        });
        return new InterventionPointResult(new Verdict(Decision.Escalate), PolicyInput: policyInput, ActionIdentity: AgentControl.ActionIdentity(policyInput));
    }

    private static ApprovalResolver AllowApproval() => (_, result, _) => ValueTask.FromResult(ApprovalResolution.Allow(result.ActionIdentity!));

    private static ApprovalResolver DenyApproval() => (_, _, _) => ValueTask.FromResult(ApprovalResolution.Deny());

    private static ApprovalResolver ThrowingApproval() => (_, _, _) => throw new InvalidOperationException("approval failed");

    private static string FindRepoRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "tests", "conformance", "streaming", "manifest.json")))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException("Repository root was not found.");
    }

    private static void AssertJsonEqual(JsonElement expected, JsonElement actual, string message)
    {
        var expectedNode = JsonNode.Parse(expected.GetRawText());
        var actualNode = JsonNode.Parse(actual.GetRawText());
        if (!JsonNode.DeepEquals(expectedNode, actualNode))
        {
            throw new InvalidOperationException($"{message} Expected {expected.GetRawText()}, got {actual.GetRawText()}.");
        }
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private static void AssertEqual<T>(T expected, T actual, string message)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"{message} Expected '{expected}', got '{actual}'.");
        }
    }

    private sealed record ModelRequest(string Prompt);

    private sealed record ToolArgs(string Command);

    private sealed class OrderingAnnotator : IAnnotatorDispatcher
    {
        public List<string> Calls { get; } = [];

        public ValueTask<JsonElement> DispatchAsync(
            string annotatorName,
            JsonElement annotatorConfig,
            JsonElement preliminaryPolicyInput,
            CancellationToken cancellationToken = default)
        {
            Calls.Add(annotatorName);
            return ValueTask.FromResult(JsonSerializer.SerializeToElement(new { order = Calls.Count }));
        }
    }

    private sealed class CodingAssistantPolicy : IPolicyDispatcher
    {
        public ValueTask<JsonElement> EvaluateAsync(JsonElement preparedInvocation, CancellationToken cancellationToken = default)
        {
            var input = preparedInvocation.GetProperty("input");
            var point = input.GetProperty("intervention_point").GetString();
            return ValueTask.FromResult(point switch
            {
                "post_model_call" => PostModel(input),
                "pre_tool_call" => PreTool(input),
                _ => JsonSerializer.SerializeToElement(new { decision = "allow" }),
            });
        }

        private static JsonElement PostModel(JsonElement input)
        {
            var content = input.GetProperty("policy_target").GetProperty("value").GetProperty("choices")[0].GetProperty("message").GetProperty("content").GetString() ?? string.Empty;
            if (!content.Contains("SECRET", StringComparison.Ordinal))
            {
                return JsonSerializer.SerializeToElement(new { decision = "allow" });
            }

            // AGT D1.1: rewrite via a Transform verdict; effects[] was removed.
            return JsonSerializer.SerializeToElement(new
            {
                decision = "transform",
                reason = "secret_redacted",
                transform = new
                {
                    path = "$policy_target.choices[0].message.content",
                    value = content.Replace("SECRET", "[REDACTED]", StringComparison.Ordinal),
                },
            });
        }

        private static JsonElement PreTool(JsonElement input)
        {
            var command = input.GetProperty("policy_target").GetProperty("value").GetProperty("args").GetProperty("command").GetString() ?? string.Empty;
            if (command == "rm -rf /")
            {
                return JsonSerializer.SerializeToElement(new { decision = "deny", reason = "dangerous_command" });
            }

            if (command == "deploy-production")
            {
                return JsonSerializer.SerializeToElement(new { decision = "escalate", reason = "sensitive_action" });
            }

            return JsonSerializer.SerializeToElement(new { decision = "allow" });
        }
    }

    private sealed class DelegateRuntime : IAgentControlRuntime
    {
        private readonly Func<InterventionPointRequest, InterventionPointResult> evaluate;

        public DelegateRuntime(Func<InterventionPointRequest, InterventionPointResult> evaluate)
        {
            this.evaluate = evaluate;
        }

        public ValueTask<InterventionPointResult> EvaluateInterventionPointAsync(InterventionPointRequest request, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = evaluate(request);
            if (result.PolicyInput.HasValue && result.ActionIdentity is not null)
            {
                return ValueTask.FromResult(result);
            }

            var policyInput = JsonSerializer.SerializeToElement(new Dictionary<string, object?>
            {
                ["intervention_point"] = request.InterventionPoint.ToWireName(),
                ["snapshot"] = request.Snapshot,
            });
            return ValueTask.FromResult(result with
            {
                PolicyInput = policyInput,
                ActionIdentity = AgentControl.ActionIdentity(policyInput),
            });
        }
    }

    private sealed class ThrowingRuntime : IAgentControlRuntime
    {
        public ValueTask<InterventionPointResult> EvaluateInterventionPointAsync(InterventionPointRequest request, CancellationToken cancellationToken = default) =>
            request.InterventionPoint == InterventionPoint.PostModelCall
                ? throw new InvalidOperationException("policy invocation failed")
                : ValueTask.FromResult(AllowResult());
    }
}
