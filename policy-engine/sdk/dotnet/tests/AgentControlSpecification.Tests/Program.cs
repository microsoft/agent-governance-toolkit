using System.Text.Json;
using System.Text.RegularExpressions;
using AgentControlSpecification;
using AgentControlSpecification.AI;
using AgentControlSpecification.AutoGen;
using AutoGen.Core;
using Microsoft.Extensions.AI;

const string BasicHostManifest = """
agent_control_specification_version: 0.3.1-beta
metadata:
  name: basic-host-example
policies:
  input_custom_policy:
    type: custom
    adapter: basic_host_mock
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: input_custom_policy
    policy_target: $.input
    annotations:
      prompt_classifier:
        from: $.input.text
annotators:
  prompt_classifier:
    type: classifier
""";

var nativeLibraryPath = Path.Combine(AppContext.BaseDirectory, "libagent_control_specification_core.so");
Assert(File.Exists(nativeLibraryPath), $"Native library was not copied to test output: {nativeLibraryPath}");

var control = AgentControl.FromNative(BasicHostManifest, new ClassifierAnnotator(), new CustomPolicy());
var result = await control.EvaluateInputAsync(
    new { text = "Please summarize account 1234." },
    new Dictionary<string, object?>
    {
        ["actor"] = new { id = "user-123" },
        ["transport"] = new { kind = "api_gateway", route = "/chat" },
    });

AssertEqual(Decision.Transform, result.Verdict.Decision, "input policy should transform.");
Assert(result.TransformedPolicyTarget.HasValue, "transform verdict should include a transformed policy target.");
Assert(result.Verdict.Transform is not null, "transform verdict should carry the transform payload.");
AssertEqual("$policy_target.text", result.Verdict.Transform!.Path, "transform path should round-trip from the dispatcher.");
var transformedPolicyTarget = result.TransformedPolicyTarget!.Value;
AssertEqual(
    "Please summarize account [REDACTED].",
    transformedPolicyTarget.GetProperty("text").GetString(),
    "account number should be redacted.");
Assert(result.InputIdentity is not null, "transform verdict should surface an input identity.");
Assert(result.EnforcedIdentity is not null, "transform verdict should surface an enforced identity.");
Assert(result.InputIdentity != result.EnforcedIdentity, "transform verdict shifts enforced_identity away from input_identity.");
AssertEqual(result.EnforcedIdentity, result.ActionIdentity, "action_identity is the back-compat alias for enforced_identity.");

var throwingControl = AgentControl.FromNative(BasicHostManifest, new ThrowingAnnotator(), new CustomPolicy());
var failureResult = await throwingControl.EvaluateInputAsync(new { text = "Please summarize account 1234." });
AssertEqual(Decision.Deny, failureResult.Verdict.Decision, "throwing annotator should map to a deny verdict.");
AssertEqual(
    "runtime_error:annotation_failed",
    failureResult.Verdict.Reason,
    "throwing annotator should map to the annotation failure reason.");

// IFC propagation: result_labels emitted by a policy must surface verbatim on
// the verdict so the host can re-supply them as source_labels next turn.
var labelingControl = AgentControl.FromNative(BasicHostManifest, new ClassifierAnnotator(), new LabelingPolicy());
var labelingResult = await labelingControl.EvaluateInputAsync(new { text = "hello" });
AssertEqual(Decision.Allow, labelingResult.Verdict.Decision, "labeling policy should allow.");
Assert(labelingResult.Verdict.ResultLabels is not null, "verdict should carry result_labels.");
AssertEqual(1, labelingResult.Verdict.ResultLabels!.Count, "result_labels should contain one label.");
AssertEqual("confidential", labelingResult.Verdict.ResultLabels![0], "result_labels should round-trip verbatim.");

const string InputOutputManifest = """
agent_control_specification_version: 0.3.1-beta
policies:
  p:
    type: custom
    adapter: test
intervention_points:
  input:
    policy:
      id: p
    policy_target: $.input
  output:
    policy:
      id: p
    policy_target: $.output
""";
var nullingControl = AgentControl.FromNative(InputOutputManifest, new ClassifierAnnotator(), new NullTransformPolicy());
var nullingRun = await nullingControl.RunAsync<object?, object?>(
    new { text = "clear me" },
    (value, _) => ValueTask.FromResult<object?>(new Dictionary<string, object?> { ["received"] = value }));
Assert(nullingRun.InputResult.TransformedPolicyTargetApplied, "explicit null transform should be marked as applied.");
Assert(
    nullingRun.InputResult.TransformedPolicyTarget.HasValue &&
    nullingRun.InputResult.TransformedPolicyTarget.Value.ValueKind == JsonValueKind.Null,
    "explicit null transform should preserve a JSON null target.");
AssertEqual(
    null,
    ((Dictionary<string, object?>)nullingRun.Value!)["received"],
    "run helper should pass explicit null transform to the guarded action.");

var nestedOutputControl = new AgentControl(new DelegateRuntime(request =>
    request.InterventionPoint == InterventionPoint.Output
        ? NestedOutputTransformResult()
        : Result(Decision.Allow)));
var nestedOutputRun = await nestedOutputControl.RunAsync<string, ShapeOutput>(
    "shape",
    (_, _) => ValueTask.FromResult(new ShapeOutput(
        "token OPS-ShapeSafe_12345",
        new Dictionary<string, string> { ["kind"] = "operation", ["status"] = "kept" })));
AssertEqual("token [REDACTED]", nestedOutputRun.Value.Raw, "nested output transform should splice into original shape.");
AssertEqual("operation", nestedOutputRun.Value.Metadata["kind"], "nested output transform should preserve metadata.");

var nonBmpIdentityControl = AgentControl.FromNative(InputOutputManifest, new ClassifierAnnotator(), new EscalatingPolicy());
var nonBmpIdentityResult = await nonBmpIdentityControl.EvaluateInputAsync(
    new Dictionary<string, object?> { ["𐀀"] = 1, ["\uE000"] = 2 });
Assert(nonBmpIdentityResult.PolicyInput.HasValue, "native identity result should carry policy input.");
AssertEqual(
    nonBmpIdentityResult.ActionIdentity,
    AgentControl.ActionIdentity(nonBmpIdentityResult.PolicyInput!.Value),
    "SDK action identity should match native core for non-BMP object keys.");

var allowMcp = new AgentControlMcpToolProvider<McpToolArgs, string>(
    AllowingToolControl(),
    (args, _) => ValueTask.FromResult($"echo:{args.Text}"));
var allowMcpResult = await allowMcp.CallToolAsync("echo", new McpToolArgs("hello"), "call-allow");
AssertEqual("echo:hello", allowMcpResult.Value, "MCP adapter should return the tool result.");

McpToolArgs? receivedArgs = null;
var transformingMcp = new AgentControlMcpToolProvider<McpToolArgs, string>(
    new AgentControl(new DelegateRuntime(request =>
        request.InterventionPoint == InterventionPoint.PreToolCall
            ? Result(Decision.Transform, new McpToolArgs("redacted"))
            : Result(Decision.Allow))),
    (args, _) =>
    {
        receivedArgs = args;
        return ValueTask.FromResult(args.Text);
    });
var transformingResult = await transformingMcp.CallToolAsync("echo", new McpToolArgs("secret"), "call-transform");
AssertEqual("redacted", transformingResult.Value, "MCP adapter should return the transformed tool result.");
AssertEqual("redacted", receivedArgs?.Text, "MCP adapter should pass transformed args to the inner tool.");

var denyMcpRan = false;
var denyMcp = new AgentControlMcpToolProvider<McpToolArgs, string>(
    new AgentControl(new DelegateRuntime(_ => Result(Decision.Deny))),
    (_, _) =>
    {
        denyMcpRan = true;
        return ValueTask.FromResult("unexpected");
    });
try
{
    await denyMcp.CallToolAsync("echo", new McpToolArgs("blocked"), "call-deny");
    throw new InvalidOperationException("MCP adapter should throw when pre_tool_call denies.");
}
catch (AgentControlBlockedException ex)
{
    AssertEqual(InterventionPoint.PreToolCall, ex.InterventionPoint, "MCP adapter should block at pre_tool_call.");
    Assert(!denyMcpRan, "MCP adapter should not run the inner tool after a pre_tool_call deny.");
}

var omittedIdMcp = new AgentControlMcpToolProvider<McpToolArgs, string>(
    new AgentControl(new DelegateRuntime(request =>
    {
        Assert(
            !request.Snapshot.GetProperty("tool_call").TryGetProperty("id", out _),
            "MCP adapter should omit tool_call.id when no caller id is supplied.");
        return Result(Decision.Allow);
    })),
    (_, _) => ValueTask.FromResult("ok"));
var omittedIdResult = await omittedIdMcp.CallToolAsync("echo", new McpToolArgs("no-id"));
AssertEqual("ok", omittedIdResult.Value, "MCP adapter should evaluate when no tool_call_id is supplied.");

try
{
    await omittedIdMcp.CallToolAsync("echo", new McpToolArgs("empty-id"), toolCallId: "");
    throw new InvalidOperationException("MCP adapter should reject explicit empty tool_call_id.");
}
catch (ArgumentException)
{
}

var suppliedIds = new List<string>();
var suppliedIdMcp = new AgentControlMcpToolProvider<McpToolArgs, string>(
    new AgentControl(new DelegateRuntime(request =>
    {
        suppliedIds.Add(request.Snapshot.GetProperty("tool_call").GetProperty("id").GetString() ?? string.Empty);
        return Result(Decision.Allow);
    })),
    (_, _) => ValueTask.FromResult("ok"));
await suppliedIdMcp.CallToolAsync("echo", new McpToolArgs("with-id"), toolCallId: "call-7");
AssertEqual(2, suppliedIds.Count, "MCP adapter should evaluate pre and post tool calls.");
AssertEqual("call-7", suppliedIds[0], "MCP adapter should use the supplied tool_call_id.");
AssertEqual(suppliedIds[0], suppliedIds[1], "MCP adapter should reuse the supplied tool_call_id.");

var whitespaceIdSeen = false;
var whitespaceIdMcp = new AgentControlMcpToolProvider<McpToolArgs, string>(
    new AgentControl(new DelegateRuntime(request =>
    {
        whitespaceIdSeen = true;
        AssertEqual(" ", request.Snapshot.GetProperty("tool_call").GetProperty("id").GetString(), "non-empty whitespace tool_call_id should remain caller-supplied.");
        return Result(Decision.Allow);
    })),
    (_, _) => ValueTask.FromResult("ok"));
await whitespaceIdMcp.CallToolAsync("echo", new McpToolArgs("with-whitespace-id"), toolCallId: " ");
Assert(whitespaceIdSeen, "MCP adapter should evaluate when whitespace tool_call_id is supplied.");

var exceptionMcp = new AgentControlMcpToolProvider<McpToolArgs, string>(
    AllowingToolControl(),
    (_, _) => throw new InvalidOperationException("tool failed"));
try
{
    await exceptionMcp.CallToolAsync("echo", new McpToolArgs("boom"), "call-exception");
    throw new InvalidOperationException("MCP adapter should propagate inner tool exceptions.");
}
catch (InvalidOperationException ex) when (ex.Message == "tool failed")
{
}

// Escalation seam conformance.
var escalateInputRuntime = new DelegateRuntime(request =>
    request.InterventionPoint == InterventionPoint.Input ? Result(Decision.Escalate) : Result(Decision.Allow));

var denyConsulted = false;
var denyResolverControl = new AgentControl(
    new DelegateRuntime(request =>
        request.InterventionPoint == InterventionPoint.Input ? Result(Decision.Deny) : Result(Decision.Allow)),
    (_, result, _) =>
    {
        denyConsulted = true;
        return ValueTask.FromResult(ApprovalResolution.Allow(result.ActionIdentity!));
    });
try
{
    await denyResolverControl.RunAsync<string, string>("hi", (input, _) => ValueTask.FromResult(input));
    throw new InvalidOperationException("deny should block.");
}
catch (AgentControlBlockedException)
{
}

Assert(!denyConsulted, "deny should not consult the resolver.");

var noResolverControl = new AgentControl(escalateInputRuntime);
try
{
    await noResolverControl.RunAsync<string, string>("hi", (input, _) => ValueTask.FromResult(input));
    throw new InvalidOperationException("escalate without a resolver should block.");
}
catch (AgentControlBlockedException)
{
}

// AGT D1: per §13.1 an escalate carries no transform. After approval the
// host proceeds with the original policy target, not a substituted one.
var escalateAllowControl = new AgentControl(escalateInputRuntime, AllowApproval());
var allowRun = await escalateAllowControl.RunAsync<string, string>("original", (input, _) => ValueTask.FromResult(input));
AssertEqual("original", allowRun.Value, "an approved escalate should proceed with the original value.");


var identitySeen = string.Empty;
var identityControl = new AgentControl(escalateInputRuntime, (_, result, _) =>
{
    identitySeen = result.ActionIdentity ?? string.Empty;
    Assert(result.PolicyInput.HasValue, "approval resolver should receive policy input.");
    AssertEqual(AgentControl.ActionIdentity(result.PolicyInput!.Value), result.ActionIdentity, "approval resolver should receive the derived action identity.");
    return ValueTask.FromResult(ApprovalResolution.Allow(result.ActionIdentity!));
});
var identityRun = await identityControl.RunAsync<string, string>("hi", (input, _) => ValueTask.FromResult(input));
AssertEqual("hi", identityRun.Value, "identity-bound approval should proceed.");
Assert(!string.IsNullOrWhiteSpace(identitySeen), "approval resolver should observe an action identity.");

var stableRuntime = new DelegateRuntime(request =>
    request.InterventionPoint == InterventionPoint.Input ? Result(Decision.Escalate) : Result(Decision.Allow));
var stableFirst = await stableRuntime.EvaluateInterventionPointAsync(new InterventionPointRequest(
    InterventionPoint.Input,
    JsonSerializer.SerializeToElement(new Dictionary<string, object?> { ["input"] = "hi" })));
var stableSecond = await stableRuntime.EvaluateInterventionPointAsync(new InterventionPointRequest(
    InterventionPoint.Input,
    JsonSerializer.SerializeToElement(new Dictionary<string, object?> { ["input"] = "hi" })));
AssertEqual(stableFirst.ActionIdentity, stableSecond.ActionIdentity, "action identity should be stable for repeated evaluation.");

JsonElement? shutdownSnapshot = null;
var shutdownControl = new AgentControl(new DelegateRuntime(request =>
{
    if (request.InterventionPoint == InterventionPoint.AgentShutdown)
    {
        shutdownSnapshot = request.Snapshot.Clone();
    }

    return Result(Decision.Allow);
}));
await shutdownControl.EvaluateAgentShutdownAsync(new { status = "done" });
Assert(
    shutdownSnapshot.HasValue && shutdownSnapshot.Value.TryGetProperty("summary", out _),
    "EvaluateAgentShutdownAsync should build a summary snapshot field.");
Assert(
    shutdownSnapshot.HasValue && !shutdownSnapshot.Value.TryGetProperty("agent", out _),
    "EvaluateAgentShutdownAsync should not build the obsolete agent snapshot field.");

var mismatchControl = new AgentControl(new DelegateRuntime(_ => MismatchedEscalateResult()), AllowApproval());
try
{
    await mismatchControl.RunAsync<string, string>("hi", (input, _) => ValueTask.FromResult(input));
    throw new InvalidOperationException("approval action mismatch should block.");
}
catch (AgentControlBlockedException ex)
{
    AssertEqual("runtime_error:approval_action_mismatch", ex.Result.Verdict.Reason, "mismatched approval should use the reserved reason.");
}

var denyApprovalControl = new AgentControl(escalateInputRuntime, DenyApproval());
try
{
    await denyApprovalControl.RunAsync<string, string>("hi", (input, _) => ValueTask.FromResult(input));
    throw new InvalidOperationException("escalate-deny should block.");
}
catch (AgentControlBlockedException)
{
}

var suspendControl = new AgentControl(
    escalateInputRuntime,
    (_, result, _) => ValueTask.FromResult(ApprovalResolution.Suspend(JsonSerializer.SerializeToElement(new { ticket = "T-1" }), result.ActionIdentity!)));
try
{
    await suspendControl.RunAsync<string, string>("hi", (input, _) => ValueTask.FromResult(input));
    throw new InvalidOperationException("escalate-suspend should raise.");
}
catch (AgentControlSuspendedException ex)
{
    Assert(ex.Handle.HasValue, "suspension should carry a handle.");
    AssertEqual("T-1", ex.Handle!.Value.GetProperty("ticket").GetString(), "suspension handle should round-trip.");
}

var evaluateOnlyConsulted = false;
var evaluateOnlyControl = new AgentControl(escalateInputRuntime, (_, result, _) =>
{
    evaluateOnlyConsulted = true;
    return ValueTask.FromResult(ApprovalResolution.Allow(result.ActionIdentity!));
});
var evaluateOnlyRun = await evaluateOnlyControl.RunAsync<string, string>(
    "hi",
    (input, _) => ValueTask.FromResult(input),
    mode: EnforcementMode.EvaluateOnly);
AssertEqual("hi", evaluateOnlyRun.Value, "evaluate_only should pass the value through.");
Assert(!evaluateOnlyConsulted, "evaluate_only should not consult the resolver.");

var postToolExecuted = false;
var postToolControl = new AgentControl(
    new DelegateRuntime(request =>
        request.InterventionPoint == InterventionPoint.PostToolCall ? Result(Decision.Escalate) : Result(Decision.Allow)),
    DenyApproval());
try
{
    await postToolControl.RunToolAsync<McpToolArgs, string>(
        "lookup",
        new McpToolArgs("q"),
        (_, _) =>
        {
            postToolExecuted = true;
            return ValueTask.FromResult("ok");
        },
        "call-post");
    throw new InvalidOperationException("post-tool escalate-deny should block.");
}
catch (AgentControlBlockedException ex)
{
    AssertEqual(InterventionPoint.PostToolCall, ex.InterventionPoint, "post-tool block should report the post_tool_call point.");
}

Assert(postToolExecuted, "post-tool escalate should still run the tool.");

var overrideControl = new AgentControl(escalateInputRuntime, DenyApproval());
var overrideRun = await overrideControl.RunAsync<string, string>(
    "hi",
    (input, _) => ValueTask.FromResult(input),
    approvalResolver: AllowApproval());
AssertEqual("hi", overrideRun.Value, "a per-call resolver should override the instance resolver.");

var throwingResolverControl = new AgentControl(
    escalateInputRuntime,
    (_, _, _) => throw new InvalidOperationException("resolver boom"));
try
{
    await throwingResolverControl.RunAsync<string, string>("hi", (input, _) => ValueTask.FromResult(input));
    throw new InvalidOperationException("a throwing resolver should block.");
}
catch (AgentControlBlockedException ex)
{
    AssertEqual("runtime_error:approval_resolver_failed", ex.Result.Verdict.Reason, "a resolver failure should use the reserved reason.");
    Assert(ex.Result.PolicyInput.HasValue, "a resolver failure should retain the original policy input.");
    AssertEqual(
        AgentControl.ActionIdentity(ex.Result.PolicyInput!.Value),
        ex.Result.ActionIdentity,
        "a resolver failure should retain the original action identity.");
    Assert(
        ex.InnerException is InvalidOperationException { Message: "resolver boom" },
        "a resolver failure should preserve the cause.");
}

var invalidModeResult = await control.EvaluateInputAsync(
    new { text = "invalid mode" },
    mode: (EnforcementMode)999);
AssertEqual(Decision.Deny, invalidModeResult.Verdict.Decision, "an invalid enforcement mode should fail closed.");
AssertEqual("runtime_error:request_invalid", invalidModeResult.Verdict.Reason, "an invalid enforcement mode should map to request_invalid.");

// Adapter-level approval-resolver parity.
var escalateModelRuntime = new DelegateRuntime(request =>
    request.InterventionPoint == InterventionPoint.PreModelCall ? Result(Decision.Escalate) : Result(Decision.Allow));
var escalateToolRuntime = new DelegateRuntime(request =>
    request.InterventionPoint == InterventionPoint.PreToolCall ? Result(Decision.Escalate) : Result(Decision.Allow));

var chatClient = new EchoChatClient()
    .UseAgentControl(new AgentControl(escalateModelRuntime), approvalResolver: AllowApproval());
var chatResponse = await chatClient.GetResponseAsync("ping");
AssertEqual("ping", chatResponse, "chat client constructor resolver should drive escalate-allow.");

var toolFilter = new AgentControlToolInvocationFilter<McpToolArgs, string>(
    new AgentControl(escalateToolRuntime, DenyApproval()));
var filterResult = await toolFilter.InvokeAsync(
    "lookup",
    new McpToolArgs("q"),
    (args, _) => ValueTask.FromResult(args.Text),
    "call-filter",
    approvalResolver: AllowApproval());
AssertEqual("q", filterResult.Value, "tool filter per-call resolver should override the instance resolver.");

var unsupportedAdapter = new UnsupportedFrameworkAdapter<object>("ExampleAI");
try
{
    unsupportedAdapter.Guard(new object(), new AgentControl(new DelegateRuntime(_ => Result(Decision.Allow))));
    throw new InvalidOperationException("unsupported framework adapter should fail closed.");
}
catch (AgentControlBlockedException ex)
{
    AssertEqual("runtime_error:adapter_unsupported", ex.Result.Verdict.Reason, "unsupported framework adapter should use the reserved reason.");
}

var agentMiddleware = new AgentControlAgentMiddleware<string, string>(new AgentControl(escalateInputRuntime));
try
{
    await agentMiddleware.InvokeAsync(
        "hi",
        (input, _) => ValueTask.FromResult(input),
        approvalResolver: (_, result, _) => ValueTask.FromResult(
            ApprovalResolution.Suspend(JsonSerializer.SerializeToElement(new { ticket = "T-2" }), result.ActionIdentity!)));
    throw new InvalidOperationException("agent middleware escalate-suspend should raise.");
}
catch (AgentControlSuspendedException ex)
{
    AssertEqual("T-2", ex.Handle!.Value.GetProperty("ticket").GetString(), "agent middleware should propagate the suspension handle.");
}

var mcpProvider = new AgentControlMcpToolProvider<McpToolArgs, string>(
    new AgentControl(escalateToolRuntime),
    (args, _) => ValueTask.FromResult(args.Text));
try
{
    await mcpProvider.CallToolAsync("lookup", new McpToolArgs("q"), "call-mcp", approvalResolver: DenyApproval());
    throw new InvalidOperationException("MCP per-call resolver escalate-deny should block.");
}
catch (AgentControlBlockedException)
{
}

var deniedChatInner = new RecordingChatClient();
var deniedChat = deniedChatInner.UseAgentControl(new AgentControl(new DelegateRuntime(request =>
    request.InterventionPoint == InterventionPoint.PreModelCall ? Result(Decision.Deny) : Result(Decision.Allow))));
try
{
    await deniedChat.GetResponseAsync("raw");
    throw new InvalidOperationException("chat client pre_model_call deny should block.");
}
catch (AgentControlBlockedException ex)
{
    AssertEqual(InterventionPoint.PreModelCall, ex.InterventionPoint, "chat client should block at pre_model_call.");
    AssertEqual(0, deniedChatInner.Calls.Count, "chat client should not call inner after pre_model_call deny.");
}

var mediatedChatInner = new RecordingChatClient();
var mediatedChat = mediatedChatInner.UseAgentControl(new AgentControl(new DelegateRuntime(request =>
    request.InterventionPoint == InterventionPoint.PreModelCall
        ? Result(Decision.Transform, "safe")
        : Result(Decision.Transform, "checked"))));
var mediatedChatResult = await mediatedChat.GetResponseAsync("raw");
AssertEqual("checked", mediatedChatResult, "chat client should return the transformed model response.");
AssertEqual("safe", mediatedChatInner.Calls.Single(), "chat client should pass transformed request to inner.");

var lookupTool = AIFunctionFactory.Create((Func<string, string>)(value => value), "lookup", "Lookup test tool", serializerOptions: null);
var deleteTool = AIFunctionFactory.Create((Func<string, string>)(value => value), "delete_customer", "Delete test tool", serializerOptions: null);
var filteredOptions = new ChatOptionsSnapshot(null, null, ["lookup"]).ApplyTo(new ChatOptions
{
    Tools = [lookupTool, deleteTool],
});
Assert(filteredOptions is not null, "filtered chat options should be present.");
AssertEqual(1, filteredOptions!.Tools!.Count, "chat options transform should remove omitted tools.");
AssertEqual("lookup", filteredOptions.Tools[0].Name, "chat options transform should preserve the named tool.");
var clearedOptions = new ChatOptionsSnapshot(null, null, []).ApplyTo(new ChatOptions
{
    Tools = [lookupTool, deleteTool],
});
Assert(clearedOptions is not null, "cleared chat options should be present.");
AssertEqual(0, clearedOptions!.Tools!.Count, "chat options transform should clear tools.");

var imageContent = new DataContent(new byte[] { 1, 2, 3 }, "image/png");
var originalMultiPart = new ChatMessage(ChatRole.User, [new TextContent("raw"), imageContent]);
var appendedMessages = new ChatRequestSnapshot(
    [
        new ChatMessageSnapshot(ChatRole.System.ToString(), "safety preface", null),
        ChatMessageSnapshot.From(originalMultiPart),
    ],
    new ChatOptionsSnapshot(null, null, [])).ApplyMessages([originalMultiPart]);
AssertEqual(2, appendedMessages.Count, "chat message transform should include inserted messages.");
Assert(ReferenceEquals(originalMultiPart, appendedMessages[1]), "unchanged multipart messages should be preserved after insertion.");
var redactedMessages = new ChatRequestSnapshot(
    [new ChatMessageSnapshot(ChatRole.User.ToString(), "safe", null)],
    new ChatOptionsSnapshot(null, null, [])).ApplyMessages([originalMultiPart]);
AssertEqual("safe", redactedMessages[0].Text, "chat message transform should apply text redaction.");
Assert(
    redactedMessages[0].Contents.OfType<DataContent>().Single().MediaType == "image/png",
    "chat message text transform should preserve non-text content.");
var responseWithData = new ChatResponse(new ChatMessage(ChatRole.Assistant, [new TextContent("ok"), imageContent]))
{
    ResponseId = "resp-1",
};
var preservedResponse = ChatResponseSnapshot.From(responseWithData).Response;
Assert(ReferenceEquals(responseWithData, preservedResponse), "allow-path chat response snapshots should preserve the original response object.");
Assert(
    preservedResponse.Messages.Single().Contents.OfType<DataContent>().Single().MediaType == "image/png",
    "allow-path chat response snapshots should preserve non-text response content.");
AssertEqual("resp-1", preservedResponse.ResponseId, "allow-path chat response snapshots should preserve response metadata.");

var filterNextCalled = false;
var deniedSkContext = new FunctionContext<McpToolArgs, string>("lookup", new McpToolArgs("raw"), "sk-deny");
var deniedSkFilter = AgentControlFrameworkAdapters.SemanticKernelFunctionFilter<McpToolArgs, string>(
    new AgentControl(new DelegateRuntime(request =>
        request.InterventionPoint == InterventionPoint.PreToolCall ? Result(Decision.Deny) : Result(Decision.Allow))));
try
{
    await deniedSkFilter.InvokeAsync(deniedSkContext, (_, _) =>
    {
        filterNextCalled = true;
        return ValueTask.CompletedTask;
    });
    throw new InvalidOperationException("Semantic Kernel filter pre_tool_call deny should block.");
}
catch (AgentControlBlockedException ex)
{
    AssertEqual(InterventionPoint.PreToolCall, ex.InterventionPoint, "Semantic Kernel filter should block at pre_tool_call.");
    Assert(!filterNextCalled, "Semantic Kernel filter should not call next after pre_tool_call deny.");
}

var allowedSkContext = new FunctionContext<McpToolArgs, string>("lookup", new McpToolArgs("raw"), "sk-allow");
var allowedSkFilter = AgentControlFrameworkAdapters.SemanticKernelFunctionFilter<McpToolArgs, string>(
    new AgentControl(new DelegateRuntime(request =>
        request.InterventionPoint == InterventionPoint.PreToolCall
            ? Result(Decision.Transform, new McpToolArgs("safe"))
            : Result(Decision.Transform, "checked"))));
await allowedSkFilter.InvokeAsync(allowedSkContext, (context, _) =>
{
    context.Result = context.Arguments.Text;
    return ValueTask.CompletedTask;
});
AssertEqual("safe", allowedSkContext.Arguments.Text, "Semantic Kernel filter should pass transformed args to next.");
AssertEqual("checked", allowedSkContext.Result, "Semantic Kernel filter should apply post_tool_call transform.");

var deniedAutoGenContext = new AgentInvocationContext<string, string>("raw");
var deniedAutoGen = AgentControlFrameworkAdapters.AutoGenMiddleware<string, string>(
    new AgentControl(new DelegateRuntime(request =>
        request.InterventionPoint == InterventionPoint.Input ? Result(Decision.Deny) : Result(Decision.Allow))));
var autoGenNextCalled = false;
try
{
    await deniedAutoGen.InvokeAsync(deniedAutoGenContext, (_, _) =>
    {
        autoGenNextCalled = true;
        return ValueTask.CompletedTask;
    });
    throw new InvalidOperationException("AutoGen middleware input deny should block.");
}
catch (AgentControlBlockedException ex)
{
    AssertEqual(InterventionPoint.Input, ex.InterventionPoint, "AutoGen middleware should block at input.");
    Assert(!autoGenNextCalled, "AutoGen middleware should not call next after input deny.");
}

var allowedAutoGenContext = new AgentInvocationContext<string, string>("raw");
var allowedAutoGen = AgentControlFrameworkAdapters.AutoGenMiddleware<string, string>(
    new AgentControl(new DelegateRuntime(request =>
        request.InterventionPoint == InterventionPoint.Input
            ? Result(Decision.Transform, "safe")
            : Result(Decision.Transform, "checked"))));
await allowedAutoGen.InvokeAsync(allowedAutoGenContext, (context, _) =>
{
    context.Output = context.Input;
    return ValueTask.CompletedTask;
});
AssertEqual("safe", allowedAutoGenContext.Input, "AutoGen middleware should pass transformed input to next.");
AssertEqual("checked", allowedAutoGenContext.Output, "AutoGen middleware should apply output transform.");

var autoGenCompanionReply = await new FakeAutoGenAgent(new TextMessage(Role.Assistant, "reply SUPPORT-TOKEN-1", "assistant"))
    .UseAgentControl(new AgentControl(new DelegateRuntime(request =>
    {
        if (request.InterventionPoint == InterventionPoint.PostModelCall &&
            (!request.Snapshot.TryGetProperty("model_response", out var modelResponse) ||
             !modelResponse.TryGetProperty("content", out var content) ||
             content.GetString() != "reply SUPPORT-TOKEN-1"))
        {
            throw new InvalidOperationException("AutoGen middleware must serialize the concrete reply content.");
        }

        return
        request.InterventionPoint == InterventionPoint.PostModelCall
            ? Result(Decision.Transform, new { role = "assistant", content = "reply [REDACTED]", from = "assistant" })
            : Result(Decision.Allow);
    })))
    .GenerateReplyAsync([new TextMessage(Role.User, "hello", "user")]);
AssertEqual("reply [REDACTED]", autoGenCompanionReply.GetContent(), "AutoGen companion should apply post_model_call transforms to replies.");

// Microsoft Agent Framework function-calling middleware maps to pre/post_tool_call.
var afFilterNextCalled = false;
var deniedAfContext = new FunctionContext<McpToolArgs, string>("lookup", new McpToolArgs("raw"), "af-deny");
var deniedAfFilter = AgentControlFrameworkAdapters.AgentFrameworkFunctionMiddleware<McpToolArgs, string>(
    new AgentControl(new DelegateRuntime(request =>
        request.InterventionPoint == InterventionPoint.PreToolCall ? Result(Decision.Deny) : Result(Decision.Allow))));
try
{
    await deniedAfFilter.InvokeAsync(deniedAfContext, (_, _) =>
    {
        afFilterNextCalled = true;
        return ValueTask.CompletedTask;
    });
    throw new InvalidOperationException("Agent Framework function middleware pre_tool_call deny should block.");
}
catch (AgentControlBlockedException ex)
{
    AssertEqual(InterventionPoint.PreToolCall, ex.InterventionPoint, "Agent Framework function middleware should block at pre_tool_call.");
    Assert(!afFilterNextCalled, "Agent Framework function middleware should not call next after pre_tool_call deny.");
}

var allowedAfContext = new FunctionContext<McpToolArgs, string>("lookup", new McpToolArgs("raw"), "af-allow");
var allowedAfFilter = AgentControlFrameworkAdapters.AgentFrameworkFunctionMiddleware<McpToolArgs, string>(
    new AgentControl(new DelegateRuntime(request =>
        request.InterventionPoint == InterventionPoint.PreToolCall
            ? Result(Decision.Transform, new McpToolArgs("safe"))
            : Result(Decision.Transform, "checked"))));
await allowedAfFilter.InvokeAsync(allowedAfContext, (context, _) =>
{
    context.Result = context.Arguments.Text;
    return ValueTask.CompletedTask;
});
AssertEqual("safe", allowedAfContext.Arguments.Text, "Agent Framework function middleware should pass transformed args to next.");
AssertEqual("checked", allowedAfContext.Result, "Agent Framework function middleware should apply post_tool_call transform.");

// Microsoft Agent Framework agent-run middleware maps to input/output.
var deniedAfRunContext = new AgentInvocationContext<string, string>("raw");
var deniedAfRun = AgentControlFrameworkAdapters.AgentFrameworkRunMiddleware<string, string>(
    new AgentControl(new DelegateRuntime(request =>
        request.InterventionPoint == InterventionPoint.Input ? Result(Decision.Deny) : Result(Decision.Allow))));
var afRunNextCalled = false;
try
{
    await deniedAfRun.InvokeAsync(deniedAfRunContext, (_, _) =>
    {
        afRunNextCalled = true;
        return ValueTask.CompletedTask;
    });
    throw new InvalidOperationException("Agent Framework run middleware input deny should block.");
}
catch (AgentControlBlockedException ex)
{
    AssertEqual(InterventionPoint.Input, ex.InterventionPoint, "Agent Framework run middleware should block at input.");
    Assert(!afRunNextCalled, "Agent Framework run middleware should not call next after input deny.");
}

var allowedAfRunContext = new AgentInvocationContext<string, string>("raw");
var allowedAfRun = AgentControlFrameworkAdapters.AgentFrameworkRunMiddleware<string, string>(
    new AgentControl(new DelegateRuntime(request =>
        request.InterventionPoint == InterventionPoint.Input
            ? Result(Decision.Transform, "safe")
            : Result(Decision.Transform, "checked"))));
await allowedAfRun.InvokeAsync(allowedAfRunContext, (context, _) =>
{
    context.Output = context.Input;
    return ValueTask.CompletedTask;
});
AssertEqual("safe", allowedAfRunContext.Input, "Agent Framework run middleware should pass transformed input to next.");
AssertEqual("checked", allowedAfRunContext.Output, "Agent Framework run middleware should apply output transform.");

// Escalate flows through the approval resolver for both Agent Framework shapes.
var approvedAfFilterContext = new FunctionContext<McpToolArgs, string>("escalating_tool", new McpToolArgs("raw"), "call-af-esc");
var approvedAfFilter = AgentControlFrameworkAdapters.AgentFrameworkFunctionMiddleware<McpToolArgs, string>(
    new AgentControl(new DelegateRuntime(request =>
        request.InterventionPoint == InterventionPoint.PreToolCall ? Result(Decision.Escalate) : Result(Decision.Allow))),
    approvalResolver: AllowApproval());
var approvedAfFilterNextCalled = false;
await approvedAfFilter.InvokeAsync(approvedAfFilterContext, (context, _) =>
{
    approvedAfFilterNextCalled = true;
    context.Result = "done";
    return ValueTask.CompletedTask;
});
Assert(approvedAfFilterNextCalled, "Agent Framework function middleware should proceed after an approved escalate.");
AssertEqual("done", approvedAfFilterContext.Result, "Agent Framework function middleware should return the result after an approved escalate.");

var deniedAfFilterEscContext = new FunctionContext<McpToolArgs, string>("escalating_tool", new McpToolArgs("raw"), "call-af-esc-deny");
var deniedAfFilterEsc = AgentControlFrameworkAdapters.AgentFrameworkFunctionMiddleware<McpToolArgs, string>(
    new AgentControl(new DelegateRuntime(request =>
        request.InterventionPoint == InterventionPoint.PreToolCall ? Result(Decision.Escalate) : Result(Decision.Allow))),
    approvalResolver: DenyApproval());
var deniedAfFilterEscNextCalled = false;
try
{
    await deniedAfFilterEsc.InvokeAsync(deniedAfFilterEscContext, (_, _) =>
    {
        deniedAfFilterEscNextCalled = true;
        return ValueTask.CompletedTask;
    });
    throw new InvalidOperationException("Agent Framework function middleware denied escalate should block.");
}
catch (AgentControlBlockedException)
{
    Assert(!deniedAfFilterEscNextCalled, "Agent Framework function middleware should not call next after a denied escalate.");
}

var approvedAfRunContext = new AgentInvocationContext<string, string>("raw");
var approvedAfRun = AgentControlFrameworkAdapters.AgentFrameworkRunMiddleware<string, string>(
    new AgentControl(new DelegateRuntime(request =>
        request.InterventionPoint == InterventionPoint.Input ? Result(Decision.Escalate) : Result(Decision.Allow))),
    approvalResolver: AllowApproval());
var approvedAfRunNextCalled = false;
await approvedAfRun.InvokeAsync(approvedAfRunContext, (context, _) =>
{
    approvedAfRunNextCalled = true;
    context.Output = "done";
    return ValueTask.CompletedTask;
});
Assert(approvedAfRunNextCalled, "Agent Framework run middleware should proceed after an approved escalate.");
AssertEqual("done", approvedAfRunContext.Output, "Agent Framework run middleware should return the output after an approved escalate.");

Console.WriteLine("AgentControlSpecification Agent Framework adapter tests passed.");

var chatInnerField = typeof(AgentControlDelegatingChatClient<string, string>)
    .GetField("inner", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
Assert(chatInnerField is not null && chatInnerField.IsPrivate, "chat client inner reference should be private.");
var mcpExecuteField = typeof(AgentControlMcpToolProvider<McpToolArgs, string>)
    .GetField("execute", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
Assert(mcpExecuteField is not null && mcpExecuteField.IsPrivate, "MCP provider execute reference should be private.");

using var parityFixture = JsonDocument.Parse(File.ReadAllText(Path.Combine(FindRepoRoot(), "tests", "conformance", "fail_closed_error_parity.json")));
AssertEqual(12, parityFixture.RootElement.GetProperty("reserved_reasons").GetArrayLength(), "build and evaluate parity fixture should cover reachable reserved reasons.");
var parityReasons = parityFixture.RootElement.GetProperty("reserved_reasons").EnumerateArray().Select(reason => reason.GetString()).ToHashSet();
var parityCoveredReasons = parityFixture.RootElement.GetProperty("cases").EnumerateArray().Select(caseElement => caseElement.GetProperty("expected_reason").GetString()).ToHashSet();
Assert(parityReasons.SetEquals(parityCoveredReasons), "parity cases should match build and evaluate reachable reserved reasons.");
foreach (var caseElement in parityFixture.RootElement.GetProperty("cases").EnumerateArray())
{
    var caseId = caseElement.GetProperty("id").GetString() ?? string.Empty;
    var expectedReason = caseElement.GetProperty("expected_reason").GetString();
    if (caseElement.GetProperty("operation").GetString() == "build")
    {
        try
        {
            AgentControl.FromNative(
                caseElement.GetProperty("manifest_yaml").GetString() ?? string.Empty,
                new ParityAnnotator(caseElement.Clone()),
                new ParityPolicy(caseElement.Clone()));
            throw new InvalidOperationException($"{caseId} should fail closed while building.");
        }
        catch (Exception exception) when (ReasonFromError(exception) == expectedReason)
        {
        }

        continue;
    }

    var parityControl = AgentControl.FromNative(
        caseElement.GetProperty("manifest_yaml").GetString() ?? string.Empty,
        new ParityAnnotator(caseElement.Clone()),
        new ParityPolicy(caseElement.Clone()));
    var parityResult = await parityControl.EvaluateInterventionPointAsync(
        InterventionPointExtensions.FromWireName(caseElement.GetProperty("intervention_point").GetString() ?? string.Empty),
        caseElement.GetProperty("snapshot").Clone());
    AssertEqual(Decision.Deny, parityResult.Verdict.Decision, $"{caseId} should deny.");
    AssertEqual(expectedReason, parityResult.Verdict.Reason, $"{caseId} should use the reserved reason.");
}

const string ChainChildManifest = """
agent_control_specification_version: 0.3.1-beta
tools:
  noop_tool:
    clearance: public
""";

// Regression guard: the high level facade must accept and thread PerfTelemetry
// through FromManifestChain (and FromPath), matching FromNative and the other
// SDKs. A live audit found these loaders had dropped the perf telemetry argument.
var chainControl = AgentControl.FromManifestChain(
    new[] { BasicHostManifest, ChainChildManifest },
    new ClassifierAnnotator(),
    new CustomPolicy(),
    perfTelemetry: PerfTelemetry.Full);
var chainResult = await chainControl.EvaluateInputAsync(new { text = "Please summarize account 1234." });
AssertEqual(Decision.Transform, chainResult.Verdict.Decision, "manifest chain with perf telemetry should transform.");

// Zero-config ergonomics: FromPath with no dispatchers must build by enabling the
// bundled native defaults (OPA policy dispatcher resolving the manifest-relative
// rego bundle, plus the default classifier annotator). The pre_model_call point
// carries no annotations, so this exercises the default OPA policy path end-to-end.
var zeroConfigManifest = Path.Combine(FindRepoRoot(), "examples", "records_agent", "manifest.yaml");
Assert(File.Exists(zeroConfigManifest), $"records_agent manifest was not found: {zeroConfigManifest}");
var zeroConfigControl = AgentControl.FromPath(zeroConfigManifest);
var zeroConfigResult = await zeroConfigControl.EvaluatePreModelCallAsync(
    new { messages = new[] { new { role = "user", content = "List my upcoming appointments." } } });
AssertEqual(Decision.Allow, zeroConfigResult.Verdict.Decision, "zero-config pre_model_call should allow.");

var originalOpaPath = Environment.GetEnvironmentVariable("ACS_OPA_PATH");
try
{
    Environment.SetEnvironmentVariable(
        "ACS_OPA_PATH",
        Path.Combine(Path.GetTempPath(), "acs-missing-opa-for-dotnet-test"));
    var badOpaPathControl = AgentControl.FromPath(zeroConfigManifest);
    var badOpaPathResult = await badOpaPathControl.EvaluatePreModelCallAsync(
        new { messages = new[] { new { role = "user", content = "hello" } } });
    AssertEqual(
        Decision.Deny,
        badOpaPathResult.Verdict.Decision,
        "bad explicit ACS_OPA_PATH should fail closed during evaluation.");
    AssertEqual(
        "runtime_error:policy_invocation_failed",
        badOpaPathResult.Verdict.Reason,
        "bad explicit ACS_OPA_PATH should use policy invocation failed reason.");
}
finally
{
    Environment.SetEnvironmentVariable("ACS_OPA_PATH", originalOpaPath);
}

await PaymentEscalationHarness.RunAsync();
await StreamingHarness.RunAsync();
await Agt5SurfaceHarness.RunAsync();
await Agt1TransformGateHarness.RunAsync();

Console.WriteLine("AgentControlSpecification native round-trip test passed.");
Console.WriteLine("AgentControlSpecification callback exception-safety test passed.");
Console.WriteLine("AgentControlSpecification MCP allow path test passed.");
Console.WriteLine("AgentControlSpecification MCP pre-tool transform test passed.");
Console.WriteLine("AgentControlSpecification MCP pre-tool deny test passed.");
Console.WriteLine("AgentControlSpecification MCP optional tool_call_id test passed.");
Console.WriteLine("AgentControlSpecification MCP inner exception propagation test passed.");
Console.WriteLine("AgentControlSpecification escalation seam conformance tests passed.");
Console.WriteLine("AgentControlSpecification payment escalation use-case tests passed.");
Console.WriteLine("AgentControlSpecification adapter approval-resolver parity tests passed.");
Console.WriteLine("AgentControlSpecification fail-closed error parity tests passed.");
Console.WriteLine("AgentControlSpecification zero-config FromPath test passed.");
Console.WriteLine("AgentControlSpecification AGT D1 transform-gate parity tests passed.");
Console.WriteLine($"Native library: {nativeLibraryPath}");

static void Assert(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

static void AssertEqual<T>(T expected, T actual, string message)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
    {
        throw new InvalidOperationException($"{message} Expected '{expected}', got '{actual}'.");
    }
}

static AgentControl AllowingToolControl() => new(new DelegateRuntime(_ => Result(Decision.Allow)));

static string FindRepoRoot()
{
    for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
    {
        if (File.Exists(Path.Combine(directory.FullName, "tests", "conformance", "fail_closed_error_parity.json")))
        {
            return directory.FullName;
        }
    }

    throw new InvalidOperationException("Repository root was not found.");
}

static string? ReasonFromError(Exception exception)
{
    var match = Regex.Match(exception.ToString(), "runtime_error:[a-z_]+");
    return match.Success ? match.Value : null;
}

static ApprovalResolver AllowApproval() => (_, result, _) => ValueTask.FromResult(ApprovalResolution.Allow(result.ActionIdentity!));

static ApprovalResolver DenyApproval() => (_, _, _) => ValueTask.FromResult(ApprovalResolution.Deny());


static InterventionPointResult MismatchedEscalateResult()
{
    var originalPolicyInput = JsonSerializer.SerializeToElement(new Dictionary<string, object?>
    {
        ["intervention_point"] = "input",
        ["snapshot"] = new Dictionary<string, object?> { ["input"] = "original" },
    });
    var mutatedPolicyInput = JsonSerializer.SerializeToElement(new Dictionary<string, object?>
    {
        ["intervention_point"] = "input",
        ["snapshot"] = new Dictionary<string, object?> { ["input"] = "mutated" },
    });
    return new InterventionPointResult(
        new Verdict(Decision.Escalate),
        PolicyInput: mutatedPolicyInput,
        ActionIdentity: AgentControl.ActionIdentity(originalPolicyInput));
}

static InterventionPointResult NestedOutputTransformResult()
{
    var policyInput = JsonSerializer.SerializeToElement(new Dictionary<string, object?>
    {
        ["policy_target"] = new Dictionary<string, object?> { ["path"] = "$.output.raw" },
    });
    return new InterventionPointResult(
        new Verdict(Decision.Transform, Transform: new Transform("$policy_target", "token [REDACTED]")),
        JsonSerializer.SerializeToElement("token [REDACTED]"),
        policyInput,
        AgentControl.ActionIdentity(policyInput),
        true);
}

static InterventionPointResult Result(Decision decision, object? transformedPolicyTarget = null)
{
    // AGT D1 fixes the only decision that may rewrite the policy target to
    // Transform. Producing a (Allow|Warn|Deny|Escalate, transformedPolicyTarget!=null)
    // result is a test-authoring mistake that would mask regressions in the
    // host gating helper, so refuse the combination here.
    if (transformedPolicyTarget is not null && decision != Decision.Transform)
    {
        throw new ArgumentException(
            $"Result(decision={decision}, transformedPolicyTarget!=null) violates AGT D1; only Transform may carry a policy-target rewrite.",
            nameof(transformedPolicyTarget));
    }

    return new(
        new Verdict(
            decision,
            // AGT D1.1: Transform decisions MUST carry the `transform` payload.
            // We synthesize a $policy_target replacement here so simulated
            // transforms match the wire shape the FFI surfaces.
            Transform: decision == Decision.Transform && transformedPolicyTarget is not null
                ? new Transform("$policy_target", transformedPolicyTarget)
                : null),
        transformedPolicyTarget is null ? null : JsonSerializer.SerializeToElement(transformedPolicyTarget),
        TransformedPolicyTargetApplied: transformedPolicyTarget is not null);
}

file sealed record McpToolArgs(string Text);

file sealed record ShapeOutput(string Raw, Dictionary<string, string> Metadata);

file sealed class EchoChatClient : IAgentControlChatClient<string, string>
{
    public ValueTask<string> GetResponseAsync(
        string request,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(request);
}

file sealed class RecordingChatClient : IAgentControlChatClient<string, string>
{
    public List<string> Calls { get; } = [];

    public ValueTask<string> GetResponseAsync(
        string request,
        IReadOnlyDictionary<string, object?>? snapshot = null,
        CancellationToken cancellationToken = default)
    {
        Calls.Add(request);
        return ValueTask.FromResult($"echo:{request}");
    }
}

file sealed class FakeAutoGenAgent : IAgent
{
    private readonly IMessage reply;

    public FakeAutoGenAgent(IMessage reply)
    {
        this.reply = reply;
    }

    public string Name => "fake-autogen";

    public Task<IMessage> GenerateReplyAsync(
        IEnumerable<IMessage> messages,
        GenerateReplyOptions? options = null,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(reply);
}

file sealed class FunctionContext<TArgs, TOutput> : IAgentControlFunctionInvocationContext<TArgs, TOutput>
{
    public FunctionContext(string functionName, TArgs arguments, string? toolCallId = null)
    {
        FunctionName = functionName;
        Arguments = arguments;
        ToolCallId = toolCallId;
    }

    public string FunctionName { get; }

    public TArgs Arguments { get; set; }

    public TOutput? Result { get; set; }

    public string? ToolCallId { get; }

    public IReadOnlyDictionary<string, object?>? Snapshot => null;
}

file sealed class AgentInvocationContext<TInput, TOutput> : IAgentControlAgentInvocationContext<TInput, TOutput>
{
    public AgentInvocationContext(TInput input)
    {
        Input = input;
    }

    public TInput Input { get; set; }

    public TOutput? Output { get; set; }

    public IReadOnlyDictionary<string, object?>? Snapshot => null;
}

file sealed class DelegateRuntime : IAgentControlRuntime
{
    private readonly Func<InterventionPointRequest, InterventionPointResult> evaluate;

    public DelegateRuntime(Func<InterventionPointRequest, InterventionPointResult> evaluate)
    {
        this.evaluate = evaluate;
    }

    public ValueTask<InterventionPointResult> EvaluateInterventionPointAsync(
        InterventionPointRequest request,
        CancellationToken cancellationToken = default)
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

file sealed class ClassifierAnnotator : IAnnotatorDispatcher
{
    public async ValueTask<JsonElement> DispatchAsync(
        string annotatorName,
        JsonElement annotatorConfig,
        JsonElement preliminaryPolicyInput,
        CancellationToken cancellationToken = default)
    {
        await Task.Yield();
        var text = preliminaryPolicyInput
            .GetProperty("policy_target")
            .GetProperty("value")
            .GetProperty("text")
            .GetString() ?? string.Empty;
        return JsonSerializer.SerializeToElement(new
        {
            annotator = annotatorName,
            contains_account_number = text.Contains("1234", StringComparison.Ordinal),
        });
    }
}

file sealed class ThrowingAnnotator : IAnnotatorDispatcher
{
    public ValueTask<JsonElement> DispatchAsync(
        string annotatorName,
        JsonElement annotatorConfig,
        JsonElement preliminaryPolicyInput,
        CancellationToken cancellationToken = default) =>
        throw new InvalidOperationException("annotator failed");
}

file sealed class ParityAnnotator : IAnnotatorDispatcher
{
    private readonly JsonElement caseElement;

    public ParityAnnotator(JsonElement caseElement)
    {
        this.caseElement = caseElement;
    }

    public ValueTask<JsonElement> DispatchAsync(
        string annotatorName,
        JsonElement annotatorConfig,
        JsonElement preliminaryPolicyInput,
        CancellationToken cancellationToken = default)
    {
        if (caseElement.TryGetProperty("annotator_behavior", out var behavior))
        {
            if (behavior.GetString() == "timeout")
            {
                throw new TimeoutException("runtime_error:annotation_timeout");
            }

            if (behavior.GetString() == "error")
            {
                throw new InvalidOperationException("annotation failed");
            }
        }

        return ValueTask.FromResult(JsonSerializer.SerializeToElement(new { ok = true }));
    }
}

file sealed class ParityPolicy : IPolicyDispatcher
{
    private readonly JsonElement caseElement;

    public ParityPolicy(JsonElement caseElement)
    {
        this.caseElement = caseElement;
    }

    public ValueTask<JsonElement> EvaluateAsync(
        JsonElement preparedInvocation,
        CancellationToken cancellationToken = default)
    {
        if (caseElement.TryGetProperty("policy_behavior", out var behavior) && behavior.GetString() == "error")
        {
            throw new InvalidOperationException("policy failed");
        }

        if (caseElement.TryGetProperty("policy_response", out var response))
        {
            return ValueTask.FromResult(response.Clone());
        }

        return ValueTask.FromResult(JsonSerializer.SerializeToElement(new { decision = "allow" }));
    }
}

file sealed class CustomPolicy : IPolicyDispatcher
{
    public ValueTask<JsonElement> EvaluateAsync(
        JsonElement preparedInvocation,
        CancellationToken cancellationToken = default)
    {
        var input = preparedInvocation.GetProperty("input");
        var containsAccountNumber = input
            .GetProperty("annotations")
            .GetProperty("prompt_classifier")
            .GetProperty("contains_account_number")
            .GetBoolean();
        if (containsAccountNumber)
        {
            // AGT D1.1: redaction now flows through a Transform verdict
            // instead of the removed `warn` + effects[] pattern.
            return ValueTask.FromResult(JsonSerializer.SerializeToElement(new
            {
                decision = "transform",
                reason = "account_number_redacted",
                message = "Account number was redacted before continuing.",
                transform = new
                {
                    path = "$policy_target.text",
                    value = "Please summarize account [REDACTED].",
                },
            }));
        }

        return ValueTask.FromResult(JsonSerializer.SerializeToElement(new
        {
            decision = "allow",
        }));
    }
}

file sealed class LabelingPolicy : IPolicyDispatcher
{
    public ValueTask<JsonElement> EvaluateAsync(
        JsonElement preparedInvocation,
        CancellationToken cancellationToken = default)
    {
        return ValueTask.FromResult(JsonSerializer.SerializeToElement(new
        {
            decision = "allow",
            result_labels = new[] { "confidential" },
        }));
    }
}

file sealed class NullTransformPolicy : IPolicyDispatcher
{
    public ValueTask<JsonElement> EvaluateAsync(
        JsonElement preparedInvocation,
        CancellationToken cancellationToken = default)
    {
        var interventionPoint = preparedInvocation
            .GetProperty("input")
            .GetProperty("intervention_point")
            .GetString();
        if (interventionPoint != "input")
        {
            return ValueTask.FromResult(JsonSerializer.SerializeToElement(new
            {
                decision = "allow",
            }));
        }

        return ValueTask.FromResult(JsonSerializer.SerializeToElement(new
        {
            decision = "transform",
            transform = new
            {
                path = "$policy_target",
                value = (object?)null,
            },
        }));
    }
}

file sealed class EscalatingPolicy : IPolicyDispatcher
{
    public ValueTask<JsonElement> EvaluateAsync(
        JsonElement preparedInvocation,
        CancellationToken cancellationToken = default)
    {
        return ValueTask.FromResult(JsonSerializer.SerializeToElement(new
        {
            decision = "escalate",
        }));
    }
}