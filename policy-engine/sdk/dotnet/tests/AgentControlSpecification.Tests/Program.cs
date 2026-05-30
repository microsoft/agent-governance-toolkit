using System.Text.Json;
using System.Text.RegularExpressions;
using AgentControlSpecification;

const string BasicHostManifest = """
agent_control_specification_version: 0.3.0-alpha
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

AssertEqual(Decision.Warn, result.Verdict.Decision, "input policy should warn.");
Assert(result.TransformedPolicyTarget.HasValue, "warn verdict should include a transformed policy target.");
var transformedPolicyTarget = result.TransformedPolicyTarget!.Value;
AssertEqual(
    "Please summarize account [REDACTED].",
    transformedPolicyTarget.GetProperty("text").GetString(),
    "account number should be redacted.");

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

var allowMcp = new AgentControlMcpToolProvider<McpToolArgs, string>(
    AllowingToolControl(),
    (args, _) => ValueTask.FromResult($"echo:{args.Text}"));
var allowMcpResult = await allowMcp.CallToolAsync("echo", new McpToolArgs("hello"), "call-allow");
AssertEqual("echo:hello", allowMcpResult.Value, "MCP adapter should return the tool result.");

McpToolArgs? receivedArgs = null;
var transformingMcp = new AgentControlMcpToolProvider<McpToolArgs, string>(
    new AgentControl(new DelegateRuntime(request =>
        request.InterventionPoint == InterventionPoint.PreToolCall
            ? Result(Decision.Allow, new McpToolArgs("redacted"))
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

var requiredIdMcp = new AgentControlMcpToolProvider<McpToolArgs, string>(
    new AgentControl(new DelegateRuntime(_ => Result(Decision.Allow))),
    (_, _) => ValueTask.FromResult("ok"));
try
{
    await requiredIdMcp.CallToolAsync("echo", new McpToolArgs("no-id"));
    throw new InvalidOperationException("MCP adapter should require a caller-supplied tool_call_id.");
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

var allowEffectsControl = new AgentControl(
    new DelegateRuntime(request =>
        request.InterventionPoint == InterventionPoint.Input
            ? Result(Decision.Escalate, "REDACTED")
            : Result(Decision.Allow)),
    AllowApproval());
var allowRun = await allowEffectsControl.RunAsync<string, string>("original", (input, _) => ValueTask.FromResult(input));
AssertEqual("REDACTED", allowRun.Value, "escalate-allow should apply escalate effects after approval.");


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
    Assert(
        ex.InnerException is InvalidOperationException { Message: "resolver boom" },
        "a resolver failure should preserve the cause.");
}

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
        ? Result(Decision.Allow, "safe")
        : Result(Decision.Allow, "checked"))));
var mediatedChatResult = await mediatedChat.GetResponseAsync("raw");
AssertEqual("checked", mediatedChatResult, "chat client should return the transformed model response.");
AssertEqual("safe", mediatedChatInner.Calls.Single(), "chat client should pass transformed request to inner.");

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
            ? Result(Decision.Allow, new McpToolArgs("safe"))
            : Result(Decision.Allow, "checked"))));
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
            ? Result(Decision.Allow, "safe")
            : Result(Decision.Allow, "checked"))));
await allowedAutoGen.InvokeAsync(allowedAutoGenContext, (context, _) =>
{
    context.Output = context.Input;
    return ValueTask.CompletedTask;
});
AssertEqual("safe", allowedAutoGenContext.Input, "AutoGen middleware should pass transformed input to next.");
AssertEqual("checked", allowedAutoGenContext.Output, "AutoGen middleware should apply output transform.");

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
            ? Result(Decision.Allow, new McpToolArgs("safe"))
            : Result(Decision.Allow, "checked"))));
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
            ? Result(Decision.Allow, "safe")
            : Result(Decision.Allow, "checked"))));
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
agent_control_specification_version: 0.3.0-alpha
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
AssertEqual(Decision.Warn, chainResult.Verdict.Decision, "manifest chain with perf telemetry should warn.");

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

await PaymentEscalationHarness.RunAsync();
await StreamingHarness.RunAsync();

Console.WriteLine("AgentControlSpecification native round-trip test passed.");
Console.WriteLine("AgentControlSpecification callback exception-safety test passed.");
Console.WriteLine("AgentControlSpecification MCP allow path test passed.");
Console.WriteLine("AgentControlSpecification MCP pre-tool transform test passed.");
Console.WriteLine("AgentControlSpecification MCP pre-tool deny test passed.");
Console.WriteLine("AgentControlSpecification MCP required tool_call_id test passed.");
Console.WriteLine("AgentControlSpecification MCP inner exception propagation test passed.");
Console.WriteLine("AgentControlSpecification escalation seam conformance tests passed.");
Console.WriteLine("AgentControlSpecification payment escalation use-case tests passed.");
Console.WriteLine("AgentControlSpecification adapter approval-resolver parity tests passed.");
Console.WriteLine("AgentControlSpecification fail-closed error parity tests passed.");
Console.WriteLine("AgentControlSpecification zero-config FromPath test passed.");
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
        new Verdict(Decision.Escalate, Effects: Array.Empty<JsonElement>()),
        PolicyInput: mutatedPolicyInput,
        ActionIdentity: AgentControl.ActionIdentity(originalPolicyInput));
}

static InterventionPointResult Result(Decision decision, object? transformedPolicyTarget = null) =>
    new(
        new Verdict(decision, Effects: Array.Empty<JsonElement>()),
        transformedPolicyTarget is null ? null : JsonSerializer.SerializeToElement(transformedPolicyTarget));

file sealed record McpToolArgs(string Text);

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
            return ValueTask.FromResult(JsonSerializer.SerializeToElement(new
            {
                decision = "warn",
                reason = "account_number_redacted",
                message = "Account number was redacted before continuing.",
                effects = new object[]
                {
                    new
                    {
                        type = "replace",
                        path = "$policy_target.text",
                        value = "Please summarize account [REDACTED].",
                    },
                },
            }));
        }

        return ValueTask.FromResult(JsonSerializer.SerializeToElement(new
        {
            decision = "allow",
            effects = Array.Empty<object>(),
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