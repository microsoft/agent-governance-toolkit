using System.Text.Json;
using AgentControlSpecification;

internal static class PaymentEscalationHarness
{
    public static async Task RunAsync()
    {
        var staleApproval = string.Empty;
        var approvedToolArgs = new List<PaymentArgs>();
        var approveControl = new AgentControl(new PaymentRuntime(), (_, result, _) =>
        {
            staleApproval = result.ActionIdentity ?? string.Empty;
            return ValueTask.FromResult(ApprovalResolution.Allow(result.ActionIdentity!));
        });
        // AGT D1: an escalate carries no transform per §13.1. After approval
        // the host proceeds with the original tool args, so the memo flows
        // through unmodified. A separate Transform-verdict policy would be
        // needed to scrub the memo before the action executes.
        var approved = await approveControl.RunToolAsync<PaymentArgs, PaymentReceipt>(
            "wire_transfer",
            new PaymentArgs(25_000, "acct-1", "payroll secret"),
            (args, _) =>
            {
                approvedToolArgs.Add(args);
                return ValueTask.FromResult(new PaymentReceipt(args.Amount, args.Beneficiary, args.Memo));
            },
            "wire-approve");
        Equal(25_000, approved.Value.Amount, "approved payment should execute.");
        Equal("payroll secret", approved.Value.Memo, "approved payment should keep the original target after escalation approval.");
        Equal(1, approvedToolArgs.Count, "approved payment should execute once.");
        Equal("payroll secret", approvedToolArgs.Single().Memo, "approved escalate should not apply a transform.");

        var rejectExecuted = false;
        var rejectControl = new AgentControl(new PaymentRuntime(), (_, _, _) => ValueTask.FromResult(ApprovalResolution.Deny()));
        try
        {
            await rejectControl.RunToolAsync<PaymentArgs, PaymentReceipt>(
                "wire_transfer",
                new PaymentArgs(30_000, "acct-2", "reject secret"),
                (args, _) =>
                {
                    rejectExecuted = true;
                    return ValueTask.FromResult(new PaymentReceipt(args.Amount, args.Beneficiary, args.Memo));
                },
                "wire-reject");
            throw new InvalidOperationException("rejected payment should block.");
        }
        catch (AgentControlBlockedException ex)
        {
            Equal(InterventionPoint.PreToolCall, ex.InterventionPoint, "rejected payment should block before execution.");
            Equal("large_transfer", ex.Result.Verdict.Reason, "rejected payment should preserve the policy reason.");
        }
        IsFalse(rejectExecuted, "rejected payment should not execute.");

        var replayControl = new AgentControl(new PaymentRuntime(), (_, _, _) => ValueTask.FromResult(ApprovalResolution.Allow(staleApproval)));
        try
        {
            await replayControl.RunToolAsync<PaymentArgs, PaymentReceipt>(
                "wire_transfer",
                new PaymentArgs(25_001, "acct-1", "payroll secret"),
                (args, _) => ValueTask.FromResult(new PaymentReceipt(args.Amount, args.Beneficiary, args.Memo)),
                "wire-replay");
            throw new InvalidOperationException("stale approval should block.");
        }
        catch (AgentControlBlockedException ex)
        {
            Equal("runtime_error:approval_action_mismatch", ex.Result.Verdict.Reason, "stale approval should fail closed.");
        }

        var firstIdentity = PaymentRuntime.IdentityFor(new PaymentArgs(40_000, "acct-3", "memo"), "stable", PropertyOrder.AmountFirst);
        var secondIdentity = PaymentRuntime.IdentityFor(new PaymentArgs(40_000, "acct-3", "memo"), "stable", PropertyOrder.BeneficiaryFirst);
        var stringAmountIdentity = PaymentRuntime.IdentityForStringAmount("40000", "acct-3", "memo", "stable");
        var mutatedIdentity = PaymentRuntime.IdentityFor(new PaymentArgs(40_001, "acct-3", "memo"), "stable", PropertyOrder.AmountFirst);
        Equal(firstIdentity, secondIdentity, "semantic equals with different key order should keep the identity stable.");
        NotEqual(firstIdentity, stringAmountIdentity, "numeric and string amounts should use different identities.");
        NotEqual(firstIdentity, mutatedIdentity, "semantic mutation should change the identity.");

        var resolverCalls = 0;
        var concurrentControl = new AgentControl(new PaymentRuntime(), async (_, result, _) =>
        {
            Interlocked.Increment(ref resolverCalls);
            await Task.Yield();
            return ApprovalResolution.Allow(result.ActionIdentity!);
        });
        var concurrent = await Task.WhenAll(
            concurrentControl.RunToolAsync<PaymentArgs, PaymentReceipt>("wire_transfer", new PaymentArgs(50_000, "acct-4", "one"), (args, _) => ValueTask.FromResult(new PaymentReceipt(args.Amount, args.Beneficiary, args.Memo)), "wire-c1").AsTask(),
            concurrentControl.RunToolAsync<PaymentArgs, PaymentReceipt>("wire_transfer", new PaymentArgs(60_000, "acct-5", "two"), (args, _) => ValueTask.FromResult(new PaymentReceipt(args.Amount, args.Beneficiary, args.Memo)), "wire-c2").AsTask());
        Equal(2, resolverCalls, "concurrent escalations should resolve independently.");
        Equal(50_000, concurrent[0].Value.Amount, "first concurrent payment should execute.");
        Equal(60_000, concurrent[1].Value.Amount, "second concurrent payment should execute.");

        await ExpectResolverFailureAsync((_, _, _) => throw new InvalidOperationException("human approval service failed"));
        await ExpectResolverFailureAsync((_, _, _) => ValueTask.FromResult<ApprovalResolution>(null!));
    }

    private static async Task ExpectResolverFailureAsync(ApprovalResolver resolver)
    {
        var control = new AgentControl(new PaymentRuntime(), resolver);
        try
        {
            await control.RunToolAsync<PaymentArgs, PaymentReceipt>(
                "wire_transfer",
                new PaymentArgs(70_000, "acct-6", "failure"),
                (args, _) => ValueTask.FromResult(new PaymentReceipt(args.Amount, args.Beneficiary, args.Memo)),
                Guid.NewGuid().ToString("N"));
            throw new InvalidOperationException("resolver failure should block.");
        }
        catch (AgentControlBlockedException ex)
        {
            Equal("runtime_error:approval_resolver_failed", ex.Result.Verdict.Reason, "resolver failure should use the reserved reason.");
        }
    }

    private static void Equal<T>(T expected, T actual, string message)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"{message} Expected '{expected}', got '{actual}'.");
        }
    }

    private static void NotEqual<T>(T left, T right, string message)
    {
        if (EqualityComparer<T>.Default.Equals(left, right))
        {
            throw new InvalidOperationException(message);
        }
    }

    private static void IsFalse(bool condition, string message)
    {
        if (condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}

internal sealed class PaymentRuntime : IAgentControlRuntime
{
    public ValueTask<InterventionPointResult> EvaluateInterventionPointAsync(
        InterventionPointRequest request,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (request.InterventionPoint != InterventionPoint.PreToolCall)
        {
            return ValueTask.FromResult(WithIdentity(request, new Verdict(Decision.Allow)));
        }

        var toolCall = request.Snapshot.GetProperty("tool_call");
        if (toolCall.GetProperty("name").GetString() != "wire_transfer")
        {
            return ValueTask.FromResult(WithIdentity(request, new Verdict(Decision.Allow)));
        }

        var args = toolCall.GetProperty("args").Deserialize<PaymentArgs>(new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
        if (args.Amount < 10_000)
        {
            return ValueTask.FromResult(WithIdentity(request, new Verdict(Decision.Allow)));
        }

        // AGT D1: escalate carries no transform per §13.1. The host's approval
        // path consents to the action as-submitted; any redaction would need
        // to come from a separate Transform verdict.
        return ValueTask.FromResult(WithIdentity(
            request,
            new Verdict(Decision.Escalate, Reason: "large_transfer")));
    }

    public static string IdentityFor(PaymentArgs args, string callId, PropertyOrder order)
    {
        var snapshot = order == PropertyOrder.AmountFirst
            ? JsonSerializer.SerializeToElement(new { tool_call = new { id = callId, name = "wire_transfer", args = new { amount = args.Amount, beneficiary = args.Beneficiary, memo = args.Memo } } })
            : JsonSerializer.SerializeToElement(new { tool_call = new { name = "wire_transfer", args = new { beneficiary = args.Beneficiary, memo = args.Memo, amount = args.Amount }, id = callId } });
        var request = new InterventionPointRequest(InterventionPoint.PreToolCall, snapshot);
        return AgentControl.ActionIdentity(PolicyInput(request));
    }

    public static string IdentityForStringAmount(string amount, string beneficiary, string memo, string callId)
    {
        var snapshot = JsonSerializer.SerializeToElement(new { tool_call = new { id = callId, name = "wire_transfer", args = new { amount, beneficiary, memo } } });
        var request = new InterventionPointRequest(InterventionPoint.PreToolCall, snapshot);
        return AgentControl.ActionIdentity(PolicyInput(request));
    }

    private static InterventionPointResult WithIdentity(InterventionPointRequest request, Verdict verdict, object? transformed = null)
    {
        var policyInput = PolicyInput(request);
        return new InterventionPointResult(
            verdict,
            transformed is null ? null : JsonSerializer.SerializeToElement(transformed),
            policyInput,
            AgentControl.ActionIdentity(policyInput));
    }

    private static JsonElement PolicyInput(InterventionPointRequest request) =>
        JsonSerializer.SerializeToElement(new Dictionary<string, object?>
        {
            ["intervention_point"] = request.InterventionPoint.ToWireName(),
            ["snapshot"] = request.Snapshot,
        });
}

internal enum PropertyOrder
{
    AmountFirst,
    BeneficiaryFirst,
}

internal sealed record PaymentArgs(int Amount, string Beneficiary, string Memo);

internal sealed record PaymentReceipt(int Amount, string Beneficiary, string Memo);
