// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Net;
using System.Text;
using System.Text.Json;
using AgentGovernance.Approvals;
using AgentGovernance.Policy;
using Xunit;

namespace AgentGovernance.Tests;

public sealed class ApprovalProtocolTests
{
    [Fact]
    public void Canonicalize_SortsKeysAndDoesNotEscapeHtml()
    {
        var value = new Dictionary<string, object?>
        {
            ["b"] = "<&>",
            ["a"] = 1
        };

        var canonical = Encoding.UTF8.GetString(ApprovalDigest.Canonicalize(value));

        Assert.Equal("{\"a\":1,\"b\":\"<&>\"}", canonical);
    }

    [Fact]
    public void ActionBinding_DigestIsStableAndActionSensitive()
    {
        var first = Binding(new Dictionary<string, object?> { ["amount"] = 42, ["currency"] = "EUR" });
        var reordered = Binding(new Dictionary<string, object?> { ["currency"] = "EUR", ["amount"] = 42 });
        var changed = Binding(new Dictionary<string, object?> { ["amount"] = 43, ["currency"] = "EUR" });

        Assert.Equal(first.Digest(), reordered.Digest());
        Assert.NotEqual(first.Digest(), changed.Digest());
        Assert.StartsWith("sha256:", first.Digest(), StringComparison.Ordinal);
    }

    [Fact]
    public void OpenRequest_RejectsMalformedBinding()
    {
        var coordinator = Coordinator(Chain(Stage(0, "alice")));
        var binding = Binding() with { Operation = " " };

        Assert.Throws<ApprovalProtocolException>(() => coordinator.OpenRequest(binding));
    }

    [Fact]
    public void OpenRequest_RoutesRequireApprovalPolicyDecision()
    {
        var coordinator = Coordinator(Chain(Stage(0, "alice")));
        var decision = new PolicyDecision
        {
            Allowed = false,
            Action = "requireapproval",
            MatchedRule = "production-write",
            Reason = "approval required"
        };

        var result = coordinator.OpenRequest(decision, Binding());

        Assert.Equal("production-write", result.PolicyDecision.PolicyRuleId);
        Assert.Equal(PolicyAction.RequireApproval, result.PolicyDecision.Verdict);
        Assert.Equal(ApprovalStatus.Pending, result.Request.Status);
    }

    [Fact]
    public void OpenRequest_RejectsNonApprovalPolicyDecision()
    {
        var coordinator = Coordinator(Chain(Stage(0, "alice")));
        var decision = new PolicyDecision
        {
            Allowed = true,
            Action = "allow",
            Reason = "allowed"
        };

        Assert.Throws<ApprovalProtocolException>(() => coordinator.OpenRequest(decision, Binding()));
    }

    [Fact]
    public void SubmitEntry_AllowsOnlyAfterEveryRequiredStage()
    {
        var coordinator = Coordinator(Chain(Stage(0, "alice"), Stage(1, "bob")));
        var opened = coordinator.OpenRequest(Binding());

        var afterFirst = coordinator.SubmitEntry(opened.Request.ApprovalRequestId, 0, Vote("alice"));
        Assert.Null(afterFirst.Resolution);
        Assert.Equal(ApprovalStatus.Pending, afterFirst.Request.Status);

        var afterSecond = coordinator.SubmitEntry(opened.Request.ApprovalRequestId, 1, Vote("bob"));
        Assert.Equal(ApprovalOutcome.Allow, afterSecond.Resolution?.Outcome);
        Assert.Equal(ApprovalStatus.Allowed, afterSecond.Request.Status);
    }

    [Fact]
    public void SubmitEntry_DenyShortCircuitsChain()
    {
        var coordinator = Coordinator(Chain(Stage(0, "alice"), Stage(1, "bob")));
        var opened = coordinator.OpenRequest(Binding());

        var result = coordinator.SubmitEntry(
            opened.Request.ApprovalRequestId,
            0,
            Vote("alice", ApprovalEntryDecision.Deny, "risk_rejected"));

        Assert.Equal(ApprovalOutcome.Deny, result.Resolution?.Outcome);
        Assert.Equal("risk_rejected", result.Resolution?.ReasonCode);
        Assert.Equal(ApprovalStatus.Denied, result.Request.Status);
    }

    [Fact]
    public void SubmitEntry_LlmAdvisoryCannotAllowOrDeny()
    {
        var advisory = Stage(0, "model") with { ApproverKind = ApproverKind.LlmAdvisory };
        var coordinator = Coordinator(Chain(advisory, Stage(1, "alice")));
        var opened = coordinator.OpenRequest(Binding());

        var afterAdvisory = coordinator.SubmitEntry(
            opened.Request.ApprovalRequestId,
            0,
            Vote("model", ApprovalEntryDecision.Deny) with { ApproverKind = ApproverKind.LlmAdvisory });

        Assert.Null(afterAdvisory.Resolution);
        Assert.Equal(ApprovalStatus.Pending, afterAdvisory.Request.Status);

        var allowed = coordinator.SubmitEntry(opened.Request.ApprovalRequestId, 1, Vote("alice"));
        Assert.Equal(ApprovalOutcome.Allow, allowed.Resolution?.Outcome);
    }

    [Fact]
    public async Task ResolveAsync_NoRequiredNonAdvisoryStageFailsClosed()
    {
        var advisory = Stage(0, "model") with
        {
            ApproverKind = ApproverKind.LlmAdvisory,
            Transport = new DelegateTransport((_, _) => Task.FromResult(
                Vote("model") with { ApproverKind = ApproverKind.LlmAdvisory }))
        };
        var coordinator = Coordinator(Chain(advisory));

        var result = await coordinator.ResolveAsync(Binding());

        Assert.Equal(ApprovalOutcome.Deny, result.Resolution?.Outcome);
        Assert.Equal(ApprovalReasonCodes.NoRequiredStage, result.Resolution?.ReasonCode);
        Assert.False(result.Execution?.Allowed ?? false);
    }

    [Theory]
    [InlineData(ApprovalEntryDecision.Allow)]
    [InlineData(ApprovalEntryDecision.Deny)]
    public void SubmitEntry_UnauthorizedDecisionLeavesRequestPending(ApprovalEntryDecision decision)
    {
        var coordinator = Coordinator(Chain(Stage(0, "alice")));
        var opened = coordinator.OpenRequest(Binding());

        Assert.Throws<ApprovalProtocolException>(() => coordinator.SubmitEntry(
            opened.Request.ApprovalRequestId,
            0,
            Vote("mallory", decision)));

        Assert.Equal(ApprovalStatus.Pending, coordinator.GetResult(opened.Request.ApprovalRequestId).Request.Status);
        Assert.Empty(coordinator.GetResult(opened.Request.ApprovalRequestId).Entries);
    }

    [Fact]
    public void SubmitEntry_CallerIdIsIdempotentBeforeAndAfterResolution()
    {
        var coordinator = Coordinator(Chain(Stage(0, "alice"), Stage(1, "bob")));
        var opened = coordinator.OpenRequest(Binding());
        var vote = Vote("alice") with { ChainEntryId = "ace_retry" };

        coordinator.SubmitEntry(opened.Request.ApprovalRequestId, 0, vote);
        var retriedPending = coordinator.SubmitEntry(opened.Request.ApprovalRequestId, 0, vote);
        Assert.Single(retriedPending.Entries);

        coordinator.SubmitEntry(opened.Request.ApprovalRequestId, 1, Vote("bob"));
        var retriedResolved = coordinator.SubmitEntry(opened.Request.ApprovalRequestId, 0, vote);
        Assert.Equal(2, retriedResolved.Entries.Count);
        Assert.Equal(ApprovalStatus.Allowed, retriedResolved.Request.Status);
    }

    [Fact]
    public void SubmitEntry_RejectsConflictingDecisionForSatisfiedStage()
    {
        var coordinator = Coordinator(Chain(Stage(0, "alice"), Stage(1, "bob")));
        var opened = coordinator.OpenRequest(Binding());
        coordinator.SubmitEntry(opened.Request.ApprovalRequestId, 0, Vote("alice"));

        Assert.Throws<ApprovalProtocolException>(() => coordinator.SubmitEntry(
            opened.Request.ApprovalRequestId,
            0,
            Vote("alice", ApprovalEntryDecision.Deny)));
    }

    [Fact]
    public void ValidateForExecution_BindsActionAndConsumesOnce()
    {
        var binding = Binding();
        var coordinator = Coordinator(Chain(Stage(0, "alice")));
        var opened = coordinator.OpenRequest(binding);
        coordinator.SubmitEntry(opened.Request.ApprovalRequestId, 0, Vote("alice"));

        var mismatch = coordinator.ValidateForExecution(
            opened.Request.ApprovalRequestId,
            binding with { Parameters = new Dictionary<string, object?> { ["amount"] = 99 } });
        var allowed = coordinator.ValidateForExecution(opened.Request.ApprovalRequestId, binding);
        var replay = coordinator.ValidateForExecution(opened.Request.ApprovalRequestId, binding);

        Assert.False(mismatch.Allowed);
        Assert.Equal(ApprovalReasonCodes.ActionDigestMismatch, mismatch.ReasonCode);
        Assert.True(allowed.Allowed);
        Assert.True(allowed.Consumed);
        Assert.False(replay.Allowed);
        Assert.Equal(ApprovalReasonCodes.Consumed, replay.ReasonCode);
    }

    [Fact]
    public void ValidateForExecution_RejectsPolicyAndChainVersionChanges()
    {
        var store = new InMemoryApprovalStore();
        var binding = Binding();
        var original = Coordinator(Chain(Stage(0, "alice")), store: store, policyVersion: "policy-v1");
        var opened = original.OpenRequest(binding);
        original.SubmitEntry(opened.Request.ApprovalRequestId, 0, Vote("alice"));

        var changedPolicy = Coordinator(Chain(Stage(0, "alice")), store: store, policyVersion: "policy-v2");
        var policyDecision = changedPolicy.CheckForExecution(opened.Request.ApprovalRequestId, binding);

        var changedChain = Coordinator(
            Chain(Stage(0, "alice")) with { Version = "chain-v2" },
            store: store,
            policyVersion: "policy-v1");
        var chainDecision = changedChain.CheckForExecution(opened.Request.ApprovalRequestId, binding);

        Assert.Equal(ApprovalReasonCodes.PolicyVersionMismatch, policyDecision.ReasonCode);
        Assert.Equal(ApprovalReasonCodes.ChainVersionMismatch, chainDecision.ReasonCode);
    }

    [Fact]
    public void ValidateForExecution_DetectsAppendedTamperEntry()
    {
        var store = new InMemoryApprovalStore();
        var binding = Binding();
        var coordinator = Coordinator(Chain(Stage(0, "alice")), store: store);
        var opened = coordinator.OpenRequest(binding);
        var allowed = coordinator.SubmitEntry(opened.Request.ApprovalRequestId, 0, Vote("alice"));
        var last = Assert.Single(allowed.Entries);
        store.AppendEntry(new ApprovalChainEntry
        {
            ApprovalRequestId = opened.Request.ApprovalRequestId,
            StageIndex = 0,
            ApproverKind = ApproverKind.LlmAdvisory,
            ApproverIdentity = "model",
            IdentityAssurance = "advisory",
            Decision = ApprovalEntryDecision.Allow,
            InputDigest = opened.Request.InputDigest(),
            PreviousEntryDigest = last.EntryDigest
        }.Seal());

        var decision = coordinator.CheckForExecution(opened.Request.ApprovalRequestId, binding);

        Assert.False(decision.Allowed);
        Assert.Equal(ApprovalReasonCodes.ChainTampered, decision.ReasonCode);
    }

    [Fact]
    public void ValidateForExecution_ConcurrentConsumeAllowsExactlyOnce()
    {
        var binding = Binding();
        var coordinator = Coordinator(Chain(Stage(0, "alice")));
        var opened = coordinator.OpenRequest(binding);
        coordinator.SubmitEntry(opened.Request.ApprovalRequestId, 0, Vote("alice"));
        var decisions = new ApprovalExecutionDecision[24];

        Parallel.For(0, decisions.Length, index =>
        {
            decisions[index] = coordinator.ValidateForExecution(opened.Request.ApprovalRequestId, binding);
        });

        Assert.Single(decisions, decision => decision.Allowed);
        Assert.Equal(23, decisions.Count(decision => decision.ReasonCode == ApprovalReasonCodes.Consumed));
    }

    [Fact]
    public void ValidateForExecution_ApprovalExpiresAfterAllow()
    {
        var now = DateTimeOffset.Parse("2026-07-17T12:00:00Z");
        var coordinator = Coordinator(
            Chain(Stage(0, "alice")),
            clock: () => now,
            ttl: TimeSpan.FromMinutes(1));
        var binding = Binding();
        var opened = coordinator.OpenRequest(binding);
        coordinator.SubmitEntry(opened.Request.ApprovalRequestId, 0, Vote("alice"));
        now = now.AddMinutes(2);

        var decision = coordinator.ValidateForExecution(opened.Request.ApprovalRequestId, binding);

        Assert.False(decision.Allowed);
        Assert.Equal(ApprovalReasonCodes.Expired, decision.ReasonCode);
    }

    [Fact]
    public void CancelRequest_IsTerminalAndCannotExecute()
    {
        var binding = Binding();
        var coordinator = Coordinator(Chain(Stage(0, "alice")));
        var opened = coordinator.OpenRequest(binding);

        var cancelled = coordinator.CancelRequest(opened.Request.ApprovalRequestId, "operator_cancelled");
        var decision = coordinator.ValidateForExecution(opened.Request.ApprovalRequestId, binding);

        Assert.Equal(ApprovalOutcome.Cancelled, cancelled.Resolution?.Outcome);
        Assert.Equal(ApprovalStatus.Cancelled, cancelled.Request.Status);
        Assert.Equal(ApprovalReasonCodes.Cancelled, decision.ReasonCode);
    }

    [Fact]
    public void AuditEvents_LinkPolicyRequestEntryResolutionAndConsumption()
    {
        var sink = new InMemoryApprovalAuditSink();
        var binding = Binding();
        var coordinator = Coordinator(Chain(Stage(0, "alice")), auditSink: sink);
        var opened = coordinator.OpenRequest(binding);
        coordinator.SubmitEntry(opened.Request.ApprovalRequestId, 0, Vote("alice"));
        coordinator.ValidateForExecution(opened.Request.ApprovalRequestId, binding);

        var events = sink.GetEvents();
        Assert.Contains(events, item => item.Type == ApprovalAuditEventType.PolicyDecision);
        Assert.Contains(events, item => item.Type == ApprovalAuditEventType.ApprovalRequested);
        Assert.Contains(events, item => item.Type == ApprovalAuditEventType.ApprovalChainEntry);
        Assert.Contains(events, item => item.Type == ApprovalAuditEventType.ApprovalResolved);
        Assert.Contains(events, item => item.Type == ApprovalAuditEventType.ApprovalConsumed);
        Assert.Contains(events, item => item.Type == ApprovalAuditEventType.ExecutionAllowed);
        Assert.All(events, item => Assert.Equal(opened.Request.ApprovalRequestId, item.ApprovalRequestId));
        Assert.All(events, item => Assert.Equal(opened.PolicyDecision.PolicyDecisionId, item.PolicyDecisionId));
    }

    [Fact]
    public async Task ResolveAsync_TimeoutFailsClosedAndRecordsDeny()
    {
        var stage = Stage(0, "alice") with
        {
            Transport = new DelegateTransport(async (_, cancellationToken) =>
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                return Vote("alice");
            })
        };
        var coordinator = Coordinator(Chain(stage), timeout: TimeSpan.FromMilliseconds(20));

        var result = await coordinator.ResolveAsync(Binding());

        Assert.Equal(ApprovalOutcome.Deny, result.Resolution?.Outcome);
        Assert.Equal("approval_timeout", result.Resolution?.ReasonCode);
        Assert.Equal(ApprovalStatus.Denied, result.Request.Status);
    }

    [Fact]
    public async Task ResolveAsync_TransportFailureFailsClosed()
    {
        var stage = Stage(0, "alice") with
        {
            Transport = new DelegateTransport((_, _) =>
                Task.FromException<ApprovalVote>(new HttpRequestException("offline")))
        };
        var coordinator = Coordinator(Chain(stage));

        var result = await coordinator.ResolveAsync(Binding());

        Assert.Equal(ApprovalOutcome.Deny, result.Resolution?.Outcome);
        Assert.Equal("approval_transport_error", result.Resolution?.ReasonCode);
    }

    private static ActionBinding Binding(IReadOnlyDictionary<string, object?>? parameters = null) => new()
    {
        Operation = "tool.invoke",
        AgentId = "did:agent:123",
        SubjectId = "user-456",
        Target = new ActionTarget
        {
            ToolName = "payments.transfer",
            ToolSchemaVersion = "1",
            Resource = "account-42"
        },
        Parameters = parameters ?? new Dictionary<string, object?> { ["amount"] = 42 }
    };

    private static ApprovalStage Stage(int index, string identity) => new()
    {
        StageIndex = index,
        AllowedIdentities = new[] { identity }
    };

    private static ApprovalChain Chain(params ApprovalStage[] stages) => new()
    {
        ChainId = "high-risk-tools",
        Version = "chain-v1",
        Stages = stages
    };

    private static ApprovalVote Vote(
        string identity,
        ApprovalEntryDecision decision = ApprovalEntryDecision.Allow,
        string reason = "reviewed") => new()
        {
            ApproverKind = ApproverKind.Human,
            ApproverIdentity = identity,
            IdentityAssurance = "oidc",
            Decision = decision,
            ReasonCode = reason
        };

    private static ApprovalCoordinator Coordinator(
        ApprovalChain chain,
        IApprovalStore? store = null,
        string policyVersion = "policy-v1",
        Func<DateTimeOffset>? clock = null,
        TimeSpan? ttl = null,
        TimeSpan? timeout = null,
        IApprovalAuditSink? auditSink = null) =>
        new(
            chain,
            store,
            new ApprovalCoordinatorOptions
            {
                PolicyRuleId = "production-write",
                PolicyVersion = policyVersion,
                Clock = clock ?? (() => DateTimeOffset.UtcNow),
                RequestTtl = ttl ?? TimeSpan.FromMinutes(5),
                StageTimeout = timeout ?? TimeSpan.FromMinutes(5),
                AuditSink = auditSink
            });

    private sealed class DelegateTransport : IApprovalTransport
    {
        private readonly Func<ApprovalRequest, CancellationToken, Task<ApprovalVote>> _handler;

        internal DelegateTransport(Func<ApprovalRequest, CancellationToken, Task<ApprovalVote>> handler)
        {
            _handler = handler;
        }

        public Task<ApprovalVote> RequestApprovalAsync(
            ApprovalRequest request,
            CancellationToken cancellationToken = default) =>
            _handler(request, cancellationToken);
    }
}

public sealed class WebhookApproverTests
{
    [Fact]
    public void BuildRequestPayload_CarriesVersionAndActionBinding()
    {
        var request = OpenRequest();

        var payload = WebhookApprover.BuildRequestPayload(request);

        Assert.Equal("1.0", payload["schema_version"]);
        Assert.Equal("approval_request", payload["type"]);
        Assert.Equal(request.ApprovalRequestId, payload["approval_request_id"]);
        Assert.Equal(request.PolicyDecisionId, payload["policy_decision_id"]);
        Assert.Equal(request.ActionDigest, payload["action_digest"]);
        Assert.Equal(request.PolicyVersion, payload["policy_version"]);
        Assert.Equal(request.ApprovalChainVersion, payload["approval_chain_version"]);
        Assert.Equal(request.InputDigest(), payload["input_digest"]);
    }

    [Fact]
    public async Task RequestApprovalAsync_VerifiedApproveReturnsBoundIdentity()
    {
        var request = OpenRequest();
        using var client = ClientFor(request, approved: true);
        using var approver = new WebhookApprover(
            new Uri("https://approvals.example/v1"),
            client,
            responseVerifier: (_, _) => new WebhookVerifiedIdentity
            {
                Identity = "did:web:example.com:alice",
                Assurance = "oidc",
                Roles = new[] { "security" }
            });

        var vote = await approver.RequestApprovalAsync(request);

        Assert.Equal(ApprovalEntryDecision.Allow, vote.Decision);
        Assert.Equal("did:web:example.com:alice", vote.ApproverIdentity);
        Assert.Equal("oidc", vote.IdentityAssurance);
        Assert.Contains("security", vote.Roles);
    }

    [Fact]
    public async Task RequestApprovalAsync_UnverifiedApproveFailsClosed()
    {
        var request = OpenRequest();
        using var client = ClientFor(request, approved: true);
        using var approver = new WebhookApprover(new Uri("https://approvals.example/v1"), client);

        var error = await Assert.ThrowsAsync<ApprovalTransportProtocolException>(
            () => approver.RequestApprovalAsync(request));

        Assert.Equal("unverified_approver_identity", error.ReasonCode);
    }

    [Fact]
    public async Task RequestApprovalAsync_BindingMismatchFailsClosed()
    {
        var request = OpenRequest();
        using var client = new HttpClient(new StubHandler((_, _) => JsonResponse(new
        {
            approval_request_id = request.ApprovalRequestId,
            action_digest = "sha256:wrong",
            approved = true
        })));
        using var approver = new WebhookApprover(new Uri("https://approvals.example/v1"), client);

        var error = await Assert.ThrowsAsync<ApprovalTransportProtocolException>(
            () => approver.RequestApprovalAsync(request));

        Assert.Equal("action_digest_mismatch", error.ReasonCode);
    }

    [Fact]
    public async Task RequestApprovalAsync_DenyDoesNotTrustBodyIdentityForAllow()
    {
        var request = OpenRequest();
        using var client = ClientFor(request, approved: false);
        using var approver = new WebhookApprover(new Uri("https://approvals.example/v1"), client);

        var vote = await approver.RequestApprovalAsync(request);

        Assert.Equal(ApprovalEntryDecision.Deny, vote.Decision);
        Assert.Equal("webhook-user", vote.ApproverIdentity);
    }

    [Fact]
    public void Constructor_BlocksMetadataEndpoints()
    {
        Assert.Throws<ArgumentException>(() => new WebhookApprover(
            new Uri("http://169.254.169.254/latest/meta-data")));
        Assert.Throws<ArgumentException>(() => new WebhookApprover(
            new Uri("http://169.254.1.2/approval")));
        Assert.Throws<ArgumentException>(() => new WebhookApprover(
            new Uri("http://[fd00:ec2::254]/latest/meta-data")));
    }

    private static ApprovalRequest OpenRequest()
    {
        var coordinator = new ApprovalCoordinator(
            new ApprovalChain
            {
                ChainId = "high-risk-tools",
                Version = "chain-v1",
                Stages = new[]
                {
                    new ApprovalStage
                    {
                        StageIndex = 0,
                        AllowedIdentities = new[] { "did:web:example.com:alice" }
                    }
                }
            },
            options: new ApprovalCoordinatorOptions { PolicyVersion = "policy-v1" });
        return coordinator.OpenRequest(new ActionBinding
        {
            Operation = "tool.invoke",
            AgentId = "did:agent:123",
            Target = new ActionTarget
            {
                ToolName = "payments.transfer",
                ToolSchemaVersion = "1"
            }
        }).Request;
    }

    private static HttpClient ClientFor(ApprovalRequest request, bool approved) =>
        new(new StubHandler((_, _) => JsonResponse(new
        {
            approval_request_id = request.ApprovalRequestId,
            action_digest = request.ActionDigest,
            approved,
            approver = "webhook-user",
            reason = approved ? "reviewed" : "rejected"
        })));

    private static HttpResponseMessage JsonResponse(object body) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json")
    };

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> _handler;

        internal StubHandler(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(_handler(request, cancellationToken));
    }
}
