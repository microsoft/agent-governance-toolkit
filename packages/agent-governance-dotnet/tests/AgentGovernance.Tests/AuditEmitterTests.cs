// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Audit;
using Xunit;

namespace AgentGovernance.Tests;

public class AuditEmitterTests
{
    [Fact]
    public void Emit_TypeSpecificHandler_ReceivesMatchingEvents()
    {
        var emitter = new AuditEmitter();
        GovernanceEvent? received = null;

        emitter.On(GovernanceEventType.PolicyCheck, e => received = e);

        emitter.Emit(GovernanceEventType.PolicyCheck, "did:mesh:test", "session-1");

        Assert.NotNull(received);
        Assert.Equal(GovernanceEventType.PolicyCheck, received!.Type);
        Assert.Equal("did:mesh:test", received.AgentId);
        Assert.Equal("session-1", received.SessionId);
    }

    [Fact]
    public void Emit_TypeSpecificHandler_DoesNotReceiveOtherEventTypes()
    {
        var emitter = new AuditEmitter();
        GovernanceEvent? received = null;

        emitter.On(GovernanceEventType.PolicyCheck, e => received = e);

        emitter.Emit(GovernanceEventType.PolicyViolation, "did:mesh:test", "session-1");

        Assert.Null(received);
    }

    [Fact]
    public void Emit_WildcardHandler_ReceivesAllEvents()
    {
        var emitter = new AuditEmitter();
        var events = new List<GovernanceEvent>();

        emitter.OnAll(e => events.Add(e));

        emitter.Emit(GovernanceEventType.PolicyCheck, "did:mesh:test", "s1");
        emitter.Emit(GovernanceEventType.PolicyViolation, "did:mesh:test", "s2");
        emitter.Emit(GovernanceEventType.ToolCallBlocked, "did:mesh:test", "s3");

        Assert.Equal(3, events.Count);
    }

    [Fact]
    public void Emit_MultipleHandlers_AllReceiveEvent()
    {
        var emitter = new AuditEmitter();
        int callCount = 0;

        emitter.On(GovernanceEventType.DriftDetected, _ => callCount++);
        emitter.On(GovernanceEventType.DriftDetected, _ => callCount++);
        emitter.On(GovernanceEventType.DriftDetected, _ => callCount++);

        emitter.Emit(GovernanceEventType.DriftDetected, "did:mesh:test", "session-1");

        Assert.Equal(3, callCount);
    }

    [Fact]
    public void Emit_PrebuiltEvent_PassedCorrectly()
    {
        var emitter = new AuditEmitter();
        GovernanceEvent? received = null;

        emitter.On(GovernanceEventType.CheckpointCreated, e => received = e);

        var evt = new GovernanceEvent
        {
            Type = GovernanceEventType.CheckpointCreated,
            AgentId = "did:mesh:test",
            SessionId = "session-42",
            PolicyName = "test-policy",
            Data = new Dictionary<string, object> { ["key"] = "value" }
        };

        emitter.Emit(evt);

        Assert.NotNull(received);
        Assert.Equal("did:mesh:test", received!.AgentId);
        Assert.Equal("session-42", received.SessionId);
        Assert.Equal("test-policy", received.PolicyName);
        Assert.Equal("value", received.Data["key"]);
    }

    [Fact]
    public void Emit_FaultyHandler_DoesNotBreakOtherHandlers()
    {
        var emitter = new AuditEmitter();
        bool secondHandlerCalled = false;

        emitter.On(GovernanceEventType.PolicyCheck, _ => throw new InvalidOperationException("boom"));
        emitter.On(GovernanceEventType.PolicyCheck, _ => secondHandlerCalled = true);

        // Should not throw.
        emitter.Emit(GovernanceEventType.PolicyCheck, "did:mesh:test", "session-1");

        Assert.True(secondHandlerCalled);
    }

    [Fact]
    public void HandlerCount_ReturnsCorrectCount()
    {
        var emitter = new AuditEmitter();

        Assert.Equal(0, emitter.HandlerCount(GovernanceEventType.PolicyCheck));

        emitter.On(GovernanceEventType.PolicyCheck, _ => { });
        emitter.On(GovernanceEventType.PolicyCheck, _ => { });

        Assert.Equal(2, emitter.HandlerCount(GovernanceEventType.PolicyCheck));
        Assert.Equal(0, emitter.HandlerCount(GovernanceEventType.DriftDetected));
    }

    [Fact]
    public void WildcardHandlerCount_ReturnsCorrectCount()
    {
        var emitter = new AuditEmitter();

        Assert.Equal(0, emitter.WildcardHandlerCount);

        emitter.OnAll(_ => { });
        Assert.Equal(1, emitter.WildcardHandlerCount);
    }

    [Fact]
    public void GovernanceEvent_HasUniqueEventId()
    {
        var e1 = new GovernanceEvent { AgentId = "a", SessionId = "s" };
        var e2 = new GovernanceEvent { AgentId = "a", SessionId = "s" };

        Assert.NotEqual(e1.EventId, e2.EventId);
        Assert.StartsWith("evt-", e1.EventId);
    }

    [Fact]
    public void GovernanceEvent_TimestampIsUtc()
    {
        var evt = new GovernanceEvent { AgentId = "a", SessionId = "s" };
        Assert.Equal(TimeSpan.Zero, evt.Timestamp.Offset);
    }

    [Fact]
    public void GovernanceEvent_ToString_IncludesKey()
    {
        var evt = new GovernanceEvent
        {
            Type = GovernanceEventType.PolicyViolation,
            AgentId = "did:mesh:test",
            SessionId = "s-1",
            PolicyName = "my-policy"
        };

        var str = evt.ToString();
        Assert.Contains("PolicyViolation", str);
        Assert.Contains("did:mesh:test", str);
        Assert.Contains("my-policy", str);
    }
}
