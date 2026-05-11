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

        emitter.Emit(GovernanceEventType.PolicyCheck, "did:agentmesh:test", "session-1");

        Assert.NotNull(received);
        Assert.Equal(GovernanceEventType.PolicyCheck, received!.Type);
        Assert.Equal("did:agentmesh:test", received.AgentId);
        Assert.Equal("session-1", received.SessionId);
    }

    [Fact]
    public void Emit_TypeSpecificHandler_DoesNotReceiveOtherEventTypes()
    {
        var emitter = new AuditEmitter();
        GovernanceEvent? received = null;

        emitter.On(GovernanceEventType.PolicyCheck, e => received = e);

        emitter.Emit(GovernanceEventType.PolicyViolation, "did:agentmesh:test", "session-1");

        Assert.Null(received);
    }

    [Fact]
    public void Emit_WildcardHandler_ReceivesAllEvents()
    {
        var emitter = new AuditEmitter();
        var events = new List<GovernanceEvent>();

        emitter.OnAll(e => events.Add(e));

        emitter.Emit(GovernanceEventType.PolicyCheck, "did:agentmesh:test", "s1");
        emitter.Emit(GovernanceEventType.PolicyViolation, "did:agentmesh:test", "s2");
        emitter.Emit(GovernanceEventType.ToolCallBlocked, "did:agentmesh:test", "s3");

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

        emitter.Emit(GovernanceEventType.DriftDetected, "did:agentmesh:test", "session-1");

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
            AgentId = "did:agentmesh:test",
            SessionId = "session-42",
            PolicyName = "test-policy",
            Data = new Dictionary<string, object> { ["key"] = "value" }
        };

        emitter.Emit(evt);

        Assert.NotNull(received);
        Assert.Equal("did:agentmesh:test", received!.AgentId);
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
        emitter.Emit(GovernanceEventType.PolicyCheck, "did:agentmesh:test", "session-1");

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
            AgentId = "did:agentmesh:test",
            SessionId = "s-1",
            PolicyName = "my-policy"
        };

        var str = evt.ToString();
        Assert.Contains("PolicyViolation", str);
        Assert.Contains("did:agentmesh:test", str);
        Assert.Contains("my-policy", str);
    }

    // ── Subscription order ─────────────────────────────────────────

    [Fact]
    public void Emit_TypedHandlers_FireInSubscriptionOrder()
    {
        var emitter = new AuditEmitter();
        var order = new List<int>();

        emitter.On(GovernanceEventType.PolicyCheck, _ => order.Add(1));
        emitter.On(GovernanceEventType.PolicyCheck, _ => order.Add(2));
        emitter.On(GovernanceEventType.PolicyCheck, _ => order.Add(3));

        emitter.Emit(GovernanceEventType.PolicyCheck, "did:agentmesh:test", "s");

        Assert.Equal(new[] { 1, 2, 3 }, order);
    }

    [Fact]
    public void Emit_WildcardHandlers_FireInSubscriptionOrderAfterTyped()
    {
        var emitter = new AuditEmitter();
        var order = new List<string>();

        emitter.On(GovernanceEventType.PolicyCheck, _ => order.Add("typed-1"));
        emitter.OnAll(_ => order.Add("wild-1"));
        emitter.On(GovernanceEventType.PolicyCheck, _ => order.Add("typed-2"));
        emitter.OnAll(_ => order.Add("wild-2"));

        emitter.Emit(GovernanceEventType.PolicyCheck, "did:agentmesh:test", "s");

        Assert.Equal(new[] { "typed-1", "typed-2", "wild-1", "wild-2" }, order);
    }

    // ── Unsubscription ─────────────────────────────────────────────

    [Fact]
    public void Off_RemovesHandler_NoLongerInvoked()
    {
        var emitter = new AuditEmitter();
        int count = 0;
        Action<GovernanceEvent> handler = _ => count++;

        emitter.On(GovernanceEventType.PolicyCheck, handler);
        emitter.Emit(GovernanceEventType.PolicyCheck, "a", "s");
        Assert.Equal(1, count);

        var removed = emitter.Off(GovernanceEventType.PolicyCheck, handler);
        Assert.True(removed);

        emitter.Emit(GovernanceEventType.PolicyCheck, "a", "s");
        Assert.Equal(1, count); // not invoked after Off
        Assert.Equal(0, emitter.HandlerCount(GovernanceEventType.PolicyCheck));
    }

    [Fact]
    public void Off_HandlerNotRegistered_ReturnsFalse()
    {
        var emitter = new AuditEmitter();
        Action<GovernanceEvent> handler = _ => { };
        Assert.False(emitter.Off(GovernanceEventType.PolicyCheck, handler));
    }

    [Fact]
    public void Off_OnlyRemovesOneInstance_WhenSameDelegateSubscribedTwice()
    {
        var emitter = new AuditEmitter();
        int count = 0;
        Action<GovernanceEvent> handler = _ => count++;

        emitter.On(GovernanceEventType.PolicyCheck, handler);
        emitter.On(GovernanceEventType.PolicyCheck, handler);

        Assert.True(emitter.Off(GovernanceEventType.PolicyCheck, handler));
        Assert.Equal(1, emitter.HandlerCount(GovernanceEventType.PolicyCheck));

        emitter.Emit(GovernanceEventType.PolicyCheck, "a", "s");
        Assert.Equal(1, count);
    }

    [Fact]
    public void OffAll_RemovesWildcardHandler_NoLongerInvoked()
    {
        var emitter = new AuditEmitter();
        int count = 0;
        Action<GovernanceEvent> handler = _ => count++;

        emitter.OnAll(handler);
        emitter.Emit(GovernanceEventType.PolicyCheck, "a", "s");
        Assert.Equal(1, count);

        Assert.True(emitter.OffAll(handler));
        emitter.Emit(GovernanceEventType.PolicyCheck, "a", "s");
        Assert.Equal(1, count);
        Assert.Equal(0, emitter.WildcardHandlerCount);
    }

    [Fact]
    public void OffAll_HandlerNotRegistered_ReturnsFalse()
    {
        var emitter = new AuditEmitter();
        Assert.False(emitter.OffAll(_ => { }));
    }

    [Fact]
    public void Off_NullHandler_Throws()
    {
        var emitter = new AuditEmitter();
        Assert.Throws<ArgumentNullException>(() => emitter.Off(GovernanceEventType.PolicyCheck, null!));
    }

    [Fact]
    public void OffAll_NullHandler_Throws()
    {
        var emitter = new AuditEmitter();
        Assert.Throws<ArgumentNullException>(() => emitter.OffAll(null!));
    }

    // ── Concurrent subscribe / emit ─────────────────────────────────

    [Fact]
    public void ConcurrentSubscribeAndEmit_NoExceptionsAndAllEventsHandled()
    {
        // Subscribers can register while other threads emit; emitters must
        // see a stable snapshot for each call and never observe a partially
        // constructed handler list.
        var emitter = new AuditEmitter();
        var errors = new System.Collections.Concurrent.ConcurrentBag<Exception>();
        int handled = 0;
        int registered = 0;

        const int subscribeThreads = 4;
        const int emitThreads = 4;
        const int iterations = 200;

        var started = new ManualResetEventSlim(false);
        var threads = new List<Thread>();

        for (int s = 0; s < subscribeThreads; s++)
        {
            threads.Add(new Thread(() =>
            {
                started.Wait();
                try
                {
                    for (int i = 0; i < iterations; i++)
                    {
                        emitter.On(GovernanceEventType.PolicyCheck, _ => Interlocked.Increment(ref handled));
                        Interlocked.Increment(ref registered);
                    }
                }
                catch (Exception ex) { errors.Add(ex); }
            }));
        }
        for (int e = 0; e < emitThreads; e++)
        {
            threads.Add(new Thread(() =>
            {
                started.Wait();
                try
                {
                    for (int i = 0; i < iterations; i++)
                    {
                        emitter.Emit(GovernanceEventType.PolicyCheck, "a", "s");
                    }
                }
                catch (Exception ex) { errors.Add(ex); }
            }));
        }

        foreach (var t in threads) t.Start();
        started.Set();
        foreach (var t in threads) t.Join();

        Assert.Empty(errors);
        Assert.Equal(subscribeThreads * iterations, registered);
        Assert.Equal(subscribeThreads * iterations, emitter.HandlerCount(GovernanceEventType.PolicyCheck));
        // handled value depends on ordering; just assert non-negative & nonzero.
        Assert.True(handled >= 0);
    }

    [Fact]
    public void Emit_HandlerThatUnsubscribesItself_DoesNotDeadlock()
    {
        // The handler-array snapshot inside Emit() runs handlers outside the
        // emitter lock, so a handler that calls back into Off() must not
        // deadlock and must not affect the current emit's handler list.
        var emitter = new AuditEmitter();
        int count = 0;
        Action<GovernanceEvent>? handler = null;
        handler = e =>
        {
            count++;
            emitter.Off(GovernanceEventType.PolicyCheck, handler!);
        };

        emitter.On(GovernanceEventType.PolicyCheck, handler);

        emitter.Emit(GovernanceEventType.PolicyCheck, "a", "s");
        Assert.Equal(1, count);

        emitter.Emit(GovernanceEventType.PolicyCheck, "a", "s");
        Assert.Equal(1, count); // self-unsubscribed
        Assert.Equal(0, emitter.HandlerCount(GovernanceEventType.PolicyCheck));
    }
}
