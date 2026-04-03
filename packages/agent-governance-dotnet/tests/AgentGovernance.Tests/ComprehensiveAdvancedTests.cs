// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance;
using AgentGovernance.Hypervisor;
using AgentGovernance.Security;
using AgentGovernance.Sre;
using AgentGovernance.Trust;
using AgentGovernance.Telemetry;
using AgentGovernance.Audit;
using Xunit;

namespace AgentGovernance.Tests;

public class ExecutionRingsAdvancedTests
{
    [Fact]
    public void ComputeRing_BoundaryScores()
    {
        var e = new RingEnforcer();
        Assert.Equal(ExecutionRing.Ring0, e.ComputeRing(0.95));
        Assert.Equal(ExecutionRing.Ring1, e.ComputeRing(0.949));
        Assert.Equal(ExecutionRing.Ring1, e.ComputeRing(0.80));
        Assert.Equal(ExecutionRing.Ring2, e.ComputeRing(0.799));
        Assert.Equal(ExecutionRing.Ring2, e.ComputeRing(0.60));
        Assert.Equal(ExecutionRing.Ring3, e.ComputeRing(0.599));
        Assert.Equal(ExecutionRing.Ring3, e.ComputeRing(0.0));
        Assert.Equal(ExecutionRing.Ring3, e.ComputeRing(-0.5));
        Assert.Equal(ExecutionRing.Ring0, e.ComputeRing(1.0));
    }

    [Fact]
    public void Check_HigherPrivilegeCanAccessLower()
    {
        var e = new RingEnforcer();
        var r = e.Check(0.85, ExecutionRing.Ring2);
        Assert.True(r.Allowed);
        Assert.Equal(ExecutionRing.Ring1, r.AgentRing);
    }

    [Fact]
    public void Check_LowerPrivilegeCannotAccessHigher()
    {
        var e = new RingEnforcer();
        var r = e.Check(0.70, ExecutionRing.Ring1);
        Assert.False(r.Allowed);
        Assert.Equal(ExecutionRing.Ring2, r.AgentRing);
        Assert.NotEmpty(r.Reason);
    }

    [Fact]
    public void Check_SameRingAllowed()
    {
        var e = new RingEnforcer();
        Assert.True(e.Check(0.3, ExecutionRing.Ring3).Allowed);
    }

    [Fact]
    public void ShouldDemote_TrustDropsSignificantly_True()
    {
        var e = new RingEnforcer();
        Assert.True(e.ShouldDemote(ExecutionRing.Ring0, 0.3));
        Assert.False(e.ShouldDemote(ExecutionRing.Ring2, 0.65));
        Assert.False(e.ShouldDemote(ExecutionRing.Ring1, 0.96)); // Promotion, not demotion.
    }

    [Fact]
    public void GetLimits_AllRings()
    {
        var e = new RingEnforcer();
        Assert.True(e.GetLimits(ExecutionRing.Ring0).MaxCallsPerMinute >= 10000);
        Assert.True(e.GetLimits(ExecutionRing.Ring1).AllowWrites);
        Assert.Equal(100, e.GetLimits(ExecutionRing.Ring2).MaxCallsPerMinute);
        Assert.False(e.GetLimits(ExecutionRing.Ring3).AllowWrites);
        Assert.False(e.GetLimits(ExecutionRing.Ring3).AllowNetwork);
    }

    [Fact]
    public void CustomThresholds()
    {
        var e = new RingEnforcer(new Dictionary<ExecutionRing, double>
        {
            [ExecutionRing.Ring0] = 0.99, [ExecutionRing.Ring1] = 0.95,
            [ExecutionRing.Ring2] = 0.80, [ExecutionRing.Ring3] = 0.0
        });
        Assert.Equal(ExecutionRing.Ring3, e.ComputeRing(0.70));
        Assert.Equal(ExecutionRing.Ring2, e.ComputeRing(0.85));
    }
}

public class AgentIdentityAdvancedTests
{
    [Fact]
    public void Create_GeneratesDid() => Assert.StartsWith("did:mesh:", AgentIdentity.Create("test").Did);

    [Fact]
    public void Create_DifferentNames_DifferentPrefixes()
    {
        // DIDs have random component, but the first 8 hex chars are deterministic from name.
        var id1 = AgentIdentity.Create("agent-a");
        var id2 = AgentIdentity.Create("agent-b");
        Assert.NotEqual(id1.Did[..17], id2.Did[..17]); // "did:mesh:" + 8 hex chars
    }

    [Fact]
    public void Sign_Verify_RoundTrip()
    {
        var id = AgentIdentity.Create("signer");
        var sig = id.Sign("message");
        Assert.True(id.Verify(System.Text.Encoding.UTF8.GetBytes("message"), sig));
    }

    [Fact]
    public void Verify_TamperedData_False()
    {
        var id = AgentIdentity.Create("signer");
        var sig = id.Sign("original");
        Assert.False(id.Verify(System.Text.Encoding.UTF8.GetBytes("tampered"), sig));
    }

    [Fact]
    public void Verify_TamperedSignature_False()
    {
        var id = AgentIdentity.Create("signer");
        var data = System.Text.Encoding.UTF8.GetBytes("msg");
        var sig = id.Sign("msg");
        sig[0] ^= 0xFF;
        Assert.False(id.Verify(data, sig));
    }

    [Fact]
    public void Sign_EmptyString_Works()
    {
        var sig = AgentIdentity.Create("signer").Sign("");
        Assert.NotEmpty(sig);
    }

    [Fact]
    public void Sign_LongData_Works()
    {
        var sig = AgentIdentity.Create("signer").Sign(new string('X', 100_000));
        Assert.NotEmpty(sig);
    }
}

public class FileTrustStoreAdvancedTests
{
    [Fact]
    public void GetScore_Unknown_ReturnsDefault()
    {
        var f = Path.Combine(Path.GetTempPath(), $"trust-{Guid.NewGuid()}.json");
        try { using var s = new FileTrustStore(f, defaultScore: 500); Assert.Equal(500, s.GetScore("did:mesh:x")); }
        finally { File.Delete(f); }
    }

    [Fact]
    public void SetScore_Clamped_0to1000()
    {
        var f = Path.Combine(Path.GetTempPath(), $"trust-{Guid.NewGuid()}.json");
        try
        {
            using var s = new FileTrustStore(f, decayRate: 0);
            s.SetScore("did:mesh:a", 2000); Assert.InRange(s.GetScore("did:mesh:a"), 999, 1001);
            s.SetScore("did:mesh:b", -100); Assert.InRange(s.GetScore("did:mesh:b"), -1, 1);
        }
        finally { File.Delete(f); }
    }

    [Fact]
    public void PositiveSignal_Increases()
    {
        var f = Path.Combine(Path.GetTempPath(), $"trust-{Guid.NewGuid()}.json");
        try { using var s = new FileTrustStore(f, defaultScore: 500); s.RecordPositiveSignal("did:mesh:a", 50); Assert.True(s.GetScore("did:mesh:a") > 500); }
        finally { File.Delete(f); }
    }

    [Fact]
    public void NegativeSignal_Decreases()
    {
        var f = Path.Combine(Path.GetTempPath(), $"trust-{Guid.NewGuid()}.json");
        try { using var s = new FileTrustStore(f, defaultScore: 500); s.RecordNegativeSignal("did:mesh:a", 100); Assert.True(s.GetScore("did:mesh:a") < 500); }
        finally { File.Delete(f); }
    }

    [Fact]
    public void Remove_ReturnsDefault()
    {
        var f = Path.Combine(Path.GetTempPath(), $"trust-{Guid.NewGuid()}.json");
        try { using var s = new FileTrustStore(f, defaultScore: 500); s.SetScore("did:mesh:a", 800); s.Remove("did:mesh:a"); Assert.Equal(500, s.GetScore("did:mesh:a")); }
        finally { File.Delete(f); }
    }

    [Fact]
    public void Persistence_SurvivesReopen()
    {
        var f = Path.Combine(Path.GetTempPath(), $"trust-{Guid.NewGuid()}.json");
        try
        {
            using (var s = new FileTrustStore(f, decayRate: 0)) { s.SetScore("did:mesh:p", 777); s.Flush(); }
            using (var s2 = new FileTrustStore(f, decayRate: 0)) { Assert.InRange(s2.GetScore("did:mesh:p"), 776, 778); }
        }
        finally { File.Delete(f); }
    }

    [Fact]
    public void Count_Correct()
    {
        var f = Path.Combine(Path.GetTempPath(), $"trust-{Guid.NewGuid()}.json");
        try { using var s = new FileTrustStore(f); Assert.Equal(0, s.Count); s.SetScore("a", 100); s.SetScore("b", 200); Assert.Equal(2, s.Count); }
        finally { File.Delete(f); }
    }
}

[Collection("MetricsTests")]
public class GovernanceMetricsAdvancedTests
{
    [Fact]
    public void RecordDecision_DoesNotThrow()
    {
        using var m = new GovernanceMetrics();
        m.RecordDecision(true, "did:mesh:a", "tool", 0.01);
        m.RecordDecision(false, "did:mesh:a", "tool", 0.01, rateLimited: true);
    }

    [Fact]
    public void RecordDecision_ManyRecords_NoError()
    {
        using var m = new GovernanceMetrics();
        for (int i = 0; i < 10_000; i++) m.RecordDecision(i % 2 == 0, $"did:mesh:a-{i % 10}", "tool", 0.01);
    }

    [Fact]
    public void AllCounters_NotNull()
    {
        using var m = new GovernanceMetrics();
        Assert.NotNull(m.PolicyDecisions);
        Assert.NotNull(m.ToolCallsBlocked);
        Assert.NotNull(m.ToolCallsAllowed);
        Assert.NotNull(m.RateLimitHits);
        Assert.NotNull(m.EvaluationLatency);
    }

    [Fact]
    public void Dispose_MultipleTimes_Safe()
    {
        var m = new GovernanceMetrics();
        m.Dispose(); m.Dispose();
    }
}

public class AuditEmitterAdvancedTests
{
    [Fact]
    public void Emit_NoHandlers_DoesNotThrow()
    {
        new AuditEmitter().Emit(new GovernanceEvent { Type = GovernanceEventType.PolicyCheck, AgentId = "a", SessionId = "s" });
    }

    [Fact]
    public void On_MultipleHandlers_AllReceive()
    {
        var emitter = new AuditEmitter();
        int count = 0;
        emitter.On(GovernanceEventType.PolicyCheck, _ => Interlocked.Increment(ref count));
        emitter.On(GovernanceEventType.PolicyCheck, _ => Interlocked.Increment(ref count));
        emitter.Emit(new GovernanceEvent { Type = GovernanceEventType.PolicyCheck, AgentId = "a", SessionId = "s" });
        Assert.Equal(2, count);
    }

    [Fact]
    public void OnAll_ReceivesAllTypes()
    {
        var emitter = new AuditEmitter();
        var types = new List<GovernanceEventType>();
        emitter.OnAll(evt => types.Add(evt.Type));
        emitter.Emit(new GovernanceEvent { Type = GovernanceEventType.PolicyCheck, AgentId = "a", SessionId = "s" });
        emitter.Emit(new GovernanceEvent { Type = GovernanceEventType.ToolCallBlocked, AgentId = "a", SessionId = "s" });
        Assert.Equal(2, types.Count);
    }

    [Fact]
    public void Emit_FaultyHandler_OthersStillRun()
    {
        var emitter = new AuditEmitter();
        bool ran = false;
        emitter.On(GovernanceEventType.PolicyCheck, _ => throw new Exception("bad"));
        emitter.On(GovernanceEventType.PolicyCheck, _ => ran = true);
        emitter.Emit(new GovernanceEvent { Type = GovernanceEventType.PolicyCheck, AgentId = "a", SessionId = "s" });
        Assert.True(ran);
    }

    [Fact]
    public void Emit_EventIdIsUnique()
    {
        var emitter = new AuditEmitter();
        var ids = new HashSet<string>();
        emitter.OnAll(evt => ids.Add(evt.EventId));
        for (int i = 0; i < 100; i++)
            emitter.Emit(new GovernanceEvent { Type = GovernanceEventType.PolicyCheck, AgentId = "a", SessionId = "s" });
        Assert.Equal(100, ids.Count);
    }

    [Fact]
    public void HandlerCount_Correct()
    {
        var emitter = new AuditEmitter();
        emitter.On(GovernanceEventType.PolicyCheck, _ => { });
        emitter.On(GovernanceEventType.PolicyCheck, _ => { });
        emitter.On(GovernanceEventType.ToolCallBlocked, _ => { });
        Assert.Equal(2, emitter.HandlerCount(GovernanceEventType.PolicyCheck));
        Assert.Equal(1, emitter.HandlerCount(GovernanceEventType.ToolCallBlocked));
        Assert.Equal(0, emitter.HandlerCount(GovernanceEventType.PolicyViolation));
    }
}

public class GovernanceKernelAdvancedTests
{
    [Fact]
    public void AllFeaturesEnabled_WorksTogether()
    {
        var k = new GovernanceKernel(new GovernanceOptions
        {
            EnableRings = true, EnablePromptInjectionDetection = true,
            EnableCircuitBreaker = true, EnableMetrics = true, EnableAudit = true
        });
        Assert.NotNull(k.Rings);
        Assert.NotNull(k.InjectionDetector);
        Assert.NotNull(k.CircuitBreaker);
        Assert.NotNull(k.Metrics);
        Assert.NotNull(k.SagaOrchestrator);
        Assert.NotNull(k.SloEngine);
    }

    [Fact]
    public void AllFeaturesDisabled_StillWorks()
    {
        var k = new GovernanceKernel(new GovernanceOptions
        {
            EnableRings = false, EnablePromptInjectionDetection = false,
            EnableCircuitBreaker = false, EnableMetrics = false, EnableAudit = false
        });
        Assert.Null(k.Rings); Assert.Null(k.InjectionDetector); Assert.Null(k.CircuitBreaker); Assert.Null(k.Metrics);
        Assert.NotNull(k.SagaOrchestrator); Assert.NotNull(k.SloEngine);
    }

    [Fact]
    public void LoadPolicyFromYaml_ThenEvaluate()
    {
        var k = new GovernanceKernel();
        k.LoadPolicyFromYaml(@"
name: test
default_action: deny
rules:
  - name: allow-search
    condition: ""tool_name == 'search'""
    action: allow");
        Assert.True(k.EvaluateToolCall("did:mesh:a", "search").Allowed);
        Assert.False(k.EvaluateToolCall("did:mesh:a", "delete").Allowed);
    }

    [Fact]
    public void OnEvent_ReceivesCorrectType()
    {
        var k = new GovernanceKernel();
        k.LoadPolicyFromYaml(@"name: deny-all
default_action: deny");
        var violations = new List<GovernanceEvent>();
        k.OnEvent(GovernanceEventType.PolicyViolation, evt => violations.Add(evt));
        k.EvaluateToolCall("did:mesh:a", "bad_tool");
        Assert.Single(violations);
    }

    [Fact]
    public void OnAllEvents_ReceivesBothAllowAndDeny()
    {
        var k = new GovernanceKernel();
        k.LoadPolicyFromYaml(@"name: mixed
default_action: deny
rules:
  - name: allow-read
    condition: ""tool_name == 'read'""
    action: allow");
        var events = new List<GovernanceEvent>();
        k.OnAllEvents(evt => events.Add(evt));
        k.EvaluateToolCall("did:mesh:a", "read");
        k.EvaluateToolCall("did:mesh:a", "write");
        Assert.True(events.Count >= 2);
    }

    [Fact]
    public void LoadPolicy_FromFile()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempFile, @"name: file-policy
default_action: allow");
            var k = new GovernanceKernel(new GovernanceOptions { PolicyPaths = new() { tempFile } });
            Assert.True(k.EvaluateToolCall("did:mesh:a", "any").Allowed);
        }
        finally { File.Delete(tempFile); }
    }
}
