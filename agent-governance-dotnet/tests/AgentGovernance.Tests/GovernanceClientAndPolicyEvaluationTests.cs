// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Hypervisor;
using AgentGovernance.Policy;
using AgentGovernance.Security;
using AgentGovernance.Sre;
using Xunit;

namespace AgentGovernance.Tests;

/// <summary>
/// Focused unit tests for the .NET governance client (<see cref="GovernanceKernel"/>)
/// and policy evaluation primitives (<see cref="PolicyDecision"/> factories,
/// <see cref="IExternalPolicyBackend"/> stubbing). These tests exercise client
/// initialization, policy checks, error handling, and the mock/stub patterns
/// callers should use for external dependencies.
/// </summary>
public class GovernanceClientAndPolicyEvaluationTests
{
    private const string AllowReadDenyDefaultPolicy = @"
apiVersion: governance.toolkit/v1
name: client-test-policy
default_action: deny
rules:
  - name: allow-read
    condition: ""tool_name == 'read'""
    action: allow
    priority: 10
";

    // -----------------------------------------------------------------
    // Client initialization
    // -----------------------------------------------------------------

    [Fact]
    public void Constructor_NullOptions_UsesDefaults()
    {
        using var kernel = new GovernanceKernel(null);

        Assert.NotNull(kernel.PolicyEngine);
        Assert.NotNull(kernel.AuditEmitter);
        Assert.NotNull(kernel.Middleware);
        Assert.NotNull(kernel.RateLimiter);
        Assert.NotNull(kernel.Metrics); // metrics enabled by default
        Assert.Null(kernel.Rings);
        Assert.Null(kernel.InjectionDetector);
        Assert.Null(kernel.CircuitBreaker);
        Assert.True(kernel.AuditEnabled);
        Assert.Equal(ConflictResolutionStrategy.PriorityFirstMatch, kernel.PolicyEngine.ConflictStrategy);
    }

    [Fact]
    public void Constructor_AllOptionalSubsystemsEnabled_AreCreated()
    {
        using var kernel = new GovernanceKernel(new GovernanceOptions
        {
            EnableMetrics = true,
            EnableRings = true,
            EnablePromptInjectionDetection = true,
            EnableCircuitBreaker = true,
            EnableAudit = false,
            ConflictStrategy = ConflictResolutionStrategy.DenyOverrides
        });

        Assert.NotNull(kernel.Metrics);
        Assert.NotNull(kernel.Rings);
        Assert.NotNull(kernel.InjectionDetector);
        Assert.NotNull(kernel.CircuitBreaker);
        Assert.False(kernel.AuditEnabled);
        Assert.Equal(ConflictResolutionStrategy.DenyOverrides, kernel.PolicyEngine.ConflictStrategy);
    }

    [Fact]
    public void Constructor_MetricsDisabled_HasNullMetrics()
    {
        using var kernel = new GovernanceKernel(new GovernanceOptions { EnableMetrics = false });

        Assert.Null(kernel.Metrics);
    }

    [Fact]
    public void Constructor_CustomRingThresholds_AreUsed()
    {
        // Custom thresholds: Ring1 lowered to 0.5 (default is 0.80) so a 0.55
        // trust score should compute to Ring1 instead of Ring2.
        var thresholds = new Dictionary<ExecutionRing, double>
        {
            [ExecutionRing.Ring0] = 0.95,
            [ExecutionRing.Ring1] = 0.5,
            [ExecutionRing.Ring2] = 0.3,
            [ExecutionRing.Ring3] = 0.0,
        };

        using var customKernel = new GovernanceKernel(new GovernanceOptions
        {
            EnableRings = true,
            RingThresholds = thresholds
        });
        using var defaultKernel = new GovernanceKernel(new GovernanceOptions
        {
            EnableRings = true
        });

        Assert.NotNull(customKernel.Rings);
        Assert.NotNull(defaultKernel.Rings);
        Assert.Equal(ExecutionRing.Ring1, customKernel.Rings!.ComputeRing(0.55));
        Assert.Equal(ExecutionRing.Ring3, defaultKernel.Rings!.ComputeRing(0.55));
    }

    [Fact]
    public void Constructor_CustomCircuitBreakerConfig_IsApplied()
    {
        // FailureThreshold=2 must trip the breaker after exactly 2 failures,
        // proving the custom config (default is 5) was actually applied.
        var cfg = new CircuitBreakerConfig { FailureThreshold = 2 };

        using var kernel = new GovernanceKernel(new GovernanceOptions
        {
            EnableCircuitBreaker = true,
            CircuitBreakerConfig = cfg
        });

        Assert.NotNull(kernel.CircuitBreaker);
        Assert.Equal(CircuitState.Closed, kernel.CircuitBreaker!.State);
        kernel.CircuitBreaker.RecordFailure();
        Assert.Equal(CircuitState.Closed, kernel.CircuitBreaker.State);
        kernel.CircuitBreaker.RecordFailure();
        Assert.Equal(CircuitState.Open, kernel.CircuitBreaker.State);
    }

    [Fact]
    public void Constructor_PolicyPaths_LoadsYamlFromDisk()
    {
        var path = Path.Combine(Path.GetTempPath(), $"agt-client-test-{Guid.NewGuid():N}.yaml");
        File.WriteAllText(path, AllowReadDenyDefaultPolicy);
        try
        {
            using var kernel = new GovernanceKernel(new GovernanceOptions
            {
                PolicyPaths = new List<string> { path }
            });

            var policies = kernel.PolicyEngine.ListPolicies();
            Assert.Single(policies);
            Assert.Equal("client-test-policy", policies[0].Name);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Constructor_NonExistentPolicyPath_ThrowsFileNotFound()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"agt-missing-{Guid.NewGuid():N}.yaml");
        var options = new GovernanceOptions { PolicyPaths = new List<string> { missing } };

        Assert.Throws<FileNotFoundException>(() => new GovernanceKernel(options));
    }

    // -----------------------------------------------------------------
    // Policy loading errors
    // -----------------------------------------------------------------

    [Fact]
    public void LoadPolicyFromYaml_InvalidYaml_Throws()
    {
        using var kernel = new GovernanceKernel();

        // Missing required apiVersion / rules; this should bubble an exception.
        Assert.ThrowsAny<Exception>(() => kernel.LoadPolicyFromYaml("not: a [valid policy"));
    }

    [Fact]
    public void LoadPolicy_MissingFile_ThrowsFileNotFound()
    {
        using var kernel = new GovernanceKernel();
        var missing = Path.Combine(Path.GetTempPath(), $"agt-missing-{Guid.NewGuid():N}.yaml");

        Assert.Throws<FileNotFoundException>(() => kernel.LoadPolicy(missing));
    }

    [Fact]
    public void LoadPolicy_FromFile_LoadsSuccessfully()
    {
        var path = Path.Combine(Path.GetTempPath(), $"agt-loadpolicy-{Guid.NewGuid():N}.yaml");
        File.WriteAllText(path, AllowReadDenyDefaultPolicy);
        try
        {
            using var kernel = new GovernanceKernel();
            kernel.LoadPolicy(path);

            Assert.Single(kernel.PolicyEngine.ListPolicies());
        }
        finally
        {
            File.Delete(path);
        }
    }

    // -----------------------------------------------------------------
    // EvaluateToolCall behavior + error handling
    // -----------------------------------------------------------------

    [Fact]
    public void EvaluateToolCall_NoPolicies_AllowsByDefault()
    {
        using var kernel = new GovernanceKernel();

        // PolicyEngine returns AllowDefault when no policies are loaded.
        var result = kernel.EvaluateToolCall("did:agentmesh:test", "read");

        Assert.NotNull(result);
        Assert.NotNull(result.PolicyDecision);
        Assert.True(result.Allowed);
        Assert.True(result.PolicyDecision!.Allowed);
        Assert.Equal("allow", result.PolicyDecision.Action);
        Assert.Null(result.PolicyDecision.MatchedRule);
    }

    [Fact]
    public void EvaluateToolCall_ArgsForwarded_AffectDecision()
    {
        using var kernel = new GovernanceKernel();
        kernel.LoadPolicyFromYaml(@"
apiVersion: governance.toolkit/v1
name: arg-aware
default_action: allow
rules:
  - name: block-etc-writes
    condition: ""path == '/etc/passwd'""
    action: deny
    priority: 10
");

        var allowed = kernel.EvaluateToolCall("did:agentmesh:test", "write",
            new Dictionary<string, object> { ["path"] = "/tmp/file" });
        var blocked = kernel.EvaluateToolCall("did:agentmesh:test", "write",
            new Dictionary<string, object> { ["path"] = "/etc/passwd" });

        Assert.True(allowed.Allowed);
        Assert.False(blocked.Allowed);
        Assert.Equal("block-etc-writes", blocked.PolicyDecision!.MatchedRule);
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        var kernel = new GovernanceKernel();

        kernel.Dispose();
        kernel.Dispose(); // must not throw on second call
    }

    // -----------------------------------------------------------------
    // PolicyDecision factory methods
    // -----------------------------------------------------------------

    [Fact]
    public void PolicyDecision_AllowDefault_HasExpectedShape()
    {
        var d = PolicyDecision.AllowDefault(evaluationMs: 1.5);

        Assert.True(d.Allowed);
        Assert.Equal("allow", d.Action);
        Assert.Null(d.MatchedRule);
        Assert.Equal(1.5, d.EvaluationMs);
        Assert.False(d.RateLimited);
    }

    [Fact]
    public void PolicyDecision_DenyDefault_HasExpectedShape()
    {
        var ts = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var d = PolicyDecision.DenyDefault(ts, evaluationMs: 0.25);

        Assert.False(d.Allowed);
        Assert.Equal("deny", d.Action);
        Assert.Equal(ts, d.EvaluatedAt);
        Assert.Null(d.MatchedRule);
    }

    [Fact]
    public void PolicyDecision_FromRule_AllowAction_IsAllowed()
    {
        var rule = new PolicyRule
        {
            Name = "r-allow",
            Condition = "true",
            Action = PolicyAction.Allow,
            Priority = 1
        };

        var d = PolicyDecision.FromRule(rule, policyName: "p1");

        Assert.True(d.Allowed);
        Assert.Equal("allow", d.Action);
        Assert.Equal("r-allow", d.MatchedRule);
        Assert.Equal("p1", d.PolicyName);
        Assert.False(d.RateLimited);
        Assert.Empty(d.Approvers);
    }

    [Fact]
    public void PolicyDecision_FromRule_RequireApproval_CopiesApprovers()
    {
        var rule = new PolicyRule
        {
            Name = "r-approval",
            Condition = "true",
            Action = PolicyAction.RequireApproval,
            Approvers = new List<string> { "alice@example.com", "bob@example.com" }
        };

        var d = PolicyDecision.FromRule(rule);

        Assert.False(d.Allowed);
        Assert.Equal("requireapproval", d.Action);
        Assert.Equal(2, d.Approvers.Count);
        Assert.Contains("alice@example.com", d.Approvers);
    }

    [Fact]
    public void PolicyDecision_FromRule_RateLimit_SetsRateLimitedFlag()
    {
        var rule = new PolicyRule
        {
            Name = "r-ratelimit",
            Condition = "true",
            Action = PolicyAction.RateLimit,
            Limit = "100/hour"
        };

        var reset = DateTime.UtcNow.AddMinutes(5);
        var d = PolicyDecision.FromRule(rule, rateLimitReset: reset);

        Assert.True(d.RateLimited);
        Assert.Equal(reset, d.RateLimitReset);
        Assert.Contains("rate-limit", d.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PolicyDecision_FromRule_WarnAndLog_AreAllowed()
    {
        var warnRule = new PolicyRule { Name = "w", Condition = "true", Action = PolicyAction.Warn };
        var logRule = new PolicyRule { Name = "l", Condition = "true", Action = PolicyAction.Log };

        Assert.True(PolicyDecision.FromRule(warnRule).Allowed);
        Assert.True(PolicyDecision.FromRule(logRule).Allowed);
    }

    // -----------------------------------------------------------------
    // External policy backend mock/stub pattern
    // -----------------------------------------------------------------

    /// <summary>
    /// Test stub implementation of <see cref="IExternalPolicyBackend"/> showing the
    /// recommended pattern for plugging custom decision sources into the engine
    /// without requiring real OPA/Cedar infrastructure in tests.
    /// </summary>
    private sealed class StubExternalBackend : IExternalPolicyBackend
    {
        private readonly Func<IReadOnlyDictionary<string, object>, ExternalPolicyDecision> _evaluator;

        public StubExternalBackend(
            string name,
            Func<IReadOnlyDictionary<string, object>, ExternalPolicyDecision> evaluator)
        {
            Name = name;
            _evaluator = evaluator;
        }

        public string Name { get; }

        public int CallCount { get; private set; }

        public ExternalPolicyDecision Evaluate(IReadOnlyDictionary<string, object> context)
        {
            CallCount++;
            return _evaluator(context);
        }
    }

    [Fact]
    public void PolicyEngine_AddExternalBackend_NullArgument_Throws()
    {
        var engine = new PolicyEngine();
        Assert.Throws<ArgumentNullException>(() => engine.AddExternalBackend(null!));
    }

    [Fact]
    public void PolicyEngine_StubBackend_AllowsRequest()
    {
        var stub = new StubExternalBackend("stub-allow", _ => new ExternalPolicyDecision
        {
            Backend = "stub-allow",
            Allowed = true,
            Reason = "stub allow"
        });

        var engine = new PolicyEngine();
        engine.AddExternalBackend(stub);

        var decision = engine.Evaluate("did:agentmesh:test", new Dictionary<string, object>
        {
            ["tool_name"] = "anything"
        });

        Assert.True(decision.Allowed);
        Assert.Equal(1, stub.CallCount);
    }

    [Fact]
    public void PolicyEngine_StubBackend_DeniesRequest()
    {
        var stub = new StubExternalBackend("stub-deny", _ => new ExternalPolicyDecision
        {
            Backend = "stub-deny",
            Allowed = false,
            Reason = "stub deny"
        });

        var engine = new PolicyEngine();
        engine.AddExternalBackend(stub);

        var decision = engine.Evaluate("did:agentmesh:test", new Dictionary<string, object>
        {
            ["tool_name"] = "anything"
        });

        Assert.False(decision.Allowed);
    }

    [Fact]
    public void PolicyEngine_StubBackend_ErrorIsFailClosed()
    {
        var stub = new StubExternalBackend("stub-error", _ => new ExternalPolicyDecision
        {
            Backend = "stub-error",
            Allowed = true, // even if backend says allow, error should override
            Reason = "transport failure",
            Error = "connection refused"
        });

        var engine = new PolicyEngine();
        engine.AddExternalBackend(stub);

        var decision = engine.Evaluate("did:agentmesh:test", new Dictionary<string, object>
        {
            ["tool_name"] = "anything"
        });

        Assert.False(decision.Allowed);
    }

    [Fact]
    public void PolicyEngine_YamlDeny_OverridesStubAllow()
    {
        var stub = new StubExternalBackend("stub-allow-all", _ => new ExternalPolicyDecision
        {
            Backend = "stub-allow-all",
            Allowed = true,
            Reason = "always allow"
        });

        var engine = new PolicyEngine();
        engine.LoadYaml(@"
apiVersion: governance.toolkit/v1
name: yaml-deny
default_action: allow
rules:
  - name: deny-write
    condition: ""tool_name == 'write'""
    action: deny
    priority: 10
");
        engine.AddExternalBackend(stub);

        var decision = engine.Evaluate("did:agentmesh:test", new Dictionary<string, object>
        {
            ["tool_name"] = "write"
        });

        Assert.False(decision.Allowed);
        Assert.Equal("deny-write", decision.MatchedRule);
    }
}
