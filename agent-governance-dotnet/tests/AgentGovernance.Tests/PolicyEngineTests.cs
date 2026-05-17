// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Policy;
using Xunit;

namespace AgentGovernance.Tests;

public class PolicyEngineTests
{
    private const string DenyPolicy = @"
apiVersion: governance.toolkit/v1
name: security-policy
scope: global
default_action: deny
rules:
  - name: block-rm
    condition: ""tool_name == 'rm'""
    action: deny
    priority: 10
  - name: allow-read
    condition: ""tool_name == 'read'""
    action: allow
    priority: 5
  - name: warn-write
    condition: ""tool_name == 'write'""
    action: warn
    priority: 3
";

    [Fact]
    public void Evaluate_NoPoliciesLoaded_AllowsByDefault()
    {
        var engine = new PolicyEngine();
        var decision = engine.Evaluate("did:mesh:test", new Dictionary<string, object>());

        Assert.True(decision.Allowed);
        Assert.Equal("allow", decision.Action);
        Assert.Null(decision.PolicyName);
    }

    [Fact]
    public void Evaluate_DenyRuleMatches_ReturnsDeny()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(DenyPolicy);

        var decision = engine.Evaluate("did:mesh:test",
            new Dictionary<string, object> { ["tool_name"] = "rm" });

        Assert.False(decision.Allowed);
        Assert.Equal("deny", decision.Action);
        Assert.Equal("block-rm", decision.MatchedRule);
        Assert.Equal("security-policy", decision.PolicyName);
    }

    [Fact]
    public void Evaluate_AllowRuleMatches_ReturnsAllow()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(DenyPolicy);

        var decision = engine.Evaluate("did:mesh:test",
            new Dictionary<string, object> { ["tool_name"] = "read" });

        Assert.True(decision.Allowed);
        Assert.Equal("allow", decision.Action);
        Assert.Equal("allow-read", decision.MatchedRule);
        Assert.Equal("security-policy", decision.PolicyName);
    }

    [Fact]
    public void Evaluate_WarnRuleMatches_ReturnsAllowedWithWarn()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(DenyPolicy);

        var decision = engine.Evaluate("did:mesh:test",
            new Dictionary<string, object> { ["tool_name"] = "write" });

        Assert.True(decision.Allowed);
        Assert.Equal("warn", decision.Action);
        Assert.Equal("security-policy", decision.PolicyName);
    }

    [Fact]
    public void Evaluate_NoRulesMatch_ReturnsDefaultAction()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(DenyPolicy);

        var decision = engine.Evaluate("did:mesh:test",
            new Dictionary<string, object> { ["tool_name"] = "unknown_tool" });

        Assert.False(decision.Allowed);
        Assert.Equal("deny", decision.Action);
        Assert.Null(decision.MatchedRule);
    }

    [Fact]
    public void Evaluate_AllowDefault_NoRulesMatch_AllowsByDefault()
    {
        var yaml = @"
apiVersion: governance.toolkit/v1
name: permissive
default_action: allow
rules: []
";
        var engine = new PolicyEngine();
        engine.LoadYaml(yaml);

        var decision = engine.Evaluate("did:mesh:test",
            new Dictionary<string, object> { ["tool_name"] = "anything" });

        Assert.True(decision.Allowed);
    }

    [Fact]
    public void Evaluate_InListCondition_DeniesBlockedTool()
    {
        var yaml = @"
apiVersion: governance.toolkit/v1
name: blocklist-policy
default_action: allow
rules:
  - name: blocklist
    condition: ""tool_name in blocked_tools""
    action: deny
    priority: 10
";
        var engine = new PolicyEngine();
        engine.LoadYaml(yaml);

        var decision = engine.Evaluate("did:mesh:test",
            new Dictionary<string, object>
            {
                ["tool_name"] = "rm",
                ["blocked_tools"] = new List<object> { "rm", "format", "shutdown" }
            });

        Assert.False(decision.Allowed);
        Assert.Equal("blocklist", decision.MatchedRule);
    }

    [Fact]
    public void LoadJson_LoadsPolicy()
    {
        var json = """
            {
              "apiVersion": "governance.toolkit/v1",
              "name": "json-policy",
              "default_action": "deny",
              "rules": [
                {
                  "name": "allow-read",
                  "condition": "tool_name == 'read'",
                  "action": "allow",
                  "priority": 10
                }
              ]
            }
            """;

        var engine = new PolicyEngine();
        engine.LoadJson(json);

        var decision = engine.Evaluate("did:mesh:test", new Dictionary<string, object> { ["tool_name"] = "read" });

        Assert.True(decision.Allowed);
        Assert.Equal("json-policy", decision.PolicyName);
    }

    [Fact]
    public void ListPolicies_ReturnsLoadedPolicies()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(DenyPolicy);

        var policies = engine.ListPolicies();
        Assert.Single(policies);
        Assert.Equal("security-policy", policies[0].Name);
    }

    [Fact]
    public void ClearPolicies_RemovesAllPolicies()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(DenyPolicy);
        Assert.Single(engine.ListPolicies());

        engine.ClearPolicies();
        Assert.Empty(engine.ListPolicies());
    }

    [Fact]
    public async Task Evaluate_ConcurrentWithClearPolicies_DoesNotThrow_AndDecisionsRemainShaped()
    {
        // Regression: Evaluate() previously snapshotted _policies and
        // _externalBackends under two separate lock acquisitions, and
        // ClearPolicies() cleared them under two separate acquisitions too --
        // so a Clear could land between the two snapshots and let Evaluate
        // run with one collection cleared and the other still populated.
        // (The two lock objects are now a single _snapshotLock guarding both
        // collections, and ClearPolicies clears both inside that lock.)
        //
        // The torn-read itself is subtle and not directly externally
        // observable as a "wrong" decision -- the engine still self-
        // consistently routes through whichever pair of snapshots it got.
        // What this test pins is the strict load-bearing property of the
        // single-lock consolidation: under heavy concurrent
        // ClearPolicies / LoadYaml / AddExternalBackend / Evaluate, no call
        // throws (the underlying List<T> mutations are safely serialized)
        // and every returned PolicyDecision is well-shaped (non-null
        // Action). If the lock consolidation regressed to two locks (or
        // worse, dropped a lock around mutation), a List<T> resize during
        // concurrent enumeration would surface as
        // InvalidOperationException here.

        var engine = new PolicyEngine();
        engine.LoadYaml(DenyPolicy);
        var backend = new AllowBackend();
        engine.AddExternalBackend(backend);

        var ctx = new Dictionary<string, object> { ["tool_name"] = "rm" };
        var stopAt = DateTime.UtcNow.AddSeconds(2);
        var exceptions = 0;
        var malformedDecisions = 0;

        var clearTask = Task.Run(() =>
        {
            while (DateTime.UtcNow < stopAt)
            {
                try
                {
                    engine.ClearPolicies();
                    engine.LoadYaml(DenyPolicy);
                    engine.AddExternalBackend(backend);
                }
                catch
                {
                    Interlocked.Increment(ref exceptions);
                }
            }
        });

        var evalTasks = Enumerable.Range(0, 4).Select(_ => Task.Run(() =>
        {
            while (DateTime.UtcNow < stopAt)
            {
                try
                {
                    var decision = engine.Evaluate("did:mesh:test", ctx);
                    if (string.IsNullOrEmpty(decision.Action))
                    {
                        Interlocked.Increment(ref malformedDecisions);
                    }
                }
                catch
                {
                    Interlocked.Increment(ref exceptions);
                }
            }
        })).ToArray();

        await Task.WhenAll(evalTasks.Append(clearTask));

        Assert.Equal(0, exceptions);
        Assert.Equal(0, malformedDecisions);
    }

    private sealed class AllowBackend : IExternalPolicyBackend
    {
        public string Name => "allow-backend";

        public ExternalPolicyDecision Evaluate(IReadOnlyDictionary<string, object> context)
        {
            return new ExternalPolicyDecision
            {
                Backend = Name,
                Allowed = true,
                Reason = "always-allow"
            };
        }
    }

    [Fact]
    public void Evaluate_RecordsEvaluationMetadata()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(DenyPolicy);

        var decision = engine.Evaluate("did:mesh:test",
            new Dictionary<string, object> { ["tool_name"] = "rm" });

        Assert.True(decision.EvaluationMs >= 0);
        Assert.True(decision.EvaluatedAt <= DateTime.UtcNow);
    }

    [Fact]
    public void Evaluate_InjectsNormalizedAgentDid()
    {
        var yaml = @"
apiVersion: governance.toolkit/v1
name: agent-check
default_action: allow
rules:
  - name: block-specific-agent
    condition: ""agent_did == 'did:mesh:blocked'""
    action: deny
    priority: 10
";
        var engine = new PolicyEngine();
        engine.LoadYaml(yaml);

        var decision1 = engine.Evaluate("did:agentmesh:blocked",
            new Dictionary<string, object> { ["tool_name"] = "anything" });
        Assert.False(decision1.Allowed);

        var decision2 = engine.Evaluate("did:mesh:other",
            new Dictionary<string, object> { ["tool_name"] = "anything" });
        Assert.True(decision2.Allowed);
    }

    [Fact]
    public void Evaluate_OrganizationScope_WinsOverTenantAndGlobal()
    {
        var engine = new PolicyEngine { ConflictStrategy = ConflictResolutionStrategy.MostSpecificWins };
        engine.LoadYaml(@"
name: global-deny
scope: global
rules:
  - name: global-deny-rule
    condition: ""tool_name == 'deploy'""
    action: deny
");
        engine.LoadYaml(@"
name: tenant-deny
scope: tenant
rules:
  - name: tenant-deny-rule
    condition: ""tool_name == 'deploy'""
    action: deny
");
        engine.LoadYaml(@"
name: org-allow
scope: organization
rules:
  - name: org-allow-rule
    condition: ""tool_name == 'deploy'""
    action: allow
");

        var decision = engine.Evaluate("did:mesh:a", new Dictionary<string, object> { ["tool_name"] = "deploy" });

        Assert.True(decision.Allowed);
        Assert.Equal("org-allow", decision.PolicyName);
    }

    [Fact]
    public void Evaluate_RateLimitAction_SetsResetWindow()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(@"
name: rate-limit-test
default_action: allow
rules:
  - name: rate-limit-rule
    condition: ""tool_name == 'api_call'""
    action: rate_limit
    limit: ""10/minute""
");
        var decision = engine.Evaluate("did:mesh:a", new Dictionary<string, object>
        {
            ["tool_name"] = "api_call"
        });

        Assert.True(decision.RateLimited);
        Assert.NotNull(decision.RateLimitReset);
        Assert.Equal("rate-limit-test", decision.PolicyName);
    }
}
