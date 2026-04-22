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
