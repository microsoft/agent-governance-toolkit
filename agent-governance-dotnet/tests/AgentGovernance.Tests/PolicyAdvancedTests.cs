// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Policy;
using Xunit;

namespace AgentGovernance.Tests;

public class PolicyAdvancedTests
{
    // ── Policy.FromYaml ─────────────────────────────────────────────

    [Fact]
    public void FromYaml_EmptyRules_LoadsWithDefaultAction()
    {
        var policy = AgentGovernance.Policy.Policy.FromYaml(@"
name: empty-rules
rules: []
");
        Assert.Empty(policy.Rules);
        Assert.Equal(PolicyAction.Deny, policy.DefaultAction);
    }

    [Fact]
    public void FromYaml_AllFields_ParsedCorrectly()
    {
        var policy = AgentGovernance.Policy.Policy.FromYaml(@"
name: Full Policy
description: A complete policy
scope: tenant
default_action: allow
rules:
  - name: rule-1
    condition: ""tool_name == 'test'""
    action: deny
    priority: 50
    enabled: true
");
        Assert.Equal("Full Policy", policy.Name);
        Assert.Equal("A complete policy", policy.Description);
        Assert.Equal(PolicyScope.Tenant, policy.Scope);
        Assert.Equal(PolicyAction.Allow, policy.DefaultAction);
        Assert.Single(policy.Rules);
        Assert.Equal(50, policy.Rules[0].Priority);
    }

    [Fact]
    public void FromYaml_NullYaml_Throws()
    {
        Assert.ThrowsAny<Exception>(() => AgentGovernance.Policy.Policy.FromYaml(null!));
    }

    [Fact]
    public void FromYaml_EmptyString_Throws()
    {
        Assert.ThrowsAny<Exception>(() => AgentGovernance.Policy.Policy.FromYaml(""));
    }

    [Fact]
    public void FromYaml_MissingName_Throws()
    {
        Assert.ThrowsAny<Exception>(() => AgentGovernance.Policy.Policy.FromYaml(@"
rules:
  - name: r1
    condition: ""true""
    action: allow
"));
    }

    [Fact]
    public void FromYaml_DisabledRule_NotEvaluated()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(@"
name: test
default_action: allow
rules:
  - name: disabled-rule
    condition: ""tool_name == 'test'""
    action: deny
    enabled: false
");
        var decision = engine.Evaluate("did:agentmesh:a", new Dictionary<string, object>
        {
            ["tool_name"] = "test"
        });
        Assert.True(decision.Allowed);
    }

    // ── Condition evaluation ────────────────────────────────────────

    [Fact]
    public void Evaluate_NestedDotNotation_ResolvesCorrectly()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(@"
name: nested
default_action: deny
rules:
  - name: nested-check
    condition: ""request.metadata.level == 'admin'""
    action: allow
");
        var context = new Dictionary<string, object>
        {
            ["request"] = new Dictionary<string, object>
            {
                ["metadata"] = new Dictionary<string, object>
                {
                    ["level"] = "admin"
                }
            }
        };
        var decision = engine.Evaluate("did:agentmesh:a", context);
        Assert.True(decision.Allowed);
    }

    [Fact]
    public void Evaluate_MissingNestedField_SafeFails()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(@"
name: missing
default_action: allow
rules:
  - name: missing-nested
    condition: ""request.metadata.missing_field == 'x'""
    action: deny
");
        var context = new Dictionary<string, object>
        {
            ["request"] = new Dictionary<string, object>()
        };
        var decision = engine.Evaluate("did:agentmesh:a", context);
        Assert.True(decision.Allowed);
    }

    [Theory]
    [InlineData("value > 10", 15, true)]
    [InlineData("value > 10", 10, false)]
    [InlineData("value > 10", 5, false)]
    [InlineData("value >= 10", 10, true)]
    [InlineData("value < 10", 5, true)]
    [InlineData("value < 10", 10, false)]
    [InlineData("value <= 10", 10, true)]
    public void Evaluate_NumericComparisons_Correct(string condition, double value, bool shouldAllow)
    {
        var engine = new PolicyEngine();
        engine.LoadYaml($@"
name: numeric
default_action: deny
rules:
  - name: numeric-rule
    condition: ""{condition}""
    action: allow
");
        var decision = engine.Evaluate("did:agentmesh:a", new Dictionary<string, object>
        {
            ["value"] = value
        });
        Assert.Equal(shouldAllow, decision.Allowed);
    }

    [Fact]
    public void Evaluate_InOperator_WithList()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(@"
name: in-list
default_action: deny
rules:
  - name: list-check
    condition: ""tool_name in allowed_tools""
    action: allow
");
        var decision = engine.Evaluate("did:agentmesh:a", new Dictionary<string, object>
        {
            ["tool_name"] = "file_read",
            ["allowed_tools"] = new List<object> { "file_read", "file_list", "search" }
        });
        Assert.True(decision.Allowed);
    }

    [Fact]
    public void Evaluate_InOperator_WithCsvString()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(@"
name: csv-list
default_action: deny
rules:
  - name: csv-check
    condition: ""tool_name in allowed_tools""
    action: allow
");
        var decision = engine.Evaluate("did:agentmesh:a", new Dictionary<string, object>
        {
            ["tool_name"] = "file_read",
            ["allowed_tools"] = "file_read,file_list,search"
        });
        Assert.True(decision.Allowed);
    }

    [Fact]
    public void Evaluate_NotInList_Denied()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(@"
name: not-in-list
default_action: deny
rules:
  - name: list-check
    condition: ""tool_name in allowed_tools""
    action: allow
");
        var decision = engine.Evaluate("did:agentmesh:a", new Dictionary<string, object>
        {
            ["tool_name"] = "rm_rf",
            ["allowed_tools"] = new List<object> { "file_read", "file_list" }
        });
        Assert.False(decision.Allowed);
    }

    [Fact]
    public void Evaluate_CompoundAnd_BothMustMatch()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(@"
name: compound-and
default_action: deny
rules:
  - name: compound
    condition: ""tool_name == 'file_write' and risk_level == 'low'""
    action: allow
");
        var allowed = engine.Evaluate("did:agentmesh:a", new Dictionary<string, object>
        {
            ["tool_name"] = "file_write",
            ["risk_level"] = "low"
        });
        Assert.True(allowed.Allowed);

        var denied = engine.Evaluate("did:agentmesh:a", new Dictionary<string, object>
        {
            ["tool_name"] = "file_write",
            ["risk_level"] = "high"
        });
        Assert.False(denied.Allowed);
    }

    [Fact]
    public void Evaluate_CompoundOr_EitherMatches()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(@"
name: compound-or
default_action: deny
rules:
  - name: or-rule
    condition: ""tool_name == 'read' or tool_name == 'list'""
    action: allow
");
        Assert.True(engine.Evaluate("did:agentmesh:a", new Dictionary<string, object> { ["tool_name"] = "read" }).Allowed);
        Assert.True(engine.Evaluate("did:agentmesh:a", new Dictionary<string, object> { ["tool_name"] = "list" }).Allowed);
        Assert.False(engine.Evaluate("did:agentmesh:a", new Dictionary<string, object> { ["tool_name"] = "write" }).Allowed);
    }

    // ── PolicyEngine management ─────────────────────────────────────

    [Fact]
    public void ClearPolicies_RemovesAll()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(@"
name: test
rules:
  - name: r1
    condition: ""true""
    action: allow
");
        Assert.Single(engine.ListPolicies());
        engine.ClearPolicies();
        Assert.Empty(engine.ListPolicies());
    }

    [Fact]
    public void Evaluate_NoPolicies_DefaultsToAllow()
    {
        var engine = new PolicyEngine();
        var decision = engine.Evaluate("did:agentmesh:a", new Dictionary<string, object>());
        Assert.True(decision.Allowed);
    }

    [Fact]
    public void Evaluate_TracksEvaluationTime()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(@"
name: test
default_action: allow
rules:
  - name: simple
    condition: ""true""
    action: allow
");
        var decision = engine.Evaluate("did:agentmesh:a", new Dictionary<string, object>());
        Assert.True(decision.EvaluationMs >= 0);
    }

    [Fact]
    public void Evaluate_AgentDidInjectedIntoContext()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml(@"
name: agent-check
default_action: deny
rules:
  - name: specific-agent
    condition: ""agent_did == 'did:mesh:special'""
    action: allow
");
        Assert.True(engine.Evaluate("did:agentmesh:special", new Dictionary<string, object>()).Allowed);
        Assert.False(engine.Evaluate("did:agentmesh:other", new Dictionary<string, object>()).Allowed);
    }

    // ── Conflict resolution strategies ──────────────────────────────

    [Fact]
    public void DenyOverrides_AnyDenyWins()
    {
        var engine = new PolicyEngine { ConflictStrategy = ConflictResolutionStrategy.DenyOverrides };
        engine.LoadYaml(@"
name: allow-policy
rules:
  - name: allow-it
    condition: ""tool_name == 'test'""
    action: allow
    priority: 100
");
        engine.LoadYaml(@"
name: deny-policy
rules:
  - name: deny-it
    condition: ""tool_name == 'test'""
    action: deny
    priority: 1
");
        var ctx = new Dictionary<string, object> { ["tool_name"] = "test" };
        Assert.False(engine.Evaluate("did:agentmesh:a", ctx).Allowed);
    }

    [Fact]
    public void AllowOverrides_AnyAllowWins()
    {
        var engine = new PolicyEngine { ConflictStrategy = ConflictResolutionStrategy.AllowOverrides };
        engine.LoadYaml(@"
name: deny-policy
rules:
  - name: deny-it
    condition: ""tool_name == 'test'""
    action: deny
    priority: 100
");
        engine.LoadYaml(@"
name: allow-policy
rules:
  - name: allow-it
    condition: ""tool_name == 'test'""
    action: allow
    priority: 1
");
        var ctx = new Dictionary<string, object> { ["tool_name"] = "test" };
        Assert.True(engine.Evaluate("did:agentmesh:a", ctx).Allowed);
    }

    [Fact]
    public void PriorityFirstMatch_HighestPriorityWins()
    {
        var engine = new PolicyEngine { ConflictStrategy = ConflictResolutionStrategy.PriorityFirstMatch };
        engine.LoadYaml(@"
name: mixed
rules:
  - name: low-pri-allow
    condition: ""tool_name == 'test'""
    action: allow
    priority: 1
  - name: high-pri-deny
    condition: ""tool_name == 'test'""
    action: deny
    priority: 100
");
        var ctx = new Dictionary<string, object> { ["tool_name"] = "test" };
        var decision = engine.Evaluate("did:agentmesh:a", ctx);
        Assert.False(decision.Allowed);
        Assert.Equal("high-pri-deny", decision.MatchedRule);
    }

    [Fact]
    public void MostSpecificWins_AgentScopeBeatsGlobal()
    {
        var engine = new PolicyEngine { ConflictStrategy = ConflictResolutionStrategy.MostSpecificWins };
        engine.LoadYaml(@"
name: global-deny
scope: global
rules:
  - name: global-deny-rule
    condition: ""tool_name == 'test'""
    action: deny
");
        engine.LoadYaml(@"
name: agent-allow
scope: agent
rules:
  - name: agent-allow-rule
    condition: ""tool_name == 'test'""
    action: allow
");
        var ctx = new Dictionary<string, object> { ["tool_name"] = "test" };
        Assert.True(engine.Evaluate("did:agentmesh:a", ctx).Allowed);
    }

    [Fact]
    public void Evaluate_RateLimitAction_MarksDecision()
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
        var decision = engine.Evaluate("did:agentmesh:a", new Dictionary<string, object>
        {
            ["tool_name"] = "api_call"
        });
        Assert.True(decision.RateLimited);
    }

    // ── File loading ────────────────────────────────────────────────

    [Fact]
    public void LoadYamlFile_NonexistentFile_Throws()
    {
        var engine = new PolicyEngine();
        Assert.ThrowsAny<Exception>(() => engine.LoadYamlFile("/nonexistent/path/policy.yaml"));
    }

    [Fact]
    public void LoadYamlFile_ValidFile_Loads()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempFile, @"
name: File Policy
rules:
  - name: test
    condition: ""true""
    action: allow
");
            var engine = new PolicyEngine();
            engine.LoadYamlFile(tempFile);
            Assert.Single(engine.ListPolicies());
            Assert.Equal("File Policy", engine.ListPolicies()[0].Name);
        }
        finally { File.Delete(tempFile); }
    }
}
