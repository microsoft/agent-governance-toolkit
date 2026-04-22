// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Policy;
using Xunit;
using GovernancePolicy = AgentGovernance.Policy.Policy;

namespace AgentGovernance.Tests;

public class PolicyTests
{
    private const string ValidYaml = @"
apiVersion: governance.toolkit/v1
version: '1.0'
name: test-policy
description: A test policy
scope: global
default_action: deny
rules:
  - name: block-dangerous-tools
    condition: ""tool_name in blocked_tools""
    action: deny
    priority: 10
    enabled: true
  - name: require-approval-for-exports
    condition: ""tool_name == 'export'""
    action: require_approval
    priority: 5
    approvers:
      - compliance@org.com
      - admin@org.com
  - name: log-reads
    condition: ""tool_name == 'read'""
    action: log
    priority: 1
";

    [Fact]
    public void FromYaml_ValidPolicy_ParsesCorrectly()
    {
        var policy = GovernancePolicy.FromYaml(ValidYaml);

        Assert.Equal("governance.toolkit/v1", policy.ApiVersion);
        Assert.Equal("1.0", policy.Version);
        Assert.Equal("test-policy", policy.Name);
        Assert.Equal("A test policy", policy.Description);
        Assert.Equal(PolicyScope.Global, policy.Scope);
        Assert.Equal(PolicyAction.Deny, policy.DefaultAction);
        Assert.Equal(3, policy.Rules.Count);
    }

    [Fact]
    public void FromYaml_ParsesRuleProperties()
    {
        var policy = GovernancePolicy.FromYaml(ValidYaml);

        var blockRule = policy.Rules[0];
        Assert.Equal("block-dangerous-tools", blockRule.Name);
        Assert.Equal("tool_name in blocked_tools", blockRule.Condition);
        Assert.Equal(PolicyAction.Deny, blockRule.Action);
        Assert.Equal(10, blockRule.Priority);
        Assert.True(blockRule.Enabled);
    }

    [Fact]
    public void FromYaml_ParsesApprovers()
    {
        var policy = GovernancePolicy.FromYaml(ValidYaml);

        var approvalRule = policy.Rules[1];
        Assert.Equal(PolicyAction.RequireApproval, approvalRule.Action);
        Assert.Equal(2, approvalRule.Approvers.Count);
        Assert.Contains("compliance@org.com", approvalRule.Approvers);
        Assert.Contains("admin@org.com", approvalRule.Approvers);
    }

    [Fact]
    public void FromYaml_TenantScope_ParsesCorrectly()
    {
        var yaml = @"
apiVersion: governance.toolkit/v1
name: tenant-policy
scope: tenant
default_action: allow
rules: []
";
        var policy = GovernancePolicy.FromYaml(yaml);
        Assert.Equal(PolicyScope.Tenant, policy.Scope);
        Assert.Equal(PolicyAction.Allow, policy.DefaultAction);
    }

    [Fact]
    public void FromYaml_AgentScope_ParsesCorrectly()
    {
        var yaml = @"
apiVersion: governance.toolkit/v1
name: agent-policy
scope: agent
default_action: deny
rules: []
";
        var policy = GovernancePolicy.FromYaml(yaml);
        Assert.Equal(PolicyScope.Agent, policy.Scope);
    }

    [Fact]
    public void FromYaml_UnsupportedApiVersion_ThrowsArgumentException()
    {
        var yaml = @"
apiVersion: governance.toolkit/v99
name: bad-policy
rules: []
";
        var ex = Assert.Throws<ArgumentException>(() => GovernancePolicy.FromYaml(yaml));
        Assert.Contains("Unsupported", ex.Message);
    }

    [Fact]
    public void FromYaml_MissingName_ThrowsArgumentException()
    {
        var yaml = @"
apiVersion: governance.toolkit/v1
rules: []
";
        Assert.Throws<ArgumentException>(() => GovernancePolicy.FromYaml(yaml));
    }

    [Fact]
    public void FromYaml_NullOrEmpty_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => GovernancePolicy.FromYaml(""));
        Assert.Throws<ArgumentException>(() => GovernancePolicy.FromYaml("   "));
    }

    [Fact]
    public void FromYaml_DefaultsToAllowAction()
    {
        var yaml = @"
apiVersion: governance.toolkit/v1
name: default-allow
default_action: allow
rules: []
";
        var policy = GovernancePolicy.FromYaml(yaml);
        Assert.Equal(PolicyAction.Allow, policy.DefaultAction);
    }

    [Fact]
    public void FromYaml_DefaultsWhenFieldsMissing()
    {
        var yaml = @"
apiVersion: governance.toolkit/v1
name: minimal-policy
rules:
  - name: simple-rule
    condition: ""tool_name == 'test'""
";
        var policy = GovernancePolicy.FromYaml(yaml);

        Assert.Equal(PolicyScope.Global, policy.Scope);
        Assert.Equal(PolicyAction.Deny, policy.DefaultAction);

        var rule = policy.Rules[0];
        Assert.Equal(PolicyAction.Deny, rule.Action);
        Assert.Equal(0, rule.Priority);
        Assert.True(rule.Enabled);
        Assert.Empty(rule.Approvers);
    }
}
