// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Policy;
using Xunit;

namespace AgentGovernance.Tests;

public class PolicyBackendTests
{
    private const string SimpleRego = """
        package agentgovernance

        default allow = false

        allow {
            input.tool_name == "file_read"
        }

        allow {
            input.role == "admin"
        }
        """;

    private const string SimpleCedar = """
        permit(
            principal,
            action == Action::"ReadData",
            resource
        );

        forbid(
            principal,
            action == Action::"DeleteFile",
            resource
        );
        """;

    [Fact]
    public void OpaBackend_Builtin_AllowsMatchingRule()
    {
        var backend = new OpaPolicyBackend(regoContent: SimpleRego, mode: OpaEvaluationMode.Local);

        var decision = backend.Evaluate(new Dictionary<string, object>
        {
            ["tool_name"] = "file_read"
        });

        Assert.True(decision.Allowed);
        Assert.Equal("opa", decision.Backend);
        Assert.Null(decision.Error);
    }

    [Fact]
    public void OpaBackend_Builtin_DeniesMissingRule()
    {
        var backend = new OpaPolicyBackend(regoContent: SimpleRego, mode: OpaEvaluationMode.Local);

        var decision = backend.Evaluate(new Dictionary<string, object>
        {
            ["tool_name"] = "file_delete",
            ["role"] = "user"
        });

        Assert.False(decision.Allowed);
    }

    [Fact]
    public void CedarBackend_Builtin_RespectsPermitAndForbid()
    {
        var backend = new CedarPolicyBackend(policyContent: SimpleCedar, mode: CedarEvaluationMode.Builtin);

        var allow = backend.Evaluate(new Dictionary<string, object>
        {
            ["tool_name"] = "read_data",
            ["agent_did"] = "did:mesh:test"
        });
        var deny = backend.Evaluate(new Dictionary<string, object>
        {
            ["tool_name"] = "delete_file",
            ["agent_did"] = "did:mesh:test"
        });

        Assert.True(allow.Allowed);
        Assert.False(deny.Allowed);
    }

    [Fact]
    public void PolicyEngine_ExternalBackends_CanAllowWithoutYamlPolicies()
    {
        var engine = new PolicyEngine();
        engine.LoadOpa(regoContent: SimpleRego, mode: OpaEvaluationMode.Local);

        var decision = engine.Evaluate("did:mesh:test", new Dictionary<string, object>
        {
            ["tool_name"] = "file_read"
        });

        Assert.True(decision.Allowed);
        Assert.Equal("allow", decision.Action);
        Assert.Contains("external policy backend", decision.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PolicyEngine_ExplicitYamlDeny_IsNotBypassedByExternalAllow()
    {
        var engine = new PolicyEngine();
        engine.LoadYaml("""
            apiVersion: governance.toolkit/v1
            name: deny-delete
            default_action: allow
            rules:
              - name: block-delete
                condition: "tool_name == 'file_delete'"
                action: deny
            """);
        engine.LoadOpa(regoContent: """
            package agentgovernance

            default allow = false

            allow {
                input.tool_name == "file_delete"
            }
            """, mode: OpaEvaluationMode.Local);

        var decision = engine.Evaluate("did:mesh:test", new Dictionary<string, object>
        {
            ["tool_name"] = "file_delete"
        });

        Assert.False(decision.Allowed);
        Assert.Equal("block-delete", decision.MatchedRule);
    }
}
