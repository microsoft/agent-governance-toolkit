using System.Text.Json;
using AgentControlSpecification;

/// <summary>
/// Conformance tests for the AGT 5.0 SDK surface added on top of upstream ACS.
/// Covers the AGT-DELTA D1 Transform decision, D1.4 bisected identity, D2
/// evidence payload, and the async <c>FromPath</c> ergonomics that match the
/// Rust / Python / Node SDKs.
/// </summary>
internal static class Agt5SurfaceHarness
{
    public static async Task RunAsync()
    {
        await TransformViaOpaAsync();
        await BisectedIdentityOnEscalateAsync();
        await EvidenceRoundTripAsync();
        await FromPathAsyncRoundTripAsync();
        Console.WriteLine("AgentControlSpecification AGT 5.0 transform-via-OPA test passed.");
        Console.WriteLine("AgentControlSpecification AGT 5.0 bisected identity test passed.");
        Console.WriteLine("AgentControlSpecification AGT 5.0 evidence round-trip test passed.");
        Console.WriteLine("AgentControlSpecification AGT 5.0 FromPathAsync test passed.");
    }

    private static async Task TransformViaOpaAsync()
    {
        var workspace = Directory.CreateTempSubdirectory("agt-dotnet-transform-").FullName;
        try
        {
            var bundleDir = Path.Combine(workspace, "policy");
            Directory.CreateDirectory(bundleDir);
            File.WriteAllText(
                Path.Combine(bundleDir, "demo.rego"),
                """
                package agt.dotnet.demo
                import rego.v1

                default pre_tool_call := {"decision": "allow"}

                pre_tool_call := {
                  "decision": "transform",
                  "reason": "secret_redacted",
                  "transform": {"path": "$policy_target", "value": "REDACTED"},
                } if {
                  input.intervention_point == "pre_tool_call"
                  input.snapshot.tool_call.args.command == "leak"
                }
                """);

            var manifestPath = Path.Combine(workspace, "manifest.yaml");
            File.WriteAllText(
                manifestPath,
                $$"""
                agent_control_specification_version: "0.3.0-alpha"
                policies:
                  demo:
                    type: rego
                    bundle: {{bundleDir}}
                    query: data.agt.dotnet.demo.pre_tool_call
                intervention_points:
                  pre_tool_call:
                    policy_target: "$.tool_call.args.command"
                    policy_target_kind: tool_args
                    tool_name_from: "$.tool_call.name"
                    policy:
                      id: demo
                tools:
                  shell:
                    clearance: confidential
                """);

            var control = AgentControl.FromPath(manifestPath);
            var snapshot = JsonSerializer.SerializeToElement(new
            {
                tool_call = new { id = "call-1", name = "shell", args = new { command = "leak" } },
                envelope = new { agent = new { id = "demo" } },
            });
            var result = await control.EvaluateInterventionPointAsync(
                InterventionPoint.PreToolCall, snapshot);
            AssertEqual(Decision.Transform, result.Verdict.Decision, "OPA transform verdict should map to Decision.Transform.");
            AssertEqual("secret_redacted", result.Verdict.Reason, "OPA transform verdict should preserve the reason string.");
            Assert(result.Verdict.Transform is not null, "OPA transform verdict should carry the transform payload.");
            AssertEqual("$policy_target", result.Verdict.Transform!.Path, "transform path should round-trip from the Rego policy.");
            Assert(result.TransformedPolicyTarget.HasValue, "OPA transform verdict should populate transformed_policy_target.");
            AssertEqual("REDACTED", result.TransformedPolicyTarget!.Value.GetString(), "transformed_policy_target should hold the rewritten value.");
            Assert(result.InputIdentity is not null, "OPA transform verdict should surface input_identity.");
            Assert(result.EnforcedIdentity is not null, "OPA transform verdict should surface enforced_identity.");
            Assert(result.InputIdentity != result.EnforcedIdentity, "OPA transform should shift enforced_identity away from input_identity.");
            AssertEqual(result.EnforcedIdentity, result.ActionIdentity, "action_identity is the back-compat alias for enforced_identity.");
        }
        finally
        {
            try { Directory.Delete(workspace, recursive: true); } catch { }
        }
    }

    private static async Task BisectedIdentityOnEscalateAsync()
    {
        var manifest = """
            agent_control_specification_version: 0.3.0-alpha
            policies:
              demo:
                type: custom
                adapter: bisected_identity_policy
            intervention_points:
              pre_tool_call:
                policy_target: "$.tool_call.args"
                policy_target_kind: tool_args
                tool_name_from: "$.tool_call.name"
                policy:
                  id: demo
              post_tool_call:
                policy_target: "$.tool_result"
                policy_target_kind: tool_result
                tool_name_from: "$.tool_call.name"
                policy:
                  id: demo
            tools:
              wire_transfer:
                clearance: confidential
            """;
        string? resolverInputIdentity = null;
        string? resolverEnforcedIdentity = null;
        string? resolverActionIdentity = null;
        InterventionPointResult? resolverResult = null;
        var control = AgentControl.FromNative(
            manifest,
            policyDispatcher: new EscalateOnPreToolPolicy(),
            approvalResolver: (_, result, _) =>
            {
                resolverResult = result;
                resolverInputIdentity = result.InputIdentity;
                resolverEnforcedIdentity = result.EnforcedIdentity;
                resolverActionIdentity = result.ActionIdentity;
                return ValueTask.FromResult(ApprovalResolution.Allow(result.EnforcedIdentity!));
            });

        var run = await control.RunToolAsync<object, string>(
            "wire_transfer",
            new { amount = 25_000 },
            (_, _) => ValueTask.FromResult("ok"),
            "escalate-call-1");

        AssertEqual("ok", run.Value, "approved escalate should execute the tool with the original args.");
        AssertEqual(Decision.Escalate, run.PreToolCallResult.Verdict.Decision, "pre_tool_call should escalate.");
        AssertEqual(Decision.Allow, run.PostToolCallResult.Verdict.Decision, "post_tool_call should allow.");

        Assert(run.PreToolCallResult.InputIdentity is not null, "escalate result should surface input_identity.");
        Assert(run.PreToolCallResult.EnforcedIdentity is not null, "escalate result should surface enforced_identity.");
        AssertEqual(
            run.PreToolCallResult.InputIdentity,
            run.PreToolCallResult.EnforcedIdentity,
            "escalate carries no transform per AGT D1.4, so input_identity == enforced_identity.");
        AssertEqual(
            run.PreToolCallResult.EnforcedIdentity,
            run.PreToolCallResult.ActionIdentity,
            "action_identity is the back-compat alias for enforced_identity.");

        Assert(resolverResult is not null, "ApprovalResolver should have been invoked.");
        Assert(resolverInputIdentity is not null, "ApprovalResolver should have received input_identity.");
        Assert(resolverEnforcedIdentity is not null, "ApprovalResolver should have received enforced_identity.");
        AssertEqual(
            resolverInputIdentity,
            run.PreToolCallResult.InputIdentity,
            "ApprovalResolver input_identity must match the verdict's input_identity.");
        AssertEqual(
            resolverEnforcedIdentity,
            run.PreToolCallResult.EnforcedIdentity,
            "ApprovalResolver enforced_identity must match the verdict's enforced_identity.");
        AssertEqual(
            resolverActionIdentity,
            run.PreToolCallResult.ActionIdentity,
            "ApprovalResolver action_identity must match the verdict's action_identity (back-compat alias).");
    }

    private static async Task EvidenceRoundTripAsync()
    {
        var manifest = """
            agent_control_specification_version: 0.3.0-alpha
            policies:
              evidence:
                type: custom
                adapter: evidence_policy
            intervention_points:
              pre_tool_call:
                policy_target: "$.tool_call.args"
                policy_target_kind: tool_args
                tool_name_from: "$.tool_call.name"
                policy:
                  id: evidence
            tools:
              audit_lookup:
                clearance: confidential
            """;

        var control = AgentControl.FromNative(manifest, policyDispatcher: new EvidencePolicy());
        var snapshot = JsonSerializer.SerializeToElement(new
        {
            tool_call = new { id = "ev-1", name = "audit_lookup", args = new { id = "row-7" } },
            envelope = new { agent = new { id = "demo" } },
        });
        var result = await control.EvaluateInterventionPointAsync(InterventionPoint.PreToolCall, snapshot);

        AssertEqual(Decision.Allow, result.Verdict.Decision, "evidence-carrying allow should remain an allow.");
        Assert(result.Verdict.Evidence is not null, "evidence-carrying allow should surface the Evidence payload.");
        AssertEqual(
            "sha256:abcdef1234567890",
            result.Verdict.Evidence!.Artefact,
            "evidence artefact should round-trip verbatim from the dispatcher.");
        Assert(result.Verdict.Evidence.VerificationPointers is not null, "evidence verification_pointers should round-trip.");
        AssertEqual(
            "https://example.com/keys/2026.pem",
            result.Verdict.Evidence.VerificationPointers!["issuer_pubkey"],
            "evidence verification_pointers value should round-trip verbatim.");
        AssertEqual(
            "https://example.com/policies/v1/",
            result.Verdict.Evidence.VerificationPointers!["policy_registry"],
            "every evidence verification_pointers entry should round-trip.");
    }

    private static async Task FromPathAsyncRoundTripAsync()
    {
        var manifestPath = Path.Combine(FindRepoRoot(), "examples", "records_agent", "manifest.yaml");
        Assert(File.Exists(manifestPath), $"records_agent manifest was not found: {manifestPath}");
        var control = await AgentControl.FromPathAsync(manifestPath);
        var snapshot = JsonSerializer.SerializeToElement(new
        {
            model_request = new
            {
                messages = new[] { new { role = "user", content = "List my upcoming appointments." } },
            },
        });
        var result = await control.EvaluateInterventionPointAsync(InterventionPoint.PreModelCall, snapshot);
        AssertEqual(Decision.Allow, result.Verdict.Decision, "zero-config FromPathAsync should allow benign pre_model_call.");
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private static void AssertEqual<T>(T expected, T actual, string message)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException($"{message} Expected '{expected}', got '{actual}'.");
        }
    }

    private static string FindRepoRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "tests", "conformance", "fail_closed_error_parity.json")))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException("Repository root was not found.");
    }
}

internal sealed class EscalateOnPreToolPolicy : IPolicyDispatcher
{
    public ValueTask<JsonElement> EvaluateAsync(
        JsonElement preparedInvocation,
        CancellationToken cancellationToken = default)
    {
        var interventionPoint = preparedInvocation
            .GetProperty("input")
            .GetProperty("intervention_point")
            .GetString();
        if (interventionPoint == "pre_tool_call")
        {
            return ValueTask.FromResult(JsonSerializer.SerializeToElement(new
            {
                decision = "escalate",
                reason = "needs_approval",
            }));
        }

        return ValueTask.FromResult(JsonSerializer.SerializeToElement(new { decision = "allow" }));
    }
}

internal sealed class EvidencePolicy : IPolicyDispatcher
{
    public ValueTask<JsonElement> EvaluateAsync(
        JsonElement preparedInvocation,
        CancellationToken cancellationToken = default)
    {
        return ValueTask.FromResult(JsonSerializer.SerializeToElement(new
        {
            decision = "allow",
            evidence = new
            {
                artefact = "sha256:abcdef1234567890",
                verification_pointers = new
                {
                    issuer_pubkey = "https://example.com/keys/2026.pem",
                    policy_registry = "https://example.com/policies/v1/",
                },
            },
        }));
    }
}
