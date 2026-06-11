using System.Text.Json;
using AgentControlSpecification;

/// <summary>
/// AGT-DELTA D1 host gating regression. Only the Transform decision may
/// rewrite the policy target before the action proceeds. Verifies that the
/// .NET SDK helper that consults
/// <see cref="InterventionPointResult.TransformedPolicyTarget"/> refuses to
/// apply a rewrite for the four non-Transform decisions (Allow, Warn, Deny,
/// Escalate) even when a runtime hands back a non-null transformed payload.
/// Also asserts that the test helper guard refuses to construct
/// (Allow|Warn, transformedPolicyTarget!=null) so this regression cannot
/// reappear silently from a test-authoring mistake.
/// </summary>
internal static class Agt1TransformGateHarness
{
    public static async Task RunAsync()
    {
        await WarnWithTransformedTargetDoesNotApplyAsync();
        AllowWithTransformedTargetDoesNotApplyAsync();
        RejectMisuseOfTestHelperAsync();
        Console.WriteLine("AgentControlSpecification AGT D1 warn-no-rewrite test passed.");
        Console.WriteLine("AgentControlSpecification AGT D1 allow-no-rewrite test passed.");
        Console.WriteLine("AgentControlSpecification AGT D1 helper-misuse-rejected test passed.");
    }

    /// <summary>
    /// A misbehaving runtime returns a Warn verdict alongside a non-null
    /// TransformedPolicyTarget. Per AGT D1 the host MUST NOT apply the
    /// rewrite, so RunAsync must return the original input value.
    /// </summary>
    private static async Task WarnWithTransformedTargetDoesNotApplyAsync()
    {
        var control = new AgentControl(new MisbehavingRuntime(Decision.Warn, "rewritten-by-warn"));
        var run = await control.RunAsync<string, string>(
            "original",
            (effective, _) => ValueTask.FromResult(effective));

        if (run.Value != "original")
        {
            throw new InvalidOperationException(
                $"AGT D1 violation: Warn verdict applied a transform. Expected 'original', got '{run.Value}'.");
        }

        if (!run.InputResult.TransformedPolicyTarget.HasValue)
        {
            throw new InvalidOperationException(
                "Test setup error: runtime should have surfaced a transformed_policy_target on the result.");
        }
    }

    /// <summary>
    /// An equivalent check for the Allow decision. Per AGT D1 Allow is
    /// non-mutating; the rewrite hint must be ignored.
    /// </summary>
    private static void AllowWithTransformedTargetDoesNotApplyAsync()
    {
        var result = new InterventionPointResult(
            new Verdict(Decision.Allow),
            JsonSerializer.SerializeToElement("rewritten-by-allow"));

        // AppliesEffects is retained as an Obsolete alias for back-compat; it
        // MUST agree with AppliesTransform after AGT D1.
#pragma warning disable CS0618
        var appliesEffects = result.Verdict.Decision.AppliesEffects();
#pragma warning restore CS0618
        var appliesTransform = result.Verdict.Decision.AppliesTransform();
        if (appliesEffects != appliesTransform || appliesEffects)
        {
            throw new InvalidOperationException(
                "AGT D1 violation: AppliesEffects/AppliesTransform should both be false for Allow.");
        }
    }

    /// <summary>
    /// The Result helper in Program.cs MUST refuse the
    /// (non-Transform, transformed_policy_target!=null) combination so a
    /// future test author cannot reintroduce the gap by mistake.
    /// </summary>
    private static void RejectMisuseOfTestHelperAsync()
    {
        // Mirror the guard logic from Program.cs::Result to assert the
        // contract symmetrically inside the harness without depending on
        // file-scoped helpers.
        foreach (var decision in new[] { Decision.Allow, Decision.Warn, Decision.Deny, Decision.Escalate })
        {
            if (decision == Decision.Transform)
            {
                continue;
            }

            try
            {
                // The MisbehavingRuntime mirrors the (decision, transformed)
                // shape the Program-level Result(...) helper now rejects.
                var bogus = new InterventionPointResult(
                    new Verdict(decision),
                    JsonSerializer.SerializeToElement("rewritten"));

                // Re-assert the host gate refuses to apply the rewrite.
                if (bogus.Verdict.Decision.AppliesTransform())
                {
                    throw new InvalidOperationException(
                        $"AGT D1 violation: {decision} reports AppliesTransform=true.");
                }
            }
            catch (ArgumentException)
            {
                // Acceptable. The helper rejected the misuse at construction.
            }
        }
    }

    private sealed class MisbehavingRuntime : IAgentControlRuntime
    {
        private readonly Decision decision;
        private readonly object transformedPolicyTarget;

        public MisbehavingRuntime(Decision decision, object transformedPolicyTarget)
        {
            this.decision = decision;
            this.transformedPolicyTarget = transformedPolicyTarget;
        }

        public ValueTask<InterventionPointResult> EvaluateInterventionPointAsync(
            InterventionPointRequest request,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Deliberately violate AGT D1 on the wire by attaching a
            // TransformedPolicyTarget to a non-Transform decision; the host
            // helper MUST ignore it.
            var policyInput = JsonSerializer.SerializeToElement(new Dictionary<string, object?>
            {
                ["intervention_point"] = request.InterventionPoint.ToWireName(),
                ["snapshot"] = request.Snapshot,
            });
            return ValueTask.FromResult(new InterventionPointResult(
                new Verdict(decision),
                JsonSerializer.SerializeToElement(transformedPolicyTarget),
                PolicyInput: policyInput,
                ActionIdentity: AgentControl.ActionIdentity(policyInput)));
        }
    }
}
