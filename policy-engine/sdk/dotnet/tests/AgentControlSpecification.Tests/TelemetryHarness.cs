// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.Metrics;
using System.Text.Json;
using AgentControlSpecification;

internal static class TelemetryHarness
{
    public static async Task RunAsync()
    {
        await EmitsOneDecisionEventAsync();
        await CapturesAllDecisionsAsync();
        await RedactsPayloadAndPointerValuesAsync();
        await ThrowingSinkDoesNotAffectVerdictAsync();
        RecordsOtelCounter();
        await DefaultNullSinkEmitsNothingAsync();
        await IndexesJsonManifestAsync();
        await AdapterRunFunnelEmitsTelemetryAsync();
        await FallsBackToResultAnnotatorsAsync();
        Console.WriteLine("AgentControlSpecification telemetry host-export tests passed.");
    }

    private static async Task FallsBackToResultAnnotatorsAsync()
    {
        // With no manifest-configured annotator list (e.g. a from_url or YAML
        // source) the event recovers the sorted annotator names from the result
        // policy input, mirroring the Python and Node host layers.
        var sink = new InMemoryTelemetrySink();
        var control = new AgentControl(
            new TelemetryRuntime(request =>
            {
                var policyInput = JsonSerializer.SerializeToElement(new Dictionary<string, object?>
                {
                    ["annotations"] = new Dictionary<string, object?>
                    {
                        ["zeta_scan"] = new { ran = true },
                        ["alpha_scan"] = new { ran = true },
                    },
                });
                return new InterventionPointResult(
                    new Verdict(Decision.Allow),
                    PolicyInput: policyInput,
                    ActionIdentity: AgentControl.ActionIdentity(policyInput),
                    InputIdentity: AgentControl.ActionIdentity(policyInput),
                    EnforcedIdentity: AgentControl.ActionIdentity(policyInput));
            }),
            telemetrySink: sink);

        await control.EvaluateInputAsync(new { text = "hi" });

        AssertSequence(
            ["alpha_scan", "zeta_scan"],
            sink.Events.Single().Annotators.ToArray(),
            "annotators should fall back to sorted result annotation keys.");
    }

    private static async Task EmitsOneDecisionEventAsync()
    {
        var sink = new InMemoryTelemetrySink();
        var control = new AgentControl(
            new TelemetryRuntime(request => WithIdentity(request, new Verdict(Decision.Deny, Reason: "unsafe_input"))),
            telemetrySink: sink);

        var result = await control.EvaluateInputAsync(new { text = "block me" });

        AssertEqual(Decision.Deny, result.Verdict.Decision, "telemetry test runtime should deny.");
        AssertEqual(1, sink.Events.Count, "one evaluation should emit one telemetry event.");
        var telemetryEvent = sink.Events.Single();
        AssertEqual(TelemetryEventType.Decision, telemetryEvent.EventType, "host telemetry should emit decision events.");
        AssertEqual(InterventionPoint.Input, telemetryEvent.InterventionPoint, "event should carry the intervention point.");
        AssertEqual(Decision.Deny, telemetryEvent.Decision, "event should carry the verdict decision.");
        AssertEqual("unsafe_input", telemetryEvent.ReasonCode, "identifier reason should pass through.");
        AssertEqual(result.ActionIdentity, telemetryEvent.ActionIdentity, "event should carry the enforced action identity.");
        AssertEqual(EnforcementMode.Enforce, telemetryEvent.EnforcementMode, "event should carry enforcement mode.");
        Assert(telemetryEvent.DurationMs is >= 0.0, "event should carry a non-negative duration.");
    }

    private static async Task CapturesAllDecisionsAsync()
    {
        var sink = new InMemoryTelemetrySink();
        var decisions = new Queue<Decision>([
            Decision.Allow,
            Decision.Deny,
            Decision.Warn,
            Decision.Escalate,
            Decision.Transform,
        ]);
        var control = new AgentControl(
            new TelemetryRuntime(request =>
            {
                var decision = decisions.Dequeue();
                var verdict = decision == Decision.Transform
                    ? new Verdict(decision, Reason: decision.ToWireName(), Transform: new Transform("$policy_target", "safe"))
                    : new Verdict(decision, Reason: decision.ToWireName());
                return WithIdentity(request, verdict);
            }),
            telemetrySink: sink);

        for (var index = 0; index < 5; index++)
        {
            await control.EvaluateInputAsync(new { text = $"case {index}" });
        }

        AssertEqual(5, sink.Events.Count, "in-memory sink should capture every evaluation.");
        AssertSequence(
            [Decision.Allow, Decision.Deny, Decision.Warn, Decision.Escalate, Decision.Transform],
            sink.Events.Select(telemetryEvent => telemetryEvent.Decision!.Value).ToArray(),
            "in-memory sink should capture all five decisions.");
    }

    private static async Task RedactsPayloadAndPointerValuesAsync()
    {
        AssertEqual(null, TelemetryRedaction.SafeReasonCode(null), "null reason should remain null.");
        AssertEqual("runtime_error:policy_failed", TelemetryRedaction.SafeReasonCode("runtime_error:policy_failed"), "identifier reason should pass through.");
        AssertEqual("policy_reason", TelemetryRedaction.SafeReasonCode("contains spaces"), "free text reason should be collapsed.");
        AssertEqual("policy_reason", TelemetryRedaction.SafeReasonCode("policy_理由"), "non-ASCII reason should be collapsed.");
        AssertEqual("runtime_error", TelemetryRedaction.ErrorClassFor("runtime_error:policy_failed"), "runtime error prefix should map to runtime_error.");
        AssertEqual(null, TelemetryRedaction.ErrorClassFor("policy_failed"), "non-runtime reasons should not carry an error class.");

        var sink = new InMemoryTelemetrySink();
        var control = new AgentControl(
            new TelemetryRuntime(request =>
            {
                var policyInput = JsonSerializer.SerializeToElement(new Dictionary<string, object?>
                {
                    ["intervention_point"] = request.InterventionPoint.ToWireName(),
                    ["policy_target"] = new Dictionary<string, object?> { ["value"] = "SECRET-PAYLOAD" },
                    ["snapshot"] = request.Snapshot,
                });
                return new InterventionPointResult(
                    new Verdict(
                        Decision.Allow,
                        Reason: "contains spaces",
                        Evidence: new Evidence(
                            "sha256:proof",
                            new Dictionary<string, string>
                            {
                                ["policy_registry"] = "https://example.com/policies/v1/",
                                ["issuer_pubkey"] = "https://example.com/keys/2026.pem",
                            })),
                    PolicyInput: policyInput,
                    ActionIdentity: AgentControl.ActionIdentity(policyInput));
            }),
            telemetrySink: sink);

        await control.EvaluateInputAsync(new { text = "SECRET-PAYLOAD" });

        var telemetryEvent = sink.Events.Single();
        AssertEqual("policy_reason", telemetryEvent.ReasonCode, "free text reason should be redacted.");
        AssertSequence(
            ["issuer_pubkey", "policy_registry"],
            telemetryEvent.EvidenceVerificationPointerKeys.ToArray(),
            "evidence pointer keys should be sorted.");
        var serialized = telemetryEvent.ToJsonString();
        Assert(!serialized.Contains("SECRET-PAYLOAD", StringComparison.Ordinal), "event should not contain policy target payload.");
        Assert(!serialized.Contains("https://example.com", StringComparison.Ordinal), "event should not contain pointer URL values.");
        Assert(serialized.Contains("issuer_pubkey", StringComparison.Ordinal), "event should contain pointer keys.");
    }

    private static async Task ThrowingSinkDoesNotAffectVerdictAsync()
    {
        var control = new AgentControl(
            new TelemetryRuntime(request => WithIdentity(request, new Verdict(Decision.Allow, Reason: "safe"))),
            telemetrySink: new ThrowingTelemetrySink());

        var result = await control.EvaluateInputAsync(new { text = "ok" });

        AssertEqual(Decision.Allow, result.Verdict.Decision, "throwing telemetry sink should not affect the verdict.");
    }

    private static void RecordsOtelCounter()
    {
        const string meterName = "agent_control_specification";
        double observed = 0.0;
        string? observedInstrument = null;
        KeyValuePair<string, object?>[] observedTags = [];
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, meterListener) =>
        {
            if (instrument.Meter.Name == meterName && instrument.Name == "acs_intervention_deny_total")
            {
                meterListener.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<double>((instrument, measurement, tags, _) =>
        {
            observedInstrument = instrument.Name;
            observed += measurement;
            observedTags = tags.ToArray();
        });
        listener.Start();

        using var sink = new OtelMetricsTelemetrySink();
        sink.Emit(new TelemetryEvent(
            TelemetryEventType.Decision,
            InterventionPoint.Input,
            Decision.Deny,
            "unsafe_input",
            policyId: "content_policy",
            annotators: ["prompt_classifier"],
            enforcementMode: EnforcementMode.Enforce,
            durationMs: 1.5,
            actionIdentity: "sha256:identity"));

        AssertEqual("acs_intervention_deny_total", observedInstrument, "OTel sink should increment the deny counter.");
        AssertEqual(1.0, observed, "OTel sink should add a double counter measurement.");
        Assert(observedTags.Any(tag => tag.Key == "decision" && (string?)tag.Value == "deny"), "OTel tags should include the decision.");
        Assert(observedTags.Any(tag => tag.Key == "policy_id" && (string?)tag.Value == "content_policy"), "OTel tags should include policy_id.");
        Assert(!observedTags.Any(tag => tag.Key == "action_identity"), "OTel tags should omit action_identity.");
    }

    private static async Task DefaultNullSinkEmitsNothingAsync()
    {
        var unusedSink = new InMemoryTelemetrySink();
        var runtime = new CountingRuntime();
        var control = new AgentControl(runtime);

        var result = await control.EvaluateInputAsync(new { text = "ok" });

        AssertEqual(Decision.Allow, result.Verdict.Decision, "default telemetry path should preserve the verdict.");
        AssertEqual(1, runtime.Calls, "default telemetry path should still evaluate once.");
        AssertEqual(0, unusedSink.Events.Count, "unconfigured sink should stay empty.");
    }

    private static async Task IndexesJsonManifestAsync()
    {
        var manifest = """
            {
              "agent_control_specification_version": "0.3.1-beta",
              "policies": {
                "content_policy": {
                  "type": "custom",
                  "adapter": "test"
                }
              },
              "intervention_points": {
                "input": {
                  "policy": {
                    "id": "content_policy"
                  },
                  "policy_target": "$.input",
                  "annotations": {
                    "zeta": {
                      "from": "$.input"
                    },
                    "alpha": {
                      "from": "$.input"
                    }
                  }
                }
              },
              "annotators": {
                "zeta": {
                  "type": "classifier"
                },
                "alpha": {
                  "type": "classifier"
                }
              }
            }
            """;
        var sink = new InMemoryTelemetrySink();
        var control = AgentControl.FromNative(
            manifest,
            new JsonManifestAnnotator(),
            new JsonManifestPolicy(),
            telemetrySink: sink);

        await control.EvaluateInputAsync(new { text = "ok" });

        var telemetryEvent = sink.Events.Single();
        AssertEqual("content_policy", telemetryEvent.PolicyId, "JSON manifest policy id should be indexed.");
        AssertSequence(["alpha", "zeta"], telemetryEvent.Annotators.ToArray(), "JSON manifest annotators should be sorted.");
    }

    private static async Task AdapterRunFunnelEmitsTelemetryAsync()
    {
        // Framework adapters (AutoGen, Agent Framework run middleware) delegate to
        // control.RunAsync, which funnels the input and output intervention points
        // through EvaluateInterventionPointAsync, so an adapter-driven call emits
        // telemetry with no adapter-specific wiring.
        var sink = new InMemoryTelemetrySink();
        var control = new AgentControl(
            new TelemetryRuntime(request => WithIdentity(request, new Verdict(Decision.Allow))),
            telemetrySink: sink);

        await control.RunAsync<object, object>(
            new { text = "hi" },
            (input, _) => new ValueTask<object>(new { answer = input }));

        AssertEqual(2, sink.Events.Count, "an adapter run should emit one event per intervention point.");
        AssertEqual(InterventionPoint.Input, sink.Events[0].InterventionPoint, "first adapter event should be the input point.");
        AssertEqual(InterventionPoint.Output, sink.Events[1].InterventionPoint, "second adapter event should be the output point.");
    }

    private static InterventionPointResult WithIdentity(InterventionPointRequest request, Verdict verdict)
    {
        var policyInput = JsonSerializer.SerializeToElement(new Dictionary<string, object?>
        {
            ["intervention_point"] = request.InterventionPoint.ToWireName(),
            ["snapshot"] = request.Snapshot,
        });
        return new InterventionPointResult(
            verdict,
            PolicyInput: policyInput,
            ActionIdentity: AgentControl.ActionIdentity(policyInput),
            InputIdentity: AgentControl.ActionIdentity(policyInput),
            EnforcedIdentity: AgentControl.ActionIdentity(policyInput));
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

    private static void AssertSequence<T>(IReadOnlyList<T> expected, IReadOnlyList<T> actual, string message)
    {
        if (!expected.SequenceEqual(actual))
        {
            throw new InvalidOperationException($"{message} Expected '{string.Join(",", expected)}', got '{string.Join(",", actual)}'.");
        }
    }
}

internal sealed class TelemetryRuntime : IAgentControlRuntime
{
    private readonly Func<InterventionPointRequest, InterventionPointResult> evaluate;

    public TelemetryRuntime(Func<InterventionPointRequest, InterventionPointResult> evaluate)
    {
        this.evaluate = evaluate;
    }

    public ValueTask<InterventionPointResult> EvaluateInterventionPointAsync(
        InterventionPointRequest request,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(evaluate(request));
    }
}

internal sealed class CountingRuntime : IAgentControlRuntime
{
    public int Calls { get; private set; }

    public ValueTask<InterventionPointResult> EvaluateInterventionPointAsync(
        InterventionPointRequest request,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Calls++;
        var policyInput = JsonSerializer.SerializeToElement(new Dictionary<string, object?>
        {
            ["intervention_point"] = request.InterventionPoint.ToWireName(),
            ["snapshot"] = request.Snapshot,
        });
        return ValueTask.FromResult(new InterventionPointResult(
            new Verdict(Decision.Allow),
            PolicyInput: policyInput,
            ActionIdentity: AgentControl.ActionIdentity(policyInput)));
    }
}

internal sealed class ThrowingTelemetrySink : ITelemetrySink
{
    public void Emit(TelemetryEvent telemetryEvent) => throw new InvalidOperationException("sink failed");

    public void ForceFlush()
    {
    }

    public void Shutdown()
    {
    }
}

internal sealed class JsonManifestAnnotator : IAnnotatorDispatcher
{
    public ValueTask<JsonElement> DispatchAsync(
        string annotatorName,
        JsonElement annotatorConfig,
        JsonElement preliminaryPolicyInput,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(JsonSerializer.SerializeToElement(new { name = annotatorName }));
    }
}

internal sealed class JsonManifestPolicy : IPolicyDispatcher
{
    public ValueTask<JsonElement> EvaluateAsync(
        JsonElement preparedInvocation,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(JsonSerializer.SerializeToElement(new
        {
            decision = "allow",
            reason = "manifest_indexed",
        }));
    }
}
