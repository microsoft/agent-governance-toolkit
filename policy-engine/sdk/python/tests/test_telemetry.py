from __future__ import annotations

import io
import json
import os
import unittest
from collections import deque

from agent_control_specification import (
    AgentControl,
    Decision,
    EnforcementMode,
    Evidence,
    InMemoryTelemetrySink,
    InterventionPoint,
    InterventionPointResult,
    JsonStdoutTelemetrySink,
    MultiSink,
    OtelMetricsTelemetrySink,
    TelemetryEvent,
    TelemetryEventType,
    Verdict,
)
from agent_control_specification._orchestration import _labels_from_client
from agent_control_specification._telemetry import error_class_for, safe_reason_code


# Every key a redaction-safe decision event is allowed to carry. Any key
# outside this set would mean a payload leaked into telemetry.
ALLOWED_EVENT_KEYS = {
    "event_type",
    "intervention_point",
    "decision",
    "reason_code",
    "error_class",
    "policy_id",
    "annotators",
    "enforcement_mode",
    "duration_ms",
    "evidence_artefact",
    "evidence_verification_pointer_keys",
    "action_identity",
    "metadata",
}


class QueueRuntime:
    """Fake RuntimeClient that returns queued results without the native core."""

    def __init__(self, results):
        self.results = deque(results)
        self.requests = []

    async def evaluate_intervention_point(self, request):
        self.requests.append(request)
        return self.results.popleft()


class RaisingSink:
    def emit(self, event):
        raise RuntimeError("sink boom")

    def force_flush(self):
        raise RuntimeError("flush boom")

    def shutdown(self):
        raise RuntimeError("shutdown boom")


class TelemetryEmissionTests(unittest.IsolatedAsyncioTestCase):
    async def test_single_event_with_decision_reason_identity(self):
        result = InterventionPointResult(
            Verdict(
                Decision.WARN,
                reason="rate_limited",
                evidence=Evidence(
                    artefact="sha256:proofblob",
                    verification_pointers={
                        "policy_registry": "https://registry.example/policy",
                        "issuer_pubkey": "https://keys.example/issuer",
                    },
                ),
            ),
            policy_input={"annotations": {"prompt_classifier": {"x": 1}, "pii_scan": {"y": 2}}},
            enforced_identity="sha256:deadbeef",
        )
        sink = InMemoryTelemetrySink()
        control = AgentControl(QueueRuntime([result]), telemetry_sink=sink)

        await control.evaluate_intervention_point(
            InterventionPoint.PRE_TOOL_CALL,
            {"tool_call": {"name": "search", "args": {"q": "secret"}}},
        )

        self.assertEqual(len(sink.events), 1)
        event = sink.events[0]
        self.assertEqual(event.event_type, TelemetryEventType.DECISION)
        self.assertEqual(event.intervention_point, InterventionPoint.PRE_TOOL_CALL)
        self.assertEqual(event.decision, Decision.WARN)
        self.assertEqual(event.reason_code, "rate_limited")
        self.assertIsNone(event.error_class)
        self.assertEqual(event.enforcement_mode, EnforcementMode.ENFORCE)
        self.assertEqual(event.action_identity, "sha256:deadbeef")
        self.assertEqual(event.evidence_artefact, "sha256:proofblob")
        # Sorted pointer keys only, never the URL values.
        self.assertEqual(
            list(event.evidence_verification_pointer_keys),
            ["issuer_pubkey", "policy_registry"],
        )
        # Annotator names are sorted; their output values are withheld.
        self.assertEqual(list(event.annotators), ["pii_scan", "prompt_classifier"])
        self.assertIsInstance(event.duration_ms, float)
        self.assertGreaterEqual(event.duration_ms, 0.0)

    async def test_in_memory_sink_captures_every_decision(self):
        decisions = [
            Decision.ALLOW,
            Decision.DENY,
            Decision.WARN,
            Decision.ESCALATE,
            Decision.TRANSFORM,
        ]
        sink = InMemoryTelemetrySink()
        control = AgentControl(
            QueueRuntime([InterventionPointResult(Verdict(d)) for d in decisions]),
            telemetry_sink=sink,
        )

        for _ in decisions:
            await control.evaluate_intervention_point(
                InterventionPoint.INPUT, {"input": {"text": "hi"}}, EnforcementMode.EVALUATE_ONLY
            )

        self.assertEqual([event.decision for event in sink.events], decisions)

    async def test_run_emits_one_event_per_intervention_point(self):
        sink = InMemoryTelemetrySink()
        control = AgentControl(
            QueueRuntime(
                [
                    InterventionPointResult(Verdict(Decision.ALLOW)),
                    InterventionPointResult(Verdict(Decision.ALLOW)),
                ]
            ),
            telemetry_sink=sink,
        )

        await control.run({"text": "hello"}, lambda value: {"answer": value})

        self.assertEqual(
            [event.intervention_point for event in sink.events],
            [InterventionPoint.INPUT, InterventionPoint.OUTPUT],
        )


class TelemetryRedactionTests(unittest.IsolatedAsyncioTestCase):
    async def test_event_dict_holds_only_safe_fields(self):
        raw_prompt = "ATTACK leak this secret prompt"
        pointer_url = "https://registry.example/secret-path"
        result = InterventionPointResult(
            Verdict(
                Decision.DENY,
                reason="This free-text reason embeds " + raw_prompt,
                message="human readable " + raw_prompt,
                evidence=Evidence(
                    artefact="sha256:safe",
                    verification_pointers={"policy_registry": pointer_url},
                ),
            ),
            policy_input={
                "policy_target": {"value": {"text": raw_prompt}},
                "snapshot": {"input": {"text": raw_prompt}},
                "annotations": {"classifier": {"verdict": raw_prompt}},
            },
            enforced_identity="sha256:abc",
        )
        sink = InMemoryTelemetrySink()
        control = AgentControl(QueueRuntime([result]), telemetry_sink=sink)

        await control.evaluate_intervention_point(
            InterventionPoint.INPUT, {"input": {"text": raw_prompt}}
        )

        event = sink.events[0]
        as_dict = event.to_dict()
        # Only the allowed structural fields are present.
        self.assertEqual(set(as_dict), ALLOWED_EVENT_KEYS)
        # Free-text policy reason is collapsed to the constant marker.
        self.assertEqual(as_dict["reason_code"], "policy_reason")
        self.assertEqual(as_dict["error_class"], None)
        # Pointer keys are surfaced; the URL value is not.
        self.assertEqual(as_dict["evidence_verification_pointer_keys"], ["policy_registry"])
        # No raw payload, message text, or pointer URL anywhere in the serialized event.
        serialized = json.dumps(as_dict)
        self.assertNotIn(raw_prompt, serialized)
        self.assertNotIn("ATTACK", serialized)
        self.assertNotIn(pointer_url, serialized)
        self.assertNotIn("registry.example", serialized)

    def test_safe_reason_code_mirrors_core(self):
        # Identifier-shaped reasons pass through verbatim.
        self.assertEqual(safe_reason_code("runtime_error:request_invalid"), "runtime_error:request_invalid")
        self.assertEqual(safe_reason_code("account_number_redacted"), "account_number_redacted")
        # Free text collapses to the marker.
        self.assertEqual(safe_reason_code("blocked because the input was unsafe"), "policy_reason")
        # Over-long identifiers collapse too.
        self.assertEqual(safe_reason_code("a" * 97), "policy_reason")
        self.assertIsNone(safe_reason_code(None))

    def test_error_class_only_for_runtime_error(self):
        self.assertEqual(error_class_for("runtime_error:annotation_failed"), "runtime_error")
        self.assertIsNone(error_class_for("account_number_redacted"))
        self.assertIsNone(error_class_for(None))


class TelemetryFailureIsolationTests(unittest.IsolatedAsyncioTestCase):
    async def test_raising_sink_does_not_change_verdict_or_propagate(self):
        result = InterventionPointResult(Verdict(Decision.ALLOW, reason="ok"))
        control = AgentControl(QueueRuntime([result]), telemetry_sink=RaisingSink())

        returned = await control.evaluate_intervention_point(
            InterventionPoint.OUTPUT, {"output": {"text": "hi"}}
        )

        self.assertIs(returned, result)
        self.assertEqual(returned.verdict.decision, Decision.ALLOW)

    async def test_multisink_isolates_a_failing_child(self):
        good = InMemoryTelemetrySink()
        control = AgentControl(
            QueueRuntime([InterventionPointResult(Verdict(Decision.ALLOW))]),
            telemetry_sink=MultiSink([RaisingSink(), good]),
        )

        await control.evaluate_intervention_point(InterventionPoint.INPUT, {"input": 1})

        self.assertEqual(len(good.events), 1)

    async def test_event_construction_error_does_not_become_load_bearing(self):
        # A malformed result (non-string reason) makes TelemetryEvent.from_result
        # raise during construction. That must be caught like a sink error, never
        # propagate to fail the verdict. Guards the "telemetry is never
        # load-bearing" invariant for the build step, not just sink.emit.
        sink = InMemoryTelemetrySink()
        result = InterventionPointResult(Verdict(Decision.ALLOW, reason=123))
        control = AgentControl(QueueRuntime([result]), telemetry_sink=sink)

        returned = await control.evaluate_intervention_point(InterventionPoint.INPUT, {"input": 1})

        self.assertIs(returned, result)
        self.assertEqual(returned.verdict.decision, Decision.ALLOW)
        self.assertEqual(sink.events, [])


class TelemetrySinkCoercionTests(unittest.IsolatedAsyncioTestCase):
    async def test_list_of_sinks_is_fanned_out(self):
        a, b = InMemoryTelemetrySink(), InMemoryTelemetrySink()
        control = AgentControl(
            QueueRuntime([InterventionPointResult(Verdict(Decision.ALLOW))]),
            telemetry_sink=[a, b],
        )

        await control.evaluate_intervention_point(InterventionPoint.INPUT, {"input": 1})

        self.assertEqual(len(a.events), 1)
        self.assertEqual(len(b.events), 1)

    def test_non_sink_raises_at_construction(self):
        # A non-sink would otherwise be swallowed by the emit guard, silently
        # dropping every event. It must fail loudly at construction instead.
        with self.assertRaises(TypeError):
            AgentControl(QueueRuntime([]), telemetry_sink="not-a-sink")
        with self.assertRaises(TypeError):
            AgentControl(QueueRuntime([]), telemetry_sink=[InMemoryTelemetrySink(), object()])


class TelemetryDefaultBehaviorTests(unittest.IsolatedAsyncioTestCase):
    async def test_none_sink_emits_nothing_and_preserves_result(self):
        result = InterventionPointResult(Verdict(Decision.ALLOW))
        control = AgentControl(QueueRuntime([result]))
        self.assertIsNone(control._telemetry_sink)

        returned = await control.evaluate_intervention_point(InterventionPoint.INPUT, {"input": 1})

        self.assertIs(returned, result)


class TelemetryAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_guard_tool_adapter_emits_telemetry_for_each_point(self):
        # Adapters route through control.run_tool / evaluate_intervention_point,
        # the single instrumented funnel, so a sink-configured control emits
        # telemetry for adapter-driven calls with no adapter changes.
        from agent_control_specification import guard_tool

        sink = InMemoryTelemetrySink()
        control = AgentControl(
            QueueRuntime(
                [
                    InterventionPointResult(Verdict(Decision.ALLOW)),
                    InterventionPointResult(Verdict(Decision.ALLOW)),
                ]
            ),
            telemetry_sink=sink,
        )
        guarded = guard_tool(control, "search", lambda args: {"hits": args})

        await guarded({"q": "x"})

        self.assertEqual(
            [event.intervention_point for event in sink.events],
            [InterventionPoint.PRE_TOOL_CALL, InterventionPoint.POST_TOOL_CALL],
        )


class JsonStdoutSinkTests(unittest.TestCase):
    def test_writes_one_json_object_per_line(self):
        stream = io.StringIO()
        sink = JsonStdoutTelemetrySink(stream)
        sink.emit(
            TelemetryEvent.from_result(
                InterventionPoint.INPUT,
                EnforcementMode.ENFORCE,
                InterventionPointResult(Verdict(Decision.ALLOW, reason="ok")),
                1.5,
                policy_id="content_policy",
            )
        )
        sink.emit(
            TelemetryEvent.from_result(
                InterventionPoint.OUTPUT,
                EnforcementMode.ENFORCE,
                InterventionPointResult(Verdict(Decision.DENY, reason="runtime_error:request_invalid")),
                2.0,
            )
        )

        lines = stream.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        first = json.loads(lines[0])
        self.assertEqual(first["decision"], "allow")
        self.assertEqual(first["policy_id"], "content_policy")
        second = json.loads(lines[1])
        self.assertEqual(second["decision"], "deny")
        self.assertEqual(second["error_class"], "runtime_error")


class PolicyLabelIndexTests(unittest.IsolatedAsyncioTestCase):
    def test_labels_from_client_builds_both_indexes(self):
        class LabeledClient:
            async def evaluate_intervention_point(self, request):
                raise NotImplementedError

            def policy_labels(self):
                return {
                    "input": {"policy_id": "content_policy", "annotators": ["prompt_classifier", "pii_scan"]},
                    "output": {"policy_id": "out_policy", "annotators": []},
                }

        policy_ids, annotators = _labels_from_client(LabeledClient())
        self.assertEqual(policy_ids, {"input": "content_policy", "output": "out_policy"})
        # Sorted; points with no annotators are omitted.
        self.assertEqual(annotators, {"input": ("pii_scan", "prompt_classifier")})

    def test_labels_from_client_without_method_is_empty(self):
        policy_ids, annotators = _labels_from_client(QueueRuntime([]))
        self.assertEqual(policy_ids, {})
        self.assertEqual(annotators, {})

    def test_labels_from_client_never_raises(self):
        class BadClient:
            async def evaluate_intervention_point(self, request):
                raise NotImplementedError

            def policy_labels(self):
                raise RuntimeError("native boom")

        self.assertEqual(_labels_from_client(BadClient()), ({}, {}))

    async def test_policy_id_lookup_populates_event(self):
        sink = InMemoryTelemetrySink()
        control = AgentControl(
            QueueRuntime([InterventionPointResult(Verdict(Decision.ALLOW))]),
            telemetry_sink=sink,
        )
        control._policy_id_index = {"input": "content_policy"}

        await control.evaluate_intervention_point(InterventionPoint.INPUT, {"input": 1})

        self.assertEqual(sink.events[0].policy_id, "content_policy")

    async def test_annotators_from_index_survive_failure_path(self):
        # On a fail-closed result the policy_input is absent, so the configured
        # annotator names must come from the manifest index (mirroring the Rust
        # annotators_for source), not the empty result annotations.
        sink = InMemoryTelemetrySink()
        failed = InterventionPointResult(
            Verdict(Decision.DENY, reason="runtime_error:annotation_failed"),
            policy_input=None,
        )
        control = AgentControl(QueueRuntime([failed]), telemetry_sink=sink)
        control._annotator_index = {"input": ("pii_scan", "prompt_classifier")}

        await control.evaluate_intervention_point(InterventionPoint.INPUT, {"input": 1})

        self.assertEqual(list(sink.events[0].annotators), ["pii_scan", "prompt_classifier"])


class OtelMetricsSinkTests(unittest.TestCase):
    def test_no_op_when_opentelemetry_absent(self):
        try:
            import opentelemetry  # noqa: F401
        except ImportError:
            pass
        else:
            self.skipTest("opentelemetry is installed; covered by the metrics test")

        sink = OtelMetricsTelemetrySink()
        self.assertFalse(sink.available)
        # emit / force_flush / shutdown must be safe no-ops.
        sink.emit(
            TelemetryEvent.from_result(
                InterventionPoint.INPUT,
                EnforcementMode.ENFORCE,
                InterventionPointResult(Verdict(Decision.DENY)),
                1.0,
            )
        )
        sink.force_flush()
        sink.shutdown()

    def test_increments_decision_counter_when_sdk_present(self):
        try:
            from opentelemetry.sdk.metrics import MeterProvider
            from opentelemetry.sdk.metrics.export import InMemoryMetricReader
        except ImportError:
            self.skipTest("opentelemetry-sdk is not installed")

        # A sibling real-package test (crewai) can set OTEL_SDK_DISABLED in the
        # process env, which turns every SDK MeterProvider into a no-op. Clear
        # it for this test so the in-memory reader can observe the metric, then
        # restore it.
        previous_disabled = os.environ.pop("OTEL_SDK_DISABLED", None)
        try:
            reader = InMemoryMetricReader()
            provider = MeterProvider(metric_readers=[reader])
            sink = OtelMetricsTelemetrySink("agent_control_specification", meter_provider=provider)
            self.assertTrue(sink.available)

            sink.emit(
                TelemetryEvent.from_result(
                    InterventionPoint.PRE_TOOL_CALL,
                    EnforcementMode.ENFORCE,
                    InterventionPointResult(Verdict(Decision.DENY, reason="blocked")),
                    3.2,
                )
            )

            data = reader.get_metrics_data()
        finally:
            if previous_disabled is not None:
                os.environ["OTEL_SDK_DISABLED"] = previous_disabled

        points = _collect_metric_points(data)
        self.assertEqual(points.get("acs_intervention_deny_total"), 1.0)
        self.assertIn("acs_intervention_duration_ms", points)
        # The counter must record a float so its OTLP Sum data point is
        # double-typed, matching the Rust f64_counter (no mixed int/float series).
        self.assertIsInstance(_counter_point_value(data, "acs_intervention_deny_total"), float)


def _collect_metric_points(metrics_data) -> dict[str, float]:
    totals: dict[str, float] = {}
    for resource_metric in metrics_data.resource_metrics:
        for scope_metric in resource_metric.scope_metrics:
            for metric in scope_metric.metrics:
                for point in metric.data.data_points:
                    value = getattr(point, "value", None)
                    if value is None:
                        value = getattr(point, "count", None)
                    totals[metric.name] = float(value) if value is not None else 0.0
    return totals


def _counter_point_value(metrics_data, name):
    for resource_metric in metrics_data.resource_metrics:
        for scope_metric in resource_metric.scope_metrics:
            for metric in scope_metric.metrics:
                if metric.name != name:
                    continue
                for point in metric.data.data_points:
                    return getattr(point, "value", None)
    return None


try:
    from agent_control_specification import _native  # noqa: F401
except ImportError:
    _NATIVE_AVAILABLE = False
else:
    _NATIVE_AVAILABLE = True


_CHAIN_BASE = """agent_control_specification_version: 0.3.1-beta
metadata:
  name: base
policies:
  content_policy:
    type: custom
    adapter: test
annotators:
  prompt_classifier:
    type: classifier
intervention_points:
  input:
    policy_target: $.input
    policy:
      id: content_policy
    annotations:
      prompt_classifier:
        from: $policy_target.text
"""

_CHAIN_OVERLAY = """agent_control_specification_version: 0.3.1-beta
intervention_points:
  output:
    policy_target: $.output
    policy:
      id: content_policy
"""


@unittest.skipUnless(_NATIVE_AVAILABLE, "native extension not built")
class NativePolicyLabelTests(unittest.IsolatedAsyncioTestCase):
    async def test_from_manifest_chain_populates_policy_id_and_annotators(self):
        # Regression: policy_id and annotators were None/empty on
        # from_manifest_chain because the host parsed manifest text it never had
        # for merged sources. They are now sourced from the native merged
        # manifest via policy_labels, so the label is present.
        class AllowPolicy:
            def evaluate(self, invocation):
                return {"decision": "allow"}

        sink = InMemoryTelemetrySink()
        control = AgentControl.from_manifest_chain(
            [_CHAIN_BASE, _CHAIN_OVERLAY],
            policy_dispatcher=AllowPolicy(),
            telemetry_sink=sink,
        )

        await control.evaluate_intervention_point(
            InterventionPoint.INPUT, {"input": {"text": "hi"}}
        )

        self.assertEqual(sink.events[0].policy_id, "content_policy")
        self.assertEqual(list(sink.events[0].annotators), ["prompt_classifier"])

    async def test_from_native_yaml_populates_labels(self):
        # A YAML manifest string through from_native now labels events, where the
        # old host-side JSON-only parse would have left policy_id None.
        class AllowPolicy:
            def evaluate(self, invocation):
                return {"decision": "allow"}

        sink = InMemoryTelemetrySink()
        control = AgentControl.from_native(
            _CHAIN_BASE, policy_dispatcher=AllowPolicy(), telemetry_sink=sink
        )

        await control.evaluate_intervention_point(
            InterventionPoint.INPUT, {"input": {"text": "hi"}}
        )

        self.assertEqual(sink.events[0].policy_id, "content_policy")
        self.assertEqual(list(sink.events[0].annotators), ["prompt_classifier"])


if __name__ == "__main__":
    unittest.main()
