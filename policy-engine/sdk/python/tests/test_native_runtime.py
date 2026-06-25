from __future__ import annotations

import asyncio
import unittest
from pathlib import Path

from agent_control_specification import AgentControl, Decision, InterventionPoint, PerfTelemetry

try:
    from agent_control_specification import _native  # noqa: F401
except ImportError:
    _NATIVE_AVAILABLE = False
else:
    _NATIVE_AVAILABLE = True


MANIFEST_YAML = """agent_control_specification_version: 0.3.1-beta
metadata:
  name: basic-host-example
policies:
  input_custom_policy:
    type: custom
    adapter: basic_host_mock
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: input_custom_policy
    policy_target: $.input
    annotations:
      prompt_classifier:
        from: $.input.text
annotators:
  prompt_classifier:
    type: classifier
"""


class MockAnnotator:
    def dispatch(self, annotator_name, annotator_config, preliminary_policy_input):
        text = preliminary_policy_input["policy_target"]["value"]["text"]
        return {
            "annotator": annotator_name,
            "contains_account_number": "1234" in text,
        }


class MockPolicy:
    def evaluate(self, invocation):
        contains_account_number = invocation["input"]["annotations"]["prompt_classifier"][
            "contains_account_number"
        ]
        if contains_account_number:
            # AGT D1: effects[] is rejected; canonical mutation path is
            # the transform decision with a single-target replacement.
            return {
                "decision": "transform",
                "reason": "account_number_redacted",
                "message": "Account number was redacted before continuing.",
                "transform": {
                    "path": "$policy_target.text",
                    "value": "Please summarize account [REDACTED].",
                },
            }
        return {"decision": "allow"}


@unittest.skipUnless(_NATIVE_AVAILABLE, "agent_control_specification._native extension is not built")
class NativeRuntimeTests(unittest.TestCase):
    def test_basic_host_scenario_through_native_runtime(self):
        async def run():
            control = AgentControl.from_native(MANIFEST_YAML, MockAnnotator(), MockPolicy())
            return await control.evaluate_intervention_point(
                InterventionPoint.INPUT,
                {
                    "input": {"text": "Please summarize account 1234."},
                    "actor": {"id": "user-123"},
                    "transport": {"kind": "api_gateway", "route": "/chat"},
                },
            )

        result = asyncio.run(run())

        self.assertEqual(result.verdict.decision, Decision.TRANSFORM)
        self.assertEqual(
            result.transformed_policy_target,
            {"text": "Please summarize account [REDACTED]."},
        )

    def test_annotator_exception_details_are_sanitized(self):
        class ThrowingAnnotator:
            def dispatch(self, annotator_name, annotator_config, preliminary_policy_input):
                raise RuntimeError("secret sentinel should not leak")

        async def run():
            control = AgentControl.from_native(MANIFEST_YAML, ThrowingAnnotator(), MockPolicy())
            return await control.evaluate_intervention_point(
                InterventionPoint.INPUT,
                {"input": {"text": "Please summarize account 1234."}},
            )

        result = asyncio.run(run())
        self.assertEqual(result.verdict.decision, Decision.DENY)
        self.assertEqual(result.verdict.reason, "runtime_error:annotation_failed")
        self.assertNotIn("secret sentinel", repr(result.verdict))

    def test_native_runtime_returns_result_labels(self):
        # IFC propagation: a policy that emits result_labels must have them
        # surfaced verbatim on the verdict so the host can re-supply them as
        # source_labels on a subsequent turn.
        class LabelingPolicy:
            def evaluate(self, invocation):
                return {"decision": "allow", "result_labels": ["confidential"]}

        async def run():
            control = AgentControl.from_native(MANIFEST_YAML, MockAnnotator(), LabelingPolicy())
            return await control.evaluate_intervention_point(
                InterventionPoint.INPUT,
                {"input": {"text": "hello"}},
            )

        result = asyncio.run(run())
        self.assertEqual(result.verdict.decision, Decision.ALLOW)
        self.assertEqual(list(result.verdict.result_labels), ["confidential"])

    def test_native_runtime_preserves_explicit_null_transform(self):
        manifest = """agent_control_specification_version: 0.3.1-beta
policies:
  p:
    type: custom
    adapter: test
intervention_points:
  input:
    policy:
      id: p
    policy_target: $.input
  output:
    policy:
      id: p
    policy_target: $.output
"""

        class NullingPolicy:
            def evaluate(self, invocation):
                if invocation["input"]["intervention_point"] != "input":
                    return {"decision": "allow"}
                return {
                    "decision": "transform",
                    "transform": {"path": "$policy_target", "value": None},
                }

        async def run():
            control = AgentControl.from_native(manifest, MockAnnotator(), NullingPolicy())
            return await control.run(
                {"text": "clear me"},
                lambda value: {"received": value},
            )

        result = asyncio.run(run())
        self.assertIsNone(result.input_result.transformed_policy_target)
        self.assertTrue(result.input_result.transformed_policy_target_applied)
        self.assertEqual(result.value, {"received": None})

    def test_native_runtime_unknown_intervention_point_fails_closed(self):
        async def run():
            control = AgentControl.from_native(MANIFEST_YAML, MockAnnotator(), MockPolicy())
            return await control.evaluate_intervention_point(
                "not_a_real_intervention_point",
                {"input": {"text": "hello"}},
            )

        result = asyncio.run(run())
        self.assertEqual(result.verdict.decision, Decision.DENY)
        self.assertEqual(result.verdict.reason, "runtime_error:intervention_point_unknown")

    def test_native_runtime_malformed_request_envelope_fails_closed(self):
        runtime = _native.NativeRuntime(
            MANIFEST_YAML,
            MockAnnotator().dispatch,
            MockPolicy().evaluate,
        )
        cases = [
            {"snapshot": {"input": {"text": "hello"}}, "mode": "enforce"},
            {"intervention_point": "input", "mode": "enforce"},
            {"intervention_point": "input", "snapshot": [], "mode": "enforce"},
            {"intervention_point": "input", "snapshot": {"input": {"text": "hello"}}, "mode": "bogus"},
            {"intervention_point": "input", "snapshot": {"input": {"text": "hello"}}, "mode": 1},
            [],
        ]

        for request in cases:
            with self.subTest(request=request):
                result = runtime.evaluate(request)
                self.assertEqual(result["verdict"]["decision"], "deny")
                self.assertEqual(result["verdict"]["reason"], "runtime_error:request_invalid")
                self.assertIsNone(result["policy_input"])

    def test_high_level_unknown_mode_fails_closed(self):
        async def run():
            control = AgentControl.from_native(MANIFEST_YAML, MockAnnotator(), MockPolicy())
            return await control.evaluate_intervention_point(
                InterventionPoint.INPUT,
                {"input": {"text": "hello"}},
                "bogus",
            )

        result = asyncio.run(run())
        self.assertEqual(result.verdict.decision, Decision.DENY)
        self.assertEqual(result.verdict.reason, "runtime_error:request_invalid")

    def test_from_manifest_chain_threads_perf_telemetry(self):
        # Regression guard: the high level facade must accept and thread
        # perf_telemetry through from_manifest_chain (and from_path), matching
        # from_native and the other SDKs. A live audit found these loaders had
        # dropped the perf_telemetry argument.
        chain_child = (
            "agent_control_specification_version: 0.3.1-beta\n"
            "tools:\n"
            "  noop_tool:\n"
            "    clearance: public\n"
        )

        async def run():
            control = AgentControl.from_manifest_chain(
                [MANIFEST_YAML, chain_child],
                MockAnnotator(),
                MockPolicy(),
                perf_telemetry=int(PerfTelemetry.FULL),
            )
            return await control.evaluate_intervention_point(
                InterventionPoint.INPUT,
                {"input": {"text": "Please summarize account 1234."}},
            )

        result = asyncio.run(run())
        self.assertEqual(result.verdict.decision, Decision.TRANSFORM)


def _opa_available() -> bool:
    import subprocess

    try:
        return subprocess.run(["opa", "version"], capture_output=True).returncode == 0
    except FileNotFoundError:
        return False


_SUPPORT_MANIFEST = (
    Path(__file__).resolve().parents[3] / "examples/support_agent/manifest.yaml"
)

NON_REGO_MANIFEST = """agent_control_specification_version: 0.3.1-beta
metadata:
  name: zero-config-non-rego
policies:
  p:
    type: custom
    adapter: host_mock
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: p
    policy_target: $.input
"""

REGO_MANIFEST = """agent_control_specification_version: 0.3.1-beta
metadata:
  name: zero-config-rego
policies:
  p:
    type: rego
    bundle: ./policy
    query: data.acs.verdict
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: p
    policy_target: $.input
"""


@unittest.skipUnless(_NATIVE_AVAILABLE, "agent_control_specification._native extension is not built")
class ZeroConfigDefaultsTests(unittest.TestCase):
    @unittest.skipUnless(_opa_available(), "opa binary not available")
    def test_from_path_builds_with_no_dispatchers(self):
        # A Rego manifest with a relative `bundle` resolves against the manifest
        # directory and wires the bundled OPA + annotator defaults with no host
        # dispatcher wiring.
        self.assertTrue(_SUPPORT_MANIFEST.exists())
        control = AgentControl.from_path(str(_SUPPORT_MANIFEST))
        self.assertIsNotNone(control._runtime_client._native)

    def test_from_url_rejects_non_https_and_fails_closed(self):
        # The top level manifest URL loader reuses the extends trust gate, so a
        # non HTTPS URL is refused before any network access, with or without a
        # pin.
        with self.assertRaises(RuntimeError) as ctx:
            AgentControl.from_url("http://policy.example/manifest.yaml")
        self.assertIn("runtime_error:manifest_invalid", str(ctx.exception))

    def test_from_url_pin_is_optional(self):
        # The pin is optional, mirroring URL extends. Omitting it still reaches
        # the loader; here a non HTTPS URL surfaces the loader error, confirming
        # the unpinned call path is wired.
        with self.assertRaises(RuntimeError) as ctx:
            AgentControl.from_url("http://policy.example/manifest.yaml", sha256=None)
        self.assertIn("unsupported URL scheme", str(ctx.exception))

    def test_from_url_malformed_pin_fails_closed_before_fetch(self):
        # A supplied pin is validated for format before any network access, which
        # confirms the sha256 argument threads through the Python wrapper, the
        # native binding, and the core loader. "zz" is not 64 hex characters.
        with self.assertRaises(RuntimeError) as ctx:
            AgentControl.from_url("https://policy.example/manifest.yaml", sha256="zz")
        self.assertIn("runtime_error:manifest_invalid", str(ctx.exception))

    def test_from_url_threads_url_fetch_limits(self):
        # The optional URL fetch limit overrides thread through the wrapper, the
        # client, and the native binding. A non HTTPS URL still fails closed
        # before any network access, confirming the extra arguments are wired
        # without changing the trust gate.
        with self.assertRaises(RuntimeError) as ctx:
            AgentControl.from_url(
                "http://policy.example/manifest.yaml",
                max_url_bytes=4096,
                url_timeout_ms=1000,
                max_url_redirects=0,
            )
        self.assertIn("unsupported URL scheme", str(ctx.exception))

    def test_from_path_bad_explicit_opa_path_fails_closed_on_evaluation(self):
        import os
        import tempfile

        previous = os.environ.get("ACS_OPA_PATH")
        os.environ["ACS_OPA_PATH"] = "/definitely/not/a/real/opa"
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
            handle.write(REGO_MANIFEST)
            path = handle.name
        try:
            control = AgentControl.from_path(path)
            result = asyncio.run(
                control.evaluate_intervention_point(
                    InterventionPoint.INPUT,
                    {"input": {"text": "hello"}},
                )
            )
            self.assertEqual(result.verdict.decision, Decision.DENY)
            self.assertEqual(result.verdict.reason, "runtime_error:policy_invocation_failed")
        finally:
            os.unlink(path)
            if previous is None:
                os.environ.pop("ACS_OPA_PATH", None)
            else:
                os.environ["ACS_OPA_PATH"] = previous

    def test_default_policy_dispatcher_rejects_non_rego(self):
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
            handle.write(NON_REGO_MANIFEST)
            path = handle.name
        try:
            with self.assertRaises(Exception) as ctx:
                AgentControl.from_path(path)
            self.assertIn("only Rego", str(ctx.exception))
        finally:
            import os

            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
