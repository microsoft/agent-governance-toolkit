from __future__ import annotations

import asyncio
import unittest
from collections import deque

from agent_control_specification import (
    AgentControl,
    Decision,
    EnforcementMode,
    Evidence,
    InterventionPoint,
    InterventionPointRequest,
    InterventionPointResult,
    Transform,
    Verdict,
    action_identity,
)


class QueueRuntime:
    """Deterministic test runtime that hands out queued results in order."""

    def __init__(self, results):
        self.results = deque(results)
        self.requests = []

    async def evaluate_intervention_point(self, request: InterventionPointRequest) -> InterventionPointResult:
        self.requests.append(request)
        return self.results.popleft()


class VerdictMappingTests(unittest.TestCase):
    """Verify Verdict.from_mapping parses the AGT D1/D2 shapes."""

    def test_decision_enum_includes_transform(self):
        self.assertEqual(Decision("transform"), Decision.TRANSFORM)
        self.assertTrue(Decision.TRANSFORM.permits)
        self.assertTrue(Decision.TRANSFORM.applies_transform)

    def test_only_transform_applies_transform(self):
        # AGT D1: every non-transform permitting decision (allow, warn)
        # MUST NOT mutate the policy target. Deny and escalate also do
        # not mutate. Only transform mutates.
        for decision, should_transform in [
            (Decision.ALLOW, False),
            (Decision.WARN, False),
            (Decision.DENY, False),
            (Decision.ESCALATE, False),
            (Decision.TRANSFORM, True),
        ]:
            self.assertEqual(decision.applies_transform, should_transform, decision.value)

    def test_applies_effects_is_deprecated_alias_of_applies_transform(self):
        import warnings as _warnings

        for decision in Decision:
            with _warnings.catch_warnings(record=True) as captured:
                _warnings.simplefilter("always")
                value = decision.applies_effects
                self.assertEqual(value, decision.applies_transform)
                self.assertEqual(len(captured), 1)
                self.assertTrue(issubclass(captured[0].category, DeprecationWarning))

    def test_from_mapping_parses_transform_payload(self):
        verdict = Verdict.from_mapping(
            {
                "decision": "transform",
                "reason": "redacted",
                "transform": {"path": "$policy_target.text", "value": "[REDACTED]"},
            }
        )
        self.assertEqual(verdict.decision, Decision.TRANSFORM)
        self.assertIsInstance(verdict.transform, Transform)
        self.assertEqual(verdict.transform.path, "$policy_target.text")
        self.assertEqual(verdict.transform.value, "[REDACTED]")

    def test_from_mapping_parses_evidence_payload(self):
        verdict = Verdict.from_mapping(
            {
                "decision": "allow",
                "evidence": {
                    "artefact": "sha256:abcd",
                    "verification_pointers": {
                        "issuer_pubkey": "https://example.com/keys/2026.pem",
                        "policy_registry": "https://example.com/policies/v1/",
                    },
                },
            }
        )
        self.assertEqual(verdict.decision, Decision.ALLOW)
        self.assertIsInstance(verdict.evidence, Evidence)
        self.assertEqual(verdict.evidence.artefact, "sha256:abcd")
        self.assertEqual(
            dict(verdict.evidence.verification_pointers),
            {
                "issuer_pubkey": "https://example.com/keys/2026.pem",
                "policy_registry": "https://example.com/policies/v1/",
            },
        )

    def test_from_mapping_rejects_non_mapping_evidence(self):
        with self.assertRaises(ValueError):
            Verdict.from_mapping({"decision": "allow", "evidence": ["not", "a", "map"]})

    def test_from_mapping_rejects_non_string_pointer(self):
        with self.assertRaises(ValueError):
            Verdict.from_mapping(
                {
                    "decision": "allow",
                    "evidence": {
                        "artefact": "sha256:a",
                        "verification_pointers": {"k": 42},
                    },
                }
            )


class InterventionPointResultIdentityTests(unittest.TestCase):
    """AGT D1.4 bisected identity surface on InterventionPointResult."""

    def test_action_identity_aliases_enforced_identity(self):
        result = InterventionPointResult(
            Verdict(Decision.ALLOW),
            input_identity="sha256:input",
            enforced_identity="sha256:enforced",
        )
        # Backwards-compatible single-identity surface MUST return the
        # enforced identity per AGT D1.4 (the action that actually ran).
        self.assertEqual(result.action_identity, "sha256:enforced")

    def test_action_identity_returns_none_when_no_identity(self):
        result = InterventionPointResult(Verdict(Decision.DENY))
        self.assertIsNone(result.action_identity)
        self.assertIsNone(result.input_identity)
        self.assertIsNone(result.enforced_identity)

    def test_bisected_identity_persists_independently(self):
        result = InterventionPointResult(
            Verdict(Decision.TRANSFORM),
            input_identity="sha256:input",
            enforced_identity="sha256:enforced",
        )
        self.assertEqual(result.input_identity, "sha256:input")
        self.assertEqual(result.enforced_identity, "sha256:enforced")
        self.assertNotEqual(result.input_identity, result.enforced_identity)


class TransformEndToEndTests(unittest.IsolatedAsyncioTestCase):
    """AGT D1.1: TRANSFORM verdicts flow the engine's transformed payload."""

    async def test_run_uses_transformed_policy_target_in_enforce(self):
        transform = Transform(path="$policy_target.text", value="redacted")
        runtime = QueueRuntime(
            [
                InterventionPointResult(
                    Verdict(Decision.TRANSFORM, reason="redact_pii", transform=transform),
                    transformed_policy_target={"text": "redacted"},
                ),
                InterventionPointResult(Verdict(Decision.ALLOW)),
            ]
        )
        control = AgentControl(runtime)
        seen = []

        async def execute(value):
            seen.append(value)
            return {"answer": "ok"}

        result = await control.run({"text": "raw"}, execute)
        # The execute() callback MUST see the transformed input, not the
        # original. The post-output result is allow so the final value
        # passes through unchanged.
        self.assertEqual(seen, [{"text": "redacted"}])
        self.assertEqual(result.value, {"answer": "ok"})

    async def test_run_evaluate_only_does_not_apply_transform(self):
        transform = Transform(path="$policy_target.text", value="redacted")
        runtime = QueueRuntime(
            [
                InterventionPointResult(
                    Verdict(Decision.TRANSFORM, transform=transform),
                    transformed_policy_target={"text": "redacted"},
                ),
                InterventionPointResult(Verdict(Decision.ALLOW)),
            ]
        )
        control = AgentControl(runtime)
        seen = []

        async def execute(value):
            seen.append(value)
            return value

        result = await control.run(
            {"text": "raw"}, execute, mode=EnforcementMode.EVALUATE_ONLY
        )
        # In evaluate_only the SDK MUST NOT apply the engine transform.
        self.assertEqual(seen, [{"text": "raw"}])
        self.assertEqual(result.value, {"text": "raw"})

    async def test_warn_does_not_apply_transformed_policy_target(self):
        # Defence-in-depth: even if a runtime mistakenly attaches a
        # transformed_policy_target to a non-transform verdict, the SDK
        # MUST NOT apply it under AGT D1.
        runtime = QueueRuntime(
            [
                InterventionPointResult(
                    Verdict(Decision.WARN, reason="audited"),
                    transformed_policy_target={"text": "leaked"},
                ),
                InterventionPointResult(Verdict(Decision.ALLOW)),
            ]
        )
        control = AgentControl(runtime)
        seen = []

        async def execute(value):
            seen.append(value)
            return value

        await control.run({"text": "raw"}, execute)
        self.assertEqual(seen, [{"text": "raw"}])


class EvidenceRoundTripTests(unittest.TestCase):
    """AGT D2: Evidence rides through the Python SDK verbatim."""

    def test_evidence_propagates_from_native_response(self):
        # Mirror what NativeRuntimeClient does after the FFI returns: the
        # raw JSON-shape dict is fed through Verdict.from_mapping, and
        # the bisected identities + transformed payload sit alongside.
        raw = {
            "verdict": {
                "decision": "transform",
                "reason": "redact_account_number",
                "transform": {
                    "path": "$policy_target.text",
                    "value": "Please summarize account [REDACTED].",
                },
                "evidence": {
                    "artefact": "sha256:proof",
                    "verification_pointers": {
                        "issuer_pubkey": "https://example.com/keys/2026.pem",
                    },
                },
            },
            "transformed_policy_target": {"text": "Please summarize account [REDACTED]."},
            "policy_input": {"policy_target": {"value": {"text": "Please summarize account 1234."}}},
            "input_identity": "sha256:input",
            "enforced_identity": "sha256:enforced",
        }
        verdict = Verdict.from_mapping(raw["verdict"])
        result = InterventionPointResult(
            verdict=verdict,
            transformed_policy_target=raw.get("transformed_policy_target"),
            policy_input=raw.get("policy_input"),
            input_identity=raw.get("input_identity"),
            enforced_identity=raw.get("enforced_identity"),
        )
        self.assertEqual(result.verdict.decision, Decision.TRANSFORM)
        self.assertEqual(result.verdict.transform.path, "$policy_target.text")
        self.assertIsNotNone(result.verdict.evidence)
        self.assertEqual(result.verdict.evidence.artefact, "sha256:proof")
        self.assertEqual(
            result.verdict.evidence.verification_pointers["issuer_pubkey"],
            "https://example.com/keys/2026.pem",
        )
        self.assertEqual(result.input_identity, "sha256:input")
        self.assertEqual(result.enforced_identity, "sha256:enforced")
        self.assertEqual(result.action_identity, "sha256:enforced")


if __name__ == "__main__":
    unittest.main()
