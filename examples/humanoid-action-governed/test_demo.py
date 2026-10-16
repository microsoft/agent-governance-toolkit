# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Behavioral tests against real AGT APIs; no physical hardware is controlled."""

import base64
import copy
import io
import json
import socket
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from demo import (
    BEATS,
    DemoSession,
    canonical,
    public_key,
    signed,
    valid_signature,
    verify_journal,
)
from verify import verify_export


class GovernanceBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.session = DemoSession()

    def approved(self):
        binding = self.session.make_binding()
        _, request = self.session.request_action(binding)
        self.session.approve(request)
        return binding, request

    def completed(self):
        for _ in range(len(BEATS) - 1):
            self.session.next()
        return self.session.export()

    def test_identical_misdirected_action_passes_motion_gate_but_agt_blocks(self):
        attack = self.session.attack
        receipt = self.session.baseline.execute(attack)
        self.assertEqual(receipt["body"]["outcome"], "completed_in_simulation")
        self.assertEqual(self.session.baseline.position, "visitor-pickup")
        decision, request = self.session.request_action(attack)
        self.assertEqual(decision.action, "deny")
        self.assertEqual(decision.matched_rule, "forbid-task-redirection")
        self.assertIsNone(request)
        self.assertEqual(self.session.controller.calls, 0)
        self.assertEqual(self.session.controller.motions, 0)

    def test_valid_agent_identity_does_not_grant_task_authority(self):
        self.session.request_action(self.session.attack)
        proof = self.session.events[-1]["body"]["request"]
        # Independent cryptography API, not the demo's verification helper.
        key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(self.session.agent_key)
        )
        key.verify(base64.b64decode(proof["signature"]), canonical(proof["body"]))
        self.assertEqual(self.session.policy_status, "deny")

    def test_unsigned_or_forged_identity_never_reaches_policy_or_controller(self):
        for signature in ("", "invalid", base64.b64encode(b"\0" * 64).decode()):
            with self.subTest(signature=signature):
                decision, request = self.session.request_action(
                    self.session.make_binding(), signature=signature
                )
                self.assertIsNone(decision)
                self.assertIsNone(request)
        self.assertEqual(self.session.controller.calls, 0)

    def test_unknown_tool_is_denied_by_default(self):
        decision, request = self.session.request_action(
            self.session.make_binding("humanoid.unknown")
        )
        self.assertEqual(decision.action, "deny")
        self.assertIsNone(request)

    def test_pending_approval_cannot_dispatch(self):
        binding = self.session.make_binding()
        decision, request = self.session.request_action(binding)
        self.assertEqual(decision.action, "require_approval")
        self.assertEqual(self.session.dispatch(binding, request), "no_resolution")
        self.assertEqual(self.session.controller.calls, 0)

    def test_approval_cannot_be_forged_by_an_untrusted_operator(self):
        binding = self.session.make_binding()
        _, request = self.session.request_action(binding)
        rogue = Ed25519PrivateKey.generate()
        proof = signed({"request_id": request.approval_request_id}, rogue)
        with self.assertRaises(ValueError):
            self.session.approve(request, proof=proof)
        self.assertEqual(self.session.dispatch(binding, request), "no_resolution")
        self.assertEqual(self.session.controller.calls, 0)

    def test_approved_parameters_cannot_be_substituted(self):
        binding, request = self.approved()
        self.assertEqual(
            self.session.dispatch(self.session.attack, request),
            "action_digest_mismatch",
        )
        self.assertEqual(self.session.controller.calls, 0)
        self.assertEqual(
            self.session.dispatch(binding, request), "completed_in_simulation"
        )
        self.assertEqual(self.session.controller.position, "inspection")

    def test_expired_approval_does_not_dispatch(self):
        binding, request = self.approved()
        self.session.clock.advance(61)
        self.assertEqual(self.session.dispatch(binding, request), "expired")
        self.assertEqual(self.session.controller.calls, 0)

    def test_policy_change_invalidates_approval(self):
        binding, request = self.approved()
        with patch("demo.Path.read_bytes", return_value=b"changed policy"):
            self.assertEqual(
                self.session.dispatch(binding, request), "policy_version_mismatch"
            )
        self.assertEqual(self.session.controller.calls, 0)

    def test_motion_gate_remains_authoritative_for_person_in_zone(self):
        binding, request = self.approved()
        self.session.controller.observe(human_present=True)
        self.assertEqual(self.session.dispatch(binding, request), "rejected")
        self.assertEqual(
            self.session.last_receipt["body"]["reason"], "person_in_work_zone"
        )
        self.assertEqual(self.session.controller.motions, 0)

    def test_stale_state_cannot_cause_motion(self):
        binding, request = self.approved()
        self.session.clock.advance(3)
        self.assertEqual(self.session.dispatch(binding, request), "rejected")
        self.assertEqual(
            self.session.last_receipt["body"]["reason"], "sensor_state_stale"
        )
        self.assertEqual(self.session.controller.motions, 0)

    def test_replay_does_not_dispatch_twice(self):
        binding, request = self.approved()
        self.assertEqual(
            self.session.dispatch(binding, request), "completed_in_simulation"
        )
        self.assertEqual(self.session.dispatch(binding, request), "already_consumed")
        self.assertEqual(self.session.controller.calls, 1)
        self.assertEqual(self.session.controller.motions, 1)

    def test_two_workers_cannot_reuse_one_approval(self):
        binding, request = self.approved()
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(
                executor.map(
                    lambda _: self.session.dispatch(binding, request), range(2)
                )
            )
        self.assertCountEqual(results, ["completed_in_simulation", "already_consumed"])
        self.assertEqual(self.session.controller.motions, 1)
        bundle = self.session.export()
        self.assertTrue(verify_export(bundle, bundle["trust"]))

    def test_missing_controller_reply_is_unknown_and_not_automatically_retried(self):
        binding, request = self.approved()
        with patch.object(
            self.session.controller, "execute", side_effect=TimeoutError
        ) as execute:
            self.assertEqual(self.session.dispatch(binding, request), "unknown")
            self.assertEqual(
                self.session.dispatch(binding, request), "already_consumed"
            )
        execute.assert_called_once()
        self.assertEqual(self.session.events[-2]["body"]["status"], "Unknown")

    def test_invalid_controller_signature_is_not_reported_as_completion(self):
        binding, request = self.approved()
        fake = signed(
            {"action_digest": binding.digest(), "outcome": "completed_in_simulation"},
            Ed25519PrivateKey.generate(),
        )
        with patch.object(self.session.controller, "execute", return_value=fake):
            self.assertEqual(self.session.dispatch(binding, request), "unknown")
        self.assertIsNone(self.session.last_receipt)

    def test_walkthrough_runs_with_external_network_disabled(self):
        with patch.object(
            socket.socket, "connect", side_effect=AssertionError("Network used")
        ):
            self.completed()
        self.assertEqual(self.session.controller.motions, 1)
        self.assertEqual(self.session.baseline.position, "visitor-pickup")
        self.assertTrue(all(self.session.verification.values()))

    def test_records_are_independently_verifiable_ed25519_signatures(self):
        bundle = self.completed()
        key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(bundle["trust"]["journal_key"])
        )
        for event in bundle["events"]:
            key.verify(base64.b64decode(event["signature"]), canonical(event["body"]))
        altered = copy.deepcopy(bundle["events"][-1])
        altered["body"]["detail"] = "An invented completion"
        with self.assertRaises(InvalidSignature):
            key.verify(
                base64.b64decode(altered["signature"]), canonical(altered["body"])
            )

    def test_export_verifies_against_separately_retained_trust(self):
        bundle = self.completed()
        self.assertTrue(verify_export(bundle, bundle["trust"]))
        self.assertFalse(
            verify_export(
                bundle,
                {
                    **bundle["trust"],
                    "journal_key": public_key(Ed25519PrivateKey.generate()),
                },
            )
        )

    def test_deleted_reordered_and_tail_truncated_evidence_is_rejected(self):
        bundle = self.completed()
        events = bundle["events"]
        for altered in ([], events[1:], list(reversed(events)), events[:-1]):
            with self.subTest(size=len(altered)):
                self.assertFalse(
                    verify_journal(
                        altered,
                        bundle["trust"]["journal_key"],
                        bundle["trust"]["expected_head"],
                    )
                )

    def test_changed_controller_outcome_is_rejected(self):
        bundle = self.completed()
        altered = copy.deepcopy(bundle)
        for event in altered["events"]:
            if event["body"]["kind"] == "controller_outcome":
                event["body"]["controller_receipt"]["body"]["position"] = (
                    "visitor-pickup"
                )
        self.assertFalse(verify_export(altered, bundle["trust"]))

    def test_untrusted_export_key_cannot_replace_pinned_key(self):
        bundle = self.completed()
        bundle["trust"]["journal_key"] = public_key(Ed25519PrivateKey.generate())
        self.assertFalse(
            valid_signature(bundle["events"][0], bundle["trust"]["journal_key"])
        )

    def test_no_private_key_is_exported(self):
        bundle = self.completed()
        serialized = json.dumps(bundle)
        self.assertNotIn("PRIVATE KEY", serialized)
        self.assertNotIn("private_key", serialized)

    def test_cli_rehearsal_exports_verifiable_evidence(self):
        import tempfile
        from pathlib import Path

        from demo import main

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "evidence.json"
            with (
                patch("sys.argv", ["demo.py", "--all", "--export", str(target)]),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(main(), 0)
            self.assertTrue(
                verify_export(
                    json.loads(target.read_text()),
                    json.loads(target.with_suffix(".trust.json").read_text()),
                )
            )


if __name__ == "__main__":
    unittest.main()
