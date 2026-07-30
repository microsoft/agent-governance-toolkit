# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the external checkpoint bridge example."""

from __future__ import annotations

import importlib.util
import json
import math
import sys
from pathlib import Path
from typing import Any

import pytest

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "external_checkpoint_bridge_demo", _HERE / "demo.py"
)
demo = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
sys.modules["external_checkpoint_bridge_demo"] = demo
_spec.loader.exec_module(demo)  # type: ignore[union-attr]


def test_stable_json_is_order_insensitive_and_unicode_preserving() -> None:
    left = {"b": 2, "a": "東京"}
    right = {"a": "東京", "b": 2}

    assert demo.stable_json(left) == demo.stable_json(right)
    assert demo.stable_json(left) == '{"a":"東京","b":2}'


def test_stable_json_rejects_non_standard_numbers() -> None:
    with pytest.raises(ValueError, match="Out of range float values"):
        demo.stable_json({"value": math.nan})


def _sample_envelope() -> demo.ActionEnvelope:
    return demo.build_action_envelope(
        actor="agent:test",
        runtime="test-runtime",
        tool_name="crm.export_customer_records",
        proposed_action="Export customer records for compliance review.",
        arguments={"record_limit": 25, "contains_pii": True},
        policy_id="policy:customer-data:v1",
    )


def test_action_ref_is_stable_and_opaque() -> None:
    first = _sample_envelope()
    second = _sample_envelope()

    assert first["action_ref"] == second["action_ref"]
    assert first["action_ref"].startswith("agt-demo-ref:")
    assert "record_limit" not in first["action_ref"]
    assert "contains_pii" not in first["action_ref"]
    assert "customer" not in first["action_ref"].lower()


@pytest.mark.parametrize(
    "url",
    [
        "http://checkpoint.example.com/review",
        "file:///tmp/checkpoint.json",
        "https:///missing-host",
    ],
)
def test_remote_checkpoint_requires_https_endpoint(url: str) -> None:
    with pytest.raises(ValueError, match="HTTPS endpoint"):
        demo.remote_checkpoint(url, _sample_envelope())


def test_remote_checkpoint_rejects_action_ref_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = _sample_envelope()
    observed: dict[str, Any] = {}

    class FakeResponse:
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps(
                {
                    "verdict": "allow",
                    "reason": "Approved by remote checkpoint.",
                    "decision_id": "dec_test",
                    "action_ref": "different-action-ref",
                }
            ).encode("utf-8")

    def fake_urlopen(request: Any, timeout: int) -> FakeResponse:
        observed["url"] = request.full_url
        observed["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(demo.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(ValueError, match="different action_ref"):
        demo.remote_checkpoint("https://checkpoint.example.com/review", envelope)

    assert observed == {
        "url": "https://checkpoint.example.com/review",
        "timeout": 10,
    }


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        ("not-json", "invalid JSON"),
        ("[]", "JSON object"),
        (
            json.dumps(
                {
                    "verdict": "escalate",
                    "reason": "Unsupported verdict.",
                    "decision_id": "dec_test",
                    "action_ref": "use-envelope-ref",
                }
            ),
            "verdict must be one of",
        ),
        (
            json.dumps(
                {
                    "verdict": "allow",
                    "reason": "",
                    "decision_id": "dec_test",
                    "action_ref": "use-envelope-ref",
                }
            ),
            "reason must be",
        ),
        (
            json.dumps(
                {
                    "verdict": "allow",
                    "reason": "Approved.",
                    "decision_id": "",
                    "action_ref": "use-envelope-ref",
                }
            ),
            "decision_id must be",
        ),
    ],
)
def test_parse_remote_verdict_rejects_malformed_payloads(
    payload: str, match: str
) -> None:
    envelope = _sample_envelope()
    payload = payload.replace("use-envelope-ref", envelope["action_ref"])

    with pytest.raises(ValueError, match=match):
        demo.parse_remote_verdict(payload, envelope)


def test_parse_remote_verdict_accepts_valid_payload() -> None:
    envelope = _sample_envelope()
    verdict = demo.parse_remote_verdict(
        json.dumps(
            {
                "verdict": "require_approval",
                "reason": "PII export requires human approval.",
                "decision_id": "dec_test",
                "action_ref": envelope["action_ref"],
            }
        ),
        envelope,
    )

    assert verdict == {
        "verdict": "require_approval",
        "reason": "PII export requires human approval.",
        "decision_id": "dec_test",
        "action_ref": envelope["action_ref"],
    }


def test_map_to_enforcement_rejects_unknown_verdict() -> None:
    with pytest.raises(ValueError, match="Unsupported checkpoint verdict"):
        demo.map_to_enforcement("escalate")  # type: ignore[arg-type]
