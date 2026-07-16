# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the external checkpoint bridge example."""

from __future__ import annotations

import importlib.util
import json
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


def _sample_envelope() -> demo.ActionEnvelope:
    return demo.build_action_envelope(
        actor="agent:test",
        runtime="test-runtime",
        tool_name="crm.export_customer_records",
        proposed_action="Export customer records for compliance review.",
        arguments={"record_limit": 25, "contains_pii": True},
        policy_id="policy:customer-data:v1",
    )


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


def test_remote_checkpoint_rejects_action_hash_mismatch(
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
                    "action_hash": "different-action-hash",
                }
            ).encode("utf-8")

    def fake_urlopen(request: Any, timeout: int) -> FakeResponse:
        observed["url"] = request.full_url
        observed["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(demo.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(ValueError, match="different action_hash"):
        demo.remote_checkpoint("https://checkpoint.example.com/review", envelope)

    assert observed == {
        "url": "https://checkpoint.example.com/review",
        "timeout": 10,
    }
