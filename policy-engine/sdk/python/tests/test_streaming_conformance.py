"""Pin the normative Python buffer-mode SSE guard to the shared streaming
conformance fixtures.

The fixtures in tests/conformance/streaming are the cross-SDK source of truth
for buffer-mode streaming. This test asserts that the Python implementation,
which generated them, continues to agree with them. If the Python guard
changes behavior the fixtures must be regenerated and every other SDK runner
re-verified, so this test fails loudly on drift.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from agent_control_specification._adapters import _sse
from agent_control_specification._adapters._errors import AdapterUnsupportedError

ROOT = pathlib.Path(__file__).resolve().parents[3]
STREAMING = ROOT / "tests" / "conformance" / "streaming"
MANIFEST = json.loads((STREAMING / "manifest.json").read_text())


def _read(rel: str) -> bytes:
    return (STREAMING / rel).read_bytes()


def test_limits_match_implementation() -> None:
    assert MANIFEST["limits"]["max_stream_bytes"] == _sse.MAX_STREAM_BYTES
    assert MANIFEST["limits"]["max_stream_events"] == _sse.MAX_STREAM_EVENTS


@pytest.mark.parametrize("case", MANIFEST["assemble"], ids=lambda c: c["name"])
def test_assemble_cases(case: dict) -> None:
    raw = _read(case["input"])
    if case["outcome"] == "ok":
        assert _sse.assemble_sse_stream(raw) == case["assembled"]
    else:
        with pytest.raises(AdapterUnsupportedError):
            _sse.assemble_sse_stream(raw)


@pytest.mark.parametrize("case", MANIFEST["synthesize"], ids=lambda c: c["name"])
def test_synthesize_cases(case: dict) -> None:
    out = _sse.synthesize_sse_stream(case["response"], case["template"])
    assert out == _read(case["expected_output"])


@pytest.mark.parametrize(
    "response",
    [
        {"choices": [{"index": 0, "message": {"content": "a"}}, {"index": 1, "message": {"content": "b"}}]},
        {"choices": [{"index": 1, "message": {"content": "wrong"}}]},
        {"choices": [{"index": 0, "message": {"content": {"not": "string"}}}]},
    ],
)
def test_synthesize_rejects_malformed_transformed_responses(response: dict) -> None:
    with pytest.raises(AdapterUnsupportedError):
        _sse.synthesize_sse_stream(response, {})
