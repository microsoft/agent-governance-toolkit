# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Test AGT retry traces against the observed-effect corpus.

The corpus uses a public test key. A valid result means corpus conformance,
not that an observed effect is trustworthy in a deployment.
"""

from __future__ import annotations

import base64
import json
import sys
from datetime import UTC, datetime, timedelta
from importlib import import_module, resources
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from agentmesh.governance.audit import AuditEntry
from agentmesh.governance.trace_model import (
    TraceModelConfig,
    TraceSession,
    session_to_trust_record,
)

_ZEROS = "0" * 64
_TARGET = "/srv/app/orders/ord-0017.json"
_CORPUS_PACKAGE = "agent_evidence_vectors"

_CONFIG = TraceModelConfig(
    model={
        "provider": "example",
        "model_id": "example-model",
        "version": "1.0",
        "weights_digest": f"sha256:{_ZEROS}",
    },
    runtime={"platform": "software-only", "measurement": f"sha256:{_ZEROS}"},
    enforcement_mode="enforce",
    build_provenance={
        "slsa_level": 2,
        "builder": "github-actions",
        "digest": f"sha256:{_ZEROS}",
    },
    verifier="https://verifier.agentrust-io.com",
)


def _corpus_dir() -> Any:
    """Return the installed observed-effect fixture directory."""
    return resources.files(_CORPUS_PACKAGE) / "corpora" / "vectors-observed-effect"


def _manifest() -> dict[str, Any]:
    """Read the corpus manifest for fixture paths and its public test key."""
    return json.loads((_corpus_dir() / "MANIFEST.json").read_text(encoding="utf-8"))


def _member(slug: str) -> bytes:
    """Return the signed fixture selected by its stable corpus slug."""
    for entry in _manifest()["vectors"]:
        if entry["slug"] == slug:
            return (_corpus_dir() / entry["file"]).read_bytes()
    raise AssertionError(f"observed-effect corpus has no member {slug!r}")


def _judge(slug: str) -> Any:
    """Verify a fixture with the corpus's public test key."""
    if sys.version_info < (3, 13):
        pytest.skip("agent-evidence-vectors requires Python 3.13 or later")
    observedeffect = import_module("agent_evidence_vectors.observedeffect")
    manifest = _manifest()
    policy = observedeffect.Policy(
        predicate_type=manifest["predicateType"],
        observer_public_key=manifest["keys"]["observer"]["publicKey"],
    )
    return observedeffect.verify(_member(slug), policy)


def _predicate(slug: str) -> dict[str, Any]:
    """Decode a fixture's predicate after signature verification."""
    payload = base64.b64decode(json.loads(_member(slug))["payload"])
    return json.loads(payload)["predicate"]


def _reported_attempts(predicate: dict[str, Any]) -> int:
    """Read the agent's reported attempt count."""
    values = [value for value in predicate["dualValues"] if value["fact"] == "tool.attempts"]
    assert len(values) == 1
    return int(values[0]["reportedValue"])


def _retried_session(attempts: int = 2) -> TraceSession:
    """Build a write trace with timeouts before the final response."""
    t0 = datetime(2026, 9, 19, 0, 0, 1, tzinfo=UTC)
    common = {
        "event_type": "tool_invocation",
        "agent_did": "did:mesh:orders-agent",
        "action": "write_order",
        "resource": _TARGET,
    }
    return TraceSession(
        agent_did="did:mesh:orders-agent",
        audit_entries=[
            AuditEntry(
                **common,
                entry_id=f"audit_op0017_attempt{attempt}",
                timestamp=t0 + timedelta(seconds=2 * (attempt - 1)),
                outcome="success" if attempt == attempts else "error",
                data={
                    "operation_id": "op-0017",
                    "attempt": attempt,
                    **({"error": "timeout"} if attempt < attempts else {}),
                },
            )
            for attempt in range(1, attempts + 1)
        ],
        data_class="internal",
    )


class TestRetryEffect:
    """Check AGT's attempt count without inferring an effect count."""

    __test__ = False

    @staticmethod
    def assert_attempt_record() -> dict[str, Any]:
        """Check AGT's mapper and return its bounded attempt claim."""
        record = session_to_trust_record(_retried_session(), _CONFIG)
        assert record["tool_transcript"]["call_count"] == 2
        assert set(record["tool_transcript"]) == {"call_count", "hash"}
        assert record["appraisal"]["status"] == "affirming"
        return record


class TestPassingCases(TestRetryEffect):
    """Check AGT's bounded attempt record."""

    __test__ = True

    def test_agt_attempt_count_on_all_supported_python_versions(self) -> None:
        """Exercise AGT even when the optional corpus cannot be installed."""
        self.assert_attempt_record()

    @settings(max_examples=20)
    @given(st.integers(min_value=1, max_value=8))
    def test_timeout_retries_remain_attempts(self, attempts: int) -> None:
        """Count calls across bounded retry lengths without inventing effects."""
        record = session_to_trust_record(_retried_session(attempts), _CONFIG)
        assert record["tool_transcript"]["call_count"] == attempts
        assert record["appraisal"]["status"] == "affirming"
        assert set(record["tool_transcript"]) == {"call_count", "hash"}

    @pytest.mark.parametrize(
        ("slug", "write_count", "absence_established"),
        [
            ("retry-one-write-across-two-attempts", 1, True),
            ("retry-duplicated-the-write", 2, True),
            ("retry-effect-not-yet-witnessed", 0, False),
        ],
    )
    def test_observed_outcome_does_not_change_agt_attempt_claim(
        self,
        slug: str,
        write_count: int,
        absence_established: bool,
    ) -> None:
        """Compare each external outcome with the same AGT-visible retry."""
        report = _judge(slug)
        record = self.assert_attempt_record()
        predicate = _predicate(slug)
        assert report.verdict == "valid"
        assert _reported_attempts(predicate) == record["tool_transcript"]["call_count"]
        assert report.effects_independently_observed
        assert report.absence_established is absence_established
        assert [write["path"] for write in predicate["writes"]] == [_TARGET] * write_count


class TestFailingCases(TestRetryEffect):
    """Check corpus refusals for overstated effects."""

    __test__ = True

    @pytest.mark.parametrize(
        ("slug", "verdict", "code"),
        [
            ("retry-duplicate-reported-as-one", "malformed", "dual-value-not-recomputable"),
            ("retry-timeout-read-as-no-write", "invalid", "authoritative-coverage-incomplete"),
        ],
    )
    def test_unsupported_effect_claim_is_not_licensed_by_agt(
        self, slug: str, verdict: str, code: str
    ) -> None:
        """Keep AGT's affirmative attempt appraisal separate from effect truth."""
        report = _judge(slug)
        record = self.assert_attempt_record()
        assert report.verdict == verdict
        assert report.codes == [code]
        assert _reported_attempts(_predicate(slug)) == record["tool_transcript"]["call_count"]
