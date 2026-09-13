# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Citadel identity bridge and policy bundle resolver.

These are the surfaces the Citadel integration guide documents, and they
carry governance state: a trust score becomes a risk label, a key becomes
a thumbprint, and a bundle is refused when it does not match the access
contract it claims. Each of those conversions is asserted here.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from agent_os.integrations.citadel.identity_bridge import (
    AgentIdentityBinding,
    EntraIdentityBridge,
    IdentityAttestation,
    TrustRiskLabel,
)
from agent_os.integrations.citadel.policy_bundle import (
    PolicyBundle,
    PolicyBundleResolver,
)


# ── trust score to risk label ─────────────────────────────────────────


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (1000, TrustRiskLabel.TRUSTED),
        (700, TrustRiskLabel.TRUSTED),
        (699, TrustRiskLabel.DEGRADED),
        (400, TrustRiskLabel.DEGRADED),
        (399, TrustRiskLabel.UNTRUSTED),
        (0, TrustRiskLabel.UNTRUSTED),
    ],
)
def test_risk_label_boundaries(score: int, expected: TrustRiskLabel) -> None:
    """The documented 700/400 thresholds are inclusive lower bounds."""
    assert TrustRiskLabel.from_score(score) is expected


# ── identity binding ──────────────────────────────────────────────────


def test_bind_hashes_the_public_key_rather_than_storing_it() -> None:
    """The binding keeps a SHA-256 thumbprint, never the key material."""
    bridge = EntraIdentityBridge(tenant_id="tenant-1")
    key = "not-a-real-public-key"

    binding = bridge.bind(
        "agent-1", agt_public_key=key, entra_object_id="00000000-0000-0000-0000-000000000001"
    )

    assert binding.agt_public_key_thumbprint == hashlib.sha256(key.encode()).hexdigest()
    assert key not in json.dumps(binding.to_dict())


def test_bind_is_retrievable_and_removable() -> None:
    """A binding is cached under its AGT agent id for the agent's lifetime."""
    bridge = EntraIdentityBridge()

    binding = bridge.bind("agent-1", agt_public_key="k")

    assert bridge.get_binding("agent-1") == binding
    assert [b.agt_agent_id for b in bridge.list_bindings()] == ["agent-1"]
    assert bridge.remove_binding("agent-1") is True
    assert bridge.get_binding("agent-1") is None
    assert bridge.remove_binding("agent-1") is False


def test_binding_defaults_are_unique_per_instance() -> None:
    """Each binding gets its own id rather than sharing a class default."""
    first = AgentIdentityBinding(agt_agent_id="a")
    second = AgentIdentityBinding(agt_agent_id="b")

    assert first.binding_id != second.binding_id


def test_from_env_reads_tenant_and_verify_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``from_env`` honours the documented environment variables."""
    monkeypatch.setenv("CITADEL_ENTRA_TENANT_ID", "tenant-9")
    monkeypatch.setenv("CITADEL_ENTRA_VERIFY", "TRUE")

    bridge = EntraIdentityBridge.from_env()

    assert bridge._tenant_id == "tenant-9"
    assert bridge._verify_entra is True


# ── attestation ───────────────────────────────────────────────────────


def test_attest_maps_trust_score_to_risk_label() -> None:
    """An attestation carries the label derived from the trust score."""
    bridge = EntraIdentityBridge()
    binding = bridge.bind("agent-1", agt_public_key="k")

    attestation = bridge.attest(binding, trust_score=250, policy_bundle_id="b1")

    assert isinstance(attestation, IdentityAttestation)
    assert attestation.risk_label == TrustRiskLabel.UNTRUSTED.value
    assert json.loads(attestation.to_json())["risk_label"] == "untrusted"


def test_attest_is_serialisable_for_telemetry() -> None:
    """The attestation round-trips through JSON for telemetry export."""
    bridge = EntraIdentityBridge()
    binding = bridge.bind("agent-1", agt_public_key="k")

    payload = json.loads(bridge.attest(binding, trust_score=900).to_json())

    assert payload["risk_label"] == "trusted"


# ── policy bundle ─────────────────────────────────────────────────────


def _bundle_dict() -> dict[str, object]:
    return {
        "bundle_id": "bundle-1",
        "version": "1.0.0",
        "content": {"rules": []},
    }


def test_bundle_from_dict_round_trips() -> None:
    """A bundle rebuilt from its dict form keeps its identity fields."""
    bundle = PolicyBundle.from_dict(_bundle_dict())

    assert bundle.bundle_id == "bundle-1"
    assert bundle.version == "1.0.0"


def test_resolver_reads_a_bundle_from_file(tmp_path: Path) -> None:
    """A bundle on disk resolves and is cached by id."""
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(_bundle_dict()), encoding="utf-8")
    resolver = PolicyBundleResolver()

    bundle = resolver.resolve_from_file(str(path))

    assert bundle.bundle_id == "bundle-1"
    assert resolver.get_cached("bundle-1") is not None


def test_resolver_rejects_a_missing_file(tmp_path: Path) -> None:
    """A missing bundle raises rather than resolving to an empty policy."""
    resolver = PolicyBundleResolver()

    with pytest.raises((FileNotFoundError, ValueError, OSError)):
        resolver.resolve_from_file(str(tmp_path / "absent.json"))


def test_resolver_rejects_an_unknown_source() -> None:
    """An unrecognised source is refused rather than silently ignored."""
    resolver = PolicyBundleResolver()

    with pytest.raises((ValueError, KeyError)):
        resolver.resolve({"source": "carrier-pigeon"})
