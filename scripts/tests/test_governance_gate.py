# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for scripts/governance_gate.py.

All tests are fully offline — no GitHub Actions environment needed.
Uses tmp_path for file I/O; no network calls are made.

Coverage:
- Policy validation: all required fields present and correct
- Policy validation: each field missing or wrong type/value
- Receipt generation: structure and fields
- Receipt signing when cryptography is available
- require_receipt with no signing key
- Audit log written as JSONL
- run() exit codes: 0 on pass, 1 on fail, 2 on missing file
- CLI arg parsing: env var fallbacks
- _get_nested: dotted key traversal
- _sha256 determinism
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
import governance_gate as gg


# Helpers

def _write_policy(tmp_path: Path, overrides: dict | None = None) -> Path:
    """Write a valid policy YAML, optionally overriding top-level keys."""
    import yaml
    data: dict = {
        "audit": {"enabled": True},
        "pii_scanning": {"enabled": True},
        "allowed_tools": ["web_search", "read_file"],
        "max_tool_calls": 10,
    }
    if overrides:
        data.update(overrides)
    p = tmp_path / "security.yaml"
    p.write_text(yaml.dump(data))
    return p


def _write_manifest(tmp_path: Path) -> Path:
    p = tmp_path / "agents.yaml"
    p.write_text("agents:\n  - name: test-agent\n    version: 1.0.0\n")
    return p


# _get_nested

class TestGetNested:
    def test_top_level_key(self):
        found, val = gg._get_nested({"a": 1}, "a")
        assert found and val == 1

    def test_nested_key(self):
        found, val = gg._get_nested({"a": {"b": True}}, "a.b")
        assert found and val is True

    def test_missing_key(self):
        found, val = gg._get_nested({"a": 1}, "b")
        assert not found and val is None

    def test_missing_nested_key(self):
        found, val = gg._get_nested({"a": {}}, "a.b")
        assert not found

    def test_empty_dict(self):
        found, _ = gg._get_nested({}, "a")
        assert not found


# _validate_policy

class TestValidatePolicy:
    def test_valid_policy_no_failures(self, tmp_path):
        import yaml
        p = _write_policy(tmp_path)
        data = yaml.safe_load(p.read_text())
        assert gg._validate_policy(data) == []

    def test_missing_audit_enabled(self, tmp_path):
        import yaml
        p = _write_policy(tmp_path, {"audit": {}})
        data = yaml.safe_load(p.read_text())
        failures = gg._validate_policy(data)
        assert any("audit_enabled" in f for f in failures)

    def test_audit_enabled_false(self, tmp_path):
        import yaml
        p = _write_policy(tmp_path, {"audit": {"enabled": False}})
        data = yaml.safe_load(p.read_text())
        failures = gg._validate_policy(data)
        assert any("audit_enabled" in f for f in failures)

    def test_missing_pii_scanning(self, tmp_path):
        import yaml
        p = _write_policy(tmp_path, {"pii_scanning": {}})
        data = yaml.safe_load(p.read_text())
        failures = gg._validate_policy(data)
        assert any("pii_scanning" in f for f in failures)

    def test_allowed_tools_not_a_list(self, tmp_path):
        import yaml
        p = _write_policy(tmp_path, {"allowed_tools": "web_search"})
        data = yaml.safe_load(p.read_text())
        failures = gg._validate_policy(data)
        assert any("allowed_tools" in f for f in failures)

    def test_max_tool_calls_not_int(self, tmp_path):
        import yaml
        p = _write_policy(tmp_path, {"max_tool_calls": "ten"})
        data = yaml.safe_load(p.read_text())
        failures = gg._validate_policy(data)
        assert any("max_tool_calls" in f for f in failures)

    def test_multiple_failures_reported(self, tmp_path):
        import yaml
        p = _write_policy(tmp_path, {"audit": {}, "pii_scanning": {}})
        data = yaml.safe_load(p.read_text())
        failures = gg._validate_policy(data)
        assert len(failures) >= 2


# _sha256

class TestSha256:
    def test_deterministic(self):
        assert gg._sha256("hello") == gg._sha256("hello")

    def test_different_inputs_differ(self):
        assert gg._sha256("a") != gg._sha256("b")

    def test_returns_hex_string(self):
        result = gg._sha256("test")
        assert len(result) == 64
        int(result, 16)  # raises if not hex


# _generate_receipt

class TestGenerateReceipt:
    def test_receipt_has_required_fields(self):
        r = gg._generate_receipt("abc", "alice", "phash", "mhash", "allow", None)
        for field in ("receipt_id", "action", "principal", "decision",
                      "commit_sha", "policy_hash", "manifest_hash", "timestamp", "nonce"):
            assert field in r

    def test_receipt_id_prefixed_rec(self):
        r = gg._generate_receipt("abc", "alice", "phash", "mhash", "allow", None)
        assert r["receipt_id"].startswith("rec_")

    def test_policy_hash_prefixed_sha256(self):
        r = gg._generate_receipt("abc", "alice", "phash", "mhash", "allow", None)
        assert r["policy_hash"].startswith("sha256:")

    def test_decision_allow(self):
        r = gg._generate_receipt("abc", "alice", "p", "m", "allow", None)
        assert r["decision"] == "allow"

    def test_decision_deny(self):
        r = gg._generate_receipt("abc", "alice", "p", "m", "deny", None)
        assert r["decision"] == "deny"

    def test_no_signature_without_key(self):
        r = gg._generate_receipt("abc", "alice", "p", "m", "allow", None)
        assert r["signature"] is None

    def test_unique_nonces(self):
        r1 = gg._generate_receipt("abc", "alice", "p", "m", "allow", None)
        r2 = gg._generate_receipt("abc", "alice", "p", "m", "allow", None)
        assert r1["nonce"] != r2["nonce"]

    @pytest.mark.skipif(not gg._HAS_CRYPTO, reason="cryptography not installed")
    def test_signed_receipt_with_real_key(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, PublicFormat, NoEncryption
        )
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
        r = gg._generate_receipt("abc", "alice", "p", "m", "allow", pem)
        assert r["signature"] is not None
        assert r["signer_public_key"] is not None


# _write_audit_entry

class TestWriteAuditEntry:
    def test_creates_file_and_appends(self, tmp_path):
        log = tmp_path / "sub" / "audit.jsonl"
        entry = {"receipt_id": "rec_001", "decision": "allow"}
        gg._write_audit_entry(entry, log)
        lines = log.read_text().strip().splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["receipt_id"] == "rec_001"

    def test_appends_multiple_entries(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        gg._write_audit_entry({"n": 1}, log)
        gg._write_audit_entry({"n": 2}, log)
        lines = log.read_text().strip().splitlines()
        assert len(lines) == 2
        assert json.loads(lines[1])["n"] == 2


# run() — integration-level

class TestRun:
    def test_valid_policy_exits_0(self, tmp_path):
        policy = _write_policy(tmp_path)
        manifest = _write_manifest(tmp_path)
        audit = tmp_path / "audit.jsonl"
        code = gg.run(policy, manifest, "abc1234", "alice", audit, None, False)
        assert code == 0

    def test_invalid_policy_exits_1(self, tmp_path):
        import yaml
        policy = tmp_path / "bad.yaml"
        policy.write_text(yaml.dump({"audit": {"enabled": False}, "pii_scanning": {"enabled": True}, "allowed_tools": [], "max_tool_calls": 5}))
        manifest = _write_manifest(tmp_path)
        audit = tmp_path / "audit.jsonl"
        code = gg.run(policy, manifest, "abc", "alice", audit, None, False)
        assert code == 1

    def test_missing_policy_file_exits_2(self, tmp_path):
        manifest = _write_manifest(tmp_path)
        audit = tmp_path / "audit.jsonl"
        code = gg.run(tmp_path / "nonexistent.yaml", manifest, "abc", "alice", audit, None, False)
        assert code == 2

    def test_missing_manifest_file_exits_2(self, tmp_path):
        policy = _write_policy(tmp_path)
        audit = tmp_path / "audit.jsonl"
        code = gg.run(policy, tmp_path / "nonexistent.yaml", "abc", "alice", audit, None, False)
        assert code == 2

    def test_audit_log_written_on_pass(self, tmp_path):
        policy = _write_policy(tmp_path)
        manifest = _write_manifest(tmp_path)
        audit = tmp_path / "audit.jsonl"
        gg.run(policy, manifest, "abc1234", "alice", audit, None, False)
        assert audit.exists()
        entry = json.loads(audit.read_text().strip())
        assert entry["decision"] == "allow"
        assert entry["commit_sha"] == "abc1234"
        assert entry["principal"] == "alice"

    def test_audit_log_written_on_fail(self, tmp_path):
        import yaml
        policy = tmp_path / "bad.yaml"
        policy.write_text(yaml.dump({"audit": {}, "pii_scanning": {"enabled": True}, "allowed_tools": [], "max_tool_calls": 5}))
        manifest = _write_manifest(tmp_path)
        audit = tmp_path / "audit.jsonl"
        gg.run(policy, manifest, "abc", "alice", audit, None, False)
        entry = json.loads(audit.read_text().strip())
        assert entry["decision"] == "deny"

    def test_receipt_id_in_audit_log(self, tmp_path):
        policy = _write_policy(tmp_path)
        manifest = _write_manifest(tmp_path)
        audit = tmp_path / "audit.jsonl"
        gg.run(policy, manifest, "abc", "alice", audit, None, False)
        entry = json.loads(audit.read_text().strip())
        assert entry["receipt_id"].startswith("rec_")

    def test_require_receipt_without_key_fails(self, tmp_path):
        if not gg._HAS_CRYPTO:
            pytest.skip("cryptography not installed")
        policy = _write_policy(tmp_path)
        manifest = _write_manifest(tmp_path)
        audit = tmp_path / "audit.jsonl"
        code = gg.run(policy, manifest, "abc", "alice", audit, None, require_receipt=True)
        assert code == 1

    def test_each_policy_failure_reported_individually(self, tmp_path):
        import yaml
        policy = tmp_path / "p.yaml"
        policy.write_text(yaml.dump({"audit": {}, "pii_scanning": {}, "allowed_tools": "bad", "max_tool_calls": "x"}))
        manifest = _write_manifest(tmp_path)
        audit = tmp_path / "audit.jsonl"
        code = gg.run(policy, manifest, "abc", "alice", audit, None, False)
        assert code == 1


# _parse_args — env var fallbacks

class TestParseArgs:
    def test_defaults_from_env(self, monkeypatch):
        monkeypatch.setenv("GOVERNANCE_POLICY", "custom/policy.yaml")
        monkeypatch.setenv("GOVERNANCE_MANIFEST", "custom/agents.yaml")
        monkeypatch.setenv("GITHUB_SHA", "deadbeef")
        monkeypatch.setenv("GITHUB_ACTOR", "octocat")
        args = gg._parse_args([])
        assert args.policy == Path("custom/policy.yaml")
        assert args.manifest == Path("custom/agents.yaml")
        assert args.commit == "deadbeef"
        assert args.deployer == "octocat"

    def test_explicit_args_override_env(self, monkeypatch):
        monkeypatch.setenv("GITHUB_SHA", "envsha")
        args = gg._parse_args(["--commit", "clisha"])
        assert args.commit == "clisha"

    def test_require_receipt_flag(self):
        args = gg._parse_args(["--require-receipt"])
        assert args.require_receipt is True

    def test_require_receipt_from_env(self, monkeypatch):
        monkeypatch.setenv("GOVERNANCE_REQUIRE_RECEIPT", "true")
        args = gg._parse_args([])
        assert args.require_receipt is True
