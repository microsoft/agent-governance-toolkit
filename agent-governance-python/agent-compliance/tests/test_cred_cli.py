# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for ``agt cred`` CLI (issue #2481)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_compliance.cli.agt import cli


pytest.importorskip("cryptography")


@pytest.fixture()
def runner() -> CliRunner:
    try:
        return CliRunner(mix_stderr=False)
    except TypeError:
        return CliRunner()


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    from agent_os.credential_vault import CredentialVault

    key = CredentialVault.generate_key().decode("ascii")
    path = str(tmp_path / "vault.bin")
    monkeypatch.setenv("AGT_VAULT_KEY", key)
    monkeypatch.setenv("AGT_VAULT_PATH", path)
    return {"AGT_VAULT_KEY": key, "AGT_VAULT_PATH": path}


def test_genkey_prints_valid_fernet_key(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["cred", "genkey"])
    assert result.exit_code == 0, result.output
    key = result.output.strip()
    # 32-byte url-safe base64 = 44 chars including padding
    assert len(key) == 44


def test_add_list_rotate_remove_roundtrip(
    runner: CliRunner, env: dict[str, str]
) -> None:
    r = runner.invoke(cli, ["cred", "add", "gh", "secret-value", "--type", "bearer_token"])
    assert r.exit_code == 0, r.output
    assert "stored: gh" in r.output

    r = runner.invoke(cli, ["cred", "list", "--json"])
    assert r.exit_code == 0, r.output
    payload = json.loads(r.output)
    assert payload == {"handles": ["gh"]}
    # Value never leaks
    assert "secret-value" not in r.output

    r = runner.invoke(cli, ["cred", "rotate", "gh", "new-value"])
    assert r.exit_code == 0
    assert "rotated: gh" in r.output
    assert "new-value" not in r.output

    r = runner.invoke(cli, ["cred", "remove", "gh"])
    assert r.exit_code == 0
    assert "removed: gh" in r.output

    r = runner.invoke(cli, ["cred", "list"])
    assert "(no credentials)" in r.output


def test_missing_key_fails_closed(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("AGT_VAULT_KEY", raising=False)
    monkeypatch.setenv("AGT_VAULT_PATH", str(tmp_path / "v.bin"))
    r = runner.invoke(cli, ["cred", "add", "k", "v"])
    assert r.exit_code != 0
    assert "AGT_VAULT_KEY" in (r.output + (r.stderr or ""))


def test_remove_unknown_errors(runner: CliRunner, env: dict[str, str]) -> None:
    r = runner.invoke(cli, ["cred", "remove", "nope"])
    assert r.exit_code != 0


def test_rotate_unknown_errors(runner: CliRunner, env: dict[str, str]) -> None:
    r = runner.invoke(cli, ["cred", "rotate", "nope", "x"])
    assert r.exit_code != 0
