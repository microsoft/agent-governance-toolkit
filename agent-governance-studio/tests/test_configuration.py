# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
import subprocess
import sys

import pytest
from click.testing import CliRunner

from agent_governance_studio.cli import serve
from agent_governance_studio.config import Configuration, ConfigurationError, Limits, configure


def test_defaults_and_explicit_empty_inventory(monkeypatch):
    monkeypatch.delenv("AGT_STUDIO_TOKEN", raising=False)
    config = configure(environ={"AGENTMESH_POLICY_DIR": "/ignored/legacy/path", "AGENTMESH_ENABLE_POLICY_SAVE": "1"})
    assert config.host == "127.0.0.1" and config.port == 8080 and config.policy_dir is None


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "::1", "localhost", "127.0.0.2", "192.168.1.1", "evil.example"])
def test_host_rejected_before_listener(host):
    with pytest.raises(ConfigurationError, match="127.0.0.1"):
        Configuration(host=host)


@pytest.mark.parametrize("port", [0, -1, 65536, True, "8080", 8.5])
def test_port_range_and_type(port):
    with pytest.raises(ConfigurationError, match="integer"):
        Configuration(port=port)


@pytest.mark.parametrize("port", [1, 65535])
def test_port_boundary(port):
    assert Configuration(port=port).port == port


@pytest.mark.parametrize("credential", ["", "invalid", "secret-looking-value"])
def test_even_empty_environment_credential_is_not_downgraded(credential):
    with pytest.raises(ConfigurationError, match="unsupported"):
        configure(environ={"AGT_STUDIO_TOKEN": credential})


def test_explicit_path_precedence_and_invalid_paths(tmp_path):
    root = tmp_path / "policies"
    root.mkdir()
    assert configure(policy_dir=root, environ={"AGT_STUDIO_POLICY_DIR": "missing"}).policy_dir == root.resolve()
    assert configure(environ={"AGT_STUDIO_POLICY_DIR": str(root)}).policy_dir == root.resolve()
    file = tmp_path / "not-directory"
    file.write_text("private", encoding="utf-8")
    for value in ("", "missing-private-path", file):
        with pytest.raises(ConfigurationError):
            configure(policy_dir=value, environ={})


@pytest.mark.parametrize("value", [0, -1, float("inf"), float("nan")])
def test_limits_cannot_be_disabled(value):
    with pytest.raises(ConfigurationError):
        Limits(execution_seconds=value)


def test_help_is_lazy_and_does_not_validate_or_scan(monkeypatch):
    monkeypatch.setenv("AGT_STUDIO_TOKEN", "secret")
    monkeypatch.setenv("AGT_STUDIO_POLICY_DIR", "/missing")
    result = CliRunner().invoke(serve, ["--help"])
    assert result.exit_code == 0 and "--policy-dir" in result.output
    script = (
        "import json,sys; from importlib.metadata import entry_points;"
        "from click.testing import CliRunner;"
        "from agent_compliance.cli.agt import cli;"
        "ep=next(e for e in entry_points(group='agt.commands') if e.name=='serve');"
        "assert ep.value=='agent_governance_studio.cli:serve';"
        "assert CliRunner().invoke(cli,['--help']).exit_code==0;"
        "assert CliRunner().invoke(cli,['serve','--help']).exit_code==0;"
        "print(json.dumps([m for m in sys.modules if m in ('uvicorn','fastapi','agentmesh.engine_api')]))"
    )
    completed = subprocess.run([sys.executable, "-I", "-c", script], capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == []


def test_existing_token_file_is_not_ignored(tmp_path, monkeypatch):
    token = tmp_path / ".config" / "agt" / "studio-token"
    token.parent.mkdir(parents=True)
    token.write_text("", encoding="utf-8")
    from pathlib import Path

    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    with pytest.raises(ConfigurationError, match="token file"):
        configure(environ={})


def test_unreadable_token_configuration_fails_closed(monkeypatch):
    from pathlib import Path

    def denied(_path):
        raise PermissionError("fixture-sensitive-path")

    monkeypatch.setattr(Path, "lstat", denied)
    with pytest.raises(ConfigurationError, match="Cannot inspect") as error:
        configure(environ={})
    assert "fixture-sensitive-path" not in str(error.value)
