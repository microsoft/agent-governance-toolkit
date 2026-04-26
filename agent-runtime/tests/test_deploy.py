# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the deployment runtime module (agent_runtime.deploy)."""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from agent_runtime.deploy import (
    DeploymentResult,
    DeploymentStatus,
    DockerDeployer,
    GovernanceConfig,
    KubernetesDeployer,
)


# ---------------------------------------------------------------------------
# GovernanceConfig
# ---------------------------------------------------------------------------

class TestGovernanceConfig:
    def test_defaults(self) -> None:
        config = GovernanceConfig()
        assert config.policy_path == ""
        assert config.trust_level == "standard"
        assert config.audit_enabled is True
        assert config.max_tool_calls == 100
        assert config.rate_limit_rpm == 60
        assert config.kill_switch_enabled is True
        assert config.retention_days == 180

    def test_custom_values(self) -> None:
        config = GovernanceConfig(
            policy_path="/policies/strict.yaml",
            trust_level="elevated",
            audit_enabled=False,
            max_tool_calls=50,
            rate_limit_rpm=30,
            kill_switch_enabled=False,
            retention_days=90,
        )
        assert config.policy_path == "/policies/strict.yaml"
        assert config.trust_level == "elevated"
        assert config.audit_enabled is False
        assert config.max_tool_calls == 50
        assert config.rate_limit_rpm == 30
        assert config.kill_switch_enabled is False
        assert config.retention_days == 90


# ---------------------------------------------------------------------------
# DeploymentResult
# ---------------------------------------------------------------------------

class TestDeploymentResult:
    def test_basic_creation(self) -> None:
        result = DeploymentResult(
            status=DeploymentStatus.RUNNING,
            target="docker",
            agent_id="test-agent",
        )
        assert result.status == DeploymentStatus.RUNNING
        assert result.target == "docker"
        assert result.agent_id == "test-agent"
        assert result.endpoint == ""
        assert result.container_id == ""
        assert result.error == ""
        assert result.metadata == {}

    def test_status_is_string_enum(self) -> None:
        assert DeploymentStatus.RUNNING == "running"
        assert DeploymentStatus.FAILED == "failed"
        assert DeploymentStatus.DEPLOYING == "deploying"
        assert DeploymentStatus.STOPPED == "stopped"
        assert DeploymentStatus.PENDING == "pending"
        assert DeploymentStatus.TERMINATED == "terminated"

    def test_metadata_field(self) -> None:
        result = DeploymentResult(
            status=DeploymentStatus.DEPLOYING,
            target="kubernetes",
            agent_id="agent-1",
            metadata={"namespace": "prod"},
        )
        assert result.metadata["namespace"] == "prod"


# ---------------------------------------------------------------------------
# DockerDeployer
# ---------------------------------------------------------------------------

class TestDockerDeployer:
    @patch("agent_runtime.deploy.shutil.which", return_value=None)
    def test_raises_if_docker_not_found(self, mock_which: MagicMock) -> None:
        with pytest.raises(RuntimeError, match="docker not found in PATH"):
            DockerDeployer()

    @patch("agent_runtime.deploy.subprocess.run")
    @patch("agent_runtime.deploy.shutil.which", return_value="/usr/bin/docker")
    def test_deploy_creates_correct_command(
        self, mock_which: MagicMock, mock_run: MagicMock,
    ) -> None:
        mock_run.return_value = MagicMock(
            stdout="abc123def456\n", stderr="", returncode=0,
        )
        deployer = DockerDeployer(network="test-net")
        config = GovernanceConfig(policy_path="/policies/strict.yaml", trust_level="elevated")
        result = deployer.deploy(
            agent_id="analyst-001",
            image="agent-os:latest",
            config=config,
            port=9090,
        )

        assert result.status == DeploymentStatus.RUNNING
        assert result.target == "docker"
        assert result.agent_id == "analyst-001"
        assert result.container_id == "abc123def456"
        assert result.endpoint == "http://localhost:9090"

        # Verify docker run was called (second call after network create)
        run_call = mock_run.call_args_list[-1]
        cmd = run_call[0][0] if run_call[0] else run_call[1].get("args", [])
        # The command should contain key args
        cmd_str = " ".join(cmd)
        assert "run" in cmd_str
        assert "--name" in cmd_str
        assert "agt-analyst-001" in cmd_str
        assert "--network" in cmd_str
        assert "test-net" in cmd_str
        assert "--cap-drop" in cmd_str
        assert "ALL" in cmd_str
        assert "AGT_POLICY_PATH=/policies/strict.yaml" in cmd_str
        assert "AGT_TRUST_LEVEL=elevated" in cmd_str
        assert "agent-os:latest" in cmd_str
        assert "127.0.0.1:9090:8080" in cmd_str

    @patch("agent_runtime.deploy.subprocess.run")
    @patch("agent_runtime.deploy.shutil.which", return_value="/usr/bin/docker")
    def test_deploy_no_port(
        self, mock_which: MagicMock, mock_run: MagicMock,
    ) -> None:
        mock_run.return_value = MagicMock(stdout="abc123\n", stderr="", returncode=0)
        deployer = DockerDeployer()
        result = deployer.deploy("a1", "img:latest", GovernanceConfig())
        assert result.endpoint == ""

    @patch("agent_runtime.deploy.subprocess.run")
    @patch("agent_runtime.deploy.shutil.which", return_value="/usr/bin/docker")
    def test_deploy_with_custom_env(
        self, mock_which: MagicMock, mock_run: MagicMock,
    ) -> None:
        mock_run.return_value = MagicMock(stdout="cid123\n", stderr="", returncode=0)
        deployer = DockerDeployer()
        result = deployer.deploy(
            "a1", "img:latest", GovernanceConfig(),
            env={"MY_VAR": "my_val"},
        )
        assert result.status == DeploymentStatus.RUNNING
        # Verify custom env was passed
        run_call = mock_run.call_args_list[-1]
        cmd = run_call[0][0] if run_call[0] else run_call[1].get("args", [])
        cmd_str = " ".join(cmd)
        assert "MY_VAR=my_val" in cmd_str

    @patch("agent_runtime.deploy.subprocess.run")
    @patch("agent_runtime.deploy.shutil.which", return_value="/usr/bin/docker")
    def test_deploy_failure(
        self, mock_which: MagicMock, mock_run: MagicMock,
    ) -> None:
        mock_run.side_effect = [
            MagicMock(stdout="", stderr="", returncode=0),  # network create
            subprocess.CalledProcessError(1, "docker", stderr="port conflict"),
        ]
        deployer = DockerDeployer()
        result = deployer.deploy("a1", "img:latest", GovernanceConfig())
        assert result.status == DeploymentStatus.FAILED
        assert "port conflict" in result.error

    @patch("agent_runtime.deploy.subprocess.run")
    @patch("agent_runtime.deploy.shutil.which", return_value="/usr/bin/docker")
    def test_stop_removes_container(
        self, mock_which: MagicMock, mock_run: MagicMock,
    ) -> None:
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        deployer = DockerDeployer()
        result = deployer.stop("analyst-001")
        assert result.status == DeploymentStatus.STOPPED
        assert result.agent_id == "analyst-001"

        # Should have called stop and rm
        calls = mock_run.call_args_list
        cmd_strs = [" ".join(c[0][0]) for c in calls]
        assert any("stop" in s and "agt-analyst-001" in s for s in cmd_strs)
        assert any("rm" in s and "agt-analyst-001" in s for s in cmd_strs)

    @patch("agent_runtime.deploy.subprocess.run")
    @patch("agent_runtime.deploy.shutil.which", return_value="/usr/bin/docker")
    def test_status_running(
        self, mock_which: MagicMock, mock_run: MagicMock,
    ) -> None:
        mock_run.return_value = MagicMock(stdout="running\n", stderr="", returncode=0)
        deployer = DockerDeployer()
        result = deployer.status("agent-1")
        assert result.status == DeploymentStatus.RUNNING

    @patch("agent_runtime.deploy.subprocess.run")
    @patch("agent_runtime.deploy.shutil.which", return_value="/usr/bin/docker")
    def test_status_exited(
        self, mock_which: MagicMock, mock_run: MagicMock,
    ) -> None:
        mock_run.return_value = MagicMock(stdout="exited\n", stderr="", returncode=0)
        deployer = DockerDeployer()
        result = deployer.status("agent-1")
        assert result.status == DeploymentStatus.STOPPED

    @patch("agent_runtime.deploy.subprocess.run")
    @patch("agent_runtime.deploy.shutil.which", return_value="/usr/bin/docker")
    def test_logs_returns_output(
        self, mock_which: MagicMock, mock_run: MagicMock,
    ) -> None:
        mock_run.return_value = MagicMock(
            stdout="line1\nline2\n", stderr="", returncode=0,
        )
        deployer = DockerDeployer()
        output = deployer.logs("agent-1", tail=50)
        assert "line1" in output
        assert "line2" in output

    @patch("agent_runtime.deploy.subprocess.run")
    @patch("agent_runtime.deploy.shutil.which", return_value="/usr/bin/docker")
    def test_logs_returns_empty_on_failure(
        self, mock_which: MagicMock, mock_run: MagicMock,
    ) -> None:
        mock_run.side_effect = subprocess.CalledProcessError(1, "docker")
        deployer = DockerDeployer()
        assert deployer.logs("nonexistent") == ""


# ---------------------------------------------------------------------------
# KubernetesDeployer
# ---------------------------------------------------------------------------

class TestKubernetesDeployer:
    @patch("agent_runtime.deploy.shutil.which", return_value=None)
    def test_raises_if_kubectl_not_found(self, mock_which: MagicMock) -> None:
        with pytest.raises(RuntimeError, match="kubectl not found in PATH"):
            KubernetesDeployer()

    @patch("agent_runtime.deploy.shutil.which", return_value="/usr/bin/kubectl")
    def test_build_pod_manifest_structure(self, mock_which: MagicMock) -> None:
        deployer = KubernetesDeployer(namespace="test-ns")
        config = GovernanceConfig(
            policy_path="/policies/strict.yaml",
            trust_level="elevated",
        )
        manifest = deployer._build_pod_manifest("agent-1", "img:latest", config)

        assert manifest["apiVersion"] == "v1"
        assert manifest["kind"] == "Pod"
        assert manifest["metadata"]["name"] == "agt-agent-1"
        assert manifest["metadata"]["namespace"] == "test-ns"
        assert manifest["metadata"]["labels"]["agt.agent-id"] == "agent-1"
        assert manifest["metadata"]["labels"]["agt.trust-level"] == "elevated"

    @patch("agent_runtime.deploy.shutil.which", return_value="/usr/bin/kubectl")
    def test_build_pod_manifest_security_context(self, mock_which: MagicMock) -> None:
        deployer = KubernetesDeployer()
        config = GovernanceConfig()
        manifest = deployer._build_pod_manifest("a1", "img:latest", config)

        # Pod-level security
        pod_sec = manifest["spec"]["securityContext"]
        assert pod_sec["runAsNonRoot"] is True
        assert pod_sec["runAsUser"] == 1000

        # Container-level security
        container_sec = manifest["spec"]["containers"][0]["securityContext"]
        assert container_sec["allowPrivilegeEscalation"] is False
        assert container_sec["capabilities"]["drop"] == ["ALL"]
        assert container_sec["readOnlyRootFilesystem"] is True

    @patch("agent_runtime.deploy.shutil.which", return_value="/usr/bin/kubectl")
    def test_build_pod_manifest_governance_env(self, mock_which: MagicMock) -> None:
        deployer = KubernetesDeployer()
        config = GovernanceConfig(
            policy_path="/p.yaml", trust_level="high",
            audit_enabled=False, max_tool_calls=50,
        )
        manifest = deployer._build_pod_manifest("a1", "img:latest", config)
        env_list = manifest["spec"]["containers"][0]["env"]
        env_dict = {e["name"]: e["value"] for e in env_list}

        assert env_dict["AGT_POLICY_PATH"] == "/p.yaml"
        assert env_dict["AGT_TRUST_LEVEL"] == "high"
        assert env_dict["AGT_AUDIT_ENABLED"] == "false"
        assert env_dict["AGT_MAX_TOOL_CALLS"] == "50"

    @patch("agent_runtime.deploy.subprocess.run")
    @patch("agent_runtime.deploy.shutil.which", return_value="/usr/bin/kubectl")
    def test_deploy_returns_deploying(
        self, mock_which: MagicMock, mock_run: MagicMock,
    ) -> None:
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        deployer = KubernetesDeployer(namespace="prod")
        result = deployer.deploy("a1", "img:latest", GovernanceConfig())
        assert result.status == DeploymentStatus.DEPLOYING
        assert result.target == "kubernetes"
        assert result.metadata["namespace"] == "prod"

    @patch("agent_runtime.deploy.subprocess.run")
    @patch("agent_runtime.deploy.shutil.which", return_value="/usr/bin/kubectl")
    def test_deploy_with_context(
        self, mock_which: MagicMock, mock_run: MagicMock,
    ) -> None:
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        deployer = KubernetesDeployer(context="my-aks-cluster")
        deployer.deploy("a1", "img:latest", GovernanceConfig())

        # Verify --context flag was used
        for call in mock_run.call_args_list:
            cmd = call[0][0] if call[0] else call[1].get("args", [])
            if "apply" in cmd:
                assert "--context" in cmd
                assert "my-aks-cluster" in cmd

    @patch("agent_runtime.deploy.subprocess.run")
    @patch("agent_runtime.deploy.shutil.which", return_value="/usr/bin/kubectl")
    def test_stop_returns_terminated(
        self, mock_which: MagicMock, mock_run: MagicMock,
    ) -> None:
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        deployer = KubernetesDeployer()
        result = deployer.stop("agent-1")
        assert result.status == DeploymentStatus.TERMINATED

    @patch("agent_runtime.deploy.subprocess.run")
    @patch("agent_runtime.deploy.shutil.which", return_value="/usr/bin/kubectl")
    def test_status_running(
        self, mock_which: MagicMock, mock_run: MagicMock,
    ) -> None:
        mock_run.return_value = MagicMock(stdout="Running", stderr="", returncode=0)
        deployer = KubernetesDeployer()
        result = deployer.status("agent-1")
        assert result.status == DeploymentStatus.RUNNING

    @patch("agent_runtime.deploy.subprocess.run")
    @patch("agent_runtime.deploy.shutil.which", return_value="/usr/bin/kubectl")
    def test_logs_returns_output(
        self, mock_which: MagicMock, mock_run: MagicMock,
    ) -> None:
        mock_run.return_value = MagicMock(stdout="k8s log line\n", stderr="", returncode=0)
        deployer = KubernetesDeployer()
        assert "k8s log line" in deployer.logs("agent-1")
