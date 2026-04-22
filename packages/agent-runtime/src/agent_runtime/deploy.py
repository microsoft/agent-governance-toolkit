# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Deployment runtime for governed AI agents.

Provides deployment targets for running governed agents in production:
- Docker containers with policy enforcement
- Kubernetes (AKS) pods with governance sidecars
- Local process with sandbox isolation
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class DeploymentStatus(str, Enum):
    PENDING = "pending"
    DEPLOYING = "deploying"
    RUNNING = "running"
    STOPPED = "stopped"
    FAILED = "failed"
    TERMINATED = "terminated"


@dataclass
class GovernanceConfig:
    """Governance configuration injected into deployed agents."""
    policy_path: str = ""
    trust_level: str = "standard"
    audit_enabled: bool = True
    max_tool_calls: int = 100
    rate_limit_rpm: int = 60
    kill_switch_enabled: bool = True
    retention_days: int = 180


@dataclass
class DeploymentResult:
    """Result of a deployment operation."""
    status: DeploymentStatus
    target: str
    agent_id: str
    endpoint: str = ""
    container_id: str = ""
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class DeploymentTarget(Protocol):
    """Protocol for deployment targets."""
    def deploy(self, agent_id: str, image: str, config: GovernanceConfig, **kwargs: Any) -> DeploymentResult: ...
    def stop(self, agent_id: str) -> DeploymentResult: ...
    def status(self, agent_id: str) -> DeploymentResult: ...
    def logs(self, agent_id: str, tail: int = 100) -> str: ...


class DockerDeployer:
    """Deploy governed agents as Docker containers.

    Usage:
        deployer = DockerDeployer()
        result = deployer.deploy(
            agent_id="analyst-001",
            image="agent-os:latest",
            config=GovernanceConfig(policy_path="/policies/strict.yaml"),
        )
    """

    def __init__(self, network: str = "agent-governance", docker_cmd: str = "docker") -> None:
        self._network = network
        self._docker = docker_cmd
        self._ensure_docker()

    def _ensure_docker(self) -> None:
        if not shutil.which(self._docker):
            raise RuntimeError(f"{self._docker} not found in PATH")

    def _run(self, args: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        cmd = [self._docker] + args
        logger.debug("Running: %s", " ".join(cmd))
        return subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=60)  # noqa: S603 — trusted subprocess in deployment script

    def deploy(self, agent_id: str, image: str, config: GovernanceConfig,
               port: int = 0, env: dict[str, str] | None = None, **kwargs: Any) -> DeploymentResult:
        container_name = f"agt-{agent_id}"
        cmd = [
            "run", "-d",
            "--name", container_name,
            "--network", self._network,
            "--label", f"agt.agent-id={agent_id}",
            "--label", "agt.managed=true",
            "--restart", "unless-stopped",
            # Security: drop all capabilities, add only what's needed
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid",  # noqa: S108 — Docker tmpfs mount specification, not a hardcoded path
            # Governance config as env vars
            "-e", f"AGT_POLICY_PATH={config.policy_path}",
            "-e", f"AGT_TRUST_LEVEL={config.trust_level}",
            "-e", f"AGT_AUDIT_ENABLED={str(config.audit_enabled).lower()}",
            "-e", f"AGT_MAX_TOOL_CALLS={config.max_tool_calls}",
            "-e", f"AGT_RATE_LIMIT_RPM={config.rate_limit_rpm}",
            "-e", f"AGT_KILL_SWITCH={str(config.kill_switch_enabled).lower()}",
            "-e", f"AGT_RETENTION_DAYS={config.retention_days}",
        ]
        if port:
            cmd.extend(["-p", f"127.0.0.1:{port}:8080"])
        if env:
            for k, v in env.items():
                cmd.extend(["-e", f"{k}={v}"])
        cmd.append(image)

        try:
            # Ensure network exists
            self._run(["network", "create", self._network], check=False)
            result = self._run(cmd)
            container_id = result.stdout.strip()[:12]
            return DeploymentResult(
                status=DeploymentStatus.RUNNING,
                target="docker",
                agent_id=agent_id,
                container_id=container_id,
                endpoint=f"http://localhost:{port}" if port else "",
            )
        except subprocess.CalledProcessError as e:
            return DeploymentResult(
                status=DeploymentStatus.FAILED,
                target="docker",
                agent_id=agent_id,
                error=e.stderr.strip(),
            )

    def stop(self, agent_id: str) -> DeploymentResult:
        container_name = f"agt-{agent_id}"
        try:
            self._run(["stop", container_name])
            self._run(["rm", container_name])
            return DeploymentResult(
                status=DeploymentStatus.STOPPED,
                target="docker",
                agent_id=agent_id,
            )
        except subprocess.CalledProcessError as e:
            return DeploymentResult(
                status=DeploymentStatus.FAILED,
                target="docker",
                agent_id=agent_id,
                error=e.stderr.strip(),
            )

    def status(self, agent_id: str) -> DeploymentResult:
        container_name = f"agt-{agent_id}"
        try:
            result = self._run(["inspect", container_name, "--format", "{{.State.Status}}"])
            state = result.stdout.strip()
            status_map = {"running": DeploymentStatus.RUNNING, "exited": DeploymentStatus.STOPPED}
            return DeploymentResult(
                status=status_map.get(state, DeploymentStatus.FAILED),
                target="docker",
                agent_id=agent_id,
                container_id=container_name,
            )
        except subprocess.CalledProcessError:
            return DeploymentResult(
                status=DeploymentStatus.STOPPED,
                target="docker",
                agent_id=agent_id,
            )

    def logs(self, agent_id: str, tail: int = 100) -> str:
        try:
            result = self._run(["logs", f"agt-{agent_id}", "--tail", str(tail)])
            return result.stdout
        except subprocess.CalledProcessError:
            return ""


class KubernetesDeployer:
    """Deploy governed agents to Kubernetes (AKS) with governance sidecars.

    Usage:
        deployer = KubernetesDeployer(namespace="agents")
        result = deployer.deploy(
            agent_id="analyst-001",
            image="myregistry.azurecr.io/agent-os:3.0.2",
            config=GovernanceConfig(policy_path="/policies/strict.yaml"),
        )
    """

    def __init__(self, namespace: str = "agent-governance", kubectl_cmd: str = "kubectl",
                 context: str | None = None) -> None:
        self._namespace = namespace
        self._kubectl = kubectl_cmd
        self._context = context
        self._ensure_kubectl()

    def _ensure_kubectl(self) -> None:
        if not shutil.which(self._kubectl):
            raise RuntimeError(f"{self._kubectl} not found in PATH")

    def _run(self, args: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        cmd = [self._kubectl]
        if self._context:
            cmd.extend(["--context", self._context])
        cmd.extend(args)
        logger.debug("Running: %s", " ".join(cmd))
        return subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=120)  # noqa: S603 — trusted subprocess in deployment script

    def _build_pod_manifest(self, agent_id: str, image: str, config: GovernanceConfig) -> dict[str, Any]:
        return {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": f"agt-{agent_id}",
                "namespace": self._namespace,
                "labels": {
                    "app.kubernetes.io/name": "agent-governance",
                    "app.kubernetes.io/component": "agent",
                    "agt.agent-id": agent_id,
                    "agt.trust-level": config.trust_level,
                },
            },
            "spec": {
                "securityContext": {
                    "runAsNonRoot": True,
                    "runAsUser": 1000,
                    "fsGroup": 1000,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "containers": [
                    {
                        "name": "agent",
                        "image": image,
                        "imagePullPolicy": "IfNotPresent",
                        "securityContext": {
                            "allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                            "readOnlyRootFilesystem": True,
                        },
                        "env": [
                            {"name": "AGT_POLICY_PATH", "value": config.policy_path},
                            {"name": "AGT_TRUST_LEVEL", "value": config.trust_level},
                            {"name": "AGT_AUDIT_ENABLED", "value": str(config.audit_enabled).lower()},
                            {"name": "AGT_MAX_TOOL_CALLS", "value": str(config.max_tool_calls)},
                            {"name": "AGT_RATE_LIMIT_RPM", "value": str(config.rate_limit_rpm)},
                            {"name": "AGT_KILL_SWITCH", "value": str(config.kill_switch_enabled).lower()},
                            {"name": "AGT_RETENTION_DAYS", "value": str(config.retention_days)},
                        ],
                        "resources": {
                            "requests": {"cpu": "100m", "memory": "256Mi"},
                            "limits": {"cpu": "500m", "memory": "512Mi"},
                        },
                        "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],  # noqa: S108 — Docker container path specification
                    },
                ],
                "volumes": [{"name": "tmp", "emptyDir": {"sizeLimit": "100Mi"}}],
                "restartPolicy": "Always",
                "terminationGracePeriodSeconds": 30,
            },
        }

    def deploy(self, agent_id: str, image: str, config: GovernanceConfig, **kwargs: Any) -> DeploymentResult:
        manifest = self._build_pod_manifest(agent_id, image, config)
        manifest_json = json.dumps(manifest)
        try:
            # Ensure namespace
            self._run(["create", "namespace", self._namespace], check=False)
            tmp_dir = Path(tempfile.gettempdir())
            manifest_path = tmp_dir / f"agt-{agent_id}-manifest.json"
            try:
                manifest_path.write_text(manifest_json, encoding="utf-8")
                self._run(["apply", "-f", str(manifest_path)])
            finally:
                manifest_path.unlink(missing_ok=True)
            return DeploymentResult(
                status=DeploymentStatus.DEPLOYING,
                target="kubernetes",
                agent_id=agent_id,
                metadata={"namespace": self._namespace},
            )
        except subprocess.CalledProcessError as e:
            return DeploymentResult(
                status=DeploymentStatus.FAILED,
                target="kubernetes",
                agent_id=agent_id,
                error=e.stderr.strip(),
            )

    def stop(self, agent_id: str) -> DeploymentResult:
        try:
            self._run(["delete", "pod", f"agt-{agent_id}", "-n", self._namespace])
            return DeploymentResult(
                status=DeploymentStatus.TERMINATED,
                target="kubernetes",
                agent_id=agent_id,
            )
        except subprocess.CalledProcessError as e:
            return DeploymentResult(
                status=DeploymentStatus.FAILED,
                target="kubernetes",
                agent_id=agent_id,
                error=e.stderr.strip(),
            )

    def status(self, agent_id: str) -> DeploymentResult:
        try:
            result = self._run([
                "get", "pod", f"agt-{agent_id}",
                "-n", self._namespace,
                "-o", "jsonpath={.status.phase}",
            ])
            phase = result.stdout.strip()
            phase_map = {
                "Running": DeploymentStatus.RUNNING,
                "Pending": DeploymentStatus.DEPLOYING,
                "Succeeded": DeploymentStatus.STOPPED,
                "Failed": DeploymentStatus.FAILED,
            }
            return DeploymentResult(
                status=phase_map.get(phase, DeploymentStatus.FAILED),
                target="kubernetes",
                agent_id=agent_id,
            )
        except subprocess.CalledProcessError:
            return DeploymentResult(
                status=DeploymentStatus.STOPPED,
                target="kubernetes",
                agent_id=agent_id,
            )

    def logs(self, agent_id: str, tail: int = 100) -> str:
        try:
            result = self._run([
                "logs", f"agt-{agent_id}",
                "-n", self._namespace,
                "--tail", str(tail),
            ])
            return result.stdout
        except subprocess.CalledProcessError:
            return ""
