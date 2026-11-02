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
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

logger = logging.getLogger(__name__)


# Conservative identifier shape that survives every downstream consumer this
# module hands `agent_id` to:
#
#   - Docker container names accept `[a-zA-Z0-9][a-zA-Z0-9_.-]+`. Combined
#     with the `agt-` prefix the deployer prepends, a leading dash or dot in
#     `agent_id` cannot trigger Docker's "invalid name" path, but `agent_id`
#     is also embedded raw into `--label agt.agent-id=<id>`, where a value
#     starting with `-` would be reinterpreted as a CLI flag if the order
#     ever changes.
#   - Kubernetes pod/label names follow RFC-1123: `[a-z0-9]([-a-z0-9]*[a-z0-9])?`,
#     63 chars max. We allow uppercase here because the runtime lowercases
#     when constructing the actual pod name (`agt-<id>`); upstream of that
#     point the value is just an opaque tag.
#
# 63 chars matches Kubernetes' label-value length cap; the `agt-` prefix uses
# the remaining 4 chars.
_AGENT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$")


def _validate_agent_id(agent_id: str) -> str:
    """Reject ``agent_id`` values that would be unsafe to interpolate into
    Docker / kubectl command-lines and label values.

    Returns the validated id unchanged so call sites can write
    ``agent_id = _validate_agent_id(agent_id)`` as a single guard.

    Raises:
        ValueError: if ``agent_id`` is empty, starts with a dash (would be
            reparsed as a CLI flag), exceeds 63 characters, or contains any
            character outside ``[a-zA-Z0-9_-]``.
    """
    if not isinstance(agent_id, str) or not _AGENT_ID_PATTERN.match(agent_id):
        raise ValueError(
            f"invalid agent_id {agent_id!r}: must match "
            f"^[a-zA-Z0-9][a-zA-Z0-9_-]{{0,62}}$ "
            "(alphanumeric start, then alphanumerics/underscores/dashes, "
            "max 63 chars)"
        )
    return agent_id


# RFC-1123 label shape that Kubernetes requires of pod names (and that the
# `agt.agent-id` label value needs at its end): lowercase alphanumerics and
# dashes, starting and ending with an alphanumeric.
_POD_NAME_PATTERN = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")


def _pod_name(agent_id: str) -> str:
    """Return the Kubernetes pod name for ``agent_id``.

    ``_validate_agent_id`` accepts uppercase letters, underscores and a
    trailing dash, but Kubernetes rejects all three in a pod name. Uppercase
    is lowercased here; an underscore or a trailing dash cannot be mapped
    without risking a collision with another id, so it is rejected.

    Raises:
        ValueError: if ``agent_id`` is invalid or cannot form a pod name.
    """
    pod_name = f"agt-{_validate_agent_id(agent_id).lower()}"
    if not _POD_NAME_PATTERN.match(pod_name):
        raise ValueError(
            f"invalid agent_id {agent_id!r} for Kubernetes: the pod name "
            f"{pod_name!r} must contain only alphanumerics and dashes and "
            "end with an alphanumeric"
        )
    return pod_name


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

    def _run(
        self, args: list[str], check: bool = True, merge_stderr: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        cmd = [self._docker] + args
        logger.debug("Running: %s", " ".join(cmd))
        if merge_stderr:
            return subprocess.run(  # noqa: S603 — trusted subprocess in deployment script
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, check=check, timeout=60,
            )
        return subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=60)  # noqa: S603 — trusted subprocess in deployment script

    def deploy(self, agent_id: str, image: str, config: GovernanceConfig,
               port: int = 0, env: dict[str, str] | None = None, **kwargs: Any) -> DeploymentResult:
        agent_id = _validate_agent_id(agent_id)
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
        ]
        # Governance config as env vars
        governance_env = {
            "AGT_POLICY_PATH": config.policy_path,
            "AGT_TRUST_LEVEL": config.trust_level,
            "AGT_AUDIT_ENABLED": str(config.audit_enabled).lower(),
            "AGT_MAX_TOOL_CALLS": str(config.max_tool_calls),
            "AGT_RATE_LIMIT_RPM": str(config.rate_limit_rpm),
            "AGT_KILL_SWITCH": str(config.kill_switch_enabled).lower(),
            "AGT_RETENTION_DAYS": str(config.retention_days),
        }
        for k, v in governance_env.items():
            cmd.extend(["-e", f"{k}={v}"])
        if port:
            cmd.extend(["-p", f"127.0.0.1:{port}:8080"])
        if env:
            # `docker run` keeps the last `-e` for a name, so an extra
            # variable with a governance name, or with an `=` in its name
            # (`-e AGT_KILL_SWITCH=false=x` sets AGT_KILL_SWITCH), would
            # replace the value taken from `config`.
            for k, v in env.items():
                if "=" in k:
                    raise ValueError(
                        f"invalid environment variable name {k!r}: must not contain '='"
                    )
                if k in governance_env:
                    raise ValueError(
                        f"env must not set {k}: it is set from GovernanceConfig"
                    )
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
        agent_id = _validate_agent_id(agent_id)
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
        agent_id = _validate_agent_id(agent_id)
        container_name = f"agt-{agent_id}"
        try:
            result = self._run(["inspect", container_name, "--format", "{{.State.Status}}"])
            state = result.stdout.strip()
            # A paused container (`docker pause`) is suspended, not broken,
            # and one being removed is on its way out, as after `stop()`.
            # The other states stay FAILED: `dead` is a failure, `created`
            # means `docker run` could not start the container, and
            # `restarting` means the agent process exited and the
            # `unless-stopped` policy is bringing it back.
            status_map = {
                "running": DeploymentStatus.RUNNING,
                "exited": DeploymentStatus.STOPPED,
                "paused": DeploymentStatus.STOPPED,
                "removing": DeploymentStatus.STOPPED,
            }
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
        agent_id = _validate_agent_id(agent_id)
        try:
            # The container runs without a TTY, so `docker logs` replays the
            # agent's stderr on its own stderr. Agents commonly log there
            # (Python's logging does by default), so read both streams, in the
            # order Docker writes them.
            result = self._run(
                ["logs", f"agt-{agent_id}", "--tail", str(tail)], merge_stderr=True,
            )
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
                "name": _pod_name(agent_id),
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
        pod_name = _pod_name(agent_id)
        manifest = self._build_pod_manifest(agent_id, image, config)
        manifest_json = json.dumps(manifest)
        try:
            # Ensure namespace
            self._run(["create", "namespace", self._namespace], check=False)
            fd, tmp_path = tempfile.mkstemp(prefix=f"{pod_name}-", suffix=".json")
            manifest_path = Path(tmp_path)
            try:
                os.close(fd)
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
        pod_name = _pod_name(agent_id)
        try:
            self._run(["delete", "pod", pod_name, "-n", self._namespace])
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
        pod_name = _pod_name(agent_id)
        try:
            result = self._run([
                "get", "pod", pod_name,
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
        pod_name = _pod_name(agent_id)
        try:
            result = self._run([
                "logs", pod_name,
                "-n", self._namespace,
                "--tail", str(tail),
            ])
            return result.stdout
        except subprocess.CalledProcessError:
            return ""
