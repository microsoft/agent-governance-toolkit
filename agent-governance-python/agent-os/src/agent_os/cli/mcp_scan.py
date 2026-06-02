# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent OS MCP Security Scanner CLI.

The CLI inspects MCP server configurations, enumerates advertised MCP
primitives like a minimal client across stdio, Streamable HTTP, and legacy SSE
transports, and scans discovered metadata with
``agent_os.mcp_security.MCPSecurityScanner``.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import queue
import re
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_os.mcp_security import MCPSecurityScanner, MCPSeverity, MCPThreat, ScanResult

try:  # rich is a package dependency, but keep a plain fallback for embedders.
    from rich.console import Console
except Exception:  # pragma: no cover - defensive fallback
    Console = None  # type: ignore[assignment]

console = Console() if Console else None

MCP_PROTOCOL_VERSION = "2025-11-25"
_SUPPORTED_PROTOCOL_VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18", MCP_PROTOCOL_VERSION}

# Module-level SSL context; set via _configure_tls(verify=False).
_SSL_CONTEXT: ssl.SSLContext | None = None


def _configure_tls(*, verify: bool = True) -> None:
    """Configure TLS verification for remote MCP endpoints."""
    global _SSL_CONTEXT  # noqa: PLW0603
    if verify:
        _SSL_CONTEXT = None
    else:
        _SSL_CONTEXT = ssl.create_default_context()
        _SSL_CONTEXT.check_hostname = False
        _SSL_CONTEXT.verify_mode = ssl.CERT_NONE

# Allowlist of known-safe MCP server runtime commands (basename without extension).
_COMMAND_ALLOWLIST: set[str] = {
    "node", "npx", "python", "python3", "uvx", "uv", "pip", "pipx",
    "docker", "podman", "deno", "bun", "tsx", "ts-node",
    "dotnet", "java", "go", "cargo",
}

# Env keys that an attacker-controlled MCP config could set to redirect
# command resolution, preload native libraries, or inject startup hooks
# that execute before the trusted binary's main entry point. Even though
# the launched command is on ``_COMMAND_ALLOWLIST``, these env vars can
# turn an allowlisted ``python`` / ``node`` / ``ruby`` into RCE on the
# scanner host. See main-branch ``_blocked_command_env_keys`` for the
# original rationale this list restores.
_COMMAND_RESOLUTION_ENV_KEYS: frozenset[str] = frozenset({
    # PATH-style resolution / loader hijack
    "PATH",
    "PATHEXT",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "NODE_OPTIONS",
    "NODE_PATH",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    # Runtime startup hooks that execute attacker code before main entry
    "DOTNET_STARTUP_HOOKS",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "RUBYOPT",
    "BASH_ENV",
    "ENV",
    "PERL5OPT",
    "PERL5LIB",
    # User-config-file lookup hijack
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "ZDOTDIR",
    "PSMODULEPATH",
    "COMSPEC",
})
_COMMAND_RESOLUTION_ENV_PREFIXES: tuple[str, ...] = (
    "UV_",
    "NPM_CONFIG_",
    "PIP_",
    "POETRY_",
    "GEM_",
    "GIT_",
)

_LOCAL_ENV_NAMES = frozenset({"dev", "development", "local"})


def _allow_all_commands_env_permitted() -> bool:
    """Return True only when AGENT_OS_ENV explicitly opts into local mode.

    Same gating pattern as the unsafe execute mode in
    ``agent_os.server.app``: the kill-switch is opt-in via a known env
    value, fails closed on anything else, and never reads from
    ambient/host indicators.
    """
    return os.environ.get("AGENT_OS_ENV", "").strip().lower() in _LOCAL_ENV_NAMES


# Module-level flag; set via --unsafe-allow-all-commands CLI flag.
_ALLOW_ALL_COMMANDS: bool = False
# Module-level flag; set via --allow-untrusted-cwd CLI flag.
_ALLOW_UNTRUSTED_CWD: bool = False


def _configure_command_policy(
    *, allow_all: bool = False, allow_untrusted_cwd: bool = False
) -> None:
    """Set command execution policy. Call once from CLI entry point."""
    global _ALLOW_ALL_COMMANDS, _ALLOW_UNTRUSTED_CWD  # noqa: PLW0603
    _ALLOW_ALL_COMMANDS = allow_all
    _ALLOW_UNTRUSTED_CWD = allow_untrusted_cwd


def _blocked_command_env_keys(env: Mapping[str, str] | None) -> list[str]:
    """Return env keys from ``env`` that would hijack the launched runtime.

    Compared case-insensitively against ``_COMMAND_RESOLUTION_ENV_KEYS``
    and ``_COMMAND_RESOLUTION_ENV_PREFIXES``. An empty list means the
    config-provided env is safe to merge into the child process env.
    """
    if not env:
        return []
    blocked: set[str] = set()
    for key in env:
        if not isinstance(key, str):
            continue
        upper = key.upper()
        if upper in _COMMAND_RESOLUTION_ENV_KEYS:
            blocked.add(upper)
            continue
        if any(upper.startswith(prefix) for prefix in _COMMAND_RESOLUTION_ENV_PREFIXES):
            blocked.add(upper)
    return sorted(blocked)


def _validate_env(env: Mapping[str, str] | None) -> None:
    """Raise if the config-provided env would hijack the child runtime.

    Suppressed when ``--unsafe-allow-all-commands`` is engaged because in
    that mode the operator has already opted into arbitrary execution.
    """
    if _ALLOW_ALL_COMMANDS:
        return
    blocked = _blocked_command_env_keys(env)
    if blocked:
        raise RuntimeError(
            f"Server env overrides {', '.join(blocked)}, which can hijack the "
            f"launched runtime (loader paths, startup hooks, package indexes). "
            f"Use --unsafe-allow-all-commands to permit this in local dev, or "
            f"--static-only to scan without executing."
        )


def _validate_launch_cwd(cwd: Path | str | None) -> None:
    """Reject untrusted config-provided working directories in live mode.

    Even with a trusted launch executable, running it in an attacker-chosen
    directory lets the runtime load attacker-controlled config files
    relative to cwd (``./package.json`` preinstall, ``./nuget.config``,
    ``./sitecustomize.py``, ``./.npmrc``, etc.). Operators opt in to this
    with ``--allow-untrusted-cwd`` when they trust the config source.
    """
    if cwd in (None, ""):
        return
    if _ALLOW_ALL_COMMANDS or _ALLOW_UNTRUSTED_CWD:
        return
    raise RuntimeError(
        f"Server cwd {str(cwd)!r} comes from the MCP config and is not allowed "
        f"during live command validation. Use --allow-untrusted-cwd to opt in "
        f"when the config source is trusted, --unsafe-allow-all-commands to "
        f"permit arbitrary execution, or --static-only to scan without "
        f"executing."
    )


def _validate_command(command: str) -> None:
    """Raise if command is not on the allowlist and policy is enforced."""
    if _ALLOW_ALL_COMMANDS:
        return
    # Handle both Unix and Windows path separators regardless of host OS
    basename = command.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    for ext in (".exe", ".cmd", ".bat"):
        if basename.endswith(ext):
            basename = basename[: -len(ext)]
            break
    if basename not in _COMMAND_ALLOWLIST:
        raise RuntimeError(
            f"Command {command!r} is not on the allowed command list. "
            f"Use --unsafe-allow-all-commands to permit execution of "
            f"untrusted commands, or use --static-only to scan without "
            f"executing."
        )


@dataclass
class SecurityFinding:
    """Represents a configuration or MCP inspection finding."""

    server: str
    severity: str
    message: str
    category: str

    def to_dict(self) -> dict[str, str]:
        """Serialize the finding to a JSON-compatible dict."""
        return {
            "server": self.server,
            "severity": self.severity,
            "message": self.message,
            "category": self.category,
        }


@dataclass
class StdioMCPServerConfig:
    """Launch configuration for a stdio MCP server."""

    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    cwd: Path | None = None


@dataclass
class RemoteMCPServerConfig:
    """Connection configuration for an HTTP-family MCP server."""

    name: str
    transport: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class StdioMCPInspection:
    """Result of enumerating metadata primitives from one MCP server."""

    server_name: str
    ok: bool
    tools: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    resource_templates: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    initialize_result: dict[str, Any] | None = None
    error: str | None = None
    stderr_tail: str = ""
    transport: str = "stdio"
    protocol_version: str | None = None


@dataclass
class MCPScanRun:
    """Aggregate result for a CLI scan run."""

    results: dict[str, ScanResult]
    threats: list[MCPThreat]
    inspections: dict[str, StdioMCPInspection]
    config_findings: list[SecurityFinding]
    inspection_findings: list[SecurityFinding]


# ---------------------------------------------------------------------------
# Config loading and parsing
# ---------------------------------------------------------------------------


def load_config(path: str | Path) -> Any:
    """Load an MCP configuration from JSON or YAML.

    Args:
        path: Path to a JSON/YAML config file.

    Returns:
        Parsed config object.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file cannot be parsed or is empty.
    """
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    raw = config_path.read_text(encoding="utf-8")
    try:
        if config_path.suffix.lower() in {".yaml", ".yml"}:
            try:
                import yaml  # type: ignore[import-untyped]
            except ImportError as exc:  # pragma: no cover - depends on environment
                raise ValueError("YAML config requires PyYAML to be installed") from exc
            data = yaml.safe_load(raw)
        else:
            data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc
    except Exception as exc:
        if exc.__class__.__name__.endswith("YAMLError"):
            raise ValueError(f"Invalid YAML: {exc}") from exc
        raise

    if data is None:
        raise ValueError("Empty config")
    return data


def _config_finding(server: str, severity: str, message: str) -> SecurityFinding:
    return SecurityFinding(server, severity, message, "configuration")


def _contains_unresolved_variable(value: str) -> bool:
    return "${" in value and "}" in value


def _resolve_cwd(value: Any, config_path: Path, findings: list[SecurityFinding], name: str) -> Path | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        findings.append(_config_finding(name, "critical", "Server cwd must be a string"))
        return None
    if _contains_unresolved_variable(value):
        findings.append(_config_finding(name, "critical", "Server cwd contains unresolved variables"))
        return None
    cwd = Path(value).expanduser()
    if not cwd.is_absolute():
        cwd = (config_path.parent / cwd).resolve()
    if not cwd.exists():
        findings.append(_config_finding(name, "critical", f"Server cwd does not exist: {cwd}"))
        return None
    if not cwd.is_dir():
        findings.append(_config_finding(name, "critical", f"Server cwd is not a directory: {cwd}"))
        return None
    return cwd


def parse_stdio_mcp_servers(
    config: Mapping[str, Any], *, config_path: Path
) -> tuple[dict[str, StdioMCPServerConfig], list[SecurityFinding]]:
    """Extract inspectable stdio MCP server configs.

    Supports Claude Desktop style ``mcpServers`` and VS Code-style ``servers``.
    Remote HTTP-family servers are handled by ``parse_remote_mcp_servers``.
    """
    findings: list[SecurityFinding] = []
    servers: dict[str, StdioMCPServerConfig] = {}

    candidates: Mapping[str, Any] = {}
    for key in ("mcpServers", "servers"):
        raw_servers = config.get(key)
        if isinstance(raw_servers, Mapping):
            candidates = {**candidates, **raw_servers}

    for name, spec in candidates.items():
        server_name = str(name)
        if not isinstance(spec, Mapping):
            findings.append(_config_finding(server_name, "critical", "Server config must be an object"))
            continue
        if spec.get("disabled") is True:
            continue

        transport = str(spec.get("type") or spec.get("transport") or "stdio").lower()
        has_url = any(key in spec for key in ("url", "httpUrl", "sseUrl"))
        if has_url or transport in {"http", "sse", "streamablehttp", "streamable-http"}:
            continue

        command = spec.get("command")
        if not isinstance(command, str) or not command.strip():
            findings.append(_config_finding(server_name, "critical", "Server command must be a string"))
            continue
        if _contains_unresolved_variable(command):
            findings.append(_config_finding(server_name, "critical", "Server command contains unresolved variables"))
            continue

        raw_args = spec.get("args", [])
        if raw_args is None:
            raw_args = []
        if not isinstance(raw_args, list) or not all(isinstance(arg, str) for arg in raw_args):
            findings.append(_config_finding(server_name, "critical", "Server args must be a list of strings"))
            continue
        if any(_contains_unresolved_variable(arg) for arg in raw_args):
            findings.append(_config_finding(server_name, "critical", "Server args contain unresolved variables"))
            continue

        raw_env = spec.get("env", {})
        if raw_env is None:
            raw_env = {}
        if not isinstance(raw_env, Mapping) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in raw_env.items()
        ):
            findings.append(_config_finding(server_name, "critical", "Server env must be a string map"))
            continue
        if any(_contains_unresolved_variable(value) for value in raw_env.values()):
            findings.append(_config_finding(server_name, "critical", "Server env contains unresolved variables"))
            continue

        cwd = _resolve_cwd(spec.get("cwd"), config_path, findings, server_name)
        if spec.get("cwd") not in (None, "") and cwd is None:
            continue
        servers[server_name] = StdioMCPServerConfig(
            name=server_name,
            command=command,
            args=list(raw_args),
            env=dict(raw_env),
            cwd=cwd,
        )

    return servers, findings


def _remote_transport(spec: Mapping[str, Any]) -> str | None:
    transport = str(spec.get("type") or spec.get("transport") or "").lower()
    if "sseUrl" in spec or transport == "sse":
        return "sse"
    if any(key in spec for key in ("url", "httpUrl")) or transport in {"http", "streamablehttp", "streamable-http"}:
        return "streamable-http"
    return None


def _remote_url(spec: Mapping[str, Any], transport: str) -> Any:
    if transport == "sse":
        return spec.get("sseUrl") or spec.get("url") or spec.get("httpUrl")
    return spec.get("url") or spec.get("httpUrl") or spec.get("sseUrl")


_HTTP_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def _valid_http_header(name: str, value: str) -> bool:
    """Return whether a configured HTTP header is safe to pass to urllib."""
    if not _HTTP_HEADER_NAME_RE.fullmatch(name):
        return False
    if not value:
        return True
    try:
        value.encode("latin-1")
    except UnicodeEncodeError:
        return False
    for char in value:
        codepoint = ord(char)
        if char in "\r\n" or codepoint == 127 or (codepoint < 32 and char != "\t"):
            return False
    return True


def parse_remote_mcp_servers(
    config: Mapping[str, Any], *, config_path: Path
) -> tuple[dict[str, RemoteMCPServerConfig], list[SecurityFinding]]:
    """Extract inspectable Streamable HTTP and legacy SSE MCP server configs."""
    del config_path  # reserved for parity with stdio parsing and future relative references
    findings: list[SecurityFinding] = []
    servers: dict[str, RemoteMCPServerConfig] = {}
    candidates: Mapping[str, Any] = {}
    for key in ("mcpServers", "servers"):
        raw_servers = config.get(key)
        if isinstance(raw_servers, Mapping):
            candidates = {**candidates, **raw_servers}

    for name, spec in candidates.items():
        server_name = str(name)
        if not isinstance(spec, Mapping):
            continue
        if spec.get("disabled") is True:
            continue
        transport = _remote_transport(spec)
        if transport is None:
            continue
        url = _remote_url(spec, transport)
        if not isinstance(url, str) or not url.strip():
            findings.append(_config_finding(server_name, "critical", "Remote MCP server url must be a string"))
            continue
        if _contains_unresolved_variable(url):
            findings.append(_config_finding(server_name, "critical", "Remote MCP server url contains unresolved variables"))
            continue
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            findings.append(_config_finding(server_name, "critical", "Remote MCP server url must use http or https"))
            continue
        raw_headers = spec.get("headers", {})
        if raw_headers is None:
            raw_headers = {}
        if not isinstance(raw_headers, Mapping) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in raw_headers.items()
        ):
            findings.append(_config_finding(server_name, "critical", "Remote MCP server headers must be a string map"))
            continue
        if any(_contains_unresolved_variable(v) for v in raw_headers.values()):
            findings.append(_config_finding(server_name, "critical", "Remote MCP server headers contain unresolved variables"))
            continue
        if any(not _valid_http_header(k, v) for k, v in raw_headers.items()):
            findings.append(_config_finding(server_name, "critical", "Remote MCP server headers contain invalid characters"))
            continue
        servers[server_name] = RemoteMCPServerConfig(
            name=server_name,
            transport=transport,
            url=url,
            headers=dict(raw_headers),
        )
    return servers, findings


def parse_config(config: Any) -> dict[str, list[dict[str, Any]]]:
    """Parse static tool definitions from config for tests/offline scans.

    Static tool definitions are optional in most real MCP configs. Live stdio
    inspection is handled by ``inspect_stdio_config``.
    """
    if isinstance(config, list):
        return {"default": [normalize_mcp_tool(tool) for tool in config if isinstance(tool, Mapping)]}
    if not isinstance(config, Mapping):
        return {"default": []}
    if isinstance(config.get("tools"), list):
        return {
            "default": [
                normalize_mcp_tool(tool) for tool in config["tools"] if isinstance(tool, Mapping)
            ]
        }
    servers: dict[str, list[dict[str, Any]]] = {}
    raw_servers = config.get("mcpServers") or config.get("servers") or {}
    if isinstance(raw_servers, Mapping):
        for name, spec in raw_servers.items():
            tools = spec.get("tools", []) if isinstance(spec, Mapping) else []
            servers[str(name)] = [normalize_mcp_tool(tool) for tool in tools if isinstance(tool, Mapping)]
    return servers or {"default": []}



def _has_inline_tools(spec: Mapping[str, Any]) -> bool:
    tools = spec.get("tools")
    return isinstance(tools, list)


def validate_stdio_launch_config(config_path: Path, single_server: str | None = None) -> list[SecurityFinding]:
    """Validate launch fields for local stdio MCP configs without launching them.

    Static-only scans should not execute configured commands, but they should
    still fail closed for malformed local stdio launch definitions that would be
    uninspectable in live mode. Inline tool-only fixtures remain valid for
    offline docs/tests even when they omit a launch command.
    """
    try:
        config = load_config(config_path)
    except Exception as exc:
        return [SecurityFinding("system", "critical", f"Failed to load config: {exc}", "configuration")]
    if not isinstance(config, Mapping):
        return []

    raw_servers = config.get("mcpServers") or config.get("servers") or {}
    if not isinstance(raw_servers, Mapping):
        return []

    findings: list[SecurityFinding] = []
    for name, spec in raw_servers.items():
        server_name = str(name)
        if single_server and server_name != single_server:
            continue
        if not isinstance(spec, Mapping):
            findings.append(_config_finding(server_name, "critical", "Server config must be an object"))
            continue
        if spec.get("disabled") is True:
            continue

        if _remote_transport(spec) is not None:
            _, remote_findings = parse_remote_mcp_servers({"servers": {server_name: spec}}, config_path=config_path)
            findings.extend(remote_findings)
            continue

        command = spec.get("command")
        if command is None and _has_inline_tools(spec):
            continue
        if not isinstance(command, str) or not command.strip():
            findings.append(_config_finding(server_name, "critical", "Server command must be a string"))
            continue
        if _contains_unresolved_variable(command):
            findings.append(_config_finding(server_name, "critical", "Server command contains unresolved variables"))
            continue

        raw_args = spec.get("args", [])
        if raw_args is None:
            raw_args = []
        if not isinstance(raw_args, list) or not all(isinstance(arg, str) for arg in raw_args):
            findings.append(_config_finding(server_name, "critical", "Server args must be a list of strings"))
            continue
        if any(_contains_unresolved_variable(arg) for arg in raw_args):
            findings.append(_config_finding(server_name, "critical", "Server args contain unresolved variables"))
            continue

        raw_env = spec.get("env", {})
        if raw_env is None:
            raw_env = {}
        if not isinstance(raw_env, Mapping) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in raw_env.items()
        ):
            findings.append(_config_finding(server_name, "critical", "Server env must be a string map"))
            continue
        if any(_contains_unresolved_variable(value) for value in raw_env.values()):
            findings.append(_config_finding(server_name, "critical", "Server env contains unresolved variables"))
            continue

        _resolve_cwd(spec.get("cwd"), config_path, findings, server_name)
    return findings


# ---------------------------------------------------------------------------
# Minimal stdio MCP client
# ---------------------------------------------------------------------------


class _StdioJSONRPCClient:
    """Small JSON-RPC line client for stdio MCP inspection."""

    def __init__(self, server: StdioMCPServerConfig, timeout: float) -> None:
        self.server = server
        self.timeout = timeout
        self.process: subprocess.Popen[str] | None = None
        self._next_id = 1
        self._stdout_queue: queue.Queue[str] = queue.Queue()
        self._stderr_lines: list[str] = []
        self._stderr_lock = threading.Lock()
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        _validate_command(self.server.command)
        _validate_env(self.server.env)
        _validate_launch_cwd(self.server.cwd)
        env = _sanitized_child_env()
        env.update(self.server.env)
        self.process = subprocess.Popen(  # noqa: S603 - command comes from user MCP config by design.
            [self.server.command, *self.server.args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(self.server.cwd) if self.server.cwd else None,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        assert self.process.stdout is not None
        assert self.process.stderr is not None
        self._threads = [
            threading.Thread(target=self._read_stdout, daemon=True),
            threading.Thread(target=self._read_stderr, daemon=True),
        ]
        for thread in self._threads:
            thread.start()

    def _read_stdout(self) -> None:
        assert self.process is not None and self.process.stdout is not None
        for line in self.process.stdout:
            self._stdout_queue.put(line)

    def _read_stderr(self) -> None:
        assert self.process is not None and self.process.stderr is not None
        for line in self.process.stderr:
            with self._stderr_lock:
                self._stderr_lines.append(line.rstrip("\n"))
                if len(self._stderr_lines) > 20:
                    del self._stderr_lines[:-20]

    def stderr_tail(self) -> str:
        """Return a bounded stderr tail for diagnostics."""
        with self._stderr_lock:
            return "\n".join(self._stderr_lines[-20:])

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send a JSON-RPC request and wait for the matching response."""
        request_id = self._next_id
        self._next_id += 1
        self._write({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}})
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if self.process is not None and self.process.poll() is not None and self._stdout_queue.empty():
                raise RuntimeError(f"Server exited before responding to {method}")
            remaining = max(0.01, min(0.25, deadline - time.monotonic()))
            try:
                line = self._stdout_queue.get(timeout=remaining)
            except queue.Empty:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if message.get("id") != request_id:
                continue
            if "error" in message:
                raise RuntimeError(f"{method} failed: {message['error']}")
            result = message.get("result", {})
            return result if isinstance(result, dict) else {"value": result}
        raise TimeoutError(f"Timed out waiting for {method} response")

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        """Send a JSON-RPC notification."""
        self._write({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def _write(self, payload: dict[str, Any]) -> None:
        if self.process is None or self.process.stdin is None:
            raise RuntimeError("MCP server process is not running")
        self.process.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
        self.process.stdin.flush()

    def close(self) -> None:
        """Terminate the child process and join reader threads."""
        if self.process is None:
            return
        try:
            if self.process.stdin is not None:
                self.process.stdin.close()
        except OSError:
            pass
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        for thread in self._threads:
            thread.join(timeout=2)



def _sanitized_child_env() -> dict[str, str]:
    """Return a minimal process environment for launched MCP servers.

    MCP configs may come from repositories or pull requests. The scanner must
    launch configured stdio servers to inspect their advertised tools, but it
    should not automatically expose the operator's full environment to that
    child process. Keep only platform essentials needed to resolve commands and
    let explicitly configured server env values opt in to additional variables.
    """
    keep = {
        "PATH",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "TMPDIR",
        "TEMP",
        "TMP",
    }
    return {key: value for key, value in os.environ.items() if key in keep}

def _schema_text(schema: Mapping[str, Any]) -> str:
    """Return scanner-visible text from schema descriptions and property names."""
    parts: list[str] = []
    description = schema.get("description")
    if isinstance(description, str):
        parts.append(description)
    properties = schema.get("properties")
    if isinstance(properties, Mapping):
        for prop_name, prop_def in properties.items():
            parts.append(str(prop_name))
            if isinstance(prop_def, Mapping):
                prop_description = prop_def.get("description")
                if isinstance(prop_description, str):
                    parts.append(prop_description)
    return "\n".join(part for part in parts if part)


def normalize_mcp_tool(tool: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize MCP tool metadata to the shape MCPSecurityScanner expects."""
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        schema = {}
    return {
        "name": str(tool.get("name", "unknown")),
        "description": _join_metadata_parts(tool.get("description", ""), _schema_text(schema)),
        "inputSchema": schema,
    }


def _join_metadata_parts(*parts: Any) -> str:
    return "\n".join(str(part) for part in parts if part not in (None, ""))


def normalize_mcp_resource(resource: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize MCP resource metadata for existing metadata scanners."""
    identity = str(resource.get("uri") or resource.get("name") or "unknown")
    return {
        "name": f"resource:{identity}",
        "description": _join_metadata_parts(
            resource.get("name"),
            resource.get("title"),
            resource.get("description"),
            resource.get("mimeType"),
            resource.get("uri"),
        ),
        "inputSchema": {},
    }


def normalize_mcp_resource_template(template: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize MCP resource template metadata for existing metadata scanners."""
    identity = str(template.get("uriTemplate") or template.get("name") or "unknown")
    return {
        "name": f"resource_template:{identity}",
        "description": _join_metadata_parts(
            template.get("name"),
            template.get("title"),
            template.get("description"),
            template.get("mimeType"),
            template.get("uriTemplate"),
        ),
        "inputSchema": {},
    }


def _prompt_arguments_schema(arguments: Any) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "object", "properties": {}}
    required: list[str] = []
    if not isinstance(arguments, list):
        return schema
    for argument in arguments:
        if not isinstance(argument, Mapping):
            continue
        name = argument.get("name")
        if not isinstance(name, str) or not name:
            continue
        property_schema: dict[str, Any] = {"type": "string"}
        description = argument.get("description")
        if isinstance(description, str) and description:
            property_schema["description"] = description
        schema["properties"][name] = property_schema
        if argument.get("required") is True:
            required.append(name)
    if required:
        schema["required"] = required
    return schema


def normalize_mcp_prompt(prompt: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize MCP prompt metadata for existing metadata scanners."""
    return {
        "name": f"prompt:{prompt.get('name', 'unknown')}",
        "description": _join_metadata_parts(prompt.get("title"), prompt.get("description")),
        "inputSchema": _prompt_arguments_schema(prompt.get("arguments")),
    }


def _capability_enabled(initialize_result: Mapping[str, Any], key: str) -> bool:
    capabilities = initialize_result.get("capabilities")
    return isinstance(capabilities, Mapping) and isinstance(capabilities.get(key), Mapping)


def _is_method_not_found(exc: Exception) -> bool:
    return "-32601" in str(exc) or "not found" in str(exc).lower() or "method not found" in str(exc).lower()


def _all_inspection_primitives(inspection: StdioMCPInspection) -> list[dict[str, Any]]:
    return [
        *inspection.tools,
        *inspection.resources,
        *inspection.resource_templates,
        *inspection.prompts,
    ]


def _client_info() -> dict[str, str]:
    try:
        from agent_os import __version__
    except Exception:  # pragma: no cover - defensive
        __version__ = "unknown"
    return {"name": "agent-os-mcp-scan", "version": str(__version__)}


def _validate_initialize_result(result: Any) -> dict[str, Any]:
    """Validate InitializeResult before entering normal operation."""
    if not isinstance(result, dict):
        raise RuntimeError("initialize result was not an object")
    protocol_version = result.get("protocolVersion")
    if protocol_version not in _SUPPORTED_PROTOCOL_VERSIONS:
        raise RuntimeError(
            f"unsupported MCP protocol version: {protocol_version!r}; "
            f"supported: {sorted(_SUPPORTED_PROTOCOL_VERSIONS)}"
        )
    if protocol_version != MCP_PROTOCOL_VERSION:
        warnings.warn(
            f"Server uses older MCP protocol {protocol_version!r}; latest is {MCP_PROTOCOL_VERSION}",
            stacklevel=2,
        )
    capabilities = result.get("capabilities")
    if not isinstance(capabilities, Mapping):
        raise RuntimeError("initialize result did not advertise capabilities")
    if not any(isinstance(capabilities.get(key), Mapping) for key in ("tools", "resources", "prompts")):
        raise RuntimeError("server did not advertise inspectable MCP capabilities")
    server_info = result.get("serverInfo")
    if not isinstance(server_info, Mapping):
        raise RuntimeError("initialize result did not include serverInfo")
    return result


def _list_stdio_primitives(
    client: _StdioJSONRPCClient,
    method: str,
    result_key: str,
    normalizer: Any,
    max_pages: int,
    *,
    optional: bool = False,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cursor: str | None = None
    for _ in range(max_pages):
        params = {"cursor": cursor} if cursor else {}
        try:
            result = client.request(method, params)
        except RuntimeError as exc:
            if optional and _is_method_not_found(exc):
                return []
            raise
        raw_items = result.get(result_key, [])
        if not isinstance(raw_items, list):
            raise RuntimeError(f"{method} result did not contain a {result_key} list")
        items.extend(normalizer(item) for item in raw_items if isinstance(item, Mapping))
        next_cursor = result.get("nextCursor")
        if not next_cursor:
            break
        cursor = str(next_cursor)
    else:
        raise RuntimeError(f"{method} pagination exceeded max_pages")
    return items


def inspect_stdio_server(
    server: StdioMCPServerConfig, *, timeout: float = 10.0, max_pages: int = 20
) -> StdioMCPInspection:
    """Start a stdio MCP server, initialize it, and enumerate advertised primitives."""
    client = _StdioJSONRPCClient(server, timeout=timeout)
    try:
        client.start()
        initialize_result = client.request(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": _client_info(),
            },
        )
        initialize_result = _validate_initialize_result(initialize_result)
        client.notify("notifications/initialized", {})

        tools = (
            _list_stdio_primitives(client, "tools/list", "tools", normalize_mcp_tool, max_pages)
            if _capability_enabled(initialize_result, "tools")
            else []
        )
        resources = (
            _list_stdio_primitives(client, "resources/list", "resources", normalize_mcp_resource, max_pages)
            if _capability_enabled(initialize_result, "resources")
            else []
        )
        resource_templates = (
            _list_stdio_primitives(
                client,
                "resources/templates/list",
                "resourceTemplates",
                normalize_mcp_resource_template,
                max_pages,
                optional=True,
            )
            if _capability_enabled(initialize_result, "resources")
            else []
        )
        prompts = (
            _list_stdio_primitives(client, "prompts/list", "prompts", normalize_mcp_prompt, max_pages)
            if _capability_enabled(initialize_result, "prompts")
            else []
        )

        return StdioMCPInspection(
            server_name=server.name,
            ok=True,
            tools=tools,
            resources=resources,
            resource_templates=resource_templates,
            prompts=prompts,
            initialize_result=initialize_result,
            stderr_tail=client.stderr_tail(),
            protocol_version=str(initialize_result.get("protocolVersion", "")) or None,
        )
    except Exception as exc:
        return StdioMCPInspection(
            server_name=server.name,
            ok=False,
            error=str(exc),
            stderr_tail=client.stderr_tail(),
        )
    finally:
        client.close()


_REQUEST_ID_COUNTER = itertools.count(1)


_REQUEST_ID_COUNTER = itertools.count(1)


def _next_request_id() -> int:
    return next(_REQUEST_ID_COUNTER)


def _jsonrpc_request(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": _next_request_id(), "method": method, "params": params or {}}


def _jsonrpc_notification(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "method": method, "params": params or {}}


def _parse_sse_events(raw: str) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    for block in raw.replace("\r\n", "\n").split("\n\n"):
        data_lines = []
        for line in block.splitlines():
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
        if not data_lines:
            continue
        data = "\n".join(data_lines)
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            messages.append(parsed)
    return messages


def _http_request(
    url: str,
    *,
    method: str = "POST",
    payload: dict[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, str], bytes]:
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(url, data=body, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CONTEXT) as response:  # noqa: S310 - URL is user-supplied MCP config by design.
        return response.status, dict(response.headers.items()), response.read()


def _response_message(
    status: int,
    headers: Mapping[str, str],
    body: bytes,
    *,
    expected_id: int | None = None,
) -> dict[str, Any] | None:
    if status == 202 or not body:
        return None
    content_type = headers.get("Content-Type", headers.get("content-type", "")).lower()
    raw = body.decode("utf-8", errors="replace")
    if "text/event-stream" in content_type:
        messages = _parse_sse_events(raw)
        if expected_id is None:
            return None
        for message in messages:
            if message.get("id") == expected_id:
                return message
        raise RuntimeError(f"SSE response did not contain JSON-RPC response id {expected_id}")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        return None
    if expected_id is not None and parsed.get("id") != expected_id:
        raise RuntimeError(f"JSON-RPC response id mismatch: expected {expected_id}, got {parsed.get('id')!r}")
    return parsed


def _sse_message_from_stream(
    response: Any,
    *,
    expected_id: int,
    timeout: float,
) -> dict[str, Any] | None:
    """Read a Streamable HTTP SSE response until the matching JSON-RPC id."""
    deadline = time.monotonic() + timeout
    event = "message"
    data_lines: list[str] = []
    while time.monotonic() < deadline:
        try:
            raw_line = response.readline()
        except TimeoutError:
            continue
        if not raw_line:
            break
        line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
        if line:
            if line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
            continue
        if not data_lines:
            event = "message"
            continue
        data = "\n".join(data_lines)
        is_message_event = event == "message"
        event = "message"
        data_lines = []
        if not is_message_event:
            continue
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and parsed.get("id") == expected_id:
            return parsed
    raise TimeoutError(f"Timed out waiting for Streamable HTTP SSE response id {expected_id}")


def _streamable_http_request(
    url: str,
    *,
    payload: dict[str, Any],
    headers: Mapping[str, str],
    timeout: float,
    expected_id: int | None,
) -> tuple[int, dict[str, str], dict[str, Any] | None]:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    for key, value in headers.items():
        req.add_header(key, value)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CONTEXT) as response:  # noqa: S310 - URL is user-supplied MCP config by design.
        response_headers = dict(response.headers.items())
        if response.status == 202:
            return response.status, response_headers, None
        content_type = response_headers.get("Content-Type", response_headers.get("content-type", "")).lower()
        if "text/event-stream" in content_type:
            if expected_id is None:
                return response.status, response_headers, None
            return response.status, response_headers, _sse_message_from_stream(
                response, expected_id=expected_id, timeout=timeout
            )
        raw = response.read()
    return response.status, response_headers, _response_message(
        response.status,
        response_headers,
        raw,
        expected_id=expected_id,
    )


def _extract_session_id(headers: Mapping[str, str]) -> str | None:
    for key, value in headers.items():
        if key.lower() == "mcp-session-id":
            return value
    return None


def _streamable_http_call(
    server: RemoteMCPServerConfig,
    payload: dict[str, Any],
    *,
    timeout: float,
    session_id: str | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    headers = {
        **server.headers,
        "Accept": "application/json, text/event-stream",
        "Mcp-Protocol-Version": MCP_PROTOCOL_VERSION,
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    expected_id = payload.get("id") if isinstance(payload.get("id"), int) else None
    _, response_headers, response_message = _streamable_http_request(
        server.url,
        payload=payload,
        headers=headers,
        timeout=timeout,
        expected_id=expected_id,
    )
    return response_message, _extract_session_id(response_headers) or session_id


def _list_remote_primitives(
    call: Any,
    method: str,
    result_key: str,
    normalizer: Any,
    max_pages: int,
    *,
    optional: bool = False,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cursor: str | None = None
    for _ in range(max_pages):
        params = {"cursor": cursor} if cursor else {}
        response = call(_jsonrpc_request(method, params))
        if not response or "error" in response:
            if optional and _is_method_not_found(RuntimeError(str(response))):
                return []
            raise RuntimeError(f"{method} failed: {response}")
        result = response.get("result", {})
        if not isinstance(result, dict):
            raise RuntimeError(f"{method} result was not an object")
        raw_items = result.get(result_key, [])
        if not isinstance(raw_items, list):
            raise RuntimeError(f"{method} result did not contain a {result_key} list")
        items.extend(normalizer(item) for item in raw_items if isinstance(item, Mapping))
        next_cursor = result.get("nextCursor")
        if not next_cursor:
            break
        cursor = str(next_cursor)
    else:
        raise RuntimeError(f"{method} pagination exceeded max_pages")
    return items


def _inspect_streamable_http_server(server: RemoteMCPServerConfig, *, timeout: float, max_pages: int) -> StdioMCPInspection:
    session_id: str | None = None
    initialize, session_id = _streamable_http_call(
        server,
        _jsonrpc_request("initialize", {"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {}, "clientInfo": _client_info()}),
        timeout=timeout,
    )
    if not initialize or "error" in initialize:
        raise RuntimeError(f"initialize failed: {initialize}")
    initialize_result = _validate_initialize_result(initialize.get("result", {}))
    _streamable_http_call(
        server,
        _jsonrpc_notification("notifications/initialized"),
        timeout=timeout,
        session_id=session_id,
    )
    def call(payload: dict[str, Any]) -> dict[str, Any] | None:
        nonlocal session_id
        response, session_id = _streamable_http_call(server, payload, timeout=timeout, session_id=session_id)
        return response

    tools = (
        _list_remote_primitives(call, "tools/list", "tools", normalize_mcp_tool, max_pages)
        if _capability_enabled(initialize_result, "tools")
        else []
    )
    resources = (
        _list_remote_primitives(call, "resources/list", "resources", normalize_mcp_resource, max_pages)
        if _capability_enabled(initialize_result, "resources")
        else []
    )
    resource_templates = (
        _list_remote_primitives(
            call,
            "resources/templates/list",
            "resourceTemplates",
            normalize_mcp_resource_template,
            max_pages,
            optional=True,
        )
        if _capability_enabled(initialize_result, "resources")
        else []
    )
    prompts = (
        _list_remote_primitives(call, "prompts/list", "prompts", normalize_mcp_prompt, max_pages)
        if _capability_enabled(initialize_result, "prompts")
        else []
    )
    return StdioMCPInspection(
        server_name=server.name,
        ok=True,
        tools=tools,
        resources=resources,
        resource_templates=resource_templates,
        prompts=prompts,
        initialize_result=initialize_result,
        transport=server.transport,
        protocol_version=str(initialize_result.get("protocolVersion", "")) or None,
    )


def _read_sse_message(queue_: queue.Queue[dict[str, Any]], request_id: int, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            message = queue_.get(timeout=max(0.01, min(0.1, deadline - time.monotonic())))
        except queue.Empty:
            continue
        if message.get("id") == request_id:
            return message
    raise TimeoutError(f"Timed out waiting for SSE response id {request_id}")


def _open_legacy_sse(url: str, headers: Mapping[str, str], timeout: float) -> tuple[urllib.response.addinfourl, str, queue.Queue[dict[str, Any]]]:
    req = urllib.request.Request(url, method="GET", headers={**headers, "Accept": "text/event-stream"})
    response = urllib.request.urlopen(req, timeout=timeout, context=_SSL_CONTEXT)  # noqa: S310 - user MCP endpoint by design.
    message_queue: queue.Queue[dict[str, Any]] = queue.Queue()
    endpoint_event = threading.Event()
    endpoint_holder: list[str] = [""]

    def reader() -> None:
        event = "message"
        data_lines: list[str] = []
        while True:
            try:
                raw_line = response.readline()
            except TimeoutError:
                break
            if not raw_line:
                break
            line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
            if not line:
                if data_lines:
                    data = "\n".join(data_lines)
                    if event == "endpoint":
                        endpoint_holder[0] = data
                        endpoint_event.set()
                    else:
                        try:
                            parsed = json.loads(data)
                        except json.JSONDecodeError:
                            parsed = None
                        if isinstance(parsed, dict):
                            message_queue.put(parsed)
                event = "message"
                data_lines = []
                continue
            if line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].lstrip())

    threading.Thread(target=reader, daemon=True).start()
    if not endpoint_event.wait(timeout=timeout):
        response.close()
        raise TimeoutError("Timed out waiting for legacy SSE endpoint event")
    endpoint = urllib.parse.urljoin(url, endpoint_holder[0])
    base = urllib.parse.urlparse(url)
    follow_up = urllib.parse.urlparse(endpoint)
    if (follow_up.scheme, follow_up.netloc) != (base.scheme, base.netloc):
        response.close()
        raise RuntimeError("Legacy SSE endpoint event resolved outside the configured MCP origin")
    return response, endpoint, message_queue


def _inspect_legacy_sse_server(server: RemoteMCPServerConfig, *, timeout: float, max_pages: int) -> StdioMCPInspection:
    response, endpoint, message_queue = _open_legacy_sse(server.url, server.headers, timeout)
    try:
        def post_and_wait(payload: dict[str, Any]) -> dict[str, Any] | None:
            _http_request(endpoint, payload=payload, headers=server.headers, timeout=timeout)
            request_id = payload.get("id")
            if request_id is None:
                return None
            return _read_sse_message(message_queue, int(request_id), timeout)

        initialize_payload = _jsonrpc_request(
            "initialize", {"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {}, "clientInfo": _client_info()}
        )
        initialize = post_and_wait(initialize_payload)
        if not initialize or "error" in initialize:
            raise RuntimeError(f"initialize failed: {initialize}")
        initialize_result = _validate_initialize_result(initialize.get("result", {}))
        post_and_wait(_jsonrpc_notification("notifications/initialized"))
        tools = (
            _list_remote_primitives(post_and_wait, "tools/list", "tools", normalize_mcp_tool, max_pages)
            if _capability_enabled(initialize_result, "tools")
            else []
        )
        resources = (
            _list_remote_primitives(post_and_wait, "resources/list", "resources", normalize_mcp_resource, max_pages)
            if _capability_enabled(initialize_result, "resources")
            else []
        )
        resource_templates = (
            _list_remote_primitives(
                post_and_wait,
                "resources/templates/list",
                "resourceTemplates",
                normalize_mcp_resource_template,
                max_pages,
                optional=True,
            )
            if _capability_enabled(initialize_result, "resources")
            else []
        )
        prompts = (
            _list_remote_primitives(post_and_wait, "prompts/list", "prompts", normalize_mcp_prompt, max_pages)
            if _capability_enabled(initialize_result, "prompts")
            else []
        )
        return StdioMCPInspection(
            server_name=server.name,
            ok=True,
            tools=tools,
            resources=resources,
            resource_templates=resource_templates,
            prompts=prompts,
            initialize_result=initialize_result,
            transport="sse",
            protocol_version=str(initialize_result.get("protocolVersion", "")) or None,
        )
    finally:
        response.close()


def inspect_remote_server(
    server: RemoteMCPServerConfig, *, timeout: float = 10.0, max_pages: int = 20
) -> StdioMCPInspection:
    """Inspect a Streamable HTTP or legacy SSE MCP server."""
    try:
        if server.transport == "sse":
            return _inspect_legacy_sse_server(server, timeout=timeout, max_pages=max_pages)
        try:
            return _inspect_streamable_http_server(server, timeout=timeout, max_pages=max_pages)
        except urllib.error.HTTPError as http_error:
            if server.transport == "streamable-http" and http_error.code in {400, 404, 405}:
                legacy_server = RemoteMCPServerConfig(server.name, "sse", server.url, server.headers)
                return _inspect_legacy_sse_server(legacy_server, timeout=timeout, max_pages=max_pages)
            raise
    except Exception as exc:
        return StdioMCPInspection(server_name=server.name, ok=False, error=str(exc), transport=server.transport)


def inspect_stdio_config(
    config_path: Path,
    *,
    server_filter: str | None = None,
    timeout: float = 10.0,
) -> tuple[dict[str, StdioMCPInspection], list[SecurityFinding]]:
    """Inspect all selected stdio MCP servers in a config file."""
    config = load_config(config_path)
    if not isinstance(config, Mapping):
        raise ValueError("MCP config must be a JSON/YAML object for live inspection")
    servers, findings = parse_stdio_mcp_servers(config, config_path=config_path)
    inspections: dict[str, StdioMCPInspection] = {}
    for name, server in servers.items():
        if server_filter and name != server_filter:
            continue
        inspection = inspect_stdio_server(server, timeout=timeout)
        inspections[name] = inspection
        if not inspection.ok:
            findings.append(
                SecurityFinding(
                    name,
                    "critical",
                    f"MCP inspection failed: {inspection.error}",
                    "inspection",
                )
            )
    return inspections, findings


def inspect_mcp_config(
    config_path: Path,
    *,
    server_filter: str | None = None,
    timeout: float = 10.0,
) -> tuple[dict[str, StdioMCPInspection], list[SecurityFinding]]:
    """Inspect selected MCP servers across stdio, Streamable HTTP, and legacy SSE."""
    config = load_config(config_path)
    if not isinstance(config, Mapping):
        raise ValueError("MCP config must be a JSON/YAML object for live inspection")
    stdio_servers, findings = parse_stdio_mcp_servers(config, config_path=config_path)
    remote_servers, remote_findings = parse_remote_mcp_servers(config, config_path=config_path)
    findings.extend(remote_findings)
    inspections: dict[str, StdioMCPInspection] = {}
    for name, server in stdio_servers.items():
        if server_filter and name != server_filter:
            continue
        inspection = inspect_stdio_server(server, timeout=timeout)
        inspections[name] = inspection
        if not inspection.ok:
            findings.append(SecurityFinding(name, "critical", f"MCP inspection failed: {inspection.error}", "inspection"))
    for name, server in remote_servers.items():
        if server_filter and name != server_filter:
            continue
        inspection = inspect_remote_server(server, timeout=timeout)
        inspections[name] = inspection
        if not inspection.ok:
            findings.append(SecurityFinding(name, "critical", f"MCP inspection failed: {inspection.error}", "inspection"))
    return inspections, findings


# ---------------------------------------------------------------------------
# Security scan and fingerprint operations
# ---------------------------------------------------------------------------


def scan_config(config_path: Path, single_server: str | None = None) -> list[SecurityFinding]:
    """Scan MCP server launch config for static risks."""
    findings: list[SecurityFinding] = []
    try:
        config = load_config(config_path)
    except Exception as exc:
        return [SecurityFinding("system", "critical", f"Failed to load config: {exc}", "configuration")]

    if not isinstance(config, Mapping):
        return []

    raw_servers = config.get("mcpServers") or config.get("servers") or {}
    if not isinstance(raw_servers, Mapping):
        return findings

    for name, server in raw_servers.items():
        server_name = str(name)
        if single_server and server_name != single_server:
            continue
        if not isinstance(server, Mapping):
            continue

        env = server.get("env", {})
        if isinstance(env, Mapping):
            for key in env:
                if any(token in str(key).upper() for token in ("KEY", "SECRET", "TOKEN")):
                    findings.append(
                        SecurityFinding(
                            server_name,
                            "warning",
                            f"Sensitive key '{key}' exposed in environment",
                            "leakage",
                        )
                    )

        cmd = str(server.get("command", ""))
        if "sudo" in cmd.lower():
            findings.append(
                SecurityFinding(server_name, "critical", "Server runs with sudo privileges", "privilege")
            )
        if tempfile.gettempdir() in cmd.lower():
            findings.append(
                SecurityFinding(server_name, "warning", "Server binary path in /tmp is risky", "execution")
            )

        args = server.get("args", [])
        if isinstance(args, list):
            for arg in args:
                if (
                    isinstance(arg, str)
                    and "/" in arg
                    and Path(arg).is_absolute()
                    and not arg.startswith(("/usr/", "/bin/", "/opt/"))
                ):
                    findings.append(
                        SecurityFinding(
                            server_name,
                            "warning",
                            f"Absolute path '{arg}' exposed in arguments",
                            "leakage",
                        )
                    )

    return findings


def _severity_rank(severity: MCPSeverity | str) -> int:
    value = severity.value if isinstance(severity, MCPSeverity) else severity
    return {"info": 0, "warning": 1, "critical": 2}.get(value, 0)


def _filter_threats(threats: list[MCPThreat], min_severity: str | None) -> list[MCPThreat]:
    if min_severity is None:
        return threats
    return [t for t in threats if _severity_rank(t.severity) >= _severity_rank(min_severity)]


def _finding_rank(finding: SecurityFinding) -> int:
    return _severity_rank(finding.severity)


def _has_critical_findings(findings: Sequence[SecurityFinding]) -> bool:
    return any(_finding_rank(finding) >= _severity_rank("critical") for finding in findings)


def _scan_exit_code(scan: MCPScanRun) -> int:
    if any(t.severity == MCPSeverity.CRITICAL for t in scan.threats):
        return 2
    if _has_critical_findings([*scan.config_findings, *scan.inspection_findings]):
        return 2
    return 0


def run_scan(
    servers: dict[str, list[dict[str, Any]]],
    server_filter: str | None = None,
    min_severity: str | None = None,
    scanner: MCPSecurityScanner | None = None,
) -> tuple[dict[str, ScanResult], list[MCPThreat]]:
    """Run MCPSecurityScanner over already-known tool definitions."""
    active_scanner = scanner or MCPSecurityScanner()
    results: dict[str, ScanResult] = {}
    all_threats: list[MCPThreat] = []

    for server_name, tools in servers.items():
        if server_filter and server_name != server_filter:
            continue
        result = active_scanner.scan_server(server_name, tools)
        filtered = _filter_threats(result.threats, min_severity)
        filtered_flagged = {t.tool_name for t in filtered}
        filtered_result = ScanResult(
            safe=len(filtered) == 0,
            threats=filtered,
            tools_scanned=result.tools_scanned,
            tools_flagged=len(filtered_flagged),
        )
        results[server_name] = filtered_result
        all_threats.extend(filtered)
        for tool in tools:
            active_scanner.register_tool(
                str(tool.get("name", "unknown")),
                str(tool.get("description", "")),
                tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else {},
                server_name,
            )

    return results, all_threats


def run_security_scan(
    config_path: Path,
    *,
    server_filter: str | None = None,
    min_severity: str | None = None,
    inspect_stdio: bool = True,
    timeout: float = 10.0,
    scanner: MCPSecurityScanner | None = None,
) -> MCPScanRun:
    """Run static config checks plus live MCP tool inspection."""
    active_scanner = scanner or MCPSecurityScanner()
    config = load_config(config_path)
    static_servers = parse_config(config)
    config_findings = scan_config(config_path, server_filter)
    config_findings.extend(validate_stdio_launch_config(config_path, server_filter))

    inspections: dict[str, StdioMCPInspection] = {}
    inspection_findings: list[SecurityFinding] = []
    live_servers: dict[str, list[dict[str, Any]]] = {}
    if inspect_stdio and isinstance(config, Mapping):
        inspections, inspection_findings = inspect_mcp_config(
            config_path, server_filter=server_filter, timeout=timeout
        )
        live_servers = {name: _all_inspection_primitives(inspection) for name, inspection in inspections.items() if inspection.ok}

    servers_to_scan = dict(static_servers)
    for name, tools in live_servers.items():
        servers_to_scan[name] = tools

    results, threats = run_scan(
        servers_to_scan,
        server_filter=server_filter,
        min_severity=min_severity,
        scanner=active_scanner,
    )
    return MCPScanRun(
        results=results,
        threats=threats,
        inspections=inspections,
        config_findings=config_findings,
        inspection_findings=inspection_findings,
    )


def compute_fingerprints(servers: dict[str, list[dict[str, Any]]]) -> dict[str, dict[str, str]]:
    """Compute per-tool fingerprints over descriptions and input schemas."""
    fingerprints: dict[str, dict[str, str]] = {}
    for server_name, tools in servers.items():
        for tool in tools:
            tool_name = str(tool.get("name", "unknown"))
            description = str(tool.get("description", ""))
            schema = tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else {}
            key = f"{server_name}::{tool_name}"
            fingerprints[key] = {
                "tool_name": tool_name,
                "server_name": server_name,
                "description_hash": hashlib.sha256(description.encode("utf-8")).hexdigest(),
                "schema_hash": hashlib.sha256(
                    json.dumps(schema, sort_keys=True, default=str).encode("utf-8")
                ).hexdigest(),
            }
    return fingerprints


def get_fingerprints(config_path: Path, *, inspect_stdio: bool = False, timeout: float = 10.0) -> dict[str, dict[str, str]]:
    """Generate per-tool fingerprints for a config file."""
    config = load_config(config_path)
    servers = parse_config(config)
    if inspect_stdio and isinstance(config, Mapping):
        inspections, _ = inspect_mcp_config(config_path, timeout=timeout)
        for name, inspection in inspections.items():
            if inspection.ok:
                servers[name] = _all_inspection_primitives(inspection)
    return compute_fingerprints(servers)


def compare_fingerprints(
    current: dict[str, dict[str, str]], saved: dict[str, dict[str, str]]
) -> list[dict[str, Any]]:
    """Compare current fingerprints against a saved baseline."""
    changes: list[dict[str, Any]] = []
    for key, current_fp in current.items():
        if key not in saved:
            tool_name = str(current_fp.get("tool_name", key))
            changes.append({"tool": key, "changed_fields": [f"new_tool:{tool_name}", tool_name]})
            continue
        changed_fields = [
            field
            for field in ("description_hash", "schema_hash")
            if current_fp.get(field) != saved[key].get(field)
        ]
        if changed_fields:
            changes.append(
                {
                    "tool": key,
                    "changed_fields": [field.removesuffix("_hash") for field in changed_fields],
                }
            )
    for key in saved:
        if key not in current:
            changes.append({"tool": key, "changed_fields": ["removed"]})
    return changes


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def _threat_to_dict(threat: MCPThreat) -> dict[str, Any]:
    return {
        "threat_type": threat.threat_type.value,
        "severity": threat.severity.value,
        "tool_name": threat.tool_name,
        "server_name": threat.server_name,
        "message": threat.message,
        "matched_pattern": threat.matched_pattern,
        "details": threat.details,
    }




def _summary(results: dict[str, ScanResult], extra_findings: Sequence[SecurityFinding] = ()) -> dict[str, int]:
    warnings = sum(1 for result in results.values() for t in result.threats if t.severity == MCPSeverity.WARNING)
    critical = sum(
        1 for result in results.values() for t in result.threats if t.severity == MCPSeverity.CRITICAL
    )
    primitives_scanned = sum(result.tools_scanned for result in results.values())
    primitives_flagged = sum(result.tools_flagged for result in results.values())
    warnings += sum(1 for f in extra_findings if f.severity == "warning")
    critical += sum(1 for f in extra_findings if f.severity == "critical")
    return {
        "servers_scanned": len(results),
        "primitives_scanned": primitives_scanned,
        "primitives_flagged": primitives_flagged,
        # Backward-compatible aliases retained because ScanResult is tool-named.
        "tools_scanned": primitives_scanned,
        "tools_flagged": primitives_flagged,
        "warnings": warnings,
        "critical": critical,
    }


def format_json_output(
    results: dict[str, ScanResult],
    threats: list[MCPThreat],
    *,
    inspections: dict[str, StdioMCPInspection] | None = None,
    config_findings: Sequence[SecurityFinding] = (),
    inspection_findings: Sequence[SecurityFinding] = (),
) -> str:
    """Format scan results as deterministic JSON."""
    all_findings = [*config_findings, *inspection_findings]
    payload = {
        "servers": {
            server: {
                "safe": result.safe,
                "primitives_scanned": result.tools_scanned,
                "primitives_flagged": result.tools_flagged,
                "tools_scanned": result.tools_scanned,
                "tools_flagged": result.tools_flagged,
                "threats": [_threat_to_dict(t) for t in result.threats],
            }
            for server, result in results.items()
        },
        "summary": _summary(results, all_findings),
        "config_findings": [finding.to_dict() for finding in config_findings],
        "inspection_errors": [finding.to_dict() for finding in inspection_findings],
    }
    if inspections is not None:
        payload["inspections"] = {
            name: {
                "ok": inspection.ok,
                "transport": inspection.transport,
                "protocol_version": inspection.protocol_version,
                "tools_discovered": len(inspection.tools),
                "resources_discovered": len(inspection.resources),
                "resource_templates_discovered": len(inspection.resource_templates),
                "prompts_discovered": len(inspection.prompts),
                "primitives_discovered": len(_all_inspection_primitives(inspection)),
                "error": inspection.error,
            }
            for name, inspection in inspections.items()
        }
    return json.dumps(payload, indent=2)


def format_table(
    results: dict[str, ScanResult],
    threats: list[MCPThreat],
    servers: dict[str, list[dict[str, Any]]] | None = None,
    extra_findings: Sequence[SecurityFinding] = (),
) -> str:
    """Format scan results as plain text suitable for terminals and tests."""
    lines = ["MCP Security Scan Results", "=" * 25]
    if not results:
        lines.append("No MCP primitive metadata found to scan.")
    for server_name, result in results.items():
        lines.append("")
        lines.append(f"Server: {server_name}")
        server_tools = servers.get(server_name, []) if servers else []
        threat_counts: dict[str, list[MCPThreat]] = {}
        for threat in result.threats:
            threat_counts.setdefault(threat.tool_name, []).append(threat)
        tool_names = [str(tool.get("name", "unknown")) for tool in server_tools] or sorted(threat_counts)
        for tool_name in tool_names:
            tool_threats = threat_counts.get(tool_name, [])
            if not tool_threats:
                lines.append(f"  OK  {tool_name} — no threats")
            else:
                worst = max(tool_threats, key=lambda t: _severity_rank(t.severity))
                lines.append(
                    f"  !!  {tool_name} — {len(tool_threats)} {worst.severity.value} threat(s)"
                )
                for threat in tool_threats:
                    lines.append(f"      {threat.severity.value.upper()}: {threat.message}")
    summary = _summary(results, extra_findings)
    lines.append("")
    if summary["critical"] or summary["warnings"]:
        lines.append(
            "Summary: "
            f"{summary['primitives_scanned']} primitives scanned, "
            f"{summary['warnings']} warnings, {summary['critical']} critical"
        )
    else:
        lines.append(
            "Summary: "
            f"{summary['primitives_scanned']} primitives scanned, 0 warnings, 0 critical — No threats detected"
        )
    return "\n".join(lines)


def format_markdown(
    results: dict[str, ScanResult],
    threats: list[MCPThreat],
    extra_findings: Sequence[SecurityFinding] = (),
) -> str:
    """Format scan results as a Markdown report."""
    summary = _summary(results, extra_findings)
    lines = [
        "# MCP Security Scan Report",
        "",
        "**Summary**",
        "",
        f"- Servers scanned: {summary['servers_scanned']}",
        f"- MCP metadata entries scanned: {summary['primitives_scanned']}",
        f"- Warnings: {summary['warnings']}",
        f"- Critical: {summary['critical']}",
        "",
        "| Primitive | Server | Severity | Finding |",
        "|---|---|---|---|",
    ]
    if not threats:
        lines.append("| _No threats detected_ | - | - | - |")
    else:
        for threat in threats:
            lines.append(
                f"| {threat.tool_name} | {threat.server_name} | "
                f"{threat.severity.value} | {threat.message} |"
            )
    lines.extend(["", "## Limitations", "", "This report is scan evidence, not a certification. It inspects MCP primitive metadata and selected launch/endpoint configuration; it does not execute tools, read resources, render prompts, or prove that a server is benign."])
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------


def cmd_scan(args: argparse.Namespace) -> int:
    """Run the scan subcommand."""
    try:
        scan = run_security_scan(
            Path(args.config),
            server_filter=args.server,
            min_severity=args.severity,
            inspect_stdio=not args.static_only,
            timeout=args.timeout,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    output_format = "json" if args.json or args.format == "json" else args.format
    if output_format == "json":
        print(
            format_json_output(
                scan.results,
                scan.threats,
                inspections=scan.inspections,
                config_findings=scan.config_findings,
                inspection_findings=scan.inspection_findings,
            )
        )
    elif output_format == "markdown":
        print(format_markdown(scan.results, scan.threats, [*scan.config_findings, *scan.inspection_findings]))
    else:
        config = load_config(args.config)
        servers = parse_config(config)
        for name, inspection in scan.inspections.items():
            if inspection.ok:
                servers[name] = _all_inspection_primitives(inspection)
        print(format_table(scan.results, scan.threats, servers, [*scan.config_findings, *scan.inspection_findings]))
        for finding in [*scan.config_findings, *scan.inspection_findings]:
            print(f"[{finding.severity.upper()}] {finding.server}: {finding.message}")

    return _scan_exit_code(scan)


def cmd_fingerprint(args: argparse.Namespace) -> int:
    """Run the fingerprint subcommand."""
    try:
        config = load_config(args.config)
        servers = parse_config(config)
        inspection_findings: list[SecurityFinding] = []
        if not args.static_only and isinstance(config, Mapping):
            inspections, inspection_findings = inspect_mcp_config(Path(args.config), timeout=args.timeout)
            for finding in inspection_findings:
                print(f"{finding.severity.title()}: {finding.server}: {finding.message}", file=sys.stderr)
            if _has_critical_findings(inspection_findings):
                return 2
            for name, inspection in inspections.items():
                if inspection.ok:
                    servers[name] = _all_inspection_primitives(inspection)
        current = compute_fingerprints(servers)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    output_format = "json" if args.json else "text"
    if args.compare:
        try:
            saved = json.loads(Path(args.compare).read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"Error: Failed to load fingerprint baseline: {exc}", file=sys.stderr)
            return 1
        changes = compare_fingerprints(current, saved)
        if output_format == "json":
            print(json.dumps({"current": current, "changes": changes}, indent=2))
        elif changes:
            print("Tool definition changes detected:")
            for change in changes:
                print(f"  {change['tool']}: {', '.join(change['changed_fields'])}")
        else:
            print("No changes")
        return 2 if changes else 0

    if args.output:
        Path(args.output).write_text(json.dumps(current, indent=2), encoding="utf-8")
        if output_format == "json":
            print(json.dumps({"status": "success", "file": args.output}, indent=2))
        else:
            print(f"Fingerprints saved to {args.output}")
        return 0

    if output_format == "json":
        print(json.dumps(current, indent=2))
        return 0

    print("Error: fingerprint requires --output, --compare, or --json", file=sys.stderr)
    return 1


def cmd_report(args: argparse.Namespace) -> int:
    """Run the report subcommand."""
    try:
        scan = run_security_scan(
            Path(args.config),
            inspect_stdio=not args.static_only,
            timeout=args.timeout,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    output_format = "json" if args.json or args.format == "json" else args.format
    if output_format == "json":
        print(
            format_json_output(
                scan.results,
                scan.threats,
                inspections=scan.inspections,
                config_findings=scan.config_findings,
                inspection_findings=scan.inspection_findings,
            )
        )
    else:
        print(format_markdown(scan.results, scan.threats, [*scan.config_findings, *scan.inspection_findings]))
    return _scan_exit_code(scan)


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="mcp-scan",
        description="Agent OS MCP Security Scanner - inspect MCP primitives and scan for risks",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    scan_parser = subparsers.add_parser("scan", help="Inspect stdio, Streamable HTTP, and SSE MCP primitives for threats")
    scan_parser.add_argument("config", help="Path to MCP config file (JSON/YAML)")
    scan_parser.add_argument("--server", default=None, help="Scan only this server")
    scan_parser.add_argument(
        "--format", choices=["json", "table", "markdown"], default="table", help="Output format"
    )
    scan_parser.add_argument("--severity", choices=["warning", "critical"], default=None)
    scan_parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout")
    scan_parser.add_argument(
        "--static-only",
        action="store_true",
        help="Do not launch or connect to MCP servers; scan only inline tool definitions and config metadata",
    )
    scan_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    scan_parser.add_argument(
        "--unsafe-allow-all-commands",
        "--allow-commands",
        dest="allow_commands",
        action="store_true",
        help=(
            "DEV/LOCAL ONLY. Bypass the command allowlist and execute any "
            "command the config asks for. Refuses to take effect unless "
            "AGENT_OS_ENV is set to one of {dev, development, local}. The "
            "legacy --allow-commands name is kept as an alias."
        ),
    )
    scan_parser.add_argument(
        "--allow-untrusted-cwd",
        dest="allow_untrusted_cwd",
        action="store_true",
        help=(
            "Allow config-provided server cwd during live launch. Off by "
            "default because the child runtime loads config files "
            "(package.json, nuget.config, sitecustomize.py, .npmrc, ...) "
            "relative to cwd, which the MCP config author can plant."
        ),
    )
    scan_parser.add_argument("--no-verify-tls", action="store_true", help="Skip TLS certificate verification for remote endpoints")

    fp_parser = subparsers.add_parser("fingerprint", help="Register/compare tool fingerprints")
    fp_parser.add_argument("config", help="Path to MCP config file (JSON/YAML)")
    fp_parser.add_argument("--output", default=None, help="Save fingerprints to file")
    fp_parser.add_argument("--compare", default=None, help="Compare against saved file")
    fp_parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout")
    fp_parser.add_argument("--static-only", action="store_true", help="Fingerprint inline tools only")
    fp_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    fp_parser.add_argument(
        "--unsafe-allow-all-commands",
        "--allow-commands",
        dest="allow_commands",
        action="store_true",
        help=(
            "DEV/LOCAL ONLY. Bypass the command allowlist; requires "
            "AGENT_OS_ENV in {dev, development, local}."
        ),
    )
    fp_parser.add_argument(
        "--allow-untrusted-cwd",
        dest="allow_untrusted_cwd",
        action="store_true",
        help="Allow config-provided server cwd during live launch.",
    )
    fp_parser.add_argument("--no-verify-tls", action="store_true", help="Skip TLS certificate verification for remote endpoints")

    report_parser = subparsers.add_parser("report", help="Generate a full security report")
    report_parser.add_argument("config", help="Path to MCP config file (JSON/YAML)")
    report_parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    report_parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout")
    report_parser.add_argument("--static-only", action="store_true", help="Report on inline tools only")
    report_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    report_parser.add_argument(
        "--unsafe-allow-all-commands",
        "--allow-commands",
        dest="allow_commands",
        action="store_true",
        help=(
            "DEV/LOCAL ONLY. Bypass the command allowlist; requires "
            "AGENT_OS_ENV in {dev, development, local}."
        ),
    )
    report_parser.add_argument(
        "--allow-untrusted-cwd",
        dest="allow_untrusted_cwd",
        action="store_true",
        help="Allow config-provided server cwd during live launch.",
    )
    report_parser.add_argument("--no-verify-tls", action="store_true", help="Skip TLS certificate verification for remote endpoints")

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    if getattr(args, "allow_commands", False):
        if not _allow_all_commands_env_permitted():
            print(
                "ERROR: --unsafe-allow-all-commands requires AGENT_OS_ENV to be "
                "one of {dev, development, local}. Refusing to bypass the "
                "command allowlist in a non-local environment.",
                file=sys.stderr,
            )
            return 2
        print(
            "WARNING: --unsafe-allow-all-commands is enabled — the MCP scan "
            "will execute commands outside the safe allowlist. This must not "
            "be used outside local development.",
            file=sys.stderr,
        )
        _configure_command_policy(
            allow_all=True,
            allow_untrusted_cwd=getattr(args, "allow_untrusted_cwd", False),
        )
    elif getattr(args, "allow_untrusted_cwd", False):
        _configure_command_policy(
            allow_all=False, allow_untrusted_cwd=True
        )
    if getattr(args, "no_verify_tls", False):
        _configure_tls(verify=False)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "fingerprint":
        return cmd_fingerprint(args)
    if args.command == "report":
        return cmd_report(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
