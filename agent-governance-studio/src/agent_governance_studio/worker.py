# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Private one-request worker; the HTTP client cannot choose code to execute."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .config import Limits


def _walk_error(error: OSError) -> None:
    raise error


def check_root(root: Path, limits: Limits, destination: Path | None = None) -> None:
    """Bound all files replay could read, not only registry YAML filenames."""
    count = total = 0
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=_walk_error):
        count += len(dirs)
        if count > limits.policy_files:
            raise ValueError("Policy root exceeds the documented finite inventory limits.")
        for name in [*dirs, *files]:
            path = Path(directory) / name
            if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
                raise ValueError("Policy roots must not contain links or junctions.")
        target_dir = destination / Path(directory).relative_to(root) if destination else None
        if target_dir is not None:
            target_dir.mkdir(parents=True, exist_ok=True)
        for name in files:
            path = Path(directory) / name
            count += 1
            stat = path.stat()
            size = stat.st_size
            total += size
            if count > limits.policy_files or size > limits.policy_file_bytes or total > limits.policy_tree_bytes:
                raise ValueError("Policy root exceeds the documented finite inventory limits.")
            with path.open("rb") as handle:
                content = handle.read(limits.policy_file_bytes + 1)
            if len(content) != size:
                raise ValueError("Policy root changed during bounded snapshot initialization.")
            if target_dir is not None:
                target = target_dir / name
                target.write_bytes(content)
                os.utime(target, ns=(stat.st_atime_ns, stat.st_mtime_ns))


async def execute(command: dict) -> dict:
    from agentmesh.engine_api import create_app
    from agentmesh.engine_api.openapi import derive_studio_client_allowlist

    limits = Limits(**command["limits"])
    root = Path(command["policy_dir"])
    if command["kind"] == "inspect" and command["source_root"]:
        source = Path(command["source_root"])
        check_root(source, limits, destination=root)
    check_root(root, limits)
    app = create_app(policy_dir=str(root), enable_policy_save=False)
    app.state.start_time = command["started_at"]
    # No HTML docs are used by this API-only profile.
    app.router.routes[:] = [
        route for route in app.router.routes
        if getattr(route, "path", None) not in {"/docs", "/docs/oauth2-redirect", "/redoc"}
    ]
    if command["kind"] == "inspect":
        from agent_compliance.policy_test import replay
        from agent_control_specification import AgentControl, run_sync
        from agent_control_specification import _native

        if not all(callable(item) for item in (replay, AgentControl.from_path, run_sync, _native.NativeRuntime.from_path)):
            raise ImportError("Incompatible native replay runtime.")
        opa = os.environ.get("ACS_OPA_PATH") or shutil.which("opa")
        if not opa or not Path(opa).is_file():
            raise ImportError("OPA is required; set ACS_OPA_PATH to the documented executable.")
        if subprocess.run([opa, "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2).returncode:
            raise ImportError("OPA cannot execute.")
        # A real native/OPA round trip must succeed before listener readiness.
        with tempfile.TemporaryDirectory(prefix="agt-startup-replay-") as probe:
            probe_root = Path(probe)
            (probe_root / "policy").mkdir()
            (probe_root / "manifest.yaml").write_text(
                "agent_control_specification_version: 0.4.0-alpha.1\n"
                "metadata:\n  name: studio-startup\nextends: []\npolicies:\n"
                "  smoke:\n    type: rego\n    bundle: ./policy\n"
                "    query: data.agent_control_specification.smoke.verdict\n"
                "intervention_points:\n  input:\n    policy_target: $.input\n"
                "    policy_target_kind: user_input\n    policy:\n      id: smoke\n"
                "      query: data.agent_control_specification.smoke.input_verdict\n"
                "tools: {}\nannotators: {}\n", encoding="utf-8",
            )
            (probe_root / "policy" / "smoke.rego").write_text(
                'package agent_control_specification.smoke\n'
                'default input_verdict := {"decision": "allow"}\n', encoding="utf-8",
            )
            fixtures = probe_root / "fixtures.json"
            fixtures.write_text(
                '[{"id":"startup","input":{"action":"read"},"expected_verdict":"allow"}]',
                encoding="utf-8",
            )
            if not replay(probe_root / "manifest.yaml", fixtures).ok:
                raise ImportError("Native replay readiness check failed.")
        document = app.openapi()
        return {"openapi": document, "read_only": derive_studio_client_allowlist(document)}

    scope = command["scope"]
    scope["query_string"] = base64.b64decode(scope["query_string"])
    scope["headers"] = [(name.encode("latin1"), value.encode("latin1")) for name, value in scope["headers"]]
    body = base64.b64decode(command["body"])
    if command["source_root"] and scope["method"] == "POST":
        try:
            data = json.loads(body)
        except (ValueError, UnicodeError):
            data = None
        if isinstance(data, dict) and isinstance(data.get("policy_dir"), str):
            candidate = Path(data["policy_dir"]).resolve()
            source = Path(command["source_root"])
            if candidate.is_relative_to(source):
                data["policy_dir"] = str(root / candidate.relative_to(source))
                body = json.dumps(data).encode()
    messages = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        messages.append(message)
        if sum(len(item.get("body", b"")) for item in messages) > limits.response_bytes:
            raise ValueError("Response exceeds its finite limit.")

    await app(scope, receive, send)
    start = next(item for item in messages if item["type"] == "http.response.start")
    payload = b"".join(item.get("body", b"") for item in messages)
    if start["status"] >= 400:
        data = json.loads(payload)
        # Preserve field locations/types, but never reflect input, parser context or paths.
        if data.get("code") == "VALIDATION_ERROR":
            data["details"] = {"errors": [
                {"loc": item.get("loc", []), "type": item.get("type", ""), "msg": "Invalid field value"}
                for item in data.get("details", {}).get("errors", [])
            ]}
        else:
            data["details"] = {}
        if start["status"] == 500:
            data["message"] = "Internal engine error"
        payload = json.dumps(data).encode()
    return {"status": start["status"], "body": base64.b64encode(payload).decode()}


def main() -> None:
    # Wait for the parent to establish process-tree containment before importing engines.
    command = json.loads(sys.stdin.buffer.readline())
    logging.disable(logging.CRITICAL)
    with open(os.devnull, "w", encoding="utf-8") as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        try:
            result = asyncio.run(execute(command))
        except (ImportError, AttributeError):
            result = {"failure": "dependencies"}
        except (OSError, ValueError):
            result = {"failure": "policy-root"}
        except Exception:
            result = {"failure": "internal"}
    sys.stdout.write(json.dumps(result))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
