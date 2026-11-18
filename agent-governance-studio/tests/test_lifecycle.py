# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest


def test_shutdown_signals_are_consumed_and_previous_handlers_restored():
    from agent_governance_studio.server import _shutdown_signals

    previous = {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)}
    received = []

    def handle(signum, _frame):
        received.append(signum)

    with _shutdown_signals(handle):
        signal.raise_signal(signal.SIGTERM)
        signal.raise_signal(signal.SIGINT)
    assert received == [signal.SIGTERM, signal.SIGINT]
    assert {signum: signal.getsignal(signum) for signum in previous} == previous


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def stop(process):
    if process.poll() is None:
        process.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGTERM)
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
            pytest.fail("Owned server did not shut down within eight seconds.")


def launch(python, cwd, port, extra=(), env=None):
    return subprocess.Popen(
        [str(python), "-I", "-c", "from agent_compliance.cli.agt import main; main()", "serve", "--port", str(port), *extra],
        cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
    )


def wait_ready(process, origin):
    deadline = time.monotonic() + 15
    with httpx.Client(base_url=origin, timeout=2) as client:
        while time.monotonic() < deadline:
            assert process.poll() is None, process.stdout.read()
            try:
                response = client.get("/api/v1/health")
                if response.status_code == 200:
                    assert response.json()["status"] == "ok"
                    return client.get("/api/v1/versions").json()
            except httpx.TransportError:
                # The listener may not be bound yet; retry only until the readiness deadline.
                pass
            time.sleep(0.05)
    raise AssertionError("No real HTTP readiness within fifteen seconds.")


def test_real_listener_replay_shutdown_release_restart(tmp_path, policy_root):
    port = unused_port()
    origin = f"http://127.0.0.1:{port}"
    for _ in range(2):
        process = launch(sys.executable, tmp_path, port, ("--policy-dir", str(policy_root)))
        try:
            versions = wait_ready(process, origin)
            assert versions["api"] == "1.0.0"
            headers = {"Origin": origin, "X-AGT-Studio-Request": "1"}
            with httpx.Client(base_url=origin, headers=headers, timeout=12) as client:
                result = client.post("/api/v1/policy/test", json={
                    "policy_dir": str(policy_root / "replay"),
                    "fixtures": [{"id": "real-listener", "input": {}, "expected_verdict": "allow"}],
                })
                assert result.status_code == 200, result.text
                assert result.json()["passed"] == 1
                assert client.get("/openapi.json", headers={"Origin": "null"}).status_code == 403
                assert client.get("/api/v1/health?private_query=never-log-this").status_code == 200
                def chunks(size):
                    yield b'{"content":"name: Chunked\\nrules: []","format":"yaml"}'
                    # The full streamed body is measured by the server, not its declared length.
                    yield b" " * size

                prefix_size = len(b'{"content":"name: Chunked\\nrules: []","format":"yaml"}')
                for size, status in ((8 * 1024 * 1024 - prefix_size, 200), (8 * 1024 * 1024 - prefix_size + 1, 413)):
                    response = client.post(
                        "/api/v1/policy/validate", content=chunks(size),
                        headers={"Content-Type": "application/json"},
                    )
                    assert response.status_code == status, response.text
        finally:
            stop(process)
        output = process.stdout.read()
        assert f"Studio ready at {origin}" in output
        assert "never-log-this" not in output and "Traceback" not in output
        assert process.returncode == 0, output
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", port))


def test_port_collision_nonzero_without_false_readiness(tmp_path):
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        process = launch(sys.executable, tmp_path, occupied.getsockname()[1])
        try:
            output, _ = process.communicate(timeout=15)
            assert process.returncode != 0 and "Cannot bind" in output
            assert "Studio ready" not in output and "Traceback" not in output
        finally:
            stop(process)


@pytest.mark.parametrize("arguments", [
    ("--host", "0.0.0.0"), ("--host", "::1"), ("--port", "0"),
    ("--port", "65536"), ("--port", "invalid"), ("--policy-dir", "missing-private-path"),
])
def test_invalid_cli_configuration_nonzero_before_listening(tmp_path, arguments):
    port = unused_port()
    process = launch(sys.executable, tmp_path, port, arguments)
    try:
        output, _ = process.communicate(timeout=10)
        assert process.returncode != 0 and "Studio ready" not in output
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", port))
    finally:
        stop(process)


def test_missing_native_backend_actionable_and_secret_safe(tmp_path):
    env = {**os.environ, "ACS_OPA_PATH": str(tmp_path / "private-secret-runtime")}
    process = launch(sys.executable, tmp_path, unused_port(), env=env)
    try:
        output, _ = process.communicate(timeout=15)
        assert process.returncode != 0 and "core/compliance/native ACS" in output and "OPA" in output
        assert "Studio ready" not in output and "private-secret-runtime" not in output and "Traceback" not in output
    finally:
        stop(process)


def test_clean_wheel_install_outside_checkout(tmp_path, policy_root):
    wheelhouse = Path(os.environ["AGT_STUDIO_TEST_WHEELHOUSE"])
    env_dir = tmp_path / "clean"
    subprocess.run([sys.executable, "-m", "venv", str(env_dir)], check=True, timeout=30)
    python = env_dir / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")
    completed = subprocess.run(
        [str(python), "-m", "pip", "install", "--no-index", "--find-links", str(wheelhouse), "agent-governance-studio==5.0.0"],
        cwd=tmp_path, capture_output=True, text=True, timeout=120,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    for arguments in (("--help",), ("serve", "--help")):
        result = subprocess.run(
            [str(python), "-I", "-c", "from agent_compliance.cli.agt import main; main()", *arguments],
            cwd=tmp_path, capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0 and "serve" in result.stdout
    result = subprocess.run(
        [str(python), "-I", "-c",
         "".join([
             "from importlib.metadata import distribution; from pathlib import Path;",
             "import agentmesh.engine_api,agent_compliance.policy_test,agent_governance_studio;",
             "assert any(str(p)=='agentmesh/engine_api/app.py' for p in distribution('agent-governance-toolkit-core').files);",
             "assert Path(agentmesh.engine_api.__file__).is_relative_to(Path(__import__('sys').prefix));",
             "print(agent_governance_studio.__file__)",
         ])],
        cwd=tmp_path, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert str(env_dir) in result.stdout
    port = unused_port()
    process = launch(python, tmp_path, port, ("--policy-dir", str(policy_root)))
    try:
        wait_ready(process, f"http://127.0.0.1:{port}")
    finally:
        stop(process)
    assert process.returncode == 0, process.stdout.read()
    missing = subprocess.run(
        [str(python), "-m", "pip", "uninstall", "-y", "fastapi"],
        capture_output=True, text=True, timeout=30,
    )
    assert missing.returncode == 0
    process = launch(python, tmp_path, unused_port())
    try:
        output, _ = process.communicate(timeout=10)
        assert process.returncode != 0 and "Studio runtime is missing or incompatible" in output
        assert "Traceback" not in output and "Studio ready" not in output
    finally:
        stop(process)
    repaired = subprocess.run(
        [str(python), "-m", "pip", "install", "--no-index", "--find-links", str(wheelhouse), "fastapi==0.141.1"],
        capture_output=True, text=True, timeout=30,
    )
    assert repaired.returncode == 0, repaired.stdout + repaired.stderr
    site = env_dir / "Lib" if os.name == "nt" else env_dir / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}"
    incompatible = site / "site-packages" / "agentmesh" / "engine_api" / "__init__.py"
    assert incompatible.is_file() and incompatible.is_relative_to(env_dir)
    incompatible.write_text(
        "# Copyright (c) Microsoft Corporation.\n# Licensed under the MIT License.\n"
        "raise AttributeError('deliberate-incompatible-private-detail')\n", encoding="utf-8",
    )
    process = launch(python, tmp_path, unused_port())
    try:
        output, _ = process.communicate(timeout=10)
        assert process.returncode != 0 and "core/compliance/native ACS" in output
        assert "deliberate-incompatible-private-detail" not in output and "Traceback" not in output
        assert "Studio ready" not in output
    finally:
        stop(process)
