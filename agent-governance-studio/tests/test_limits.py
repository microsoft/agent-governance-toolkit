# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import asyncio
import ctypes
import json
import os
import time
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from agent_governance_studio.application import create_sidecar
from agent_governance_studio.config import Configuration, ConfigurationError, Limits
from conftest import POLICY

HEADERS = {"Origin": "http://127.0.0.1:8080", "X-AGT-Studio-Request": "1"}


def alive(pid):
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            status = Path(f"/proc/{pid}/stat")
            return not (status.exists() and status.read_text(encoding="utf-8").split()[2] == "Z")
        except ProcessLookupError:
            return False
    import ctypes.wintypes as wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        return False
    code = wintypes.DWORD()
    try:
        assert kernel.GetExitCodeProcess(handle, ctypes.byref(code))
        return code.value == 259
    finally:
        kernel.CloseHandle(handle)


async def wait_marker(marker):
    deadline = time.monotonic() + 8
    while not marker.exists():
        assert time.monotonic() < deadline, "real native replay did not reach the failing executable"
        await asyncio.sleep(0.02)
    lines = marker.read_text(encoding="utf-8").splitlines()
    return int(lines[0]), int(lines[1]), Path(lines[2])


def assert_reaped(marker_data, app):
    parent, child, scratch = marker_data
    assert not alive(parent) and not alive(child)
    assert not scratch.exists()
    assert not app.workers.active


@pytest.mark.asyncio
@pytest.mark.parametrize("streamed", [False, True])
async def test_body_at_and_over_exact_limit(policy_root, streamed):
    data = json.dumps({"content": POLICY, "format": "yaml"}).encode()
    limit = len(data) + 16
    app = create_sidecar(Configuration(policy_dir=policy_root, limits=replace(Limits(), body_bytes=limit)))
    await app.start()
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://127.0.0.1:8080", headers=HEADERS) as client:
            async def chunks(payload):
                yield payload[:10]
                yield payload[10:]

            for size, status in ((limit, 200), (limit + 1, 413)):
                payload = data + b" " * (size - len(data))
                response = await client.post(
                    "/api/v1/policy/validate",
                    content=chunks(payload) if streamed else payload,
                    headers={"Content-Type": "application/json"},
                )
                assert response.status_code == status, response.text
                if status == 413:
                    assert response.json()["code"] == "VALIDATION_ERROR"
            assert not app.workers.active
    finally:
        await app.close()


def test_canonical_content_limit_exact_and_one_over(client):
    prefix = POLICY + "#"
    limit = 1024 * 1024
    for size, expected in ((limit, 200), (limit + 1, 422)):
        content = prefix + "x" * (size - len(prefix))
        response = client.post("/api/v1/policy/validate", json={"content": content, "format": "yaml"})
        assert response.status_code == expected, response.text
        if expected == 422:
            assert response.json()["code"] == "VALIDATION_ERROR"
            assert response.json()["details"]["errors"][0]["type"] == "string_too_long"


def test_canonical_fixture_count_exact_and_one_over(client):
    fixture = {"id": "fixture", "input": {}, "expected_verdict": "allow"}
    at = client.post("/api/v1/policy/test", json={"fixtures": [fixture] * 1000})
    assert at.status_code == 422 and at.json()["code"] == "FIXTURE_LOAD_ERROR"
    over = client.post("/api/v1/policy/test", json={"fixtures": [fixture] * 1001})
    assert over.status_code == 422 and over.json()["code"] == "VALIDATION_ERROR"
    assert over.json()["details"]["errors"][0]["type"] == "too_long"


@pytest.mark.asyncio
async def test_rate_exact_threshold_expiry_and_reserved_probes(policy_root):
    app = create_sidecar(Configuration(policy_dir=policy_root, limits=replace(Limits(), requests_per_minute=2)))
    await app.start()
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://127.0.0.1:8080", headers=HEADERS) as client:
            for _ in range(2):
                assert (await client.get("/openapi.json")).status_code == 200
            response = await client.get("/openapi.json")
            assert response.status_code == 429 and response.headers["retry-after"] == "60"
            assert (await client.get("/api/v1/health")).status_code == 200
            app.requests = type(app.requests)(stamp - 61 for stamp in app.requests)
            assert (await client.get("/openapi.json")).status_code == 200
    finally:
        await app.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["files", "file-bytes", "tree-bytes"])
async def test_inventory_exact_threshold_and_one_over(tmp_path, boundary):
    root = tmp_path / "root"
    root.mkdir()
    limits = Limits()
    if boundary == "files":
        limits = replace(limits, policy_files=2)
        (root / "a.yaml").write_text("name: A", encoding="utf-8")
        (root / "b.yaml").write_text("name: B", encoding="utf-8")
    else:
        limits = replace(limits, **{"policy_file_bytes" if boundary == "file-bytes" else "policy_tree_bytes": 64})
        (root / "a.yaml").write_bytes(b"#" + b"x" * 63)
    app = create_sidecar(Configuration(policy_dir=root, limits=limits))
    await app.start()
    await app.close()
    if boundary == "files":
        (root / "c.yaml").write_text("name: C", encoding="utf-8")
    else:
        with (root / "a.yaml").open("ab") as handle:
            handle.write(b"x")
    app = create_sidecar(Configuration(policy_dir=root, limits=limits))
    try:
        with pytest.raises(ConfigurationError, match="finite"):
            await app.start()
    finally:
        await app.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["timeout", "disconnect", "shutdown"])
async def test_real_slow_replay_tree_terminated_before_scratch_cleanup(policy_root, slow_opa, tmp_path, monkeypatch, mode):
    limits = replace(Limits(), execution_seconds=4 if mode == "timeout" else 15)
    app = create_sidecar(Configuration(policy_dir=policy_root, limits=limits))
    await app.start()
    marker = tmp_path / "owned-pids"
    monkeypatch.setenv("ACS_OPA_PATH", str(slow_opa))
    monkeypatch.setenv("STUDIO_TEST_PID_FILE", str(marker))
    body = json.dumps({
        "policy_dir": str(policy_root / "replay"),
        "fixtures": [{"id": "slow", "input": {}, "expected_verdict": "allow"}],
    }).encode()
    disconnect = asyncio.Event()
    delivered = False
    sent = []

    async def receive():
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        await disconnect.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http", "method": "POST", "path": "/api/v1/policy/test", "root_path": "",
        "http_version": "1.1", "scheme": "http", "query_string": b"",
        "headers": [(b"host", b"127.0.0.1:8080"), (b"origin", b"http://127.0.0.1:8080"),
                    (b"x-agt-studio-request", b"1"), (b"content-type", b"application/json")],
    }
    task = asyncio.create_task(app(scope, receive, send))
    try:
        marker_data = await wait_marker(marker)
        started = time.monotonic()
        if mode == "disconnect":
            disconnect.set()
        elif mode == "shutdown":
            await app.close()
        else:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://127.0.0.1:8080", headers=HEADERS) as client:
                assert (await client.get("/api/v1/health")).status_code == 200
        await asyncio.wait_for(task, 6)
        assert time.monotonic() - started < 6
        assert_reaped(marker_data, app)
        if mode == "timeout":
            assert sent[0]["status"] == 504
            assert json.loads(sent[-1]["body"])["code"] == "ENGINE_UNAVAILABLE"
        elif mode == "disconnect":
            assert not sent
    finally:
        disconnect.set()
        await app.close()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_concurrency_exact_admission_and_healthy_probe(policy_root, slow_opa, tmp_path, monkeypatch):
    app = create_sidecar(Configuration(policy_dir=policy_root, limits=replace(Limits(), concurrent_requests=1, execution_seconds=5)))
    await app.start()
    marker = tmp_path / "owned-pids"
    monkeypatch.setenv("ACS_OPA_PATH", str(slow_opa))
    monkeypatch.setenv("STUDIO_TEST_PID_FILE", str(marker))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://127.0.0.1:8080", headers=HEADERS) as client:
        request = asyncio.create_task(client.post("/api/v1/policy/test", json={
            "policy_dir": str(policy_root / "replay"),
            "fixtures": [{"id": "slow", "input": {}, "expected_verdict": "allow"}],
        }))
        try:
            marker_data = await wait_marker(marker)
            assert (await client.get("/api/v1/policies")).status_code == 429
            assert (await client.get("/api/v1/health")).status_code == 200
            assert (await request).status_code == 504
            assert_reaped(marker_data, app)
        finally:
            await app.close()
            await asyncio.gather(request, return_exceptions=True)


@pytest.mark.asyncio
async def test_stream_receive_deadline_and_huge_length_are_enveloped(policy_root):
    app = create_sidecar(Configuration(policy_dir=policy_root, limits=replace(Limits(), receive_seconds=0.05)))
    await app.start()
    messages = []

    async def receive():
        await asyncio.sleep(10)

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http", "method": "GET", "path": "/openapi.json", "root_path": "",
        "http_version": "1.1", "scheme": "http", "query_string": b"",
        "headers": [(b"host", b"127.0.0.1:8080")],
    }
    try:
        await app(scope, receive, send)
        assert messages[0]["status"] == 408
        messages.clear()
        scope["headers"].append((b"content-length", b"9" * 5000))
        await app(scope, receive, send)
        assert messages[0]["status"] == 422
    finally:
        await app.close()
