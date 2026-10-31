# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import asyncio
import os
import shutil
import sys
import time

import httpx
import pytest

from test_lifecycle import launch, stop, unused_port, wait_ready
from test_limits import alive, wait_marker


@pytest.mark.asyncio
async def test_termination_during_startup_reaps_owned_descendants(tmp_path, slow_opa):
    port = unused_port()
    marker = tmp_path / "startup-pids"
    process = launch(sys.executable, tmp_path, port, env={
        **os.environ, "ACS_OPA_PATH": str(slow_opa), "STUDIO_TEST_PID_FILE": str(marker),
    })
    try:
        parent, child, scratch = await wait_marker(marker)
        started = time.monotonic()
        stop(process)
        assert time.monotonic() - started < 8
        assert not alive(parent) and not alive(child) and not scratch.exists()
        output = process.stdout.read()
        assert "Studio ready" not in output and "Traceback" not in output
        assert process.returncode == 0, output
    finally:
        stop(process)


@pytest.mark.asyncio
async def test_listener_shutdown_under_real_native_load_releases_port(tmp_path, policy_root, slow_opa):
    original = os.environ["ACS_OPA_PATH"]
    mutable = tmp_path / ("runtime.exe" if os.name == "nt" else "runtime")
    shutil.copy2(original, mutable)
    marker = tmp_path / "live-pids"
    port = unused_port()
    origin = f"http://127.0.0.1:{port}"
    process = launch(sys.executable, tmp_path, port, ("--policy-dir", str(policy_root)), env={
        **os.environ, "ACS_OPA_PATH": str(mutable), "STUDIO_TEST_PID_FILE": str(marker),
    })
    request = None
    try:
        await asyncio.to_thread(wait_ready, process, origin)
        shutil.copy2(slow_opa, mutable)
        async with httpx.AsyncClient(base_url=origin, timeout=15, headers={
            "Origin": origin, "X-AGT-Studio-Request": "1",
        }) as client:
            request = asyncio.create_task(client.post("/api/v1/policy/test", json={
                "policy_dir": str(policy_root / "replay"),
                "fixtures": [{"id": "shutdown", "input": {}, "expected_verdict": "allow"}],
            }))
            parent, child, scratch = await wait_marker(marker)
            started = time.monotonic()
            await asyncio.to_thread(stop, process)
            assert time.monotonic() - started < 8
            response = await request
            assert response.status_code == 503 and response.json()["code"] == "ENGINE_UNAVAILABLE"
            assert not alive(parent) and not alive(child) and not scratch.exists()
        output = process.stdout.read()
        assert "Traceback" not in output and process.returncode == 0, output
        restarted = launch(sys.executable, tmp_path, port)
        try:
            await asyncio.to_thread(wait_ready, restarted, origin)
        finally:
            stop(restarted)
        assert restarted.returncode == 0, restarted.stdout.read()
    finally:
        stop(process)
        if request is not None:
            await asyncio.gather(request, return_exceptions=True)
