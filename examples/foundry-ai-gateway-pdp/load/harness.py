# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tiny latency harness for the Foundry AI Gateway + Functions PDP sample.

Sends synthetic decision requests directly to the PDP Function (or through
APIM if --url points at the gateway) and reports p50/p95/p99 latency plus
decision distribution. Use this to validate your own SLO before adopting
the pattern.

Usage:
    python load/harness.py --url https://<fn-host>/api/decide --rps 20 --duration 30
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import secrets
import statistics
import time
from collections import Counter

import urllib.request
import urllib.error

SCHEMA_VERSION = "1.0"
SAMPLE_TARGETS = [
    ("model.invoke", "gpt-4o"),
    ("tool.invoke", "github.create_issue"),
    ("tool.invoke", "github.delete_repo"),
    ("tool.invoke", "search.web"),
]


def _build_payload(i: int) -> bytes:
    operation, target = random.choice(SAMPLE_TARGETS)
    # Synthetic 32-byte hex string with the same shape as a real SHA-256
    # digest. The PDP only validates shape, not the hash itself.
    digest = secrets.token_hex(32)
    return json.dumps(
        {
            "schemaVersion": SCHEMA_VERSION,
            "agentId": f"agent-{i % 16:x}",
            "callerIdentity": "harness@example.com",
            "tenantId": "00000000-0000-0000-0000-000000000000",
            "environment": "dev",
            "operation": operation,
            "target": target,
            "inputDigest": f"sha256:{digest}",
            "correlationId": f"harness-{i}",
            "traceparent": "",
        }
    ).encode()


async def _send(url: str, payload: bytes) -> tuple[float, str]:
    loop = asyncio.get_running_loop()
    start = time.perf_counter()

    def _do_request() -> str:
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = json.loads(resp.read().decode())
                return body.get("decision", "unknown")
        except urllib.error.HTTPError as exc:
            return f"http_{exc.code}"
        except (urllib.error.URLError, TimeoutError):
            return "transport_error"

    decision = await loop.run_in_executor(None, _do_request)
    return (time.perf_counter() - start) * 1000.0, decision


async def _run(url: str, rps: int, duration: int) -> None:
    latencies: list[float] = []
    decisions: Counter[str] = Counter()
    interval = 1.0 / rps
    end_at = time.perf_counter() + duration
    i = 0

    async def _one(idx: int) -> None:
        elapsed, decision = await _send(url, _build_payload(idx))
        latencies.append(elapsed)
        decisions[decision] += 1

    tasks: list[asyncio.Task[None]] = []
    while time.perf_counter() < end_at:
        tasks.append(asyncio.create_task(_one(i)))
        i += 1
        await asyncio.sleep(interval)

    await asyncio.gather(*tasks)

    if not latencies:
        print("no samples collected")
        return

    latencies.sort()

    def _pct(p: float) -> float:
        # Nearest-rank percentile on a pre-sorted list (1-based rank).
        import math
        rank = max(1, math.ceil(p * len(latencies)))
        return latencies[rank - 1]

    print(f"samples: {len(latencies)}")
    print(f"p50: {_pct(0.50):.1f} ms")
    print(f"p95: {_pct(0.95):.1f} ms")
    print(f"p99: {_pct(0.99):.1f} ms")
    print(f"mean: {statistics.fmean(latencies):.1f} ms")
    print(f"decisions: {dict(decisions)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="PDP decide endpoint URL")
    parser.add_argument("--rps", type=int, default=10, help="Requests per second")
    parser.add_argument("--duration", type=int, default=15, help="Run duration (s)")
    args = parser.parse_args()

    asyncio.run(_run(args.url, args.rps, args.duration))


if __name__ == "__main__":
    main()
